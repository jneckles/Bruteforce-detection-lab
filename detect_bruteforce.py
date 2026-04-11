#!/usr/bin/env python3
"""
SSH brute-force detection CLI.

Parses Linux auth logs and identifies likely SSH brute-force activity using
several simple, explainable rules. Designed for a SOC-style home lab using
Ubuntu as the target and Kali as the attacker.
"""

import argparse
import csv
import json
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import TextIO


DEFAULT_IP_FAILURE_THRESHOLD = 5
DEFAULT_USERNAME_FAILURE_THRESHOLD = 5
DEFAULT_USERNAME_SPRAY_THRESHOLD = 3
DEFAULT_SUCCESS_AFTER_FAILURES_THRESHOLD = 5
DEFAULT_WINDOW_SECONDS = 300
DEFAULT_SUCCESS_WINDOW_SECONDS = 300
DEFAULT_TOP_USERS = 10
FOLLOW_POLL_SECONDS = 1.0

EVENT_FAILURE = "failure"
EVENT_SUCCESS = "success"

MONTHS = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}

TIMESTAMP_PATTERN = re.compile(
    r"^(?:(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))|"
    r"(?P<month>\w{3})\s+(?P<day>\d+)\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2}))"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:(?P<invalid_user>invalid user)\s+)?"
    r"(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

PAM_FAILURE_PATTERN = re.compile(
    r"PAM (?P<count>\d+) more authentication failures?.*?"
    r"rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+user=(?P<user>\S+))?"
)

ACCEPTED_LOGIN_PATTERN = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


@dataclass(frozen=True)
class AuthEvent:
    """A parsed SSH authentication event from an auth log line."""

    timestamp: datetime
    username: str
    source_ip: str
    event_type: str
    count: int = 1


@dataclass(frozen=True)
class DetectionConfig:
    """Runtime thresholds for SSH brute-force detection rules."""

    ip_failure_threshold: int
    username_failure_threshold: int
    username_spray_threshold: int
    success_after_failures_threshold: int
    window_seconds: int
    success_window_seconds: int


@dataclass(frozen=True)
class DetectionFinding:
    """A labeled detection finding for a suspicious source IP."""

    source_ip: str
    rule_id: str
    reason: str
    failed_attempts: int
    first_seen: datetime
    last_seen: datetime
    usernames: tuple[str, ...]
    successful_username: str | None = None
    success_time: datetime | None = None


@dataclass(frozen=True)
class DetectionResult:
    """Aggregated SSH brute-force detection results."""

    log_path: Path
    config: DetectionConfig
    parsed_events: int
    total_failed: int
    total_successful: int
    attempts_by_ip: dict[str, int]
    attempts_by_user: dict[str, int]
    findings: list[DetectionFinding]


def parse_timestamp(line: str, year: int) -> datetime | None:
    """Parse a timestamp from a supported auth log line."""
    match = TIMESTAMP_PATTERN.search(line)
    if not match:
        return None

    try:
        if match.group("iso"):
            timestamp = datetime.fromisoformat(
                match.group("iso").replace("Z", "+00:00")
            )
            if timestamp.tzinfo is not None:
                timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
            return timestamp

        month = MONTHS.get(match.group("month"))
        if month is None:
            return None

        day = int(match.group("day"))
        time_value = match.group("time")
        return datetime.strptime(
            f"{year}-{month:02d}-{day:02d} {time_value}",
            "%Y-%m-%d %H:%M:%S",
        )
    except (TypeError, ValueError):
        return None


def parse_failed_password_event(line: str, timestamp: datetime) -> AuthEvent | None:
    """Parse 'Failed password for ...' SSH auth log lines."""
    match = FAILED_PASSWORD_PATTERN.search(line)
    if not match:
        return None

    return AuthEvent(
        timestamp=timestamp,
        username=match.group("user"),
        source_ip=match.group("ip"),
        event_type=EVENT_FAILURE,
    )


def parse_pam_failure_event(line: str, timestamp: datetime) -> AuthEvent | None:
    """Parse PAM summary lines that combine multiple SSH auth failures."""
    match = PAM_FAILURE_PATTERN.search(line)
    if not match:
        return None

    try:
        count = int(match.group("count"))
    except (TypeError, ValueError):
        return None

    return AuthEvent(
        timestamp=timestamp,
        username=match.group("user") or "unknown",
        source_ip=match.group("ip"),
        event_type=EVENT_FAILURE,
        count=count,
    )


def parse_accepted_login_event(line: str, timestamp: datetime) -> AuthEvent | None:
    """Parse 'Accepted password for ...' and similar SSH success log lines."""
    match = ACCEPTED_LOGIN_PATTERN.search(line)
    if not match:
        return None

    return AuthEvent(
        timestamp=timestamp,
        username=match.group("user"),
        source_ip=match.group("ip"),
        event_type=EVENT_SUCCESS,
    )


def parse_auth_event(line: str, year: int) -> AuthEvent | None:
    """Parse a supported SSH authentication event from a single log line."""
    timestamp = parse_timestamp(line, year)
    if timestamp is None:
        return None

    parsers = (
        parse_failed_password_event,
        parse_pam_failure_event,
        parse_accepted_login_event,
    )
    for parser in parsers:
        try:
            event = parser(line, timestamp)
        except (IndexError, TypeError, ValueError):
            # Malformed or unexpected log lines should be ignored safely.
            continue

        if event is not None:
            return event

    return None


def read_auth_events(log_file: TextIO, year: int) -> list[AuthEvent]:
    """Read supported SSH authentication events from an open log file."""
    events = []

    for line in log_file:
        event = parse_auth_event(line, year)
        if event:
            events.append(event)

    return events


def event_count(events: list[AuthEvent]) -> int:
    """Return the weighted count for events that may summarize multiple attempts."""
    return sum(event.count for event in events)


def event_usernames(events: list[AuthEvent]) -> tuple[str, ...]:
    """Return sorted usernames observed in a group of auth events."""
    return tuple(sorted({event.username for event in events}))


def find_threshold_window(
    events: list[AuthEvent],
    threshold: int,
    window_seconds: int,
) -> list[AuthEvent]:
    """Return the first event window whose weighted count meets a threshold."""
    sorted_events = sorted(events, key=lambda event: event.timestamp)
    for start_index, start_event in enumerate(sorted_events):
        current_window = []
        current_count = 0

        for event in sorted_events[start_index:]:
            window_size = (event.timestamp - start_event.timestamp).total_seconds()
            if window_size > window_seconds:
                break

            current_window.append(event)
            current_count += event.count
            if current_count >= threshold:
                return current_window

    return []


def make_finding(
    source_ip: str,
    rule_id: str,
    reason: str,
    events: list[AuthEvent],
    successful_username: str | None = None,
    success_time: datetime | None = None,
) -> DetectionFinding:
    """Create a detection finding from the events that triggered a rule."""
    timestamps = [event.timestamp for event in events]
    return DetectionFinding(
        source_ip=source_ip,
        rule_id=rule_id,
        reason=reason,
        failed_attempts=event_count(events),
        first_seen=min(timestamps),
        last_seen=max(timestamps),
        usernames=event_usernames(events),
        successful_username=successful_username,
        success_time=success_time,
    )


def detect_repeated_failures_by_ip(
    failures_by_ip: dict[str, list[AuthEvent]],
    config: DetectionConfig,
) -> list[DetectionFinding]:
    """Detect repeated failed logins from the same source IP."""
    findings = []

    for source_ip, failures in failures_by_ip.items():
        window = find_threshold_window(
            failures,
            config.ip_failure_threshold,
            config.window_seconds,
        )
        if window:
            findings.append(
                make_finding(
                    source_ip=source_ip,
                    rule_id="repeated_failures_from_ip",
                    reason=(
                        f"{event_count(window)} failed logins from this IP within "
                        f"{config.window_seconds} seconds"
                    ),
                    events=window,
                )
            )

    return findings


def detect_repeated_failures_by_username(
    failures_by_ip: dict[str, list[AuthEvent]],
    config: DetectionConfig,
) -> list[DetectionFinding]:
    """Detect repeated failed logins against the same username from one IP."""
    findings = []

    for source_ip, failures in failures_by_ip.items():
        failures_by_username: dict[str, list[AuthEvent]] = defaultdict(list)
        for event in failures:
            failures_by_username[event.username].append(event)

        for username, username_failures in failures_by_username.items():
            window = find_threshold_window(
                username_failures,
                config.username_failure_threshold,
                config.window_seconds,
            )
            if window:
                findings.append(
                    make_finding(
                        source_ip=source_ip,
                        rule_id="repeated_failures_for_username",
                        reason=(
                            f"{event_count(window)} failed logins for username "
                            f"'{username}' from this IP within "
                            f"{config.window_seconds} seconds"
                        ),
                        events=window,
                    )
                )

    return findings


def detect_username_spraying(
    failures_by_ip: dict[str, list[AuthEvent]],
    config: DetectionConfig,
) -> list[DetectionFinding]:
    """Detect one source IP attempting multiple usernames in a short window."""
    findings = []

    for source_ip, failures in failures_by_ip.items():
        sorted_failures = sorted(failures, key=lambda event: event.timestamp)
        for start_index, start_event in enumerate(sorted_failures):
            current_window = []
            usernames = set()

            for event in sorted_failures[start_index:]:
                window_size = (event.timestamp - start_event.timestamp).total_seconds()
                if window_size > config.window_seconds:
                    break

                current_window.append(event)
                if event.username != "unknown":
                    usernames.add(event.username)

                if len(usernames) >= config.username_spray_threshold:
                    findings.append(
                        make_finding(
                            source_ip=source_ip,
                            rule_id="multiple_usernames_from_ip",
                            reason=(
                                f"this IP attempted {len(usernames)} distinct "
                                f"usernames within {config.window_seconds} seconds"
                            ),
                            events=current_window,
                        )
                    )
                    break

            if findings and findings[-1].source_ip == source_ip and (
                findings[-1].rule_id == "multiple_usernames_from_ip"
            ):
                break

    return findings


def detect_success_after_failures(
    failures_by_ip: dict[str, list[AuthEvent]],
    successes_by_ip: dict[str, list[AuthEvent]],
    config: DetectionConfig,
) -> list[DetectionFinding]:
    """Detect a successful login after many recent failures from the same IP."""
    findings = []

    for source_ip, successes in successes_by_ip.items():
        failures = sorted(
            failures_by_ip.get(source_ip, []),
            key=lambda event: event.timestamp,
        )
        if not failures:
            continue

        for success in sorted(successes, key=lambda event: event.timestamp):
            recent_failures = [
                failure
                for failure in failures
                if 0
                <= (success.timestamp - failure.timestamp).total_seconds()
                <= config.success_window_seconds
            ]
            if event_count(recent_failures) >= config.success_after_failures_threshold:
                findings.append(
                    make_finding(
                        source_ip=source_ip,
                        rule_id="success_after_many_failures",
                        reason=(
                            f"successful login for '{success.username}' after "
                            f"{event_count(recent_failures)} failures from this IP "
                            f"within {config.success_window_seconds} seconds"
                        ),
                        events=recent_failures,
                        successful_username=success.username,
                        success_time=success.timestamp,
                    )
                )
                break

    return findings


def deduplicate_findings(findings: list[DetectionFinding]) -> list[DetectionFinding]:
    """Remove duplicate findings while preserving rule-level explanations."""
    deduplicated = {}

    for finding in findings:
        key = (finding.source_ip, finding.rule_id, finding.usernames)
        current = deduplicated.get(key)
        if current is None or finding.failed_attempts > current.failed_attempts:
            deduplicated[key] = finding

    return sorted(
        deduplicated.values(),
        key=lambda finding: (finding.source_ip, finding.rule_id),
    )


def detect_bruteforce(
    events: list[AuthEvent],
    log_path: Path,
    config: DetectionConfig,
) -> DetectionResult:
    """Aggregate auth events and run SSH brute-force detection rules."""
    failures_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    successes_by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    attempts_by_ip: dict[str, int] = defaultdict(int)
    attempts_by_user: dict[str, int] = defaultdict(int)
    total_failed = 0
    total_successful = 0

    for event in events:
        if event.event_type == EVENT_FAILURE:
            total_failed += event.count
            failures_by_ip[event.source_ip].append(event)
            attempts_by_ip[event.source_ip] += event.count
            attempts_by_user[event.username] += event.count
        elif event.event_type == EVENT_SUCCESS:
            total_successful += event.count
            successes_by_ip[event.source_ip].append(event)

    findings = []
    findings.extend(detect_repeated_failures_by_ip(failures_by_ip, config))
    findings.extend(detect_repeated_failures_by_username(failures_by_ip, config))
    findings.extend(detect_username_spraying(failures_by_ip, config))
    findings.extend(
        detect_success_after_failures(failures_by_ip, successes_by_ip, config)
    )

    return DetectionResult(
        log_path=log_path,
        config=config,
        parsed_events=len(events),
        total_failed=total_failed,
        total_successful=total_successful,
        attempts_by_ip=dict(attempts_by_ip),
        attempts_by_user=dict(attempts_by_user),
        findings=deduplicate_findings(findings),
    )


def analyze_log(
    log_path: Path,
    config: DetectionConfig,
    year: int = datetime.now().year,
) -> DetectionResult:
    """Analyze a Linux auth log and return SSH brute-force detection results."""
    try:
        with log_path.open("r", errors="ignore") as log_file:
            events = read_auth_events(log_file, year)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {log_path}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {log_path}", file=sys.stderr)
        sys.exit(1)

    return detect_bruteforce(events, log_path, config)


def get_top_users(result: DetectionResult, limit: int) -> list[tuple[str, int]]:
    """Return the highest-count targeted usernames."""
    return sorted(
        result.attempts_by_user.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:limit]


def format_usernames(usernames: tuple[str, ...]) -> str:
    """Format usernames for human-readable reporting."""
    return ", ".join(usernames) if usernames else "unknown"


def alert_severity(finding: DetectionFinding, config: DetectionConfig) -> str:
    """Classify a finding into a simple alert severity."""
    if finding.rule_id == "success_after_many_failures":
        return "critical"

    if finding.failed_attempts >= config.ip_failure_threshold * 2:
        return "critical"

    if finding.rule_id in {"repeated_failures_from_ip", "multiple_usernames_from_ip"}:
        return "warning"

    return "info"


def alert_message(finding: DetectionFinding, config: DetectionConfig) -> str:
    """Build a clear human-readable alert message for a finding."""
    severity = alert_severity(finding, config).upper()
    return (
        f"[{severity}] SSH brute-force activity from {finding.source_ip}: "
        f"{finding.reason}; failed_attempts={finding.failed_attempts}; "
        f"usernames={format_usernames(finding.usernames)}; "
        f"first_seen={finding.first_seen}; last_seen={finding.last_seen}"
    )


def write_alert_to_log(
    finding: DetectionFinding,
    config: DetectionConfig,
    alerts_log: Path | None,
) -> None:
    """Append one alert to the optional alerts log file."""
    if alerts_log is None:
        return

    timestamp = datetime.now().isoformat(timespec="seconds")
    with alerts_log.open("a") as log_file:
        log_file.write(f"{timestamp} {alert_message(finding, config)}\n")


def write_alerts_to_log(
    findings: list[DetectionFinding],
    config: DetectionConfig,
    alerts_log: Path | None,
) -> None:
    """Append multiple alerts to the optional alerts log file."""
    for finding in findings:
        write_alert_to_log(finding, config, alerts_log)


def format_report(result: DetectionResult, top_users: int, verbose: bool) -> str:
    """Build a human-readable SSH brute-force detection report."""
    lines = [
        "=" * 60,
        "SSH BRUTE-FORCE DETECTION REPORT",
        "=" * 60,
        f"Log file: {result.log_path}",
        f"Total failed SSH login attempts: {result.total_failed}",
        f"Total successful SSH logins: {result.total_successful}",
        f"Detection window: {result.config.window_seconds} seconds",
        f"Success-after-failures window: {result.config.success_window_seconds} seconds",
        "",
        "Thresholds:",
        f"- Repeated failures from IP: {result.config.ip_failure_threshold}",
        f"- Repeated failures for username: {result.config.username_failure_threshold}",
        f"- Distinct usernames from IP: {result.config.username_spray_threshold}",
        (
            "- Success after failures: "
            f"{result.config.success_after_failures_threshold}"
        ),
    ]

    if verbose:
        lines.extend(
            [
                "",
                "Metadata:",
                f"- Parsed SSH auth events: {result.parsed_events}",
                f"- Unique source IPs with failures: {len(result.attempts_by_ip)}",
                f"- Unique targeted usernames: {len(result.attempts_by_user)}",
            ]
        )

    lines.append("")

    if not result.findings:
        lines.append("No likely brute-force activity detected with current thresholds.")
    else:
        lines.append("Alerts:")
        for finding in result.findings:
            lines.append(f"- {alert_message(finding, result.config)}")

        lines.append("")
        lines.append("Findings:")
        for finding in result.findings:
            lines.extend(
                [
                    f"- {finding.source_ip}",
                    f"  Severity: {alert_severity(finding, result.config)}",
                    f"  Rule: {finding.rule_id}",
                    f"  Detection reason: {finding.reason}",
                    f"  Failed attempts in evidence: {finding.failed_attempts}",
                    f"  Usernames targeted: {format_usernames(finding.usernames)}",
                    f"  First seen: {finding.first_seen}",
                    f"  Last seen:  {finding.last_seen}",
                ]
            )
            if finding.successful_username and finding.success_time:
                lines.extend(
                    [
                        f"  Successful username: {finding.successful_username}",
                        f"  Success time: {finding.success_time}",
                    ]
                )
            lines.append("")

    lines.append("Top targeted usernames:")
    for username, count in get_top_users(result, top_users):
        lines.append(f"- {username}: {count} failed attempts")

    return "\n".join(lines)


def finding_to_dict(
    finding: DetectionFinding,
    config: DetectionConfig,
) -> dict[str, object]:
    """Convert a detection finding to a JSON-serializable dictionary."""
    output: dict[str, object] = {
        "event_type": "ssh_bruteforce_detection",
        "alert_severity": alert_severity(finding, config),
        "alert_message": alert_message(finding, config),
        "source_ip": finding.source_ip,
        "rule_id": finding.rule_id,
        "detection_reason": finding.reason,
        "failed_attempts": finding.failed_attempts,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "usernames_targeted": list(finding.usernames),
    }

    if finding.successful_username and finding.success_time:
        output["successful_username"] = finding.successful_username
        output["success_time"] = finding.success_time.isoformat()

    return output


def result_to_dict(
    result: DetectionResult,
    top_users: int,
    verbose: bool,
) -> dict[str, object]:
    """Convert detection results to a JSON-serializable dictionary."""
    output: dict[str, object] = {
        "schema_version": "1.0",
        "event_type": "ssh_bruteforce_report",
        "log_file": str(result.log_path),
        "total_failed": result.total_failed,
        "total_successful": result.total_successful,
        "thresholds": {
            "ip_failure_threshold": result.config.ip_failure_threshold,
            "username_failure_threshold": result.config.username_failure_threshold,
            "username_spray_threshold": result.config.username_spray_threshold,
            "success_after_failures_threshold": (
                result.config.success_after_failures_threshold
            ),
            "window_seconds": result.config.window_seconds,
            "success_window_seconds": result.config.success_window_seconds,
        },
        "detections": [
            finding_to_dict(finding, result.config) for finding in result.findings
        ],
        "top_users": [
            {"username": username, "failed_attempts": count}
            for username, count in get_top_users(result, top_users)
        ],
    }

    if verbose:
        output["metadata"] = {
            "parsed_ssh_auth_events": result.parsed_events,
            "unique_source_ips_with_failures": len(result.attempts_by_ip),
            "unique_targeted_usernames": len(result.attempts_by_user),
        }

    return output


def format_json_report(
    result: DetectionResult,
    top_users: int,
    verbose: bool,
) -> str:
    """Build a JSON SSH brute-force detection report."""
    return json.dumps(result_to_dict(result, top_users, verbose), indent=2)


def csv_fieldnames() -> list[str]:
    """Return CSV columns shared by batch and follow modes."""
    return [
        "row_type",
        "alert_severity",
        "alert_message",
        "source_ip",
        "failed_attempts",
        "first_seen",
        "last_seen",
        "usernames_targeted",
        "detection_reason",
        "rule_id",
        "successful_username",
        "success_time",
        "metric",
        "value",
    ]


def finding_to_csv_row(
    finding: DetectionFinding,
    config: DetectionConfig,
) -> dict[str, object]:
    """Convert a finding to a flat CSV row."""
    return {
        "row_type": "detection",
        "alert_severity": alert_severity(finding, config),
        "alert_message": alert_message(finding, config),
        "source_ip": finding.source_ip,
        "failed_attempts": finding.failed_attempts,
        "first_seen": finding.first_seen.isoformat(),
        "last_seen": finding.last_seen.isoformat(),
        "usernames_targeted": ";".join(finding.usernames),
        "detection_reason": finding.reason,
        "rule_id": finding.rule_id,
        "successful_username": finding.successful_username or "",
        "success_time": finding.success_time.isoformat() if finding.success_time else "",
        "metric": "",
        "value": "",
    }


def format_csv_report(
    result: DetectionResult,
    top_users: int,
    verbose: bool,
) -> str:
    """Build a CSV SSH brute-force detection report."""
    output = StringIO()
    writer = csv.DictWriter(output, fieldnames=csv_fieldnames())
    writer.writeheader()

    for finding in result.findings:
        writer.writerow(finding_to_csv_row(finding, result.config))

    for username, count in get_top_users(result, top_users):
        writer.writerow(
            {
                "row_type": "top_user",
                "alert_severity": "",
                "alert_message": "",
                "source_ip": "",
                "failed_attempts": count,
                "first_seen": "",
                "last_seen": "",
                "usernames_targeted": username,
                "detection_reason": "",
                "rule_id": "",
                "successful_username": "",
                "success_time": "",
                "metric": "",
                "value": "",
            }
        )

    if verbose:
        metrics = {
            "total_failed": result.total_failed,
            "total_successful": result.total_successful,
            "parsed_ssh_auth_events": result.parsed_events,
            "unique_source_ips_with_failures": len(result.attempts_by_ip),
            "unique_targeted_usernames": len(result.attempts_by_user),
            "ip_failure_threshold": result.config.ip_failure_threshold,
            "username_failure_threshold": result.config.username_failure_threshold,
            "username_spray_threshold": result.config.username_spray_threshold,
            "success_after_failures_threshold": (
                result.config.success_after_failures_threshold
            ),
            "window_seconds": result.config.window_seconds,
            "success_window_seconds": result.config.success_window_seconds,
        }
        for metric, value in metrics.items():
            writer.writerow(
                {
                    "row_type": "metadata",
                    "alert_severity": "",
                    "alert_message": "",
                    "source_ip": "",
                    "failed_attempts": "",
                    "first_seen": "",
                    "last_seen": "",
                    "usernames_targeted": "",
                    "detection_reason": "",
                    "rule_id": "",
                    "successful_username": "",
                    "success_time": "",
                    "metric": metric,
                    "value": value,
                }
            )

    return output.getvalue().rstrip()


def format_output(
    result: DetectionResult,
    output_format: str,
    top_users: int,
    verbose: bool,
) -> str:
    """Build the requested output format."""
    if output_format == "json":
        return format_json_report(result, top_users, verbose)

    if output_format == "csv":
        return format_csv_report(result, top_users, verbose)

    return format_report(result, top_users, verbose)


def finding_key(finding: DetectionFinding) -> tuple[str, str, tuple[str, ...], str | None]:
    """Return a stable key used to suppress duplicate follow-mode alerts."""
    return (
        finding.source_ip,
        finding.rule_id,
        finding.usernames,
        finding.successful_username,
    )


def format_follow_text_alert(
    finding: DetectionFinding,
    config: DetectionConfig,
) -> str:
    """Build a compact human-readable alert for follow mode."""
    lines = [
        alert_message(finding, config),
        f"- Source IP: {finding.source_ip}",
        f"- Severity: {alert_severity(finding, config)}",
        f"- Rule: {finding.rule_id}",
        f"- Detection reason: {finding.reason}",
        f"- Failed attempts: {finding.failed_attempts}",
        f"- First seen: {finding.first_seen}",
        f"- Last seen:  {finding.last_seen}",
        f"- Usernames targeted: {format_usernames(finding.usernames)}",
    ]

    if finding.successful_username and finding.success_time:
        lines.extend(
            [
                f"- Successful username: {finding.successful_username}",
                f"- Success time: {finding.success_time}",
            ]
        )

    return "\n".join(lines)


def format_follow_json_alert(
    finding: DetectionFinding,
    result: DetectionResult,
    verbose: bool,
) -> str:
    """Build a newline-delimited JSON alert for follow mode."""
    output = finding_to_dict(finding, result.config)
    output["schema_version"] = "1.0"
    output["log_file"] = str(result.log_path)

    if verbose:
        output["thresholds"] = {
            "ip_failure_threshold": result.config.ip_failure_threshold,
            "username_failure_threshold": result.config.username_failure_threshold,
            "username_spray_threshold": result.config.username_spray_threshold,
            "success_after_failures_threshold": (
                result.config.success_after_failures_threshold
            ),
            "window_seconds": result.config.window_seconds,
            "success_window_seconds": result.config.success_window_seconds,
        }

    return json.dumps(output)


def write_follow_csv_header() -> None:
    """Write the CSV header used by follow-mode alerts."""
    writer = csv.DictWriter(sys.stdout, fieldnames=csv_fieldnames())
    writer.writeheader()
    sys.stdout.flush()


def write_follow_alert(
    finding: DetectionFinding,
    result: DetectionResult,
    output_format: str,
    verbose: bool,
    alerts_log: Path | None,
) -> None:
    """Write one follow-mode alert in the requested output format."""
    write_alert_to_log(finding, result.config, alerts_log)

    if output_format == "json":
        print(format_follow_json_alert(finding, result, verbose), flush=True)
        return

    if output_format == "csv":
        writer = csv.DictWriter(sys.stdout, fieldnames=csv_fieldnames())
        writer.writerow(finding_to_csv_row(finding, result.config))
        sys.stdout.flush()
        return

    print(format_follow_text_alert(finding, result.config), flush=True)
    print("", flush=True)


def prune_events(events: list[AuthEvent], newest_event: AuthEvent, retention: int) -> list[AuthEvent]:
    """Keep only events close enough to matter for future follow-mode detections."""
    return [
        event
        for event in events
        if (newest_event.timestamp - event.timestamp).total_seconds() <= retention
    ]


def file_identity(log_path: Path) -> tuple[int, int]:
    """Return the device/inode pair for a log path."""
    stat_result = log_path.stat()
    return stat_result.st_dev, stat_result.st_ino


def reopen_if_rotated(
    log_path: Path,
    log_file: TextIO,
    identity: tuple[int, int],
) -> tuple[TextIO, tuple[int, int]]:
    """Reopen the followed file if log rotation or truncation is detected."""
    try:
        current_identity = file_identity(log_path)
        current_size = log_path.stat().st_size
    except FileNotFoundError:
        # During rotation there can be a short gap before the new file appears.
        return log_file, identity

    if current_identity != identity:
        log_file.close()
        return log_path.open("r", errors="ignore"), current_identity

    if current_size < log_file.tell():
        # copytruncate-style rotation keeps the inode but resets file size.
        log_file.seek(0)

    return log_file, identity


def follow_log_file(
    log_path: Path,
    config: DetectionConfig,
    output_format: str,
    verbose: bool,
    alerts_log: Path | None,
    year: int = datetime.now().year,
) -> int:
    """Watch a log file like tail -f and alert on newly appended SSH events."""
    recent_events: list[AuthEvent] = []
    emitted_alerts: set[tuple[str, str, tuple[str, ...], str | None]] = set()
    retention_seconds = max(config.window_seconds, config.success_window_seconds)

    try:
        log_file = log_path.open("r", errors="ignore")
    except FileNotFoundError:
        print(f"[ERROR] File not found: {log_path}", file=sys.stderr)
        return 1
    except PermissionError:
        print(f"[ERROR] Permission denied: {log_path}", file=sys.stderr)
        return 1

    try:
        identity = file_identity(log_path)
        # Start at EOF so follow mode only processes newly appended lines.
        log_file.seek(0, 2)

        if output_format == "csv":
            write_follow_csv_header()
        elif verbose:
            print(f"[INFO] Following {log_path}; waiting for new lines.", file=sys.stderr)

        while True:
            line = log_file.readline()
            if not line:
                time.sleep(FOLLOW_POLL_SECONDS)
                # Reopen if the log path was rotated/recreated or truncated.
                log_file, identity = reopen_if_rotated(log_path, log_file, identity)
                continue

            event = parse_auth_event(line, year)
            if not event:
                continue

            recent_events.append(event)
            recent_events = prune_events(recent_events, event, retention_seconds)
            result = detect_bruteforce(recent_events, log_path, config)

            for finding in result.findings:
                key = finding_key(finding)
                if key in emitted_alerts:
                    continue

                # Suppress repeats unless the rule/user/success combination changes.
                emitted_alerts.add(key)
                write_follow_alert(
                    finding=finding,
                    result=result,
                    output_format=output_format,
                    verbose=verbose,
                    alerts_log=alerts_log,
                )
    finally:
        log_file.close()


def positive_int(value: str) -> int:
    """Parse a positive integer CLI argument."""
    try:
        parsed_value = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc

    if parsed_value < 1:
        raise argparse.ArgumentTypeError("must be greater than or equal to 1")

    return parsed_value


def build_argument_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Detect likely SSH brute-force attacks in Linux auth logs using "
            "multiple configurable rules: repeated failures from one IP, "
            "repeated failures for one username, username spraying, and "
            "successful login after many failures."
        )
    )
    parser.add_argument(
        "legacy_log_file",
        nargs="?",
        type=Path,
        help="Path to the auth log file (backward-compatible positional form)",
    )
    parser.add_argument(
        "legacy_threshold",
        nargs="?",
        type=positive_int,
        help=(
            "Repeated-IP failure threshold "
            "(backward-compatible positional form)"
        ),
    )
    parser.add_argument(
        "--log-file",
        dest="log_file",
        type=Path,
        help="Path to the auth log file",
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        help=(
            "Backward-compatible alias for --ip-failure-threshold "
            f"(default: {DEFAULT_IP_FAILURE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--ip-failure-threshold",
        type=positive_int,
        help=(
            "Failed-login threshold for repeated failures from one source IP "
            f"(default: {DEFAULT_IP_FAILURE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--username-failure-threshold",
        type=positive_int,
        default=DEFAULT_USERNAME_FAILURE_THRESHOLD,
        help=(
            "Failed-login threshold for one source IP attacking one username "
            f"(default: {DEFAULT_USERNAME_FAILURE_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--username-spray-threshold",
        type=positive_int,
        default=DEFAULT_USERNAME_SPRAY_THRESHOLD,
        help=(
            "Distinct-username threshold for one source IP "
            f"(default: {DEFAULT_USERNAME_SPRAY_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--success-after-failures-threshold",
        type=positive_int,
        default=DEFAULT_SUCCESS_AFTER_FAILURES_THRESHOLD,
        help=(
            "Failure threshold before a later successful login is flagged "
            f"(default: {DEFAULT_SUCCESS_AFTER_FAILURES_THRESHOLD})"
        ),
    )
    parser.add_argument(
        "--window-seconds",
        type=positive_int,
        default=DEFAULT_WINDOW_SECONDS,
        help=(
            "Detection window for failure burst and username-spray rules "
            f"(default: {DEFAULT_WINDOW_SECONDS})"
        ),
    )
    parser.add_argument(
        "--success-window-seconds",
        type=positive_int,
        default=DEFAULT_SUCCESS_WINDOW_SECONDS,
        help=(
            "Lookback window for successful login after failures "
            f"(default: {DEFAULT_SUCCESS_WINDOW_SECONDS})"
        ),
    )
    parser.add_argument(
        "--output-format",
        choices=("text", "json", "csv"),
        default="text",
        help="Report output format (default: text)",
    )
    parser.add_argument(
        "--top-users",
        type=positive_int,
        default=DEFAULT_TOP_USERS,
        help=f"Number of targeted usernames to include (default: {DEFAULT_TOP_USERS})",
    )
    parser.add_argument(
        "--follow",
        action="store_true",
        help=(
            "Watch the log like tail -f. Starts at the current end of the file "
            "and only processes newly appended lines."
        ),
    )
    parser.add_argument(
        "--alerts-log",
        type=Path,
        help="Optional path to append clear text alert messages, for example alerts.log",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Include additional parsing and aggregation metadata",
    )
    return parser


def resolve_cli_options(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> tuple[Path, DetectionConfig]:
    """Resolve new flags and legacy positional arguments into final settings."""
    log_path = args.log_file or args.legacy_log_file
    if log_path is None:
        parser.error("the following argument is required: --log-file or legacy_log_file")

    ip_failure_threshold = (
        args.ip_failure_threshold
        or args.threshold
        or args.legacy_threshold
        or DEFAULT_IP_FAILURE_THRESHOLD
    )
    config = DetectionConfig(
        ip_failure_threshold=ip_failure_threshold,
        username_failure_threshold=args.username_failure_threshold,
        username_spray_threshold=args.username_spray_threshold,
        success_after_failures_threshold=args.success_after_failures_threshold,
        window_seconds=args.window_seconds,
        success_window_seconds=args.success_window_seconds,
    )
    return log_path, config


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)
    log_path, config = resolve_cli_options(args, parser)

    if args.follow:
        try:
            return follow_log_file(
                log_path=log_path,
                config=config,
                output_format=args.output_format,
                verbose=args.verbose,
                alerts_log=args.alerts_log,
            )
        except KeyboardInterrupt:
            print("\n[INFO] Stopped following log file.", file=sys.stderr)
            return 0

    result = analyze_log(log_path=log_path, config=config)
    write_alerts_to_log(result.findings, result.config, args.alerts_log)
    print(format_output(result, args.output_format, args.top_users, args.verbose))
    return 0


if __name__ == "__main__":
    sys.exit(main())
