from pathlib import Path

import detect_bruteforce as detector


def test_parse_common_ssh_auth_log_variations():
    failed_invalid_user = detector.parse_auth_event(
        "Apr  9 13:32:00 ubuntu sshd[111]: Failed password for invalid user admin "
        "from 10.0.2.15 port 4455 ssh2",
        year=2026,
    )
    failed_known_user = detector.parse_auth_event(
        "Apr  9 13:32:01 ubuntu sshd[112]: Failed password for root "
        "from 10.0.2.16 port 4456 ssh2",
        year=2026,
    )
    accepted_password = detector.parse_auth_event(
        "Apr  9 13:32:02 ubuntu sshd[113]: Accepted password for jamarneckles "
        "from 10.0.2.17 port 4457 ssh2",
        year=2026,
    )

    assert failed_invalid_user == detector.AuthEvent(
        timestamp=detector.datetime(2026, 4, 9, 13, 32, 0),
        username="admin",
        source_ip="10.0.2.15",
        event_type=detector.EVENT_FAILURE,
    )
    assert failed_known_user == detector.AuthEvent(
        timestamp=detector.datetime(2026, 4, 9, 13, 32, 1),
        username="root",
        source_ip="10.0.2.16",
        event_type=detector.EVENT_FAILURE,
    )
    assert accepted_password == detector.AuthEvent(
        timestamp=detector.datetime(2026, 4, 9, 13, 32, 2),
        username="jamarneckles",
        source_ip="10.0.2.17",
        event_type=detector.EVENT_SUCCESS,
    )


def test_parse_auth_event_ignores_malformed_lines_safely():
    assert detector.parse_auth_event("this is not an auth log line", year=2026) is None
    assert (
        detector.parse_auth_event(
            "Bad 99 25:99:99 ubuntu sshd[999]: Failed password for root "
            "from 10.0.2.15 port 22 ssh2",
            year=2026,
        )
        is None
    )


def test_failed_login_counting_includes_pam_summary_counts():
    events = [
        detector.parse_auth_event(
            "Apr  9 13:32:00 ubuntu sshd[111]: Failed password for root "
            "from 10.0.2.15 port 4455 ssh2",
            year=2026,
        ),
        detector.parse_auth_event(
            "Apr  9 13:32:03 ubuntu sshd[111]: PAM 3 more authentication failures; "
            "logname= uid=0 euid=0 tty=ssh ruser= rhost=10.0.2.15 user=root",
            year=2026,
        ),
    ]

    result = detector.detect_bruteforce(
        events=[event for event in events if event is not None],
        log_path=Path("sample-auth.log"),
        config=detector.DetectionConfig(
            ip_failure_threshold=10,
            username_failure_threshold=10,
            username_spray_threshold=10,
            success_after_failures_threshold=10,
            window_seconds=300,
            success_window_seconds=300,
        ),
    )

    assert result.total_failed == 4
    assert result.attempts_by_ip["10.0.2.15"] == 4
    assert result.attempts_by_user["root"] == 4


def test_suspicious_ip_detection_flags_repeated_failures_in_window():
    events = [
        detector.parse_auth_event(
            f"Apr  9 13:32:0{second} ubuntu sshd[111]: Failed password for root "
            "from 10.0.2.15 port 4455 ssh2",
            year=2026,
        )
        for second in range(3)
    ]

    result = detector.detect_bruteforce(
        events=[event for event in events if event is not None],
        log_path=Path("sample-auth.log"),
        config=detector.DetectionConfig(
            ip_failure_threshold=3,
            username_failure_threshold=10,
            username_spray_threshold=10,
            success_after_failures_threshold=10,
            window_seconds=60,
            success_window_seconds=60,
        ),
    )

    assert len(result.findings) == 1
    assert result.findings[0].source_ip == "10.0.2.15"
    assert result.findings[0].rule_id == "repeated_failures_from_ip"
    assert result.findings[0].failed_attempts == 3


def test_successful_login_after_failures_is_flagged():
    events = [
        detector.parse_auth_event(
            f"Apr  9 13:32:0{second} ubuntu sshd[111]: Failed password for root "
            "from 10.0.2.15 port 4455 ssh2",
            year=2026,
        )
        for second in range(3)
    ]
    events.append(
        detector.parse_auth_event(
            "Apr  9 13:32:04 ubuntu sshd[113]: Accepted password for root "
            "from 10.0.2.15 port 4457 ssh2",
            year=2026,
        )
    )

    result = detector.detect_bruteforce(
        events=[event for event in events if event is not None],
        log_path=Path("sample-auth.log"),
        config=detector.DetectionConfig(
            ip_failure_threshold=10,
            username_failure_threshold=10,
            username_spray_threshold=10,
            success_after_failures_threshold=3,
            window_seconds=60,
            success_window_seconds=60,
        ),
    )

    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "success_after_many_failures"
    assert result.findings[0].source_ip == "10.0.2.15"
    assert result.findings[0].successful_username == "root"
    assert result.findings[0].failed_attempts == 3
