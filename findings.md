# Detection Engineering Findings

## Summary

This project detects likely SSH brute-force activity from Linux auth logs using small, explainable rules. The goal is not to build a full SIEM, but to show the core workflow of a detection engineering project: parse logs, normalize events, define suspicious behavior, tune thresholds, produce analyst-friendly output, and validate the logic with tests.

## Sample Detection Scenario

The included `sample_auth.log` contains safe, fake SSH authentication events using documentation IP ranges. One source IP, `192.0.2.44`, attempts multiple usernames within a short period and then successfully logs in. This should trigger multiple suspicious behaviors:

- Repeated failed logins from the same source IP.
- One source IP trying multiple usernames.
- A successful login after many recent failures.

These patterns are realistic enough for a student SOC lab because they map to common SSH brute-force and account-guessing investigation questions:

- Which IP generated the failures?
- Which usernames were targeted?
- Did the activity happen in a short burst?
- Was there a later successful login from the same source?
- What evidence supports the alert?

## Detection Rules

| Rule | Purpose | Default Threshold |
| --- | --- | --- |
| `repeated_failures_from_ip` | Flags repeated SSH failures from one source IP within a time window. | 5 failures / 300 seconds |
| `repeated_failures_for_username` | Flags repeated failures against one username from the same IP. | 5 failures / 300 seconds |
| `multiple_usernames_from_ip` | Flags one IP attempting multiple usernames. | 3 usernames / 300 seconds |
| `success_after_many_failures` | Flags successful login after recent failures from the same IP. | 5 failures / 300 seconds |

## Strengths

- Uses compiled regex patterns for common SSH auth log formats.
- Separates parsing, detection, reporting, CLI handling, and alerting logic.
- Supports text, JSON, and CSV output for different analyst workflows.
- Includes configurable thresholds and time windows.
- Handles malformed lines safely instead of crashing.
- Includes pytest coverage for parsing and detection behavior.
- Uses safe sample data suitable for a public GitHub repository.

## Known Limitations

- The parser currently focuses on IPv4 SSH authentication events.
- Syslog lines without a year use the current year, which can be inaccurate for old or rotated logs.
- The detection logic is threshold-based and does not include baselining, allowlists, or asset context.
- Follow mode is intentionally simple and is not a replacement for a production log shipper.
- The project does not parse every OpenSSH authentication message variant.

## Tuning Notes

Default thresholds are meant for a small lab environment. In a real environment, tuning should consider:

- Normal failed-login volume for administrators and service accounts.
- Whether the source IP belongs to a VPN, NAT gateway, vulnerability scanner, or jump host.
- Whether the target system is internet-facing.
- Whether successful login after failures should always be high priority.
- Whether username-spraying thresholds should be different for privileged usernames.

## Analyst Workflow

1. Run the detector against a saved auth log.
2. Review the alert severity, source IP, detection reason, and targeted usernames.
3. Check whether a successful login happened after the failures.
4. Compare the source IP against known admin networks, scanners, or expected automation.
5. Export JSON or CSV output for case notes, enrichment, or SIEM-style ingestion.

## Future Improvements

- Add IPv6 support.
- Add support for more OpenSSH log variants, including preauth disconnect patterns.
- Add an allowlist file for known scanners or trusted admin networks.
- Add severity tuning based on privileged usernames such as `root`.
- Add structured event output for every parsed auth event, not only detections.
- Add GitHub Actions CI to run pytest automatically on pull requests.

