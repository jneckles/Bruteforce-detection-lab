# SSH Brute-Force Detection Lab

## Project Overview

This project is a Python-based SSH brute-force detection tool built for a student cybersecurity lab. It parses Linux authentication logs, identifies suspicious SSH login behavior, and produces analyst-friendly output in text, JSON, or CSV format.

The goal of this project is to demonstrate practical entry-level SOC and detection engineering skills:

- Parsing semi-structured Linux auth logs.
- Converting raw log lines into structured authentication events.
- Applying explainable detection logic with configurable thresholds.
- Detecting brute-force behavior within realistic time windows.
- Producing clear alert context for analyst triage.
- Writing unit tests for parsing and detection logic.

The detector is intentionally lightweight and uses only the Python standard library at runtime. `pytest` is included for local testing.

## Lab Architecture

The project was designed around a simple home-lab workflow:

```text
+------------------+        SSH traffic        +----------------------+
| Test workstation | -------------------------> | Ubuntu lab VM        |
| or Kali lab VM   |                            | OpenSSH server       |
+------------------+                            +----------------------+
                                                           |
                                                           | writes auth events
                                                           v
                                                  /var/log/auth.log
                                                           |
                                                           | parsed by
                                                           v
                                                detect_bruteforce.py
```

Recommended lab components:

- Ubuntu VM running OpenSSH Server as the monitored host.
- Separate testing host or VM to generate controlled SSH login attempts.
- `detect_bruteforce.py` running against `/var/log/auth.log` or an exported sample log.
- Optional `alerts.log` file for writing alert messages separately from the report output.

The included `sample_auth.log` uses fake usernames and documentation IP ranges, so it is safe to commit publicly.

## Repository Structure

```text
.
├── README.md
├── detect_bruteforce.py
├── findings.md
├── requirements.txt
├── sample_auth.log
└── tests
    └── test_detect_bruteforce.py
```

## Quick Start

Run the detector against the included sample log:

```bash
python3 detect_bruteforce.py --log-file sample_auth.log
```

Install test dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run unit tests:

```bash
python3 -m pytest -q
```

Show all CLI options:

```bash
python3 detect_bruteforce.py --help
```

## Attack Simulation Steps

Only run attack simulation in a lab environment you own or are explicitly authorized to test.

1. Set up an Ubuntu VM and install OpenSSH Server.

```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl enable --now ssh
```

2. Confirm SSH authentication events are being written.

```bash
sudo tail -f /var/log/auth.log
```

3. From a separate authorized lab machine, generate controlled failed SSH logins. For example, use a small test username list and password list against the lab VM only.

```bash
hydra -L users.txt -P passwords.txt ssh://<lab-vm-ip>
```

4. Run the detector against the Ubuntu auth log.

```bash
sudo python3 detect_bruteforce.py --log-file /var/log/auth.log --threshold 5
```

5. For real-time monitoring, use follow mode.

```bash
sudo python3 detect_bruteforce.py --log-file /var/log/auth.log --follow
```

6. For a safe GitHub demo without generating traffic, use the included sample log.

```bash
python3 detect_bruteforce.py --log-file sample_auth.log
```

## Detection Logic Summary

The script parses supported SSH authentication log lines into structured events with:

- Timestamp.
- Username.
- Source IP.
- Event type, such as failure or success.
- Weighted count for PAM summary messages.

It then applies four detection rules:

| Rule ID | What It Detects | Default Logic |
| --- | --- | --- |
| `repeated_failures_from_ip` | One IP repeatedly failing SSH logins. | 5 failures from one IP within 300 seconds |
| `repeated_failures_for_username` | One IP repeatedly targeting the same username. | 5 failures for one username within 300 seconds |
| `multiple_usernames_from_ip` | One IP trying several usernames. | 3 distinct usernames from one IP within 300 seconds |
| `success_after_many_failures` | Possible account compromise after guessing. | Successful login after 5 recent failures from the same IP |

This time-window approach is more useful than counting failures across the entire file. Five failures in 30 seconds is a stronger signal than five failures spread across several weeks.

## Output Formats

Text output is intended for quick analyst review:

```bash
python3 detect_bruteforce.py --log-file sample_auth.log --output-format text
```

JSON output is structured for SIEM-style ingestion:

```bash
python3 detect_bruteforce.py --log-file sample_auth.log --output-format json
```

CSV output is designed for Excel or spreadsheet review:

```bash
python3 detect_bruteforce.py --log-file sample_auth.log --output-format csv
```

## Sample Output

Example text output from `sample_auth.log`:

```text
============================================================
SSH BRUTE-FORCE DETECTION REPORT
============================================================
Log file: sample_auth.log
Total failed SSH login attempts: 9
Total successful SSH logins: 2
Detection window: 300 seconds
Success-after-failures window: 300 seconds

Thresholds:
- Repeated failures from IP: 5
- Repeated failures for username: 5
- Distinct usernames from IP: 3
- Success after failures: 5

Alerts:
- [WARNING] SSH brute-force activity from 192.0.2.44: this IP attempted 3 distinct usernames within 300 seconds; failed_attempts=3; usernames=admin, root, test; first_seen=2026-04-09 13:32:00; last_seen=2026-04-09 13:32:09
- [WARNING] SSH brute-force activity from 192.0.2.44: 5 failed logins from this IP within 300 seconds; failed_attempts=5; usernames=admin, backup, root, test, ubuntu; first_seen=2026-04-09 13:32:00; last_seen=2026-04-09 13:32:19
- [CRITICAL] SSH brute-force activity from 192.0.2.44: successful login for 'ubuntu' after 5 failures from this IP within 300 seconds; failed_attempts=5; usernames=admin, backup, root, test, ubuntu; first_seen=2026-04-09 13:32:00; last_seen=2026-04-09 13:32:19
```

Each detection includes the source IP, rule ID, failed-attempt evidence, targeted usernames, first-seen time, last-seen time, and a clear reason for why the activity was flagged.

## MITRE ATT&CK Mapping

| Technique | ID | Project Relevance |
| --- | --- | --- |
| Brute Force | `T1110` | The main detection focus is repeated SSH authentication failures. |
| Password Guessing | `T1110.001` | Repeated failures against the same username can indicate password guessing. |
| Password Spraying | `T1110.003` | One source IP attempting multiple usernames can indicate spraying or enumeration. |
| Valid Accounts | `T1078` | A successful login after multiple failures may indicate a guessed or compromised account. |

## Testing

The pytest suite covers:

- Parsing `Failed password for invalid user ...` lines.
- Parsing `Failed password for <user> ...` lines.
- Parsing `Accepted password for <user> ...` lines.
- Safely ignoring malformed log lines.
- Counting PAM summary failure events.
- Flagging repeated failures from a suspicious IP.
- Flagging successful login after multiple recent failures.

Run tests with:

```bash
python3 -m pytest -q
```

## Limitations

- The parser currently focuses on common IPv4 OpenSSH auth log formats.
- IPv6 source addresses are not currently parsed.
- Syslog lines without a year use the current year, which may misdate older rotated logs.
- The rules are threshold-based and do not include environment-specific baselining.
- The tool does not currently support allowlists for known scanners, VPN ranges, or admin jump hosts.
- Follow mode is useful for a lab but is not a replacement for a production log shipper or SIEM pipeline.
- Real production detections should include asset criticality, identity context, successful-login enrichment, and false-positive tuning.

## Future Improvements

- Add IPv6 parsing support.
- Add more OpenSSH log variants, including pre-auth disconnect and public-key failure patterns.
- Add allowlist support for known scanners and trusted admin networks.
- Add optional structured output for every parsed authentication event, not only detections.
- Add GitHub Actions CI to run pytest automatically on pull requests.
- Add configuration-file support for thresholds and environment-specific tuning.
- Add severity tuning for privileged usernames such as `root`, `admin`, or service accounts.

## Ethical Use

This project is for authorized lab testing, defensive learning, and portfolio demonstration. Do not run brute-force tools or authentication testing against systems you do not own or have explicit permission to assess.
