# Security Log Analyzer

A command-line tool that parses authentication and web-server logs, finds repeated failed logins and unusual patterns, and generates a structured **Markdown security incident report**. Built for the CodeNova Cyber Security Internship (Task 4).

## Safety and scope

- Use **sanitised or synthetic** logs only. The tool can generate its own synthetic logs.
- It only reads the log files you give it. It has no network features.
- Sample logs contain invented usernames and documentation-range IP addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Supported formats

- Linux `auth.log` (sshd): failed/accepted password or public-key logins and invalid users
- Apache/Nginx **combined** access logs: login attempts (HTTP 401/403 on login paths) and attack signatures

Lines that match neither format are counted as *unparsed* in the report.

## Detections

| Detection | Rule | Severity |
|---|---|---|
| Routine login errors | fewer than 5 failures from an IP (configurable) | LOW |
| Suspicious repeated failures | 5 or more failures from an IP | MEDIUM |
| Brute-force attack | 10 or more failures within 5 minutes from one IP | HIGH |
| Rapid sequential attempts | 5 or more failures within 10 seconds | HIGH |
| Successful login after repeated failures | success after at least the threshold number of failures from the same IP | CRITICAL |
| Off-hours login | successful login outside business hours (default 08:00-18:00) | MEDIUM |
| Username enumeration | 3 or more non-existent usernames tried from one IP | MEDIUM |
| SQL injection, XSS, path traversal signatures | pattern match on the decoded request | HIGH |
| Sensitive-path probing, scanner user-agents | e.g. `/.env`, `wp-login.php`, `sqlmap`, `nikto` | MEDIUM |

`Invalid user ...` lines are not counted as extra attempts because sshd also writes a matching `Failed password` line (no double counting).

The report distinguishes **routine errors** (a mistyped password) from **high-volume brute force** by count and by time window.

## Requirements

- Python 3.8 or newer
- No external packages. Markdown tables are built by a small helper function, so `tabulate` is not required.

## Usage

```
python task4.py --generate-sample
python task4.py sample_auth.log sample_access.log --year 2026 -o incident_report.md
```

Options:

| Option | Meaning | Default |
|---|---|---|
| `-o`, `--output` | report file | `incident_report.md` |
| `--year` | year for `auth.log` lines (they contain none) | current year |
| `--threshold` | failures that make an IP suspicious | 5 |
| `--work-start`, `--work-end` | business hours (24-hour clock) | 8, 18 |

## Report contents

1. Executive summary (files, lines parsed, incident counts, overall severity)
2. Failed logins by source IP, with classification, time range and usernames tried
3. Detected anomalies and incidents, sorted by severity
4. Attack signatures found in web logs
5. Severity key
6. Recommended actions and limitations

Your own generated report is saved as `incident_report.md`. Commit it to the repository as the sample incident report.

## Project files

```
task4.py
sample_auth.log          generated (synthetic)
sample_access.log        generated (synthetic)
incident_report.md       generated report
README.md
```

## Screenshots

<img width="486" height="83" alt="WhatsApp Image 2026-10-22 at 5 27 58 AM" src="https://github.com/user-attachments/assets/7e7257e4-5f21-46ea-b966-7baa933560ac" />
<img width="670" height="189" alt="WhatsApp Image 2026-10-22 at 5 28 26 AM" src="https://github.com/user-attachments/assets/1b41ab0d-c192-4ec7-b19b-0e88e65b2cec" />
<img width="518" height="188" alt="WhatsApp Image 2026-10-22 at 5 32 43 AM" src="https://github.com/user-attachments/assets/2e45fe3e-a435-4d33-ae2c-4d2bd0b25661" />
<img width="500" height="124" alt="WhatsApp Image 2026-10-22 at 5 33 56 AM" src="https://github.com/user-attachments/assets/f872a071-1ade-4bce-b1d6-056f9368a52a" />
<img width="956" height="193" alt="WhatsApp Image 2026-10-22 at 5 34 48 AM" src="https://github.com/user-attachments/assets/acecf367-b67a-4c0e-a940-e66f9cfe7359" />


## Limitations

- Pattern matching can produce false positives and only sees what was logged.
- `auth.log` lines have no year, so use `--year` for older logs.
- Only the formats listed above are parsed.
-
