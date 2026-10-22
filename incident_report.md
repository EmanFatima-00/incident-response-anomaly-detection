# Security Incident Report

**Generated:** 2026-10-22 05:28:07  
**Overall severity:** CRITICAL  
**Data:** sanitised / synthetic log files only

## 1. Executive Summary

| Metric | Value |
|---|---|
| Log files analysed | 2 |
| Lines read / parsed / unparsed | 159 / 159 / 0 |
| Distinct IPs with failed logins | 6 |
| Incidents (Critical / High / Medium) | 1 / 7 / 6 |

## 2. Failed Logins by Source IP

| Source IP | Failed | Max in 5 min | Classification | Severity | First seen | Last seen | Usernames tried |
|---|---|---|---|---|---|---|---|
| 203.0.113.50 | 40 | 40 | Brute-force attack | HIGH | 10-16 03:12:00 | 10-16 03:13:18 | admin, git, oracle, root, test... |
| 203.0.113.60 | 20 | 20 | Brute-force attack | HIGH | 10-16 01:05:00 | 10-16 01:05:57 |  |
| 203.0.113.77 | 12 | 12 | Brute-force attack | HIGH | 10-16 04:40:00 | 10-16 04:43:40 | carol |
| 198.51.100.99 | 6 | 2 | Suspicious repeated failures | MEDIUM | 10-16 13:02:00 | 10-16 13:17:00 | dave |
| 198.51.100.11 | 2 | 2 | Routine login errors | LOW | 10-16 11:05:00 | 10-16 11:05:09 | bob |
| 198.51.100.12 | 1 | 1 | Routine login errors | LOW | 10-16 12:00:00 | 10-16 12:00:00 |  |

*Classification: **Routine** = fewer than 5 failures; **Suspicious** = 5 or more; **Brute-force** = 10+ failures within 5 minutes.*

## 3. Detected Anomalies and Incidents

| Severity | Incident | Source IP | Details |
|---|---|---|---|
| **CRITICAL** | Successful login after repeated failures (possible compromise) | 203.0.113.77 | 12 failures then a success for user 'carol' (auth log). |
| **HIGH** | Brute-force attack | 203.0.113.60 | 20 failed logins, up to 20 within 5 minutes; 0 username(s) tried. |
| **HIGH** | Brute-force attack | 203.0.113.50 | 40 failed logins, up to 40 within 5 minutes; 6 username(s) tried. |
| **HIGH** | Rapid sequential login attempts | 203.0.113.50 | 6 failures within 10 seconds (automated behaviour). |
| **HIGH** | Brute-force attack | 203.0.113.77 | 12 failed logins, up to 12 within 5 minutes; 1 username(s) tried. |
| **HIGH** | SQL injection attempt | 203.0.113.99 | 1 matching request(s), e.g. /products?id=1%27%20OR%20%271%27=%271 |
| **HIGH** | Cross-site scripting (XSS) attempt | 203.0.113.99 | 1 matching request(s), e.g. /search?q=%3Cscript%3Ealert(1)%3C/script%3E |
| **HIGH** | Path traversal attempt | 203.0.113.99 | 1 matching request(s), e.g. /download?file=../../etc/passwd |
| **MEDIUM** | Username enumeration | 203.0.113.50 | 6 non-existent usernames tried: admin, git, oracle, root, test, ubuntu |
| **MEDIUM** | Off-hours login | 192.0.2.44 | Successful login for 'alice' at 02:30 (outside 08:00-18:00). |
| **MEDIUM** | Off-hours login | 203.0.113.77 | Successful login for 'carol' at 04:45 (outside 08:00-18:00). |
| **MEDIUM** | Sensitive file / admin path probing | 203.0.113.99 | 2 matching request(s), e.g. /.env |
| **MEDIUM** | Known scanner tool in User-Agent | 203.0.113.99 | 5 matching request(s), e.g. /.env |
| **MEDIUM** | Suspicious repeated failed logins | 198.51.100.99 | 6 failed logins (threshold 5). |

## 4. Attack Signatures (web logs)

| Source IP | Signature | Severity | Hits |
|---|---|---|---|
| 203.0.113.99 | SQL injection attempt | HIGH | 1 |
| 203.0.113.99 | Cross-site scripting (XSS) attempt | HIGH | 1 |
| 203.0.113.99 | Path traversal attempt | HIGH | 1 |
| 203.0.113.99 | Sensitive file / admin path probing | MEDIUM | 2 |
| 203.0.113.99 | Known scanner tool in User-Agent | MEDIUM | 5 |

## 5. Severity Key

- **CRITICAL** - likely compromise; act immediately
- **HIGH** - active attack pattern
- **MEDIUM** - suspicious, needs review
- **LOW** - routine errors (e.g. mistyped passwords)

## 6. Recommended Actions

- Block or rate-limit IPs flagged HIGH/CRITICAL (after review).
- Reset credentials and review sessions for any account in a CRITICAL incident.
- Enforce key-based SSH or MFA, and use fail2ban-style lockouts.
- Review off-hours logins with the account owner.

*Limitations: findings come from pattern matching on the supplied logs; they can include false positives and cannot see activity that was not logged.*
