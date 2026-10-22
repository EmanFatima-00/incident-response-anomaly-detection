"""
task4.py - Security Log Analyzer (CodeNova Cyber Security Internship, Task 4)

Parses Linux auth.log (sshd) and Apache/Nginx access logs, finds repeated
failed logins per source IP, detects anomalies (off-hours logins, rapid
sequential attempts, success-after-failures, known attack signatures) and
writes a Markdown security incident report with tables and severity flags.

SAFETY: it only READS the log files you give it. It has no network features.
Use sanitised or synthetic logs only. This script can generate such logs.

Usage (Windows):
  python task4.py --generate-sample
  python task4.py sample_auth.log sample_access.log -o incident_report.md
Options:
  --year 2026        year for auth.log lines (they contain no year)
  --threshold 5      failed attempts that make an IP "suspicious"
  --work-start 8 --work-end 18   business hours (24h clock) for off-hours check

Only the Python standard library is used. (The 'tabulate' package is not
needed; Markdown tables are built by a small helper function below.)
"""

import argparse
import datetime as dt
import random
import re
import sys
from collections import defaultdict
from urllib.parse import unquote

BRUTE_FORCE_ATTEMPTS = 10   # failures inside the window => brute force
WINDOW_SECONDS = 300        # 5-minute sliding window
RAPID_ATTEMPTS = 5          # this many failures ...
RAPID_SECONDS = 10          # ... inside this many seconds => rapid attempts
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
     "Nov", "Dec"], 1)}

# ------------------------------------------------------------- log formats
AUTH_LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+(?P<msg>.*)$")
AUTH_FAIL = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)")
AUTH_OK = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+)")
AUTH_INVALID = re.compile(
    r"Invalid user (?P<user>\S*) from (?P<ip>[0-9a-fA-F:.]+)")
WEB_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) '
    r'(?P<path>\S+)[^"]*" (?P<status>\d{3}) \S+'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?')
LOGIN_PATH = re.compile(r"login|signin|auth|wp-admin|admin", re.IGNORECASE)

# Known attack signatures: (name, severity, regex on the decoded request)
SIGNATURES = [
    ("SQL injection attempt", "HIGH",
     re.compile(r"union\s+select|' ?or ?'?1'?='?1|sleep\(\d+\)|;\s*drop\s+table"
                r"|information_schema", re.I)),
    ("Cross-site scripting (XSS) attempt", "HIGH",
     re.compile(r"<script|onerror\s*=|javascript:", re.I)),
    ("Path traversal attempt", "HIGH",
     re.compile(r"\.\./|\.\.\\|/etc/passwd|boot\.ini", re.I)),
    ("Sensitive file / admin path probing", "MEDIUM",
     re.compile(r"/\.env|/\.git|wp-login\.php|phpmyadmin|/xmlrpc\.php"
                r"|/server-status", re.I)),
    ("Known scanner tool in User-Agent", "MEDIUM",
     re.compile(r"sqlmap|nikto|nmap|masscan|hydra|dirbuster|gobuster", re.I)),
]
# ----------------------------------------------------------------- parsing
def parse_logs(paths, year):
    """Read every file; return (events, signature_hits, invalid_users, stats)."""
    events, hits = [], []
    invalid = defaultdict(set)          # ip -> usernames that do not exist
    stats = {"lines": 0, "parsed": 0, "unparsed": 0, "files": []}

    for path in paths:
        count_before = stats["parsed"]
        try:
            fh = open(path, "r", encoding="utf-8", errors="replace")
        except OSError as err:
            raise SystemExit(f"Error: cannot open '{path}': {err.strerror}")
        with fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line.strip():
                    continue
                stats["lines"] += 1
                if parse_auth_line(line, year, path, events, invalid):
                    stats["parsed"] += 1
                elif parse_web_line(line, path, events, hits):
                    stats["parsed"] += 1
                else:
                    stats["unparsed"] += 1
        stats["files"].append((path, stats["parsed"] - count_before))
    events.sort(key=lambda e: e["ts"])
    hits.sort(key=lambda h: h["ts"])
    return events, hits, invalid, stats


def parse_auth_line(line, year, source, events, invalid):
    m = AUTH_LINE.match(line)
    if not m or m["mon"] not in MONTHS:
        return False
    try:
        ts = dt.datetime.strptime(
            f"{year} {MONTHS[m['mon']]} {m['day']} {m['time']}",
            "%Y %m %d %H:%M:%S")
    except ValueError:
        return False
    msg = m["msg"]
    for regex, kind in ((AUTH_FAIL, "fail"), (AUTH_OK, "success")):
        found = regex.search(msg)
        if found:
            events.append({"ts": ts, "ip": found["ip"], "kind": kind,
                           "user": found["user"], "source": "auth"})
            return True
    found = AUTH_INVALID.search(msg)
    if found:       # not counted as an attempt (sshd also logs "Failed ...")
        invalid[found["ip"]].add(found["user"] or "(empty)")
        return True
    return True     # a valid auth.log line we do not need (e.g. session open)


def parse_web_line(line, source, events, hits):
    m = WEB_LINE.match(line)
    if not m:
        return False
    try:
        ts = dt.datetime.strptime(m["ts"], "%d/%b/%Y:%H:%M:%S %z").replace(
            tzinfo=None)
    except ValueError:
        return False
    ip, path, status = m["ip"], m["path"], int(m["status"])
    decoded = unquote(unquote(path)) + " " + (m["ua"] or "")
    for name, severity, regex in SIGNATURES:
        if regex.search(decoded):
            hits.append({"ts": ts, "ip": ip, "name": name,
                         "severity": severity, "detail": path[:70]})
    if LOGIN_PATH.search(path.split("?")[0]):
        if status in (401, 403):
            events.append({"ts": ts, "ip": ip, "kind": "fail",
                           "user": "-", "source": "web"})
        elif status in (200, 302) and m["method"] == "POST":
            events.append({"ts": ts, "ip": ip, "kind": "success",
                           "user": "-", "source": "web"})
    return True


# ---------------------------------------------------------------- analysis
def max_in_window(times, seconds):
    """Largest number of timestamps inside any sliding window."""
    best, left = 0, 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def analyze(events, hits, invalid, threshold, work_start, work_end):
    per_ip = {}
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)

    incidents = []

    def incident(sev, title, ip, detail, when):
        incidents.append({"severity": sev, "title": title, "ip": ip,
                          "detail": detail, "time": when})

    for ip, evs in by_ip.items():
        fails = [e for e in evs if e["kind"] == "fail"]
        succ = [e for e in evs if e["kind"] == "success"]
        ftimes = [e["ts"] for e in fails]
        window = max_in_window(ftimes, WINDOW_SECONDS) if fails else 0
        rapid = max_in_window(ftimes, RAPID_SECONDS) if fails else 0
        users = sorted({e["user"] for e in fails if e["user"] != "-"})

        if window >= BRUTE_FORCE_ATTEMPTS:
            cls, sev = "Brute-force attack", "HIGH"
        elif len(fails) >= threshold:
            cls, sev = "Suspicious repeated failures", "MEDIUM"
        elif fails:
            cls, sev = "Routine login errors", "LOW"
        else:
            cls, sev = "-", "-"
        per_ip[ip] = {"fails": len(fails), "window": window, "rapid": rapid,
                      "users": users, "class": cls, "severity": sev,
                      "first": ftimes[0] if fails else None,
                      "last": ftimes[-1] if fails else None}

        if cls == "Brute-force attack":
            incident("HIGH", "Brute-force attack", ip,
                     f"{len(fails)} failed logins, up to {window} within "
                     f"{WINDOW_SECONDS // 60} minutes; "
                     f"{len(users)} username(s) tried.", ftimes[0])
        elif cls == "Suspicious repeated failures":
            incident("MEDIUM", "Suspicious repeated failed logins", ip,
                     f"{len(fails)} failed logins (threshold {threshold}).",
                     ftimes[0])
        if rapid >= RAPID_ATTEMPTS:
            incident("HIGH", "Rapid sequential login attempts", ip,
                     f"{rapid} failures within {RAPID_SECONDS} seconds "
                     f"(automated behaviour).", ftimes[0])

        # Success after many failures => possible compromised account
        for s in succ:
            before = [t for t in ftimes if t < s["ts"]]
            if len(before) >= threshold:
                incident("CRITICAL", "Successful login after repeated "
                         "failures (possible compromise)", ip,
                         f"{len(before)} failures then a success for user "
                         f"'{s['user']}' ({s['source']} log).", s["ts"])
                break

        # Off-hours successful logins
        for s in succ:
            if not (work_start <= s["ts"].hour < work_end):
                incident("MEDIUM", "Off-hours login", ip,
                         f"Successful login for '{s['user']}' at "
                         f"{s['ts']:%H:%M} (outside {work_start:02d}:00-"
                         f"{work_end:02d}:00).", s["ts"])

    for ip, names in invalid.items():
        if len(names) >= 3:
            incident("MEDIUM", "Username enumeration", ip,
                     f"{len(names)} non-existent usernames tried: "
                     + ", ".join(sorted(names)[:6]), dt.datetime.min)

    sig_summary = defaultdict(lambda: {"count": 0, "severity": "LOW",
                                       "first": None, "example": ""})
    for h in hits:
        entry = sig_summary[(h["ip"], h["name"])]
        entry["count"] += 1
        entry["severity"] = h["severity"]
        entry["first"] = entry["first"] or h["ts"]
        entry["example"] = entry["example"] or h["detail"]
    for (ip, name), s in sig_summary.items():
        incident(s["severity"], name, ip,
                 f"{s['count']} matching request(s), e.g. {s['example']}",
                 s["first"])

    incidents.sort(key=lambda i: (-SEVERITY_ORDER[i["severity"]], i["time"]))
    return per_ip, incidents, sig_summary
# ------------------------------------------------------------------ report
def md_table(headers, rows):
    """Build a Markdown table (so no extra package is needed)."""
    esc = lambda x: str(x).replace("|", "\\|")
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(esc(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def build_report(files, stats, per_ip, incidents, sig_summary, threshold):
    overall = max((i["severity"] for i in incidents),
                  key=lambda s: SEVERITY_ORDER[s], default="NONE")
    counts = {s: sum(1 for i in incidents if i["severity"] == s)
              for s in SEVERITY_ORDER}
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    L = ["# Security Incident Report", "",
         f"**Generated:** {now}  ",
         f"**Overall severity:** {overall}  ",
         "**Data:** sanitised / synthetic log files only", "",
         "## 1. Executive Summary", ""]
    L.append(md_table(["Metric", "Value"], [
        ["Log files analysed", len(files)],
        ["Lines read / parsed / unparsed",
         f"{stats['lines']} / {stats['parsed']} / {stats['unparsed']}"],
        ["Distinct IPs with failed logins",
         sum(1 for v in per_ip.values() if v["fails"])],
        ["Incidents (Critical / High / Medium)",
         f"{counts['CRITICAL']} / {counts['HIGH']} / {counts['MEDIUM']}"],
    ]))
    L += ["", "## 2. Failed Logins by Source IP", ""]
    ranked = sorted((kv for kv in per_ip.items() if kv[1]["fails"]),
                    key=lambda kv: -kv[1]["fails"])
    if ranked:
        L.append(md_table(
            ["Source IP", "Failed", "Max in 5 min", "Classification",
             "Severity", "First seen", "Last seen", "Usernames tried"],
            [[ip, v["fails"], v["window"], v["class"], v["severity"],
              f"{v['first']:%m-%d %H:%M:%S}", f"{v['last']:%m-%d %H:%M:%S}",
              ", ".join(v["users"][:5]) + ("..." if len(v["users"]) > 5 else "")]
             for ip, v in ranked]))
        L += ["", f"*Classification: **Routine** = fewer than {threshold} "
              f"failures; **Suspicious** = {threshold} or more; "
              f"**Brute-force** = {BRUTE_FORCE_ATTEMPTS}+ failures within "
              f"{WINDOW_SECONDS // 60} minutes.*"]
    else:
        L.append("No failed logins found.")

    L += ["", "## 3. Detected Anomalies and Incidents", ""]
    if incidents:
        L.append(md_table(
            ["Severity", "Incident", "Source IP", "Details"],
            [[f"**{i['severity']}**", i["title"], i["ip"], i["detail"]]
             for i in incidents]))
    else:
        L.append("No incidents detected.")

    L += ["", "## 4. Attack Signatures (web logs)", ""]
    if sig_summary:
        L.append(md_table(
            ["Source IP", "Signature", "Severity", "Hits"],
            [[ip, name, s["severity"], s["count"]]
             for (ip, name), s in sorted(
                 sig_summary.items(),
                 key=lambda kv: -SEVERITY_ORDER[kv[1]["severity"]])]))
    else:
        L.append("No known attack signatures matched.")

    L += ["", "## 5. Severity Key", "",
          "- **CRITICAL** - likely compromise; act immediately",
          "- **HIGH** - active attack pattern",
          "- **MEDIUM** - suspicious, needs review",
          "- **LOW** - routine errors (e.g. mistyped passwords)", "",
          "## 6. Recommended Actions", "",
          "- Block or rate-limit IPs flagged HIGH/CRITICAL (after review).",
          "- Reset credentials and review sessions for any account in a "
          "CRITICAL incident.",
          "- Enforce key-based SSH or MFA, and use fail2ban-style lockouts.",
          "- Review off-hours logins with the account owner.", "",
          "*Limitations: findings come from pattern matching on the supplied "
          "logs; they can include false positives and cannot see activity "
          "that was not logged.*", ""]
    return "\n".join(L), overall


COLOURS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
           "LOW": "\033[92m", "NONE": "\033[92m"}
RESET, BOLD = "\033[0m", "\033[1m"


def print_summary(stats, per_ip, incidents, overall, out_path):
    print("=" * 66)
    print(f"{BOLD}SECURITY LOG ANALYSIS{RESET}")
    print("=" * 66)
    for path, n in stats["files"]:
        print(f"  {path}: {n} lines parsed")
    print(f"  Lines: {stats['lines']}   Unparsed: {stats['unparsed']}")
    print(f"  Overall severity: {COLOURS[overall]}{BOLD}{overall}{RESET}")
    print("-" * 66)
    print(f"{'Source IP':<18}{'Failed':>7}{'In 5min':>9}  Classification")
    for ip, v in sorted(per_ip.items(), key=lambda kv: -kv[1]["fails"]):
        if v["fails"]:
            c = COLOURS[v["severity"]]
            print(f"{ip:<18}{v['fails']:>7}{v['window']:>9}  "
                  f"{c}{v['class']}{RESET}")
    print("-" * 66)
    print(f"{BOLD}Incidents{RESET}")
    for i in incidents:
        print(f"  {COLOURS[i['severity']]}[{i['severity']:<8}]{RESET} "
              f"{i['ip']:<16} {i['title']}")
    print("=" * 66)
    print(f"Full report written to: {out_path}")


# ---------------------------------------------------------- sample logs
def generate_samples(auth_path="sample_auth.log", web_path="sample_access.log"):
    """Create SYNTHETIC logs (documentation IP ranges, invented users)."""
    rnd = random.Random(42)            # fixed seed => same output every time
    auth, web = [], []

    def a(ts, text, pid=None):
        pid = pid or rnd.randint(1000, 9999)
        auth.append((ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} lab-server "
                         f"sshd[{pid}]: {text}"))

    base = dt.datetime(2026, 10, 16)
    # Normal business-hours logins
    for hour, user, ip in [(9, "alice", "198.51.100.10"),
                           (10, "bob", "198.51.100.11"),
                           (14, "alice", "198.51.100.10"),
                           (16, "carol", "198.51.100.12")]:
        t = base + dt.timedelta(hours=hour, minutes=rnd.randint(0, 59))
        a(t, f"Accepted password for {user} from {ip} port "
             f"{rnd.randint(40000, 60000)} ssh2")
    # Routine typo: 2 failures then success
    t = base + dt.timedelta(hours=11, minutes=5)
    for k in range(2):
        a(t + dt.timedelta(seconds=k * 9),
          f"Failed password for bob from 198.51.100.11 port 5{k}022 ssh2")
    a(t + dt.timedelta(seconds=30),
      "Accepted password for bob from 198.51.100.11 port 51022 ssh2")
    # Brute force with invalid users (rapid, 03:xx)
    t = base + dt.timedelta(hours=3, minutes=12)
    for k in range(40):
        user = rnd.choice(["root", "admin", "test", "oracle", "ubuntu", "git"])
        ts = t + dt.timedelta(seconds=k * 2)
        a(ts, f"Invalid user {user} from 203.0.113.50 port {40000 + k}")
        a(ts, f"Failed password for invalid user {user} from 203.0.113.50 "
              f"port {40000 + k} ssh2")
    # Slow attack that eventually succeeds (possible compromise)
    t = base + dt.timedelta(hours=4, minutes=40)
    for k in range(12):
        a(t + dt.timedelta(seconds=k * 20),
          f"Failed password for carol from 203.0.113.77 port {50000 + k} ssh2")
    a(t + dt.timedelta(seconds=300),
      "Accepted password for carol from 203.0.113.77 port 50999 ssh2")
    # Off-hours login by a normal user
    a(base + dt.timedelta(hours=2, minutes=30),
      "Accepted publickey for alice from 192.0.2.44 port 44100 ssh2")
    # Medium: a few failures from one address
    t = base + dt.timedelta(hours=13, minutes=2)
    for k in range(6):
        a(t + dt.timedelta(minutes=k * 3),
          f"Failed password for dave from 198.51.100.99 port 6{k}001 ssh2")

    def w(ts, ip, method, path, status, ua="Mozilla/5.0 (X11; Linux x86_64)"):
        web.append((ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] '
                        f'"{method} {path} HTTP/1.1" {status} '
                        f'{rnd.randint(200, 5000)} "-" "{ua}"'))

    for k in range(25):                           # normal traffic
        w(base + dt.timedelta(hours=9, minutes=k * 17),
          f"198.51.100.{10 + k % 3}", "GET",
          rnd.choice(["/", "/about", "/products", "/contact"]), 200)
    t = base + dt.timedelta(hours=1, minutes=5)   # web login failures
    for k in range(20):
        w(t + dt.timedelta(seconds=k * 3), "203.0.113.60", "POST",
          "/login", 401, "python-requests/2.31")
    t = base + dt.timedelta(hours=5)              # scanner / injection
    w(t, "203.0.113.99", "GET", "/.env", 404, "Nikto/2.5")
    w(t + dt.timedelta(seconds=2), "203.0.113.99", "GET", "/wp-login.php",
      404, "Nikto/2.5")
    w(t + dt.timedelta(seconds=4), "203.0.113.99", "GET",
      "/products?id=1%27%20OR%20%271%27=%271", 500, "sqlmap/1.7")
    w(t + dt.timedelta(seconds=6), "203.0.113.99", "GET",
      "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", 200, "sqlmap/1.7")
    w(t + dt.timedelta(seconds=8), "203.0.113.99", "GET",
      "/download?file=../../etc/passwd", 403, "sqlmap/1.7")
    w(base + dt.timedelta(hours=12), "198.51.100.12", "POST", "/login", 401)
    w(base + dt.timedelta(hours=12, seconds=20), "198.51.100.12", "POST",
      "/login", 302)

    for path, rows in ((auth_path, auth), (web_path, web)):
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(line for _, line in sorted(rows)) + "\n")
    print(f"Created synthetic logs: {auth_path}, {web_path}")
    print("They contain invented users and documentation-range IPs only.")


# -------------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Security Log Analyzer")
    p.add_argument("logs", nargs="*", help="auth.log / access.log files")
    p.add_argument("-o", "--output", default="incident_report.md")
    p.add_argument("--year", type=int, default=dt.date.today().year)
    p.add_argument("--threshold", type=int, default=5)
    p.add_argument("--work-start", type=int, default=8)
    p.add_argument("--work-end", type=int, default=18)
    p.add_argument("--generate-sample", action="store_true")
    args = p.parse_args()

    if sys.platform == "win32":
        import os
        os.system("")  # enable ANSI colours in Windows terminals
    if args.generate_sample:
        generate_samples()
        return 0
    if not args.logs:
        p.error("give at least one log file, or use --generate-sample")
    if args.threshold < 1:
        p.error("--threshold must be 1 or more")

    events, hits, invalid, stats = parse_logs(args.logs, args.year)
    if stats["lines"] == 0:
        print("The log files are empty - nothing to analyse.")
        return 1
    per_ip, incidents, sigs = analyze(events, hits, invalid, args.threshold,
                                      args.work_start, args.work_end)
    report, overall = build_report(args.logs, stats, per_ip, incidents, sigs,
                                   args.threshold)
    try:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
    except OSError as err:
        print(f"Error: cannot write report: {err.strerror}")
        return 1
    print_summary(stats, per_ip, incidents, overall, args.output)
    return 0


if __name__ == "__main__":
    sys.exit(main())