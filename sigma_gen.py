"""
Generate Sigma detection rules (web server logs) from scan findings.
Usage: python sigma_gen.py before.json
Writes rules to ./rules/ and prints a coverage summary.
"""
import json
import os
import sys
import uuid
from datetime import date

# finding id -> (title, description, field|modifier, values, ATT&CK tags, level)
RULES = {
    "exposed/ftp": (
        "Access to exposed /ftp directory",
        "Requests to the /ftp directory, which a scan found publicly exposed.",
        "c-uri|startswith", ["/ftp"],
        ["attack.discovery", "attack.t1083"], "medium"),
    "nuclei-prometheus-metrics": (
        "Access to exposed Prometheus metrics endpoint",
        "Requests to /metrics, which a scan found publicly exposed.",
        "c-uri|startswith", ["/metrics"],
        ["attack.reconnaissance", "attack.t1595.002"], "medium"),
    "exposed/.git/HEAD": (
        "Access to exposed .git repository files",
        "Requests for .git files that could leak source code.",
        "c-uri|contains", ["/.git/"],
        ["attack.credential_access", "attack.t1552.001"], "high"),
    "exposed/.env": (
        "Access to exposed .env file",
        "Requests for .env files that often contain secrets.",
        "c-uri|endswith", ["/.env"],
        ["attack.credential_access", "attack.t1552.001"], "high"),
    "exposed/backup.zip": (
        "Access to exposed backup archive",
        "Requests for backup.zip, which may hold sensitive data.",
        "c-uri|endswith", ["/backup.zip"],
        ["attack.discovery", "attack.t1083"], "high"),
    "exposed/server-status": (
        "Access to exposed server-status page",
        "Requests to /server-status, which can reveal server internals.",
        "c-uri|startswith", ["/server-status"],
        ["attack.discovery", "attack.t1083"], "medium"),
    "exposed/.DS_Store": (
        "Access to exposed .DS_Store file",
        "Requests for .DS_Store, which can reveal directory contents.",
        "c-uri|endswith", ["/.DS_Store"],
        ["attack.discovery", "attack.t1083"], "low"),
}

# Always generated rules (they do not depend on a specific finding)
# Honest user-agent rule: only catches scanners that announce themselves.
SCANNER_RULE = (
    "Known scanner user agent seen",
    "Requests from scanners that announce themselves (this tool, sqlmap, Nikto, Nmap, gobuster, wfuzz). Nuclei rotates browser user agents, so it is NOT caught here.",
    "cs-user-agent|contains",
    ["ai-vuln-scanner", "sqlmap", "nikto", "nmap scripting engine", "gobuster", "wfuzz"],
    ["attack.reconnaissance", "attack.t1595.002"], "medium")

# Fragile but real: a path requested by a Nuclei template during testing.
NUCLEI_PROBE = (
    "Nuclei template probe path",
    "Request for /nuclei.svg, a path requested by a Nuclei template (seen in my lab logs). Fragile: template changes can break it.",
    "c-uri|contains", ["/nuclei.svg"],
    ["attack.reconnaissance", "attack.t1595.002"], "medium")

ALWAYS = {"scanner-activity": SCANNER_RULE, "nuclei-probe": NUCLEI_PROBE}

RATE_THRESHOLD = 300  # requests per minute from one client; tune for your site

NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")


def build_rule(rule_id, spec):
    title, desc, field, values, tags, level = spec
    lines = [
        f"title: {title}",
        f"id: {uuid.uuid5(NAMESPACE, rule_id)}",
        "status: experimental",
        f'description: "{desc}"',
        "author: ai-vuln-scanner",
        f"date: {date.today():%Y-%m-%d}",
        "tags:",
        *[f"    - {t}" for t in tags],
        "logsource:",
        "    category: webserver",
        "detection:",
        "    selection:",
        f"        {field}:",
        *[f"            - '{v}'" for v in values],
        "    condition: selection",
        "falsepositives:",
        "    - Legitimate use of this path by administrators",
        f"level: {level}",
    ]
    return "\n".join(lines) + "\n"


def build_rate_rules():
    today = f"{date.today():%Y-%m-%d}"
    base = f"""title: Any web request (helper for the rate rule)
name: all_web_requests
id: {uuid.uuid5(NAMESPACE, "all-web-requests")}
status: experimental
description: Helper rule used by the request-rate correlation rule.
author: ai-vuln-scanner
date: {today}
logsource:
    category: webserver
detection:
    selection:
        c-uri|startswith: '/'
    condition: selection
level: informational
"""
    corr = f"""title: High request rate from one client (possible scanner)
id: {uuid.uuid5(NAMESPACE, "high-request-rate")}
status: experimental
description: One client sent a very high number of requests in a minute. Works even when a scanner hides its user agent.
author: ai-vuln-scanner
date: {today}
tags:
    - attack.reconnaissance
    - attack.t1595.002
correlation:
    type: event_count
    rules:
        - all_web_requests
    group-by:
        - c-ip
    timespan: 1m
    condition:
        gte: {RATE_THRESHOLD}
falsepositives:
    - Load tests, busy search engine crawlers
level: high
"""
    return base, corr


def safe_name(rule_id):
    return rule_id.replace("/", "_").replace(".", "").strip("_") + ".yml"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python sigma_gen.py findings.json")
    with open(sys.argv[1]) as f:
        findings = json.load(f)

    os.makedirs("rules", exist_ok=True)
    made, skipped = [], []
    for item in findings:
        fid = item["id"]
        if fid in RULES:
            path = os.path.join("rules", safe_name(fid))
            with open(path, "w") as out:
                out.write(build_rule(fid, RULES[fid]))
            made.append((item["title"], path))
        else:
            skipped.append(item["title"])

    for rid, spec in ALWAYS.items():
        path = os.path.join("rules", rid.replace("-", "_") + ".yml")
        with open(path, "w") as out:
            out.write(build_rule(rid, spec))
        made.append((spec[0] + " (always generated)", path))

    base, corr = build_rate_rules()
    with open(os.path.join("rules", "all_web_requests.yml"), "w") as out:
        out.write(base)
    path = os.path.join("rules", "high_request_rate.yml")
    with open(path, "w") as out:
        out.write(corr)
    made.append(("High request rate from one client (always generated)", path))

    print(f"Rules written: {len(made)}")
    for title, path in made:
        print(f"  [rule] {title} -> {path}")
    print(f"No log-based rule possible: {len(skipped)}")
    for title in skipped:
        print(f"  [skip] {title} (configuration finding, nothing to see in logs)")


if __name__ == "__main__":
    main()
