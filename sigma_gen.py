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

# Always generated: detects the scanners themselves
SCANNER_RULE = (
    "Vulnerability scanner user agent seen",
    "Web requests from known vulnerability scanners (Nuclei or this tool).",
    "cs-user-agent|contains", ["Nuclei", "ai-vuln-scanner"],
    ["attack.reconnaissance", "attack.t1595.002"], "medium")

NAMESPACE = uuid.UUID("12345678-1234-5678-1234-567812345678")


def build_rule(rule_id, spec):
    title, desc, field, values, tags, level = spec
    lines = [
        f"title: {title}",
        f"id: {uuid.uuid5(NAMESPACE, rule_id)}",
        "status: experimental",
        f"description: {desc}",
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

    path = os.path.join("rules", "scanner_activity.yml")
    with open(path, "w") as out:
        out.write(build_rule("scanner-activity", SCANNER_RULE))
    made.append(("Scanner activity (always generated)", path))

    print(f"Rules written: {len(made)}")
    for title, path in made:
        print(f"  [rule] {title} -> {path}")
    print(f"No log-based rule possible: {len(skipped)}")
    for title in skipped:
        print(f"  [skip] {title} (configuration finding, nothing to see in logs)")


if __name__ == "__main__":
    main()
