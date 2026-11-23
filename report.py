"""
Offline report generator: findings -> Markdown report (no AI, no internet).
Usage: python report.py before.json [--after after.json] [--target URL]
Writes security_report.md
"""
import argparse
import json
from datetime import date

from sigma_gen import RULES, safe_name

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# finding id -> (OWASP Top 10 2021, CWE, explanation, fix)
KB = {
    "hdr-strict-transport-security": (
        "A05:2021 Security Misconfiguration", "CWE-319",
        "Browsers are not told to always use HTTPS, which allows downgrade attacks.",
        "Add the header (only after HTTPS works):\n    Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    "hdr-content-security-policy": (
        "A05:2021 Security Misconfiguration", "CWE-693",
        "No browser-level limit on where scripts load from, so any XSS bug is more dangerous.",
        "Start with report-only mode, then enforce:\n    Content-Security-Policy: default-src 'self'"),
    "hdr-referrer-policy": (
        "A05:2021 Security Misconfiguration", "CWE-200",
        "Full page URLs may leak to other sites when users click links.",
        "Add the header:\n    Referrer-Policy: strict-origin-when-cross-origin"),
    "hdr-x-content-type-options": (
        "A05:2021 Security Misconfiguration", "CWE-693",
        "Browsers may guess content types, which can turn uploads into scripts.",
        "Add the header:\n    X-Content-Type-Options: nosniff"),
    "hdr-x-frame-options": (
        "A05:2021 Security Misconfiguration", "CWE-1021",
        "The page can be embedded in another site, enabling clickjacking.",
        "Add the header:\n    X-Frame-Options: SAMEORIGIN"),
    "hdr-server": (
        "A05:2021 Security Misconfiguration", "CWE-200",
        "The server reveals its software and version, which helps attackers.",
        "Hide it. Nginx:\n    server_tokens off;"),
    "cookie-flags": (
        "A05:2021 Security Misconfiguration", "CWE-614 / CWE-1004",
        "Cookies lack HttpOnly, Secure or SameSite, so scripts or other sites may reach them.",
        "Set the flags:\n    Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax"),
    "tls-none": (
        "A02:2021 Cryptographic Failures", "CWE-319",
        "Traffic over plain HTTP can be read or changed on the network. Expected on localhost, serious on a public site.",
        "Serve over HTTPS and redirect HTTP. Nginx:\n    server { listen 80; return 301 https://$host$request_uri; }"),
    "tls-expiry": (
        "A02:2021 Cryptographic Failures", "CWE-324",
        "The certificate expires soon, and browsers will block the site afterwards.",
        "Renew it, and automate renewal (for example certbot)."),
    "tls-old": (
        "A02:2021 Cryptographic Failures", "CWE-326",
        "An old TLS version with known weaknesses is accepted.",
        "Allow only modern versions. Nginx:\n    ssl_protocols TLSv1.2 TLSv1.3;"),
    "tls-error": (
        "A02:2021 Cryptographic Failures", "see details",
        "The TLS connection failed or the certificate is invalid.",
        "Check the certificate chain, hostname and expiry date."),
    "exposed/ftp": (
        "A01:2021 Broken Access Control", "CWE-548",
        "A file directory is reachable without logging in and may expose backups or documents.",
        "Remove it from the public web root, or require authentication."),
    "exposed/.git/HEAD": (
        "A05:2021 Security Misconfiguration", "CWE-538",
        "The .git folder is public, so attackers can download source code and secrets.",
        "Block it. Nginx:\n    location ~ /\\.git { deny all; }"),
    "exposed/.env": (
        "A05:2021 Security Misconfiguration", "CWE-538",
        "The .env file is public and usually holds passwords and API keys.",
        "Block dotfiles, move the file out of the web root, and rotate every secret in it."),
    "exposed/backup.zip": (
        "A05:2021 Security Misconfiguration", "CWE-530",
        "A backup archive is publicly downloadable.",
        "Delete it from the web root and store backups elsewhere."),
    "exposed/server-status": (
        "A05:2021 Security Misconfiguration", "CWE-200",
        "The server status page reveals internal details.",
        "Restrict it. Apache:\n    Require ip 127.0.0.1"),
    "exposed/.DS_Store": (
        "A05:2021 Security Misconfiguration", "CWE-538",
        "A .DS_Store file can reveal folder and file names.",
        "Delete it and block dotfiles."),
    "nuclei-prometheus-metrics": (
        "A05:2021 Security Misconfiguration", "CWE-200",
        "The metrics page is public and reveals request counts, routes and software details.",
        "Require authentication or allow only internal addresses."),
}
DEFAULT = ("Needs review", "n/a",
           "Reported by Nuclei. Read the evidence and the template description.",
           "Review the matching Nuclei template and apply its remediation advice.")


def load(path):
    with open(path) as f:
        return json.load(f)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("before", help="scan results JSON")
    ap.add_argument("--after", help="re-scan results JSON (adds verification)")
    ap.add_argument("--target", default="(not given)")
    args = ap.parse_args()

    findings = sorted(load(args.before),
                      key=lambda f: SEV_ORDER.get(f["severity"], 9))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    out = ["# Security Assessment Report", "",
           f"- Target: {args.target}",
           f"- Date: {date.today():%Y-%m-%d}",
           f"- Findings: {len(findings)} (" +
           ", ".join(f"{n} {s}" for s, n in sorted(counts.items(), key=lambda x: SEV_ORDER.get(x[0], 9))) + ")",
           "- Method: automated scan; findings are not manually confirmed", ""]

    out += ["## Fix these first", ""]
    for i, f in enumerate(findings[:3], 1):
        out.append(f"{i}. [{f['severity']}] {f['title']}")
    out.append("")

    out += ["## Findings", ""]
    for f in findings:
        owasp, cwe, why, fix = KB.get(f["id"], DEFAULT)
        out += [f"### [{f['severity'].upper()}] {f['title']}", "",
                f"- Location: {f['location']}",
                f"- OWASP: {owasp}",
                f"- CWE: {cwe}",
                f"- Evidence: {f['evidence']}", "",
                f"**What it means:** {why}", "",
                "**Fix:**", "", "```", fix, "```", ""]
        if f["id"] in RULES:
            out += [f"**Detection:** Sigma rule `rules/{safe_name(f['id'])}`", ""]
        else:
            out += ["**Detection:** no log-based rule (configuration finding)", ""]

    if args.after:
        before = {f["id"]: f for f in findings}
        after = {f["id"]: f for f in load(args.after)}
        fixed = [before[i] for i in before if i not in after]
        still = [after[i] for i in after if i in before]
        new = [after[i] for i in after if i not in before]
        rate = round(100 * len(fixed) / len(before)) if before else 0
        out += ["## Fix verification", "",
                f"Re-scan confirmed {len(fixed)} of {len(before)} findings fixed ({rate}%).", ""]
        for title, items in (("Fixed", fixed), ("Still open", still), ("New after fix", new)):
            out.append(f"**{title}**")
            out += [f"- [{x['severity']}] {x['title']}" for x in items] or ["- none"]
            out.append("")

    out += ["## Limits", "",
            "- Automated checks only; a clean result does not mean the site is secure.",
            "- Severity ratings are simple defaults, not full CVSS scores.", ""]

    with open("security_report.md", "w") as f:
        f.write("\n".join(out))
    print("Saved to security_report.md")


if __name__ == "__main__":
    main()
