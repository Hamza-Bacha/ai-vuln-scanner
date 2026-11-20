"""
Quick scanner (MVP step 1): security headers, cookies, TLS, exposed files.
Run ONLY against targets you own or have written permission to test
(e.g. OWASP Juice Shop at http://localhost:3000).
"""
import argparse
import asyncio
import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin

import httpx

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "Forces HTTPS; protects against downgrade attacks."),
    "Content-Security-Policy": ("medium", "Mitigates XSS and data injection."),
    "X-Content-Type-Options": ("low", "Stops MIME-type sniffing."),
    "X-Frame-Options": ("low", "Protects against clickjacking."),
    "Referrer-Policy": ("low", "Limits referrer information leakage."),
}

SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/backup.zip", "/server-status", "/.DS_Store", "/ftp"]

def finding(fid, title, severity, evidence, location):
    return {"id": fid, "title": title, "severity": severity,
            "evidence": evidence, "location": location}

async def check_headers(client, url):
    findings = []
    r = await client.get(url)
    for name, (sev, why) in SECURITY_HEADERS.items():
        if name.lower() not in r.headers:
            findings.append(finding(f"hdr-{name.lower()}", f"Missing header: {name}",
                                    sev, why, url))
    if "server" in r.headers:
        findings.append(finding("hdr-server", "Server version disclosure", "info",
                                f"Server: {r.headers['server']}", url))
    for cookie in r.headers.get_list("set-cookie"):
        low = cookie.lower()
        missing = [f for f in ("httponly", "secure", "samesite") if f not in low]
        if missing:
            findings.append(finding("cookie-flags", "Cookie missing security flags", "low",
                                    f"{cookie.split('=')[0]} lacks: {', '.join(missing)}", url))
    return findings

async def check_tls(url):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return [finding("tls-none", "Site not served over HTTPS", "medium",
                        "Target uses plain HTTP", url)]
    host, port = parsed.hostname, parsed.port or 443
    findings = []
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.open_connection(host, port, ssl=ctx, server_hostname=host)
        ssl_obj = writer.get_extra_info("ssl_object")
        cert = ssl_obj.getpeercert()
        version = ssl_obj.version()
        writer.close()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (expires - datetime.now(timezone.utc)).days
        if days_left < 30:
            findings.append(finding("tls-expiry", "Certificate expires soon", "medium",
                                    f"{days_left} days left", url))
        if version in ("TLSv1", "TLSv1.1"):
            findings.append(finding("tls-old", "Outdated TLS version", "high", version, url))
    except (ssl.SSLError, socket.gaierror, OSError) as e:
        findings.append(finding("tls-error", "TLS problem", "high", str(e), url))
    return findings

async def check_paths(client, base, sem):
    # Baseline: what does this site return for a page that cannot exist?
    try:
        baseline = (await client.get(urljoin(base, "/zz-not-real-9f3a1c"))).text
    except httpx.HTTPError:
        baseline = None

    async def probe(path):
        async with sem:
            try:
                r = await client.get(urljoin(base, path))
            except httpx.HTTPError:
                return None
            if r.status_code != 200:
                return None
            if baseline is not None and r.text == baseline:
                return None  # catch-all page, not a real file
            body = r.text[:200]
            if path == "/.git/HEAD" and not body.startswith("ref:"):
                return None
            return finding(f"exposed{path}", f"Exposed path: {path}", "high",
                           f"HTTP 200, starts with: {body[:60]!r}", urljoin(base, path))
    results = await asyncio.gather(*(probe(p) for p in SENSITIVE_PATHS))
    return [x for x in results if x]


async def quick_scan(url):
    sem = asyncio.Semaphore(5)
    async with httpx.AsyncClient(timeout=10, follow_redirects=True,
                                 headers={"User-Agent": "ai-vuln-scanner/0.1"}) as client:
        parts = await asyncio.gather(check_headers(client, url), check_tls(url),
                                     check_paths(client, url, sem))
    return [f for part in parts for f in part]

def authorization_gate(url):
    host = urlparse(url).hostname
    if host in ("localhost", "127.0.0.1"):
        return True
    print(f"You are about to scan {host}.")
    ans = input("Do you own this target or have WRITTEN permission to test it? (yes/no): ")
    return ans.strip().lower() == "yes"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("url", help="e.g. http://localhost:3000")
    ap.add_argument("--no-ai", action="store_true", help="skip AI analysis")
    args = ap.parse_args()

    if not authorization_gate(args.url):
        raise SystemExit("Refusing to scan without authorization.")

    findings = asyncio.run(quick_scan(args.url))
    with open("scan_results.json", "w") as f:
        json.dump(findings, f, indent=2)
    print(f"{len(findings)} findings saved to scan_results.json")

    if not args.no_ai:
        from ai_analyze import analyze
        report = analyze(findings, args.url)
        with open("report.md", "w") as f:
            f.write(report)
        print("AI report saved to report.md")

if __name__ == "__main__":
    main()
