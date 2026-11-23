# AI Vulnerability Scanner

A web security scanner with a local dashboard. It finds common weaknesses, explains each one, gives a fix, and then re-scans to prove the fix worked. It also writes Sigma detection rules so a SOC team can spot attacks on the same weaknesses.

**Legal notice:** only scan targets you own or have written permission to test.

![Dashboard](dashboard.png)

## What it does
- **Quick scan (seconds):** missing security headers, cookie flags, HTTPS/TLS problems, exposed files and folders (with false-positive filtering).
- **Deep scan (optional):** runs Nuclei templates in the background while the quick results are already visible.
- **Explanations and fixes:** every finding is mapped to OWASP Top 10 and CWE, with a concrete fix.
- **Fix verification:** re-scan and see what is fixed, still open, or new.
- **Detection rules:** Sigma rules tagged with MITRE ATT&CK, tested against real scanner traffic.
- **Optional AI explanation:** works with a local Ollama model or the Claude API (implemented, not yet evaluated).

## Quick start
    pip install -r requirements.txt
    docker run -d -p 3000:3000 --name juice bkimminich/juice-shop
    python dashboard.py

Then open http://127.0.0.1:8765 and scan `http://localhost:3000`.

Command line:

    python scanner.py http://localhost:3000 --no-ai --nuclei --out before.json
    python scanner.py http://localhost:8080 --no-ai --nuclei --out after.json
    python verify.py before.json after.json
    python report.py before.json --after after.json --target http://localhost:3000
    python sigma_gen.py before.json
    python sigma_test.py access.log

Port 8080 is `fix_proxy.py`, a demo hardening proxy in front of Juice Shop that also writes `access.log`.

See [`example_report.md`](example_report.md) for a report downloaded from the dashboard.

## Results (OWASP Juice Shop lab)
| Test | Result |
|---|---|
| Quick scan | 5 findings in seconds |
| Quick scan plus Nuclei | 6 findings (adds exposed Prometheus metrics) |
| Fix verification, command line (hardening proxy in front of the app) | 4 of 6 fixed (67%) |
| Fix verification, dashboard (quick scan only) | 3 of 5 fixed; HSTS and HTTPS stayed open because the proxy has no TLS |
| Sigma rules against 3,705 logged requests | 5 of 5 rules fired |

## Detection rules (SOC side)
`sigma_gen.py` turns findings into Sigma rules for web server logs, tagged with MITRE ATT&CK techniques. Only findings that leave a trace in logs get a rule: in my Juice Shop test, 2 of 6 findings did, plus rules that detect scanner traffic. Missing-header and HTTPS findings are configuration issues, so the tool reports them as "no log-based rule" instead of inventing a weak one.

### Rule testing
`sigma_test.py` replays a web access log against the generated rules. I ran my scanner and Nuclei through a logging proxy in front of OWASP Juice Shop (3,705 requests). All 5 rules fired:

| Rule | Result |
|---|---|
| Exposed /ftp access | 34 matching requests |
| Exposed /metrics access | 6 matching requests |
| Nuclei template probe path | 204 matching requests |
| Known scanner user agent | 8 matching requests (my own tool) |
| High request rate (300+/min from one client) | peak of 1,211 requests in one minute |

## What I learned
- My first scan flagged `/server-status` as exposed. It was a false positive: the app returns its home page for unknown URLs. Comparing each result with a "page that cannot exist" baseline fixed it.
- The first fix introduced a new leak (a `Server` banner from my proxy). The re-scan caught it.
- A rule that looks for "Nuclei" in the user agent never matched, because Nuclei rotates browser user agents. A request-rate rule catches it anyway.

## Limitations
- Findings are things to review, not confirmed vulnerabilities. A quick scan cannot tell a real cookie problem from a deliberate design choice.
- Severity ratings are simple defaults, not CVSS.
- The dashboard is a local, single-user tool with scan history kept in memory. A hosted product would need accounts, domain-ownership verification and a job queue.
- Sigma rules were tested on traffic from one machine. The 300 requests/minute threshold has not been tested against normal visitors, and the Nuclei path rule can break when templates change.
- The OWASP/CWE table is hand-written and should be reviewed before use.

## Project files
| File | Purpose |
|---|---|
| `scanner.py` | quick scan and Nuclei integration |
| `dashboard.py` | local web dashboard |
| `report.py` | OWASP/CWE/fix table and offline report |
| `verify.py` | before/after comparison |
| `sigma_gen.py`, `sigma_test.py` | detection rules and their tests |
| `fix_proxy.py` | demo hardening proxy that also writes an access log |
| `ai_analyze.py` | optional AI explanation (Ollama or Claude API) |

## Roadmap
- [x] Headers, cookies, TLS, exposed paths
- [x] Nuclei integration
- [x] Fix, then re-scan verification
- [x] Sigma detection rules, tested on real traffic
- [x] Local dashboard and offline report
- [ ] Evaluate the AI explanations (accuracy against my own table)
- [ ] Show the real response headers as evidence
- [ ] Lower severity for harmless findings (such as non-session cookies)
- [ ] AI-written fixes applied in a sandbox and verified by re-scan
