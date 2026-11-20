# AI Vulnerability Scanner (MVP)

Quick web security scanner with AI-written triage and fix suggestions.

**Only scan targets you own or have written permission to test.**

## What it checks
- Missing security headers
- Cookie flags
- HTTPS and TLS issues
- Exposed files and folders (with false-positive filtering)

## Run it
    pip install -r requirements.txt
    docker run -d -p 3000:3000 bkimminich/juice-shop
    python scanner.py http://localhost:3000 --no-ai
    python scanner.py http://localhost:3000 --no-ai --nuclei
See `sample_report.md` for example AI output.

## Lessons learned
My first version flagged `/server-status` on Juice Shop as exposed. It was a false positive, because the app returns its home page for unknown URLs. I fixed it by comparing each result against a baseline "page that cannot exist" response.

## Roadmap
- [x] Headers, cookies, TLS, exposed paths
- [x] AI triage and fix suggestions
- [x] Nuclei integration
- [ ] Fix, then re-scan verification
- [ ] Sigma detection rule per finding
- [ ] HTML/PDF report and benchmarks
