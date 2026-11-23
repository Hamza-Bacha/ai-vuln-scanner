# Security Assessment Report

Target: http://localhost:8080
Findings: 2

## [MEDIUM] Missing header: Strict-Transport-Security

- A05:2021 Security Misconfiguration | CWE-319
- Location: http://localhost:8080
- Evidence: Forces HTTPS; protects against downgrade attacks.

What it means: Browsers are not told to always use HTTPS, which allows downgrade attacks.

Fix:

    Add the header (only after HTTPS works):
        Strict-Transport-Security: max-age=31536000; includeSubDomains

## [MEDIUM] Site not served over HTTPS

- A02:2021 Cryptographic Failures | CWE-319
- Location: http://localhost:8080
- Evidence: Target uses plain HTTP

What it means: Traffic over plain HTTP can be read or changed on the network. Expected on localhost, serious on a public site.

Fix:

    Serve over HTTPS and redirect HTTP. Nginx:
        server { listen 80; return 301 https://$host$request_uri; }
