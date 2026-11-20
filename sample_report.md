
## Executive summary

The target at `http://localhost:3000` has one high-severity finding (an exposed `/ftp` directory), three medium findings (HTTPS, HSTS and CSP) and one low finding (Referrer-Policy). Three of the five are missing security headers or transport protection, which are easy fixes. The exposed directory is the one to look at first.

## Findings

**1. Exposed path: /ftp (High)**
- **What it means:** The `/ftp` path returns a page on its own, which suggests a file directory is reachable without logging in. Files there could include backups, documents or internal data.
- **Mapping:** OWASP A01:2021 Broken Access Control (also A05 Security Misconfiguration). CWE-548 (directory listing) and CWE-200 (information exposure).
- **Fix:** Remove the directory from the public web root, or require authentication. In Express:
```js
app.use('/ftp', requireAuth, serveIndex('ftp'));  // or delete the route entirely
```
- **Confidence note:** The evidence only shows that an HTML page loaded. Open `http://localhost:3000/ftp` in your browser to confirm it lists files. Your scanner can't prove the files are sensitive on its own.

**2. Site not served over HTTPS (Medium)**
- **What it means:** Traffic over plain HTTP can be read or changed by anyone on the network path.
- **Mapping:** A02:2021 Cryptographic Failures. CWE-319.
- **Fix:** Terminate TLS in a reverse proxy and redirect HTTP to HTTPS. Nginx:
```nginx
server { listen 80; return 301 https://$host$request_uri; }
```
- **Confidence note:** On `localhost` for local testing this is expected, so treat it as informational here. It would be a real issue on a public site.

**3. Missing Strict-Transport-Security (Medium)**
- **What it means:** Browsers aren't told to always use HTTPS, so users can be tricked into downgrade attacks.
- **Mapping:** A05:2021 Security Misconfiguration. CWE-319.
- **Fix:** Add the header, but only after HTTPS works:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains
```
- **Dependency:** Fix #2 first, since HSTS does nothing over plain HTTP.

**4. Missing Content-Security-Policy (Medium)**
- **What it means:** There is no browser-level defense that limits where scripts can load from, so any XSS bug becomes more dangerous.
- **Mapping:** A05:2021 Security Misconfiguration. CWE-693.
- **Fix:** In Express, use the `helmet` package, and start with a simple policy:
```js
app.use(helmet.contentSecurityPolicy({
  directives: { defaultSrc: ["'self'"] }
}));
```
- **Caution:** A strict CSP can break pages that use inline scripts, so test it in report-only mode first.

**5. Missing Referrer-Policy (Low)**
- **What it means:** Full page URLs may be sent to other sites when users click links, which can leak private paths or tokens in URLs.
- **Mapping:** A05:2021 Security Misconfiguration. CWE-200.
- **Fix:**
```
Referrer-Policy: strict-origin-when-cross-origin
```

## Fix these first
1. Confirm and lock down `/ftp`.
2. Add HTTPS, then HSTS.
3. Add CSP in report-only mode, then enforce it.
4. Add Referrer-Policy (one line).

