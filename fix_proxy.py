"""
Demo 'fix': a reverse proxy in front of Juice Shop that adds security
headers, blocks sensitive paths, hides the server banner and writes an
access.log (Apache combined format) for testing detection rules.
For testing only.
"""
import threading
from datetime import datetime, timezone

import httpx
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

UPSTREAM = "http://localhost:3000"
LISTEN_PORT = 8080
LOG_FILE = "access.log"
BLOCKED = ("/ftp", "/metrics")
EXTRA_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src * data:; font-src * data:"
    ),
    "Referrer-Policy": "strict-origin-when-cross-origin",
}
SKIP = ("content-length", "transfer-encoding", "connection",
        "content-encoding", "date")
LOG_LOCK = threading.Lock()


class Proxy(BaseHTTPRequestHandler):
    def handle(self):
        # Ignore errors when a browser closes the connection early
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def send_response(self, code, message=None):
        # Same as the default, but without the Server banner
        self.send_response_only(code, message)
        self.send_header("Date", self.date_time_string())

    def log_access(self, status, size):
        now = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
        ua = self.headers.get("User-Agent", "-")
        ref = self.headers.get("Referer", "-")
        line = (f'{self.client_address[0]} - - [{now}] '
                f'"{self.command} {self.path} HTTP/1.1" {status} {size} '
                f'"{ref}" "{ua}"\n')
        with LOG_LOCK:
            with open(LOG_FILE, "a") as f:
                f.write(line)

    def handle_any(self):
        path = self.path.split("?")[0]
        if any(path == b or path.startswith(b + "/") for b in BLOCKED):
            self.send_response(403)
            self.send_header("Content-Length", "9")
            self.end_headers()
            self.wfile.write(b"Forbidden")
            self.log_access(403, 9)
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items()
                   if k.lower() not in ("host", "content-length",
                                        "connection", "accept-encoding")}
        r = httpx.request(self.command, UPSTREAM + self.path, headers=headers,
                          content=body, follow_redirects=False, timeout=30)

        self.send_response(r.status_code)
        for k, v in r.headers.multi_items():
            if k.lower() not in SKIP:
                self.send_header(k, v)
        for k, v in EXTRA_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(r.content)))
        self.end_headers()
        self.wfile.write(r.content)
        self.log_access(r.status_code, len(r.content))

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_OPTIONS = handle_any

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"Proxy on http://localhost:{LISTEN_PORT} -> {UPSTREAM}")
    print(f"Writing access log to {LOG_FILE}")
    ThreadingHTTPServer(("", LISTEN_PORT), Proxy).serve_forever()
