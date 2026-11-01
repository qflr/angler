"""Angler decoy sensor: looks like an unpatched Apache 2.4.49 + PHP 8.1 + PHPUnit box (high-volume targets).

Low-interaction by design. It logs every request and answers with static pages. It never runs,
evaluates, fetches or stores-and-serves anything an attacker sends, so there is nothing to exploit.
Standard library only, so the VM needs nothing but python3.

Hits are shipped in batches to the Angler API (POST /ingest/events). If the API is down they wait
in a local spool file and are retried, so nothing captured is lost.

    ANGLER_API=https://angler-api.onrender.com INGEST_KEY=... python3 sensor.py --port 80
"""

import argparse
import hashlib
import json
import os
import re
import ssl
import threading
import time
import urllib.request
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

API = os.getenv("ANGLER_API", "https://angler-api.onrender.com").rstrip("/")
INGEST_KEY = os.getenv("INGEST_KEY", "")
SPOOL = os.getenv("ANGLER_SPOOL", "/var/lib/angler/spool.jsonl")
MAX_BODY = 4096  # bytes of request body kept for analysis; the rest is read and discarded
FLUSH_SECONDS = 2

# Apache 2.4.49 is the exact build hit by CVE-2021-41773, and PHP 8.1.10 predates the CVE-2024-4577 fix:
# a banner that version-matching scanners flag as vulnerable on sight.
SERVER_HEADER = "Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/8.1.10"
INDEX = b"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Welcome to XAMPP</title></head>
<body><h1>Welcome to XAMPP 8.1.10</h1>
<p>You have successfully installed XAMPP on this system! Now you can start using Apache, MariaDB,
PHP and other components.</p><p><a href="/dashboard/">Dashboard</a> | <a href="/phpmyadmin/">phpMyAdmin</a></p>
</body></html>"""
# Static fake: no real accounts, served only so traversal scanners believe they got through.
FAKE_PASSWD = b"""root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
"""
NOT_FOUND = b"""<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head><title>404 Not Found</title></head><body><h1>Not Found</h1>
<p>The requested URL was not found on this server.</p><hr>
<address>Apache/2.4.49 (Unix) OpenSSL/1.1.1k PHP/8.1.10 Server at localhost Port 80</address>
</body></html>"""

# --- emulation ---------------------------------------------------------------------------------
# Probes usually check for a tell-tale output (md5 of a marker, an echoed string, `id`) before
# sending the real payload. We fake those outputs with regexes and hashlib. Nothing is executed.

_MD5 = re.compile(r"md5\(\s*['\"]([^'\"]{1,128})['\"]\s*\)")
_ECHO = re.compile(r"(?:echo|print)\s*\(?\s*['\"]([^'\"]{1,256})['\"]")
_TRAVERSAL = re.compile(r"/(cgi-bin|icons)/(\.|%2e|%%32%65)+(%2e|\.)?/", re.I)
_PHP_CGI = re.compile(r"allow_url_include|auto_prepend_file|php-cgi", re.I)


def fake_output(code: str) -> str:
    """What a vulnerable box would print for common probe payloads, computed without running them."""
    out = [hashlib.md5(m.encode()).hexdigest() for m in _MD5.findall(code)]
    out += [m for m in _ECHO.findall(code) if "Content-Type" not in m and m.strip()]
    if re.search(r"(^|[;|&`\s])id(\s|;|$)", code):
        out.append("uid=1(daemon) gid=1(daemon) groups=1(daemon)")
    if re.search(r"\buname\b", code):
        out.append("Linux web01 5.4.0-150-generic #167-Ubuntu SMP x86_64 GNU/Linux")
    if re.search(r"\bwhoami\b", code):
        out.append("daemon")
    return "\n".join(out)


def route(method: str, raw_path: str, body: str) -> tuple[int, bytes, str]:
    """Pick a believable static response. Returns (status, body, content type)."""
    path = raw_path.split("?", 1)[0]
    html, text = "text/html; charset=UTF-8", "text/plain"

    # CVE-2023-1389, TP-Link Archer AX21 locale injection (Mirai's favourite).
    if path.startswith("/cgi-bin/luci/") and "locale" in raw_path:
        return 200, b'{"success":true,"data":{"country":"US"}}', "application/json"
    # CVE-2017-9841, PHPUnit eval-stdin.php: body is PHP; vulnerable boxes print its output.
    if path.endswith("eval-stdin.php"):
        return 200, fake_output(body).encode(), html
    # CVE-2021-41773 / CVE-2021-42013, Apache 2.4.49/50 path traversal and CGI RCE.
    if _TRAVERSAL.search(raw_path):
        if method == "POST" or "/bin/sh" in raw_path:
            return 200, fake_output(body).encode(), text
        if "passwd" in raw_path:
            return 200, FAKE_PASSWD, text
        return 403, NOT_FOUND, html
    # CVE-2024-4577, PHP-CGI argument injection: auto_prepend_file=php://input runs the body.
    if _PHP_CGI.search(raw_path):
        return 200, (fake_output(body) + "\n").encode() + INDEX, html
    if path in ("/", "/index.php", "/dashboard/"):
        return 200, INDEX, html
    return 404, NOT_FOUND, html


_lock = threading.Lock()
_buffer: list[dict] = []


class Decoy(BaseHTTPRequestHandler):
    server_version = SERVER_HEADER
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 15

    def log_message(self, *args):  # silence stderr access log; we keep our own
        pass

    def _capture(self) -> str:
        length = int(self.headers.get("Content-Length") or 0)
        body = b""
        if length > 0:
            body = self.rfile.read(min(length, MAX_BODY))
            remaining = length - len(body)
            while remaining > 0:  # drain without keeping
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    break
                remaining -= len(chunk)
        hit = {
            "id": f"h_{uuid.uuid4().hex[:16]}",
            "source_ip": self.client_address[0],
            "port": self.server.server_port,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "method": self.command,
            "path": self.path[:2048],
            "user_agent": self.headers.get("User-Agent", "")[:512],
            "headers": {k: v[:512] for k, v in list(self.headers.items())[:40]},
            "body_preview": body.decode("utf-8", "replace"),
            "is_test": self.headers.get("X-Angler-Test") == "1",
        }
        with _lock:
            _buffer.append(hit)
        return hit["body_preview"]

    def _respond(self) -> None:
        body_text = self._capture()
        status, body, ctype = route(self.command, self.path, body_text)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/8.1.10")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = do_OPTIONS = do_DELETE = do_PATCH = _respond


def _ship(batch: list[dict]) -> bool:
    req = urllib.request.Request(
        f"{API}/ingest/events",
        data=json.dumps(batch).encode(),
        headers={"Content-Type": "application/json", "X-Ingest-Key": INGEST_KEY},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as res:
            return res.status == 200
    except Exception as e:  # network or API error: keep the batch spooled
        print(f"ship failed ({len(batch)} hits): {e}", flush=True)
        return False


def shipper() -> None:
    os.makedirs(os.path.dirname(SPOOL), exist_ok=True)
    while True:
        time.sleep(FLUSH_SECONDS)
        with _lock:
            fresh, _buffer[:] = list(_buffer), []
        spooled = []
        if os.path.exists(SPOOL):
            with open(SPOOL) as f:
                spooled = [json.loads(line) for line in f if line.strip()]
        batch = spooled + fresh
        if not batch:
            continue
        ok = all(_ship(batch[i : i + 200]) for i in range(0, len(batch), 200))
        with open(SPOOL, "w") as f:
            if not ok:
                f.writelines(json.dumps(h) + "\n" for h in batch[-50000:])
        if ok:
            print(f"shipped {len(batch)} hits", flush=True)


class QuietServer(ThreadingHTTPServer):
    # Scanners drop connections and reject our self-signed cert constantly; not worth a traceback each.
    def handle_error(self, request, client_address):
        pass


def serve(host: str, port: int, certfile: str | None, keyfile: str | None) -> None:
    httpd = QuietServer((host, port), Decoy)
    httpd.daemon_threads = True
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    print(f"decoy listening on {host}:{port}{' (tls)' if certfile else ''}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="0.0.0.0", help="bind address; use 127.0.0.1 for local testing")
    ap.add_argument("--port", type=int, action="append", help="plain HTTP port (repeatable)")
    ap.add_argument("--tls-port", type=int, help="HTTPS port (needs --cert and --key)")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    args = ap.parse_args()
    if not INGEST_KEY:
        raise SystemExit("INGEST_KEY is required")
    threading.Thread(target=shipper, daemon=True).start()
    for p in args.port or [80]:
        threading.Thread(target=serve, args=(args.host, p, None, None), daemon=True).start()
    if args.tls_port:
        threading.Thread(target=serve, args=(args.host, args.tls_port, args.cert, args.key), daemon=True).start()
    while True:
        time.sleep(3600)
