"""Shared pytest fixtures: env config, local fixture web server."""

import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

os.environ.setdefault("DATABASE_URL", "sqlite:////tmp/wg_pytest.db")
os.environ.setdefault("ALLOW_PRIVATE_NETWORKS", "true")
os.environ.setdefault("SECRET_KEY", "pytest-secret-key")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))


class FixtureHandler(BaseHTTPRequestHandler):
    """Deliberately misconfigured fixture server for scanner tests."""

    def _send(self, code=200, body=b"<html><head><title>t</title>"
              b'<meta name="generator" content="FixtureCMS 1.0">'
              b'<script src="/static/jquery-1.12.4.min.js"></script>'
              b"</head><body>hi</body></html>"):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "FixtureServer/2.0")
        self.send_header("Set-Cookie", "sessid=abc123; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/robots.txt":
            return self._send(body=b"User-agent: *\nDisallow: /admin/\n")
        if self.path.startswith("/webguard-nonexistent-"):
            return self._send(500, b"<html><body>Traceback: NullPointerException at com.example.App</body></html>")
        return self._send()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, PUT, DELETE, TRACE, OPTIONS")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def fixture_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()
