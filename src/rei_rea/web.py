"""Read-only loopback dashboard. No arbitrary target browsing or shell endpoints."""
from __future__ import annotations
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
import json
from urllib.parse import urlparse

from . import __version__
from .registry import list_tools


class CatalogHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            body = resources.files("rei_rea").joinpath("webui/index.html").read_bytes()
            mime, status = "text/html; charset=utf-8", 200
        elif path == "/api/tools":
            body = json.dumps({"tools": list_tools()}, ensure_ascii=False).encode("utf-8")
            mime, status = "application/json; charset=utf-8", 200
        elif path == "/api/health":
            body = json.dumps({"status": "ok", "version": __version__, "mode": "local-read-only"}).encode()
            mime, status = "application/json; charset=utf-8", 200
        else:
            body, mime, status = b"Not found", "text/plain; charset=utf-8", 404
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; connect-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        # Log only request metadata locally, never artifact contents.
        pass


def serve_local(port: int = 8765) -> None:
    if not (1024 <= port <= 65535):
        raise ValueError("Port must be between 1024 and 65535")
    server = ThreadingHTTPServer(("127.0.0.1", port), CatalogHandler)
    print(f"REI REA local dashboard: http://127.0.0.1:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
