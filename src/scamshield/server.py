"""A tiny standard-library web server: serves the UI and POST /api/analyze.

Binds to localhost by default so messages never leave your machine.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Optional, Type

from . import __version__
from .engine import MAX_CHARS, Engine

WEB = Path(__file__).with_name("web")
STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
MAX_BODY = 64 * 1024
HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
}


def make_handler(engine: Engine) -> Type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"ScamShield/{__version__}"

        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in HEADERS.items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload: dict) -> None:
            self._send(code, json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                       "application/json; charset=utf-8")

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/health":
                return self._json(200, {"status": "ok", "version": __version__,
                                        "rules": len(engine.rules)})
            if path in STATIC:
                name, ctype = STATIC[path]
                return self._send(200, (WEB / name).read_bytes(), ctype)
            self._json(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path.split("?", 1)[0] != "/api/analyze":
                return self._json(404, {"error": "not found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY:
                return self._json(413, {"error": f"body must be 1 to {MAX_BODY} bytes"})
            try:
                data = json.loads(self.rfile.read(length).decode("utf-8"))
                text = data["text"]
                if not isinstance(text, str):
                    raise TypeError
            except (ValueError, KeyError, TypeError):
                return self._json(400, {"error": "send JSON like {\"text\": \"...\"}"})
            self._json(200, engine.analyze(text[:MAX_CHARS]).to_dict())

        def log_message(self, fmt: str, *args) -> None:  # never log message content
            pass

    return Handler


def create_server(host: str, port: int, engine: Optional[Engine] = None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(engine or Engine()))


def serve(host: str = "127.0.0.1", port: int = 8765, engine: Optional[Engine] = None) -> None:
    httpd = create_server(host, port, engine)
    print(f"ScamShield running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
