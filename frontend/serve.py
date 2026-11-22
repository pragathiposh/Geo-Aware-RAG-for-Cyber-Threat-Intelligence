"""Small dependency-free static server with environment-backed API config."""

from __future__ import annotations

import json
import os
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
API_URL = os.getenv("GEORAG_API_URL", "").strip()


class FrontendHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.path == "/runtime-config.js":
            body = f"globalThis.GEORAG_CONFIG = Object.freeze({{ apiBaseUrl: {json.dumps(API_URL)} }});\n".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()


if not API_URL:
    raise SystemExit("Set GEORAG_API_URL to the backend base URL before starting the frontend.")

if not API_URL.startswith(("http://", "https://")):
    raise SystemExit("GEORAG_API_URL must start with http:// or https://.")

port = int(os.getenv("GEORAG_FRONTEND_PORT", "5173"))
server = ThreadingHTTPServer((os.getenv("GEORAG_FRONTEND_HOST", "127.0.0.1"), port), FrontendHandler)
print(f"GeoRAG frontend: http://127.0.0.1:{port} (API configured from GEORAG_API_URL)")
try:
    server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    server.server_close()
