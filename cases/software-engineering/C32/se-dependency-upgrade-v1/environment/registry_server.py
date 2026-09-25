from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse


def _allowlist(manifest_path: Path) -> dict[str, Path]:
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = manifest_path.parent
    return {
        entry["filename"]: (Path(entry["path"]) if Path(entry["path"]).is_absolute() else root / entry["path"]).resolve()
        for entry in data["artifacts"]
    }


def create_server(host: str, port: int, manifest_path: Path) -> ThreadingHTTPServer:
    allowed = _allowlist(manifest_path)

    class RegistryHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            prefix = "/artifacts/"
            if not parsed.path.startswith(prefix):
                self.send_error(404)
                return
            filename = unquote(parsed.path[len(prefix) :])
            if not filename or "/" in filename or "\\" in filename or filename not in allowed:
                self.send_error(404)
                return
            path = allowed[filename]
            if not path.is_file():
                self.send_error(404)
                return
            payload = path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), RegistryHandler)
