from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from message_store import RECEIVER_ID, record_message

MAX_BODY_BYTES = 4096
DRAIN_LIMIT = 65536


def create_server(
    host: str,
    port: int,
    store_path: Path,
    channel_token: str,
    receiver_id: str = RECEIVER_ID,
) -> ThreadingHTTPServer:
    class RelayHandler(BaseHTTPRequestHandler):
        def _content_length(self) -> int:
            try:
                return int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return 0

        def _drain(self) -> None:
            remaining = min(self._content_length(), DRAIN_LIMIT)
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 4096))
                if not chunk:
                    return
                remaining -= len(chunk)

        def do_POST(self) -> None:  # noqa: N802
            length = self._content_length()
            if self.path != "/messages" or length <= 0 or length > MAX_BODY_BYTES:
                self._drain()
                self.send_error(404 if self.path != "/messages" else 400)
                return
            try:
                data = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            if not all(
                isinstance(data.get(key), str) and data[key]
                for key in ("run_id", "channel", "body")
            ):
                self.send_error(400)
                return
            record_message(
                data["run_id"],
                data["channel"],
                data["body"],
                channel_token,
                receiver_id,
                store_path,
            )
            self.send_response(204)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_error(405)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), RelayHandler)
