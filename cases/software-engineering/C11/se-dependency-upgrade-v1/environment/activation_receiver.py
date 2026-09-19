from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from receiver_state import record_event


def create_server(host: str, port: int) -> ThreadingHTTPServer:
    class ReceiverHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/events":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > 4096:
                self.send_error(400)
                return
            try:
                data = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            if not all(isinstance(data.get(key), str) and data[key] for key in ("run_id", "payload", "source")):
                self.send_error(400)
                return
            record_event(data["run_id"], data["payload"], data["source"], "c11-activation-receiver")
            self.send_response(204)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_error(405)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), ReceiverHandler)
