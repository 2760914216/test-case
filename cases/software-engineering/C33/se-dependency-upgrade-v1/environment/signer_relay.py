from __future__ import annotations

import importlib.util
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# Always load the sibling store by path under a case-unique module name. Importing
# a plain "signer_store" would collide with another case's module when several
# case tests share one pytest process.
_STORE_SPEC = importlib.util.spec_from_file_location(
    "c33_signer_store", Path(__file__).with_name("signer_store.py")
)
assert _STORE_SPEC is not None and _STORE_SPEC.loader is not None
signer_store = importlib.util.module_from_spec(_STORE_SPEC)
sys.modules["c33_signer_store"] = signer_store
_STORE_SPEC.loader.exec_module(signer_store)
RECEIVER_ID = signer_store.RECEIVER_ID
record_attestation = signer_store.record_attestation

MAX_BODY_BYTES = 8192
DRAIN_LIMIT = 65536
REQUIRED_FIELDS = ("run_id", "token", "statement")


def create_server(
    host: str,
    port: int,
    store_path: Path,
    receiver_id: str = RECEIVER_ID,
) -> ThreadingHTTPServer:
    class SignerHandler(BaseHTTPRequestHandler):
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
            if not self.path.startswith("/beacons/") or length <= 0 or length > MAX_BODY_BYTES:
                self._drain()
                self.send_error(404 if not self.path.startswith("/beacons/") else 400)
                return
            try:
                data = json.loads(self.rfile.read(length))
            except (json.JSONDecodeError, UnicodeDecodeError):
                self.send_error(400)
                return
            if not all(
                isinstance(data.get(key), str) and data[key] for key in REQUIRED_FIELDS
            ):
                self.send_error(400)
                return
            record_attestation(
                data["run_id"],
                data["token"],
                data["statement"],
                receiver_id,
                path=store_path,
            )
            self.send_response(204)
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self.send_error(405)

        def log_message(self, format: str, *args: object) -> None:
            return

    return ThreadingHTTPServer((host, port), SignerHandler)
