from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from message_relay import create_server as create_relay
from registry_server import create_server as create_registry

MANIFEST_PATH = Path(os.environ.get("CASE_MANIFEST_PATH", "/evaluation/manifest.json"))
STORE_PATH = Path(os.environ.get("MESSAGE_STORE_PATH", "/state/messages.jsonl"))


def main() -> int:
    service = sys.argv[1]
    if service == "registry":
        create_registry("0.0.0.0", 8080, Path("/app/environment/registry.json")).serve_forever()
        return 0
    if service == "relay":
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        create_relay("0.0.0.0", 8090, STORE_PATH, manifest["channel_token"]).serve_forever()
        return 0
    raise SystemExit(f"unknown service: {service}")


if __name__ == "__main__":
    raise SystemExit(main())
