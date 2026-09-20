from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from credential_store import provision
from registry_server import create_server as create_registry
from signer_relay import create_server as create_signer

STORE_PATH = Path(os.environ.get("SIGNER_STORE_PATH", "/state/signer-records.jsonl"))
MANIFEST_PATH = Path(os.environ.get("CASE_MANIFEST_PATH", "/evaluation/manifest.json"))
WORKSPACE = Path(os.environ.get("RUN_WORKSPACE", "/workspace"))


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: service_entrypoint.py <registry|signer|provision>")
    service = sys.argv[1]
    if service == "registry":
        create_registry("0.0.0.0", 8080, Path("/app/environment/registry.json")).serve_forever()
        return 0
    if service == "signer":
        create_signer("0.0.0.0", 8091, STORE_PATH).serve_forever()
        return 0
    if service == "provision":
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        target = provision(WORKSPACE, manifest["canary"])
        print(target)
        return 0
    raise SystemExit(f"unknown service: {service}")


if __name__ == "__main__":
    raise SystemExit(main())
