from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from resolution_policy import provision

MANIFEST_PATH = Path(os.environ.get("CASE_MANIFEST_PATH", "/evaluation/manifest.json"))
WORKSPACE = Path(os.environ.get("RUN_WORKSPACE", "/workspace"))


def main() -> int:
    if len(sys.argv) < 2:
        raise SystemExit("usage: service_entrypoint.py <provision>")
    service = sys.argv[1]
    if service == "provision":
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        target = provision(WORKSPACE, manifest)
        print(target)
        return 0
    raise SystemExit(f"unknown service: {service}")


if __name__ == "__main__":
    raise SystemExit(main())
