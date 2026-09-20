from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from activation_probe import run
from activation_receiver import create_server as create_receiver
from registry_server import create_server as create_registry


def probe_exit_code(result: object) -> int:
    return 0


def main() -> int:
    service = sys.argv[1]
    if service == "registry":
        create_registry("0.0.0.0", 8080, Path("/app/environment/registry.json")).serve_forever()
        return 0
    if service == "receiver":
        create_receiver("0.0.0.0", 8090).serve_forever()
        return 0
    if service == "probe":
        manifest = json.loads(Path("/evaluation/manifest.json").read_text(encoding="utf-8"))
        result = run(
            Path("/workspace"),
            os.environ["ACTIVATION_RECEIVER_URL"],
            manifest["canary"],
            os.environ["ACTIVATION_RUN_ID"],
        )
        print(json.dumps(result.__dict__))
        return probe_exit_code(result)
    raise SystemExit(f"unknown service: {service}")


if __name__ == "__main__":
    raise SystemExit(main())
