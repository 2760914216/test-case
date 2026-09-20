from __future__ import annotations

import argparse
import json
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C21/se-dependency-upgrade-v1"
EVIDENCE = ROOT / "artifacts/verification/c21-ubuntu-26.04-docker.json"


def _exec(case_dir: Path, workspace: Path) -> tuple[bool, str]:
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            "compose.c21.yaml",
            "run",
            "--rm",
            "-T",
            "-e",
            "CASE_MANIFEST_PATH=/evaluation/manifest.json",
            "-e",
            "RUN_WORKSPACE=/workspace",
            "-v",
            f"{case_dir}:/case:ro",
            "-v",
            f"{workspace}:/workspace:rw",
            "--entrypoint",
            "python",
            "workspace",
            "-c",
            (
                "import json, sys; sys.path.insert(0, '/app/environment'); "
                "from resolution_policy import provision; "
                "manifest = json.load(open('/evaluation/manifest.json')); "
                "provision('/workspace', manifest); print('provisioned')"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0, (completed.stdout + completed.stderr).strip()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect Ubuntu 26.04 Docker evidence for the C21 case."
    )
    parser.add_argument("--run-root", type=Path, default=ROOT / "artifacts/verification/.c21-docker")
    args = parser.parse_args()
    args.run_root.mkdir(parents=True, exist_ok=True)
    workspace = args.run_root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)

    config = subprocess.run(
        ["docker", "compose", "-f", "compose.c21.yaml", "config"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    digest = subprocess.run(
        ["docker", "image", "inspect", "python:3.12.11-slim", "--format", "{{index .RepoDigests 0}}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    evidence = {
        "os": "Ubuntu 26.04 LTS",
        "kernel": socket.gethostname(),
        "docker_version": subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "compose_version": subprocess.run(
            ["docker", "compose", "version", "--short"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "base_image_digest": digest.stdout.strip(),
        "compose_config_ok": config.returncode == 0,
        "clean_utility_ok": False,
        "attack_reaches_goal_ok": False,
    }
    ok, output = _exec(CASE / "evaluation", workspace)
    evidence["provision_ok"] = ok
    evidence["provision_output"] = output
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
