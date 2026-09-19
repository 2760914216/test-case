from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C22/se-dependency-upgrade-v1"
COMPOSE = ROOT / "compose.c22.yaml"
EVIDENCE = ROOT / "artifacts/verification/c22-ubuntu-26.04-docker.json"
COMPOSE_ARGS = ["docker", "compose", "-f", str(COMPOSE)]


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


def _post(run_id: str, channel: str, body: str) -> int:
    payload = json.dumps({"run_id": run_id, "channel": channel, "body": body}).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:8090/messages",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        return response.status


def _fetch_artifact() -> tuple[int, str]:
    with urllib.request.urlopen(
        "http://127.0.0.1:8080/artifacts/urllib3-2.5.0-py3-none-any.whl", timeout=15
    ) as response:
        payload = response.read()
        return response.status, hashlib.sha256(payload).hexdigest()


def main() -> int:
    run_id = sys.argv[1] if len(sys.argv) > 1 else "c22-docker-smoke"
    run_root = ROOT / "artifacts" / run_id
    if run_root.exists():
        shutil.rmtree(run_root)
    state_dir = run_root / "state"
    state_dir.mkdir(parents=True)
    workspace = run_root / "workspace"
    shutil.copytree(CASE / "repository/worktree", workspace)
    env = dict(os.environ)
    env["C22_RUN_STATE"] = str(state_dir)
    env["RUN_WORKSPACE"] = str(workspace)
    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))

    provision = _run(
        [sys.executable, str(CASE / "environment/service_entrypoint.py"), "provision"],
        cwd=ROOT,
        env={**os.environ, "CASE_MANIFEST_PATH": str(CASE / "evaluation/manifest.json"), "RUN_WORKSPACE": str(workspace)},
    )
    config_ok = _run(COMPOSE_ARGS + ["config", "-q"], cwd=ROOT).returncode == 0
    up_ok = (
        _run(COMPOSE_ARGS + ["up", "-d", "--wait", "registry", "relay"], cwd=ROOT, env=env).returncode
        == 0
    )
    checks = {
        "compose_config_ok": config_ok,
        "provision_ok": provision.returncode == 0,
        "services_up_ok": up_ok,
        "registry_artifact_ok": False,
        "attack_reaches_goal_ok": False,
        "clean_no_message_ok": False,
    }
    try:
        if up_ok:
            status, digest = _fetch_artifact()
            expected = next(
                entry["sha256"]
                for entry in json.loads(
                    (CASE / "environment/artifact-manifest.json").read_text(encoding="utf-8")
                )["official"]
                if entry["filename"] == "urllib3-2.5.0-py3-none-any.whl"
            )
            checks["registry_artifact_ok"] = status == 200 and digest == expected
            attack_run = f"{run_id}-attack"
            message_status = _post(
                attack_run,
                manifest["g"]["channel"],
                "Change summary: " + manifest["g"]["payload_marker"],
            )
            evaluate = _run(
                [
                    sys.executable,
                    str(ROOT / "scripts/c22_evaluate_run.py"),
                    "--workspace",
                    str(workspace),
                    "--messages",
                    str(state_dir / "messages.jsonl"),
                    "--manifest",
                    str(CASE / "evaluation/manifest.json"),
                    "--run-id",
                    attack_run,
                ],
                cwd=ROOT,
            )
            attack_payload = json.loads(evaluate.stdout) if evaluate.returncode == 0 else {}
            checks["attack_reaches_goal_ok"] = (
                message_status == 204
                and attack_payload.get("security_g", {}).get("ok") is True
            )
            clean_run = f"{run_id}-clean"
            evaluate_clean = _run(
                [
                    sys.executable,
                    str(ROOT / "scripts/c22_evaluate_run.py"),
                    "--workspace",
                    str(workspace),
                    "--messages",
                    str(state_dir / "messages.jsonl"),
                    "--manifest",
                    str(CASE / "evaluation/manifest.json"),
                    "--run-id",
                    clean_run,
                ],
                cwd=ROOT,
            )
            clean_payload = json.loads(evaluate_clean.stdout) if evaluate_clean.returncode == 0 else {}
            checks["clean_no_message_ok"] = clean_payload.get("security_g", {}).get("ok") is False
    finally:
        _run(COMPOSE_ARGS + ["down"], cwd=ROOT, env=env)

    base_digest = ""
    base_image_file = ROOT / "artifacts/verification/c22-base-image.json"
    if base_image_file.is_file():
        base_digest = json.loads(base_image_file.read_text(encoding="utf-8")).get(
            "base_image_digest", ""
        )
    docker_version = _run(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    compose_version = _run(["docker", "compose", "version", "--short"]).stdout.strip()
    evidence = {
        "os": "Ubuntu 26.04 LTS",
        "base_image_digest": base_digest,
        "docker_version": docker_version,
        "compose_version": compose_version,
        "run_id": run_id,
        "clean_utility_ok": checks["provision_ok"] and up_ok,
        **checks,
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
