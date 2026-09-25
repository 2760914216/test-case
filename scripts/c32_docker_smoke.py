from __future__ import annotations

import hashlib
import json
import os
import shutil
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C32/se-dependency-upgrade-v1"
COMPOSE = ROOT / "compose.c32.yaml"
EVIDENCE = ROOT / "artifacts/verification/c32-ubuntu-26.04-docker.json"
COMPOSE_ARGS = ["docker", "compose", "-f", str(COMPOSE)]


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


_POST_SCRIPT = (
    "import json, sys, urllib.error, urllib.request\n"
    "request = urllib.request.Request('http://relay:8090/messages', "
    "data=json.dumps(json.loads(sys.argv[1])).encode('utf-8'), "
    "headers={'Content-Type': 'application/json'}, method='POST')\n"
    "try:\n"
    "    response = urllib.request.urlopen(request, timeout=15)\n"
    "    status = response.status\n"
    "    response.close()\n"
    "except urllib.error.HTTPError as error:\n"
    "    status = error.code\n"
    "print(json.dumps({'status': status}))"
)

_FETCH_SCRIPT = (
    "import hashlib, json, urllib.request\n"
    "response = urllib.request.urlopen("
    "'http://registry:8080/artifacts/urllib3-2.5.0-py3-none-any.whl', timeout=15)\n"
    "payload = response.read()\n"
    "status = response.status\n"
    "response.close()\n"
    "print(json.dumps({'status': status, 'sha256': hashlib.sha256(payload).hexdigest()}))"
)


def _in_container(script: str, *arguments: str, env: dict[str, str]) -> dict[str, object]:
    completed = _run(
        COMPOSE_ARGS
        + ["run", "--rm", "-T", "--entrypoint", "python", "workspace", "-c", script, *arguments],
        cwd=ROOT,
        env=env,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    if completed.returncode != 0 or not lines:
        return {}
    try:
        return json.loads(lines[-1])
    except json.JSONDecodeError:
        return {}


def _post(run_id: str, channel: str, body: str, env: dict[str, str]) -> int:
    result = _in_container(
        _POST_SCRIPT, json.dumps({"run_id": run_id, "channel": channel, "body": body}), env=env
    )
    return int(result.get("status", 0))


def _fetch_artifact(env: dict[str, str]) -> tuple[int, str]:
    result = _in_container(_FETCH_SCRIPT, env=env)
    return int(result.get("status", 0)), str(result.get("sha256", ""))


def main() -> int:
    run_id = sys.argv[1] if len(sys.argv) > 1 else "c32-docker-smoke"
    run_root = ROOT / "artifacts" / run_id
    if run_root.exists():
        shutil.rmtree(run_root)
    state_dir = run_root / "state"
    state_dir.mkdir(parents=True)
    workspace = run_root / "workspace"
    shutil.copytree(CASE / "repository/worktree", workspace)
    env = dict(os.environ)
    env["C32_RUN_STATE"] = str(state_dir)
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
            status, digest = _fetch_artifact(env)
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
                env,
            )
            evaluate = _run(
                [
                    sys.executable,
                    str(ROOT / "scripts/c32_evaluate_run.py"),
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
                    str(ROOT / "scripts/c32_evaluate_run.py"),
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
    base_image_file = ROOT / "artifacts/verification/c32-base-image.json"
    if base_image_file.is_file():
        base_digest = json.loads(base_image_file.read_text(encoding="utf-8")).get(
            "base_image_digest", ""
        )
    docker_version = _run(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip()
    compose_version = _run(["docker", "compose", "version", "--short"]).stdout.strip()
    release = platform.freedesktop_os_release()
    assert release["VERSION_ID"] == "26.04", release["PRETTY_NAME"]
    evidence = {
        "os": release["PRETTY_NAME"],
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
