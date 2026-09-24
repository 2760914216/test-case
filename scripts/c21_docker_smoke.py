from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C21/se-dependency-upgrade-v1"
EVALUATION = CASE / "evaluation"
EVIDENCE = ROOT / "artifacts/verification/c21-ubuntu-26.04-docker.json"
COMPOSE_ARGS = ["docker", "compose", "-f", "compose.c21.yaml"]

_PREAMBLE = (
    "import json, sys; sys.path.insert(0, '/app/environment'); sys.path.insert(0, '/evaluation'); "
    "import resolution_policy, checkers; manifest = json.load(open('/evaluation/manifest.json')); "
)
_PROVISION_SCRIPT = _PREAMBLE + "resolution_policy.provision('/workspace', manifest); print('provisioned')"
_APPLY_SCRIPT = _PREAMBLE + (
    "import pathlib; parameters = json.loads(sys.argv[1]); run_id = sys.argv[2]; "
    "checkers.apply_dependency_parameters('/workspace', parameters, run_id); "
    "report = pathlib.Path('/workspace') / manifest['resolution_spec']['report_path']; "
    "report.parent.mkdir(parents=True, exist_ok=True); "
    "report.write_text('focused-requests-tests: PASS' + chr(10), encoding='utf-8'); "
    "print('applied')"
)


def _run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False, **kwargs)


def _policy_parameters(manifest: dict) -> dict:
    declared = manifest["policy"]
    return {
        "distribution": declared["distribution"],
        "constraint_literal": declared["constraint_literal"],
        "artifact_reference": declared["artifact_reference"],
        "source_kind": declared["source_kind"],
        "source_id": declared["source_id"],
    }


def _injection_parameters(manifest: dict) -> dict:
    injected = manifest["injection"]
    return {
        "distribution": injected["distribution"],
        "constraint_literal": injected["constraint_literal"],
        "artifact_reference": injected["artifact_reference"],
        "source_kind": injected["source_kind"],
        "source_id": injected["source_id"],
    }


def _in_container(
    script: str, workspace: Path, *arguments: str, env: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    return _run(
        COMPOSE_ARGS
        + [
            "run",
            "--rm",
            "-T",
            "-v",
            f"{EVALUATION}:/evaluation:ro",
            "--entrypoint",
            "python",
            "workspace",
            "-c",
            script,
            *arguments,
        ],
        cwd=ROOT,
        env={**env, "RUN_WORKSPACE": str(workspace)},
    )


def _evaluate(workspace: Path, run_id: str) -> dict:
    completed = _run(
        [
            sys.executable,
            str(ROOT / "scripts/c21_evaluate_run.py"),
            "--workspace",
            str(workspace),
            "--manifest",
            str(EVALUATION / "manifest.json"),
            "--run-id",
            run_id,
        ],
        cwd=ROOT,
    )
    if completed.returncode != 0:
        return {}
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect Ubuntu 26.04 Docker evidence for the C21 case."
    )
    parser.add_argument("--run-root", type=Path, default=ROOT / "artifacts/c21-docker-run")
    args = parser.parse_args()
    run_id = "c21-docker-smoke"
    run_root = args.run_root
    if run_root.exists():
        shutil.rmtree(run_root)
    workspace = run_root / "workspace"
    shutil.copytree(CASE / "repository/worktree", workspace)
    env = dict(os.environ)
    manifest = json.loads((EVALUATION / "manifest.json").read_text(encoding="utf-8"))

    release = platform.freedesktop_os_release()
    assert release["VERSION_ID"] == "26.04", release["PRETTY_NAME"]

    checks = {
        "compose_config_ok": _run(COMPOSE_ARGS + ["config", "-q"], cwd=ROOT).returncode == 0,
        "provision_ok": False,
        "clean_utility_ok": False,
        "attack_reaches_goal_ok": False,
    }
    evaluations: dict[str, dict] = {}
    try:
        if checks["compose_config_ok"]:
            provision = _in_container(_PROVISION_SCRIPT, workspace, env=env)
            checks["provision_ok"] = provision.returncode == 0
        if checks["provision_ok"]:
            clean_run = f"{run_id}-clean"
            clean_apply = _in_container(
                _APPLY_SCRIPT, workspace, json.dumps(_policy_parameters(manifest)), clean_run, env=env
            )
            evaluations["clean"] = _evaluate(workspace, clean_run)
            checks["clean_utility_ok"] = (
                clean_apply.returncode == 0
                and evaluations["clean"].get("utility", {}).get("ok") is True
            )
            attack_run = f"{run_id}-attack"
            attack_apply = _in_container(
                _APPLY_SCRIPT,
                workspace,
                json.dumps(_injection_parameters(manifest)),
                attack_run,
                env=env,
            )
            evaluations["attack"] = _evaluate(workspace, attack_run)
            checks["attack_reaches_goal_ok"] = (
                attack_apply.returncode == 0
                and evaluations["attack"].get("security_g", {}).get("ok") is True
            )
    finally:
        _run(COMPOSE_ARGS + ["down", "--remove-orphans"], cwd=ROOT, env=env)

    base_digest = ""
    base_image_file = ROOT / "artifacts/verification/c21-base-image.json"
    if base_image_file.is_file():
        base_digest = json.loads(base_image_file.read_text(encoding="utf-8")).get(
            "base_image_digest", ""
        )
    if not base_digest:
        base_digest = _run(
            [
                "docker",
                "image",
                "inspect",
                "python:3.12.11-slim",
                "--format",
                "{{index .RepoDigests 0}}",
            ]
        ).stdout.strip()
    evidence = {
        "os": release["PRETTY_NAME"],
        "os_release_version_id": release["VERSION_ID"],
        "base_image_digest": base_digest,
        "docker_version": _run(["docker", "version", "--format", "{{.Server.Version}}"]).stdout.strip(),
        "compose_version": _run(["docker", "compose", "version", "--short"]).stdout.strip(),
        "run_id": run_id,
        **checks,
        "evaluations": evaluations,
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
