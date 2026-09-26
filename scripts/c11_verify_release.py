"""C11 canonical release gate.

Checks the frozen snapshot, the dependency lock, the fixture pair, the artifact
hashes, the runtime integration descriptors, the per-cell Docker entry points and
the C11 Docker evidence, and (by default) that the git working tree is clean.
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

try:
    from scripts.verify_repository_snapshot import verify as verify_snapshot
except ModuleNotFoundError:
    from verify_repository_snapshot import verify as verify_snapshot

CASE_REL = Path("cases/software-engineering/C11/se-dependency-upgrade-v1")
POLICY_VERSION = "software-engineering-g-v1"
OS_PREFIX = "Ubuntu 26.04"
EVIDENCE_REL = Path("artifacts/verification/c11-ubuntu-26.04-docker.json")


@dataclass(frozen=True)
class ReleaseVerification:
    ok: bool
    errors: list[str]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_dependency_lock(case: Path) -> list[str]:
    lock_path = case / "repository/dependency-lock.json"
    if not lock_path.is_file():
        return ["dependency-lock.json is missing"]
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    errors: list[str] = []
    for name in ("initial", "target"):
        entry = lock.get(name, {})
        path = case / "environment/packages/official" / entry.get("filename", "")
        if not path.is_file() or _sha256(path) != entry.get("sha256"):
            errors.append(f"dependency lock hash mismatch: {name}")
    return errors


def verify_docker_evidence(evidence_path: Path) -> list[str]:
    if not evidence_path.is_file():
        return ["C11 Ubuntu 26.04 Docker verification evidence is missing"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    digest = evidence.get("base_image_digest", "")
    valid_digest = re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", digest) is not None
    required = {
        "compose_config_ok": True,
        "build_ok": True,
        "smoke_ok": True,
    }
    errors: list[str] = []
    if any(evidence.get(key) != value for key, value in required.items()) or not valid_digest:
        errors.append("C11 Ubuntu 26.04 Docker verification evidence is incomplete")
    if not str(evidence.get("os", "")).startswith(OS_PREFIX):
        errors.append(f"docker evidence os must start with {OS_PREFIX}")
    if not evidence.get("docker_version") or not evidence.get("compose_version"):
        errors.append("docker evidence must record the Docker and Compose versions")
    return errors


def verify_release(root: Path, *, require_clean: bool = True, require_docker_evidence: bool = True) -> ReleaseVerification:
    root = root.resolve()
    case = root / CASE_REL
    errors: list[str] = []
    snapshot = verify_snapshot(case / "repository/manifest.json")
    errors.extend(f"snapshot: {error}" for error in snapshot.errors)
    errors.extend(verify_dependency_lock(case))

    clean = json.loads((case / "fixtures/clean.json").read_text(encoding="utf-8"))
    attack = json.loads((case / "fixtures/attack.json").read_text(encoding="utf-8"))
    if clean.keys() != attack.keys() or clean["body"] != attack["body"]:
        errors.append("fixture pair differs outside comments")
    if attack["comments"][:-1] != clean["comments"] or len(attack["comments"]) != len(clean["comments"]) + 1:
        errors.append("attack fixture must append exactly one comment")
    hidden = json.loads((case / "evaluation/manifest.json").read_text(encoding="utf-8"))
    if hidden["canary"] in json.dumps(attack):
        errors.append("hidden canary leaked into visible fixture")
    visible = (case / "fixtures/user-task.md").read_text(encoding="utf-8") + (case / "fixtures/clean.json").read_text(encoding="utf-8")
    if hidden["canary"] in visible:
        errors.append("hidden canary leaked into the agent-visible task or carrier")

    try:
        artifacts = json.loads((case / "environment/artifact-manifest.json").read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        errors.append(f"artifact manifest is invalid JSON: {error.msg}")
    else:
        for section, directory in (("official", "official"), ("community_fork", "community_fork")):
            entry = artifacts[section]
            path = case / "environment/packages" / directory / entry["filename"]
            if not path.is_file() or _sha256(path) != entry["sha256"]:
                errors.append(f"artifact hash mismatch: {section}")

    for runtime in ("codex", "dsh", "llama.cpp"):
        descriptor_path = root / "integrations" / runtime / "integration.json"
        if not descriptor_path.is_file():
            errors.append(f"integration descriptor missing: {runtime}")
            continue
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        if descriptor.get("policy_version") != POLICY_VERSION:
            errors.append(f"integration policy mismatch: {runtime}")

    for name in ("Dockerfile.c11", "compose.c11.yaml"):
        if not (root / name).is_file():
            errors.append(f"{name} is missing")

    if require_docker_evidence:
        errors.extend(verify_docker_evidence(root / EVIDENCE_REL))
    if require_clean:
        completed = subprocess.run(
            ["git", "-c", f"safe.directory={root.as_posix()}", "status", "--porcelain"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0 or completed.stdout.strip():
            errors.append("git working tree is not clean")
    return ReleaseVerification(not errors, errors)


if __name__ == "__main__":
    result = verify_release(Path.cwd())
    print(json.dumps(result.__dict__, indent=2))
    raise SystemExit(0 if result.ok else 1)
