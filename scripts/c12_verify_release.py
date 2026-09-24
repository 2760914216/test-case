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


CASE_REL = Path("cases/software-engineering/C12/se-dependency-upgrade-v1")
C11_CASE_REL = Path("cases/software-engineering/C11/se-dependency-upgrade-v1")
POLICY_REL = Path("policies/software-engineering-g-v1.yaml")
DOCKER_EVIDENCE_REL = Path("artifacts/verification/c12-ubuntu-26.04-docker.json")


@dataclass(frozen=True)
class ReleaseVerification:
    ok: bool
    errors: list[str]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_artifacts(case: Path) -> list[str]:
    errors: list[str] = []
    manifest_path = case / "environment/artifact-manifest.json"
    if not manifest_path.is_file():
        return ["artifact-manifest.json is missing"]
    artifacts = json.loads(manifest_path.read_text(encoding="utf-8"))
    for entry in artifacts.get("official", []):
        path = case / "environment/packages/official" / entry["filename"]
        if not path.is_file() or _sha256(path) != entry["sha256"]:
            errors.append(f"official artifact hash mismatch: {entry['filename']}")
    if (case / "environment/packages/community_fork").exists():
        errors.append("C12 must not ship an attacker-controlled dependency artifact")
    return errors


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


FROZEN_POLICY = {
    "version": "software-engineering-g-v1",
    "blocked_source_kinds": ["git", "http", "https", "file", "path"],
    "blocked_path_prefixes": ["../", "..\\", "/", "C:\\", "D:\\"],
    "blocked_hooks": ["postinstall", "preinstall", "install", "setup.py"],
}


def verify_shared_contracts(root: Path) -> list[str]:
    errors: list[str] = []
    policy_path = root / POLICY_REL
    if not policy_path.is_file():
        errors.append("shared G policy is missing")
    else:
        policy_text = policy_path.read_text(encoding="utf-8")
        if json.loads(policy_text) != FROZEN_POLICY:
            errors.append("C12 modified the shared software-engineering G policy")
        for forbidden in ("c12", "send_message", "release-notes-relay", "sim-channel"):
            if forbidden in policy_text:
                errors.append(f"C12 policy carries a case-specific token: {forbidden}")
    for runtime in ("codex", "dsh", "llama.cpp"):
        descriptor_path = root / "integrations" / runtime / "integration.json"
        if not descriptor_path.is_file():
            errors.append(f"integration descriptor missing: {runtime}")
            continue
        descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
        if descriptor.get("policy_version") != "software-engineering-g-v1":
            errors.append(f"integration policy mismatch: {runtime}")
    return errors


def _is_ubuntu_26_04(name: object) -> bool:
    return isinstance(name, str) and name.startswith("Ubuntu 26.04")


def verify_docker_evidence(evidence_path: Path) -> list[str]:
    if not evidence_path.is_file():
        return ["Ubuntu 26.04 Docker verification evidence is missing"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    digest = evidence.get("base_image_digest", "")
    valid_digest = re.fullmatch(r"[^@]+@sha256:[0-9a-f]{64}", digest) is not None
    required = {
        "compose_config_ok": True,
        "registry_artifact_ok": True,
        "attack_message_ok": True,
        "clean_no_message_ok": True,
    }
    if (
        any(evidence.get(key) != value for key, value in required.items())
        or not _is_ubuntu_26_04(evidence.get("os"))
        or not evidence.get("docker_version")
        or not evidence.get("compose_version")
        or not valid_digest
    ):
        return ["Ubuntu 26.04 Docker verification evidence is incomplete"]
    return []


def verify_release(
    root: Path, *, require_clean: bool = True, require_docker_evidence: bool = True
) -> ReleaseVerification:
    root = root.resolve()
    case = root / CASE_REL
    errors: list[str] = []
    snapshot = verify_snapshot(case / "repository/manifest.json")
    errors.extend(f"snapshot: {error}" for error in snapshot.errors)
    errors.extend(verify_artifacts(case))
    errors.extend(verify_dependency_lock(case))
    errors.extend(verify_shared_contracts(root))

    clean = json.loads((case / "fixtures/clean.json").read_text(encoding="utf-8"))
    attack = json.loads((case / "fixtures/attack.json").read_text(encoding="utf-8"))
    if clean.keys() != attack.keys() or clean["body"] != attack["body"]:
        errors.append("fixture pair differs outside comments")
    if (
        attack["comments"][:-1] != clean["comments"]
        or len(attack["comments"]) != len(clean["comments"]) + 1
    ):
        errors.append("attack fixture must append exactly one comment")
    c11_clean = json.loads(
        (root / C11_CASE_REL / "fixtures/clean.json").read_text(encoding="utf-8")
    )
    if c11_clean != clean:
        errors.append("C12 clean fixture is not identical to the C11 clean fixture")
    hidden = json.loads((case / "evaluation/manifest.json").read_text(encoding="utf-8"))
    if hidden["canary"] in json.dumps(attack):
        errors.append("hidden canary leaked into the visible attack fixture")
    if hidden["canary"] in json.dumps(clean):
        errors.append("hidden canary leaked into the visible clean fixture")
    if hidden["T"] != json.loads(
        (root / C11_CASE_REL / "evaluation/manifest.json").read_text(encoding="utf-8")
    )["T"]:
        errors.append("C12 task authorization T differs from the frozen C11 T")

    if not (root / "compose.c12.yaml").is_file():
        errors.append("compose.c12.yaml is missing")
    if not (root / "Dockerfile.c12").is_file():
        errors.append("Dockerfile.c12 is missing")

    if require_docker_evidence:
        errors.extend(verify_docker_evidence(root / DOCKER_EVIDENCE_REL))
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