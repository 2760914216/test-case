import json
from pathlib import Path

from scripts.c11_verify_release import (
    verify_dependency_lock,
    verify_docker_evidence,
    verify_release,
    verify_repository_evidence,
)

EVIDENCE = Path("artifacts/verification/c11-ubuntu-26.04-docker.json")
UPSTREAM_EVIDENCE = Path("artifacts/verification/c11-repository-evidence.json")


def test_release_verifier_accepts_the_code_contract_without_requiring_a_clean_tree():
    result = verify_release(Path.cwd(), require_clean=False, require_docker_evidence=False)

    assert result.ok is True, result.errors
    assert result.errors == []


def test_c11_docker_evidence_is_present_and_complete():
    assert EVIDENCE.is_file(), "run scripts/c11_build.sh and scripts/c11_docker_smoke.py first"
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["compose_config_ok"] is True
    assert evidence["build_ok"] is True
    assert evidence["smoke_ok"] is True
    assert evidence["os"].startswith("Ubuntu 26.04")
    assert verify_docker_evidence(EVIDENCE) == []


def test_c11_upstream_repository_evidence_is_present_and_consistent():
    assert UPSTREAM_EVIDENCE.is_file(), "run scripts/c11_repository_evidence.py first"
    evidence = json.loads(UPSTREAM_EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["ok"] is True
    assert evidence["repository"]["license"] == "Apache-2.0"
    assert evidence["frozen_commit"]["sha"] == "0c2bbe73982a70623fb81bf16b2507ea0ca80b99"
    assert evidence["snapshot"]["ok"] is True
    assert all(entry["match"] for entry in evidence["upstream_files"].values())
    assert verify_repository_evidence(UPSTREAM_EVIDENCE) == []


def test_repository_evidence_gate_rejects_a_missing_or_unexpected_document(tmp_path):
    assert verify_repository_evidence(tmp_path / "absent.json") == [
        "C11 upstream repository evidence is missing"
    ]
    bad = tmp_path / "bad.json"
    bad.write_text(
        json.dumps(
            {
                "ok": False,
                "repository": {"license": "MIT"},
                "frozen_commit": {"sha": "0" * 40},
                "snapshot": {"ok": False},
            }
        ),
        encoding="utf-8",
    )
    errors = verify_repository_evidence(bad)
    assert "C11 upstream repository evidence is not ok" in errors
    assert "C11 upstream repository evidence reports a bad snapshot" in errors
    assert "C11 upstream repository evidence reports an unexpected license" in errors
    assert "C11 upstream repository evidence reports an unexpected commit" in errors


def test_docker_evidence_requires_the_ubuntu_26_04_prefix(tmp_path):
    evidence = tmp_path / "docker.json"
    evidence.write_text(
        json.dumps(
            {
                "os": "Ubuntu 24.04 LTS",
                "docker_version": "29.8.1",
                "compose_version": "5.5.1",
                "base_image_digest": "python@sha256:" + "a" * 64,
                "compose_config_ok": True,
                "build_ok": True,
                "smoke_ok": True,
            }
        ),
        encoding="utf-8",
    )

    assert verify_docker_evidence(evidence) == ["docker evidence os must start with Ubuntu 26.04"]


def test_docker_evidence_requires_an_immutable_base_image_digest(tmp_path):
    evidence = tmp_path / "docker.json"
    evidence.write_text(
        json.dumps(
            {
                "os": "Ubuntu 26.04.1 LTS",
                "docker_version": "29.8.1",
                "compose_version": "5.5.1",
                "base_image_digest": "python:3.12.11-slim",
                "compose_config_ok": True,
                "build_ok": True,
                "smoke_ok": True,
            }
        ),
        encoding="utf-8",
    )

    assert verify_docker_evidence(evidence) == [
        "C11 Ubuntu 26.04 Docker verification evidence is incomplete"
    ]


def test_dependency_lock_checks_both_artifact_hashes(tmp_path):
    case = tmp_path / "case"
    packages = case / "environment/packages/official"
    packages.mkdir(parents=True)
    (case / "repository").mkdir()
    import hashlib

    entries = {}
    for name in ("initial", "target"):
        path = packages / f"{name}.whl"
        path.write_bytes(name.encode())
        entries[name] = {
            "version": "1",
            "filename": path.name,
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
        }
    (case / "repository/dependency-lock.json").write_text(
        json.dumps({"package": "urllib3", **entries}), encoding="utf-8"
    )

    assert verify_dependency_lock(case) == []
    (packages / "target.whl").write_bytes(b"changed")
    assert verify_dependency_lock(case) == ["dependency lock hash mismatch: target"]
