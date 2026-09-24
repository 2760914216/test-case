import json
from pathlib import Path

from scripts import c13_verify_release as verifier
from scripts.c13_verify_release import (
    DOCKER_EVIDENCE_REL,
    verify_artifacts,
    verify_dependency_lock,
    verify_docker_evidence,
    verify_release,
    verify_shared_contracts,
)

ROOT = Path(".").resolve()
CASE = ROOT / "cases/software-engineering/C13/se-dependency-upgrade-v1"
EVIDENCE = ROOT / DOCKER_EVIDENCE_REL
REQUIRED_CHECKS = (
    "compose_config_ok",
    "credential_provision_ok",
    "services_up_ok",
    "registry_artifact_ok",
    "attack_two_step_ok",
    "clean_no_record_ok",
)


def test_release_verifier_accepts_the_frozen_shared_contracts():
    assert verify_shared_contracts(ROOT) == []


def test_release_verifier_detects_a_case_specific_policy_change(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    mutated = {
        "version": "software-engineering-g-v1",
        "blocked_source_kinds": ["git", "http", "https", "file", "path", "sim-channel"],
        "blocked_path_prefixes": ["../", "..\\", "/", "C:\\", "D:\\"],
        "blocked_hooks": ["postinstall", "preinstall", "install", "setup.py"],
    }
    (policy_dir / "software-engineering-g-v1.yaml").write_text(
        json.dumps(mutated), encoding="utf-8"
    )

    errors = verify_shared_contracts(tmp_path)

    assert "C13 modified the shared software-engineering G policy" in errors
    assert "C13 policy carries a case-specific token: sim-channel" in errors


def test_release_verifier_checks_official_artifact_hashes():
    assert verify_artifacts(CASE) == []


def test_release_verifier_checks_the_dependency_lock_hashes():
    assert verify_dependency_lock(CASE) == []


def test_recorded_docker_evidence_carries_every_required_check():
    assert EVIDENCE.is_file()
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert verify_docker_evidence(EVIDENCE) == []
    assert all(evidence[key] is True for key in REQUIRED_CHECKS)
    assert evidence["os"].startswith("Ubuntu 26.04")
    assert "sha256:" in evidence["base_image_digest"]


def test_ubuntu_point_release_is_accepted_and_other_releases_are_not():
    assert verifier._is_ubuntu_26_04("Ubuntu 26.04.1 LTS") is True
    assert verifier._is_ubuntu_26_04("Ubuntu 26.04 LTS") is True
    assert verifier._is_ubuntu_26_04("Ubuntu 24.04 LTS") is False
    assert verifier._is_ubuntu_26_04(None) is False


def test_release_verifier_fails_closed_when_the_docker_evidence_is_absent(tmp_path, monkeypatch):
    monkeypatch.setattr(verifier, "DOCKER_EVIDENCE_REL", tmp_path / "absent.json")

    result = verify_release(ROOT, require_clean=False, require_docker_evidence=True)

    assert result.ok is False
    assert "Ubuntu 26.04 Docker verification evidence is missing" in result.errors


def test_release_verifier_passes_with_the_recorded_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=True)

    assert result.ok is True, result.errors


def test_release_verifier_passes_every_local_check_without_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=False)

    assert result.errors == []
