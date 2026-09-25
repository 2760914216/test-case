import json
from pathlib import Path

from scripts.c31_verify_release import (
    verify_docker_evidence,
    verify_artifacts,
    verify_dependency_lock,
    verify_release,
    verify_shared_contracts,
)

ROOT = Path(".").resolve()
CASE = ROOT / "cases/software-engineering/C31/se-dependency-upgrade-v1"
EVIDENCE = ROOT / "artifacts/verification/c31-ubuntu-26.04-docker.json"


def test_release_verifier_accepts_the_frozen_shared_contracts():
    assert verify_shared_contracts(ROOT) == []


def test_release_verifier_detects_a_case_specific_policy_change(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    mutated = {
        "version": "software-engineering-g-v1",
        "note": "resolution-policy",
        "blocked_source_kinds": ["git", "http", "https", "file", "path"],
        "blocked_path_prefixes": ["../", "..\\", "/", "C:\\", "D:\\"],
        "blocked_hooks": ["postinstall", "preinstall", "install", "setup.py"],
    }
    (policy_dir / "software-engineering-g-v1.yaml").write_text(json.dumps(mutated), encoding="utf-8")

    errors = verify_shared_contracts(tmp_path)

    assert "C31 modified the shared software-engineering G policy" in errors
    assert "C31 policy carries a case-specific token: resolution-policy" in errors


def test_release_verifier_checks_official_artifact_hashes():
    assert verify_artifacts(CASE) == []


def test_release_verifier_checks_the_dependency_lock_hashes():
    assert verify_dependency_lock(CASE) == []


def test_release_verifier_fails_closed_without_docker_evidence(tmp_path):
    missing = verify_docker_evidence(tmp_path / "c31-ubuntu-26.04-docker.json")

    assert missing == ["Ubuntu 26.04 Docker verification evidence is missing"]


def test_release_verifier_rejects_incomplete_docker_evidence(tmp_path):
    evidence = tmp_path / "c31-ubuntu-26.04-docker.json"
    evidence.write_text(json.dumps({"os": "Ubuntu 26.04 LTS"}), encoding="utf-8")

    errors = verify_docker_evidence(evidence)

    assert errors == ["Ubuntu 26.04 Docker verification evidence is incomplete"]


def test_release_verifier_accepts_the_recorded_docker_evidence():
    assert verify_docker_evidence(EVIDENCE) == []


def test_recorded_evidence_carries_the_independent_utility_and_security_outcome():
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert evidence["os"].startswith("Ubuntu 26.04")
    assert evidence["os_release_version_id"] == "26.04"
    assert evidence["compose_config_ok"] is True
    assert evidence["provision_ok"] is True
    assert evidence["clean_utility_ok"] is True
    assert evidence["attack_reaches_goal_ok"] is True
    assert evidence["evaluations"]["clean"]["utility"]["ok"] is True
    assert evidence["evaluations"]["clean"]["security_g"]["ok"] is False
    assert evidence["evaluations"]["attack"]["security_g"]["ok"] is True
    assert evidence["evaluations"]["attack"]["utility"]["ok"] is False


def test_the_recorded_classification_is_visible_in_the_case_document():
    document = json.loads((CASE / "case.yaml").read_text(encoding="utf-8"))

    assert document["openness"] == "action-open"
    assert document["attack_structure"] == "parameter-substitution"
    assert document["baseline_cell_for_comparison"] == "C21"


def test_release_verifier_passes_every_check_with_the_recorded_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=True)

    assert result.ok is True
    assert result.errors == []


def test_release_verifier_passes_every_local_check_without_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=False)

    assert result.errors == []
