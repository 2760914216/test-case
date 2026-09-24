import json
from pathlib import Path

from scripts.c22_verify_release import (
    verify_artifacts,
    verify_attack_secrets_stay_hidden,
    verify_dependency_lock,
    verify_docker_evidence,
    verify_fixtures,
    verify_release,
    verify_shared_contracts,
)

ROOT = Path(".").resolve()
CASE = ROOT / "cases/software-engineering/C22/se-dependency-upgrade-v1"


def test_release_verifier_accepts_the_frozen_shared_contracts():
    assert verify_shared_contracts(ROOT) == []


def test_release_verifier_detects_a_case_specific_policy_change(tmp_path):
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir()
    mutated = {
        "version": "software-engineering-g-v1",
        "note": "release-notes-relay",
        "blocked_source_kinds": ["git", "http", "https", "file", "path"],
        "blocked_path_prefixes": ["../", "..\\", "/", "C:\\", "D:\\"],
        "blocked_hooks": ["postinstall", "preinstall", "install", "setup.py"],
    }
    (policy_dir / "software-engineering-g-v1.yaml").write_text(json.dumps(mutated), encoding="utf-8")

    errors = verify_shared_contracts(tmp_path)

    assert "C22 modified the shared software-engineering G policy" in errors
    assert "C22 policy carries a case-specific token: release-notes-relay" in errors


def test_release_verifier_checks_official_artifact_hashes():
    assert verify_artifacts(CASE) == []


def test_release_verifier_checks_the_dependency_lock_hashes():
    assert verify_dependency_lock(CASE) == []


def test_release_verifier_accepts_the_paired_fixtures_and_the_frozen_toolset():
    assert verify_fixtures(CASE) == []


def test_release_verifier_confirms_the_attack_secrets_stay_hidden():
    assert verify_attack_secrets_stay_hidden(CASE) == []


def test_release_verifier_fails_closed_when_the_docker_evidence_file_is_absent(tmp_path):
    errors = verify_docker_evidence(tmp_path / "absent.json")

    assert errors == ["Ubuntu 26.04 Docker verification evidence is missing"]


def _evidence(**overrides) -> dict:
    document = {
        "os": "Ubuntu 26.04 LTS",
        "base_image_digest": "python@sha256:" + "a" * 64,
        "docker_version": "29.8.1",
        "compose_version": "v5.5.1",
        "compose_config_ok": True,
        "clean_utility_ok": True,
        "attack_reaches_goal_ok": True,
    }
    document.update(overrides)
    return document


def test_release_verifier_accepts_an_ubuntu_26_04_point_release(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(_evidence(os="Ubuntu 26.04.1 LTS")), encoding="utf-8")

    assert verify_docker_evidence(path) == []


def test_release_verifier_rejects_evidence_from_another_release(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(_evidence(os="Ubuntu 24.04 LTS")), encoding="utf-8")

    assert verify_docker_evidence(path) == [
        "Ubuntu 26.04 Docker verification evidence is incomplete"
    ]


def test_release_verifier_accepts_the_recorded_c22_docker_evidence():
    evidence_path = ROOT / "artifacts/verification/c22-ubuntu-26.04-docker.json"
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    assert evidence["os"].startswith("Ubuntu 26.04")
    assert evidence["compose_config_ok"] is True
    assert evidence["clean_utility_ok"] is True
    assert evidence["attack_reaches_goal_ok"] is True
    assert verify_docker_evidence(evidence_path) == []


def test_release_verifier_passes_on_the_frozen_release_state():
    result = verify_release(ROOT, require_clean=False)

    assert result.errors == []
    assert result.ok is True
