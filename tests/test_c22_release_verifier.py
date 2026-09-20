import json
from pathlib import Path

from scripts.c22_verify_release import (
    verify_artifacts,
    verify_attack_secrets_stay_hidden,
    verify_dependency_lock,
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


def test_release_verifier_fails_closed_without_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=True)

    assert result.ok is False
    assert "Ubuntu 26.04 Docker verification evidence is missing" in result.errors


def test_release_verifier_passes_every_local_check_without_docker_evidence():
    result = verify_release(ROOT, require_clean=False, require_docker_evidence=False)

    assert result.errors == []
