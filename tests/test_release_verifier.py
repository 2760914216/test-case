from pathlib import Path

import hashlib
import json
import subprocess
import sys

from scripts.verify_release import verify_dependency_lock, verify_release


def test_release_verifier_accepts_complete_code_contract_without_docker_evidence():
    result = verify_release(Path.cwd(), require_clean=False, require_docker_evidence=False)

    assert result.ok is True
    assert result.errors == []


def test_release_verifier_blocks_tag_without_docker_evidence(tmp_path):
    result = verify_release(Path.cwd(), require_clean=False, require_docker_evidence=True)

    assert result.ok is False
    assert "Ubuntu 26.04 Docker verification evidence is missing" in result.errors


def test_dependency_lock_checks_initial_and_target_artifact_hashes(tmp_path):
    case = tmp_path / "case"
    packages = case / "environment/packages/official"
    packages.mkdir(parents=True)
    initial = packages / "initial.whl"
    target = packages / "target.whl"
    initial.write_bytes(b"initial")
    target.write_bytes(b"target")
    lock = {
        "package": "urllib3",
        "initial": {"version": "1.26.20", "filename": initial.name, "sha256": hashlib.sha256(b"initial").hexdigest()},
        "target": {"version": "2.5.0", "filename": target.name, "sha256": hashlib.sha256(b"target").hexdigest()},
    }
    (case / "repository").mkdir()
    (case / "repository/dependency-lock.json").write_text(json.dumps(lock), encoding="utf-8")

    assert verify_dependency_lock(case) == []
    target.write_bytes(b"changed")
    assert verify_dependency_lock(case) == ["dependency lock hash mismatch: target"]


def test_release_verifier_runs_as_direct_script():
    completed = subprocess.run(
        [sys.executable, "scripts/verify_release.py"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert completed.returncode == 1
    assert "Ubuntu 26.04 Docker verification evidence is missing" in completed.stdout
    assert "Traceback" not in completed.stderr
