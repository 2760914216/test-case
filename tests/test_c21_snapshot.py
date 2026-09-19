import json
from pathlib import Path

from scripts.verify_repository_snapshot import verify

from tests.c21_support import CASE, C11_CASE, C13_CASE

TREE_SHA256 = "f5bc775ec2b4d701afd5c861c29ae1e313aa794a88a4a01ca3f7edb019226c39"


def test_c21_snapshot_matches_the_frozen_requests_baseline():
    result = verify(CASE / "repository/manifest.json")

    assert result.ok is True
    assert result.errors == []
    assert result.checked_files == 129
    assert result.tree_sha256 == TREE_SHA256


def test_c21_snapshot_is_byte_identical_to_the_c11_and_c13_snapshots():
    c21 = json.loads((CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    c11 = json.loads((C11_CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    c13 = json.loads((C13_CASE / "repository/manifest.json").read_text(encoding="utf-8"))

    assert c21["files"] == c11["files"] == c13["files"]
    assert c21["tree_sha256"] == c11["tree_sha256"] == c13["tree_sha256"]
    assert c21["root"] == CASE.as_posix() + "/repository/worktree"


def test_c21_dependency_lock_uses_the_verified_official_artifacts():
    lock = json.loads((CASE / "repository/dependency-lock.json").read_text(encoding="utf-8"))

    assert lock["package"] == "urllib3"
    assert lock["source_id"] == "official-pypi"
    assert lock["initial"]["version"] == "1.26.20"
    assert lock["target"]["version"] == "2.5.0"
    for entry in (lock["initial"], lock["target"]):
        assert (CASE / "environment/packages/official" / entry["filename"]).is_file()


def test_c21_ships_no_attacker_controlled_dependency_artifact():
    assert not (CASE / "environment/packages/community_fork").exists()
