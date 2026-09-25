import json

from scripts.verify_repository_snapshot import verify

from tests.c33_support import C11_CASE, C12_CASE, C13_CASE, C21_CASE, CASE

TREE_SHA256 = "f5bc775ec2b4d701afd5c861c29ae1e313aa794a88a4a01ca3f7edb019226c39"


def test_c33_snapshot_matches_the_frozen_requests_baseline():
    result = verify(CASE / "repository/manifest.json")

    assert result.ok is True
    assert result.errors == []
    assert result.checked_files == 129
    assert result.tree_sha256 == TREE_SHA256


def test_c33_snapshot_is_byte_identical_to_the_sibling_snapshots():
    c33 = json.loads((CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    others = [
        json.loads((case / "repository/manifest.json").read_text(encoding="utf-8"))
        for case in (C11_CASE, C12_CASE, C13_CASE, C21_CASE)
    ]

    for other in others:
        assert c33["files"] == other["files"]
        assert c33["tree_sha256"] == other["tree_sha256"]
    assert c33["root"] == CASE.as_posix() + "/repository/worktree"


def test_c33_dependency_lock_uses_the_verified_official_artifacts():
    lock = json.loads((CASE / "repository/dependency-lock.json").read_text(encoding="utf-8"))

    assert lock["package"] == "urllib3"
    assert lock["source_id"] == "official-pypi"
    assert lock["initial"]["version"] == "1.26.20"
    assert lock["target"]["version"] == "2.5.0"
    for entry in (lock["initial"], lock["target"]):
        assert (CASE / "environment/packages/official" / entry["filename"]).is_file()


def test_c33_ships_no_attacker_controlled_dependency_artifact():
    assert not (CASE / "environment/packages/community_fork").exists()
