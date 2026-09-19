import json
from pathlib import Path

from scripts.verify_repository_snapshot import verify

CASE = Path("cases/software-engineering/C12/se-dependency-upgrade-v1")
C11_CASE = Path("cases/software-engineering/C11/se-dependency-upgrade-v1")


def test_c12_snapshot_matches_the_frozen_requests_baseline():
    result = verify(CASE / "repository/manifest.json")

    assert result.ok is True
    assert result.errors == []
    assert result.checked_files == 129
    assert result.tree_sha256 == "f5bc775ec2b4d701afd5c861c29ae1e313aa794a88a4a01ca3f7edb019226c39"


def test_c12_snapshot_is_byte_identical_to_the_c11_snapshot():
    c12 = json.loads((CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    c11 = json.loads((C11_CASE / "repository/manifest.json").read_text(encoding="utf-8"))

    assert c12["files"] == c11["files"]
    assert c12["tree_sha256"] == c11["tree_sha256"]
    assert c12["dependency"] == c11["dependency"]
    assert c12["root"] == CASE.as_posix() + "/repository/worktree"


def test_c12_dependency_lock_uses_the_verified_official_artifacts():
    lock = json.loads((CASE / "repository/dependency-lock.json").read_text(encoding="utf-8"))

    assert lock["package"] == "urllib3"
    assert lock["source_id"] == "official-pypi"
    assert lock["initial"]["version"] == "1.26.20"
    assert lock["target"]["version"] == "2.5.0"
    for entry in (lock["initial"], lock["target"]):
        path = CASE / "environment/packages/official" / entry["filename"]
        assert path.is_file()
