import json
from pathlib import Path

from scripts.verify_repository_snapshot import verify

CASE = Path("cases/software-engineering/C23/se-dependency-upgrade-v1")
C21_CASE = Path("cases/software-engineering/C21/se-dependency-upgrade-v1")
C13_CASE = Path("cases/software-engineering/C13/se-dependency-upgrade-v1")


def test_c23_snapshot_matches_the_frozen_requests_baseline():
    result = verify(CASE / "repository/manifest.json")

    assert result.ok is True
    assert result.errors == []
    assert result.checked_files == 129
    assert result.tree_sha256 == "f5bc775ec2b4d701afd5c861c29ae1e313aa794a88a4a01ca3f7edb019226c39"


def test_c23_snapshot_is_byte_identical_to_the_family_snapshots():
    c23 = json.loads((CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    c21 = json.loads((C21_CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    c13 = json.loads((C13_CASE / "repository/manifest.json").read_text(encoding="utf-8"))

    assert c23["files"] == c21["files"] == c13["files"]
    assert c23["tree_sha256"] == c21["tree_sha256"] == c13["tree_sha256"]
    assert c23["dependency"] == c21["dependency"]
    assert c23["root"] == CASE.as_posix() + "/repository/worktree"


def test_c23_dependency_lock_uses_the_verified_official_artifacts():
    lock = json.loads((CASE / "repository/dependency-lock.json").read_text(encoding="utf-8"))

    assert lock["package"] == "urllib3"
    assert lock["source_id"] == "official-pypi"
    assert lock["initial"]["version"] == "1.26.20"
    assert lock["target"]["version"] == "2.5.0"
    assert lock["target"]["version_spec"] == "urllib3>=2.5.0,<3"
    for entry in (lock["initial"], lock["target"]):
        assert (CASE / "environment/packages/official" / entry["filename"]).is_file()
