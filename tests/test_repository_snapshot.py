import json
import hashlib
from pathlib import Path

from scripts.verify_repository_snapshot import build_manifest, verify


def _manifest(tmp_path: Path) -> Path:
    root = tmp_path / "worktree"
    root.mkdir()
    (root / "LICENSE").write_text("Apache License\n", encoding="utf-8")
    (root / "pyproject.toml").write_text(
        '[project]\nname = "requests"\ndependencies = ["urllib3>=1.21.1,<3"]\n',
        encoding="utf-8",
    )
    files = []
    for path in sorted(root.iterdir()):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append({"path": path.name, "sha256": digest})
    data = {
        "repository": {
            "url": "https://github.com/psf/requests",
            "commit": "0c2bbe73982a70623fb81bf16b2507ea0ca80b99",
            "license": "Apache-2.0",
        },
        "root": str(root),
        "files": files,
        "dependency": {
            "package": "urllib3",
            "starting_version": "1.26.20",
            "target_version": "2.5.0",
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_valid_snapshot_is_accepted(tmp_path):
    result = verify(_manifest(tmp_path))

    assert result.ok is True
    assert result.errors == []
    assert result.checked_files >= 2


def test_changed_file_is_rejected(tmp_path):
    manifest = _manifest(tmp_path)
    root = Path(json.loads(manifest.read_text(encoding="utf-8"))["root"])
    (root / "LICENSE").write_text("changed\n", encoding="utf-8")

    result = verify(manifest)

    assert result.ok is False
    assert any("hash" in error for error in result.errors)


def test_commit_mismatch_is_rejected(tmp_path):
    manifest = _manifest(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["repository"]["commit"] = "0" * 40
    manifest.write_text(json.dumps(data), encoding="utf-8")

    result = verify(manifest)

    assert result.ok is False
    assert any("commit" in error for error in result.errors)


def test_build_manifest_records_every_file_and_dependency_versions(tmp_path):
    source_manifest = _manifest(tmp_path)
    source = json.loads(source_manifest.read_text(encoding="utf-8"))
    root = Path(source["root"])

    generated = build_manifest(root, "1.26.20", "2.5.0")

    assert {entry["path"] for entry in generated["files"]} == {
        "LICENSE",
        "pyproject.toml",
    }
    assert generated["dependency"] == {
        "package": "urllib3",
        "starting_version": "1.26.20",
        "target_version": "2.5.0",
    }
