from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXPECTED_COMMIT = "0c2bbe73982a70623fb81bf16b2507ea0ca80b99"


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    errors: list[str]
    checked_files: int
    tree_sha256: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tree_hash(root: Path, relative_paths: list[str] | None = None) -> str:
    digest = hashlib.sha256()
    if relative_paths is None:
        relative_paths = [
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file()
        ]
    for relative_text in sorted(relative_paths):
        path = root / relative_text
        relative = relative_text.encode("utf-8")
        file_hash = _sha256(path) if path.is_file() else ""
        digest.update(relative + b"\0" + file_hash.encode("ascii") + b"\n")
    return digest.hexdigest()


def build_manifest(
    root: Path, starting_version: str, target_version: str
) -> dict[str, Any]:
    files = [
        {"path": path.relative_to(root).as_posix(), "sha256": _sha256(path)}
        for path in sorted(path for path in root.rglob("*") if path.is_file())
    ]
    return {
        "repository": {
            "url": "https://github.com/psf/requests",
            "commit": EXPECTED_COMMIT,
            "license": "Apache-2.0",
        },
        "root": root.as_posix(),
        "files": files,
        "dependency": {
            "package": "urllib3",
            "starting_version": starting_version,
            "target_version": target_version,
        },
        "tree_sha256": _tree_hash(root, [entry["path"] for entry in files]),
    }


def verify(manifest_path: Path) -> VerificationResult:
    data: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    root = Path(data["root"])
    errors: list[str] = []
    repository = data.get("repository", {})
    if repository.get("commit") != EXPECTED_COMMIT:
        errors.append("repository commit does not match frozen baseline")
    if repository.get("license") != "Apache-2.0":
        errors.append("repository license must be Apache-2.0")
    dependency = data.get("dependency", {})
    if dependency.get("package") != "urllib3":
        errors.append("dependency package must be urllib3")
    if not dependency.get("starting_version"):
        errors.append("dependency starting_version is required")
    if dependency.get("target_version") != "2.5.0":
        errors.append("dependency target_version must be 2.5.0")
    license_path = root / "LICENSE"
    project_path = root / "pyproject.toml"
    if not license_path.is_file():
        errors.append("LICENSE is missing")
    if not project_path.is_file():
        errors.append("pyproject.toml is missing")
    elif "urllib3" not in project_path.read_text(encoding="utf-8"):
        errors.append("pyproject.toml has no urllib3 dependency slot")

    checked_files = 0
    for entry in data.get("files", []):
        path = root / entry["path"]
        checked_files += 1
        if not path.is_file():
            errors.append(f"snapshot file missing: {entry['path']}")
        elif _sha256(path) != entry["sha256"]:
            errors.append(f"snapshot file hash mismatch: {entry['path']}")
    declared_paths = [entry["path"] for entry in data.get("files", [])]
    tree_hash = _tree_hash(root, declared_paths) if root.is_dir() else ""
    if data.get("tree_sha256") != tree_hash:
        errors.append("snapshot tree hash mismatch")
    return VerificationResult(not errors, errors, checked_files, tree_hash)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--create-from", type=Path)
    parser.add_argument("--starting-version", default="1.26.20")
    parser.add_argument("--target-version", default="2.5.0")
    args = parser.parse_args()
    if args.create_from:
        manifest = build_manifest(
            args.create_from, args.starting_version, args.target_version
        )
        args.manifest.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    result = verify(args.manifest)
    print(json.dumps(result.__dict__, indent=2))
    raise SystemExit(0 if result.ok else 1)
