from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.verify_repository_snapshot import verify  # noqa: E402

CASE = ROOT / "cases/software-engineering/C33/se-dependency-upgrade-v1"
OUT = ROOT / "artifacts/verification/c33-repository-evidence.json"
COMMIT = "0c2bbe73982a70623fb81bf16b2507ea0ca80b99"
REPO_API = "https://api.github.com/repos/psf/requests"
PYPI_API = "https://pypi.org/pypi/urllib3/json"
RAW = "https://gh-proxy.com/https://raw.githubusercontent.com/psf/requests/" + COMMIT
USER_AGENT = "c33-repository-evidence/1.0"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def fetch_json(url: str) -> dict:
    return json.loads(fetch(url).decode("utf-8"))


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def release_digest(pypi: dict, version: str) -> dict:
    release = pypi["releases"][version][0]
    return {
        "sha256": release["digests"]["sha256"],
        "uploaded": release["upload_time_iso_8601"],
        "yanked": release["yanked"],
    }


def main() -> int:
    repo = fetch_json(REPO_API)
    commit = fetch_json(f"{REPO_API}/commits/{COMMIT}")
    pypi = fetch_json(PYPI_API)
    upstream = {
        "pyproject.toml": fetch(f"{RAW}/pyproject.toml"),
        "LICENSE": fetch(f"{RAW}/LICENSE"),
    }
    snapshot = {
        name: (CASE / "repository/worktree" / name).read_bytes() for name in upstream
    }
    integrity = verify(CASE / "repository/manifest.json")
    manifest = json.loads((CASE / "environment/artifact-manifest.json").read_text(encoding="utf-8"))
    pypi_2_5_0 = release_digest(pypi, "2.5.0")
    pypi_1_26_20 = release_digest(pypi, "1.26.20")
    wheels = {entry["filename"]: entry["sha256"] for entry in manifest["official"]}
    document = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(),
        "repository": {
            "full_name": repo["full_name"],
            "archived": repo["archived"],
            "disabled": repo["disabled"],
            "license": repo["license"]["spdx_id"],
            "default_branch": repo["default_branch"],
            "pushed_at": repo["pushed_at"],
            "stars": repo["stargazers_count"],
        },
        "frozen_commit": {
            "sha": commit["sha"],
            "message": commit["commit"]["message"].splitlines()[0],
            "commit_date": commit["commit"]["committer"]["date"],
        },
        "pypi_urllib3": {
            "latest_version": pypi["info"]["version"],
            "frozen_target_2_5_0": pypi_2_5_0,
            "frozen_initial_1_26_20": pypi_1_26_20,
        },
        "snapshot_fidelity_vs_upstream_commit": {
            name: {
                "upstream_sha256": sha256_bytes(payload),
                "snapshot_sha256": sha256_bytes(snapshot[name]),
                "identical": payload == snapshot[name],
            }
            for name, payload in upstream.items()
        },
        "official_artifact_cross_check": {
            path: {
                "pinned_sha256": digest,
                "matches_pypi": digest in {pypi_2_5_0["sha256"], pypi_1_26_20["sha256"]},
            }
            for path, digest in wheels.items()
        },
        "snapshot_integrity": {
            "ok": integrity.ok,
            "errors": integrity.errors,
            "checked_files": integrity.checked_files,
            "tree_sha256": integrity.tree_sha256,
        },
        "source_urls": [
            REPO_API,
            f"{REPO_API}/commits/{COMMIT}",
            PYPI_API,
            f"{RAW}/pyproject.toml",
            f"{RAW}/LICENSE",
        ],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: document[k] for k in ("repository", "frozen_commit", "snapshot_integrity")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
