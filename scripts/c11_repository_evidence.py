"""Record fresh upstream evidence for the frozen C11 repository snapshot.

Queries the GitHub API for the pinned repository, fetches the pinned files through
the GitHub proxy and compares their SHA-256 hashes with the vendored snapshot.
Writes artifacts/verification/c11-repository-evidence.json.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import urllib.request
from pathlib import Path

try:
    from scripts.verify_repository_snapshot import verify as verify_snapshot
except ModuleNotFoundError:
    from verify_repository_snapshot import verify as verify_snapshot

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C11/se-dependency-upgrade-v1"
OUTPUT = ROOT / "artifacts/verification/c11-repository-evidence.json"
API = "https://api.github.com"
PROXY = "https://gh-proxy.com/https://raw.githubusercontent.com"
FILES = ("pyproject.toml", "LICENSE")
TIMEOUT = 60


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "c11-repository-evidence"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_bytes(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "c11-repository-evidence"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args()

    manifest = json.loads((CASE / "repository/manifest.json").read_text(encoding="utf-8"))
    repository = manifest["repository"]
    commit = repository["commit"]
    full_name = "/".join(repository["url"].rstrip("/").split("/")[-2:])

    repo = fetch_json(f"{API}/repos/{full_name}")
    frozen = fetch_json(f"{API}/repos/{full_name}/commits/{commit}")

    files: dict[str, dict[str, object]] = {}
    for name in FILES:
        upstream = fetch_bytes(f"{PROXY}/{full_name}/{commit}/{name}")
        local = (CASE / "repository/worktree" / name).read_bytes()
        files[name] = {
            "upstream_sha256": sha256(upstream),
            "snapshot_sha256": sha256(local),
            "match": sha256(upstream) == sha256(local),
        }

    snapshot = verify_snapshot(CASE / "repository/manifest.json")

    evidence = {
        "checked_at_utc": datetime.datetime.now(datetime.UTC).replace(microsecond=0).isoformat(),
        "repository": {
            "full_name": repo["full_name"],
            "archived": repo["archived"],
            "disabled": repo.get("disabled", False),
            "license": (repo.get("license") or {}).get("spdx_id"),
            "default_branch": repo["default_branch"],
            "pushed_at": repo["pushed_at"],
            "stars": repo["stargazers_count"],
        },
        "frozen_commit": {
            "sha": frozen["sha"],
            "message": frozen["commit"]["message"].splitlines()[0],
            "commit_date": frozen["commit"]["committer"]["date"],
        },
        "upstream_files": files,
        "snapshot": {
            "checked_files": snapshot.checked_files,
            "tree_sha256": snapshot.tree_sha256,
            "ok": snapshot.ok,
            "errors": list(snapshot.errors),
        },
        "ok": (
            all(entry["match"] for entry in files.values())
            and snapshot.ok
            and (repo.get("license") or {}).get("spdx_id") == repository["license"]
            and frozen["sha"] == commit
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(evidence, indent=2))
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
