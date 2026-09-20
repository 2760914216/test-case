from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from argparse import ArgumentParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_REPO = ROOT.parents[1]
BRANCH = "feature/c13-dependent-multi-step-chain"
ORIGIN = "git@github.com:2760914216/test-case.git"
OUTPUT = ROOT / "artifacts/verification/c13-fresh-clone.json"


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()
    source = ORIGIN if args.remote else str(LOCAL_REPO)

    scratch = Path(tempfile.mkdtemp(prefix="c13clone-"))
    clone = scratch / "clone"
    base_temp = scratch / "pt"
    cloned = _run(
        ["git", "-c", "core.longpaths=true", "clone", "--quiet", "--branch", BRANCH, source, str(clone)],
        ROOT,
    )
    if cloned.returncode != 0:
        print(cloned.stdout + cloned.stderr)
        return 1
    head = _run(["git", "rev-parse", "HEAD"], clone).stdout.strip()

    cases = {
        "C11": "cases/software-engineering/C11/se-dependency-upgrade-v1/repository/manifest.json",
        "C13": "cases/software-engineering/C13/se-dependency-upgrade-v1/repository/manifest.json",
    }
    snapshots = {}
    for name, manifest in cases.items():
        completed = _run([sys.executable, "scripts/verify_repository_snapshot.py", manifest], clone)
        snapshots[name] = json.loads(completed.stdout)

    base_temp.mkdir(parents=True, exist_ok=True)
    pytest = _run([sys.executable, "-m", "pytest", "tests", "-q", "--basetemp", str(base_temp)], clone)
    summary = [line for line in pytest.stdout.strip().splitlines() if line.strip()]
    release = _run([sys.executable, "scripts/c13_verify_release.py"], clone)

    payload = {
        "clone_source": source,
        "snapshot_C11": snapshots["C11"],
        "snapshot_C13": snapshots["C13"],
        "pytest_summary": summary[-1] if summary else "",
        "pytest_returncode": pytest.returncode,
        "commit": head,
        "release_verification": json.loads(release.stdout) if release.stdout.strip() else {},
        "note": (
            "Captured inside a fresh git clone of the pushed branch, before writing this file. "
            "Release verification is expected to fail only on the missing Ubuntu 26.04 LTS Docker "
            "evidence until that evidence exists."
        ),
    }
    OUTPUT.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8", newline=chr(10))
    print(json.dumps(payload, indent=2))
    shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
