from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]
BRANCH = "feature/c13-dependent-multi-step-chain"
OUTPUT = ROOT / "artifacts/verification/c13-fresh-clone.json"


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)


def main() -> int:
    scratch = Path(tempfile.mkdtemp(prefix="c13clone-"))
    CLONE = scratch / "clone"
    BASE_TEMP = scratch / "pt"
    cloned = _run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "clone",
            "--quiet",
            "--branch",
            BRANCH,
            str(REPO),
            str(CLONE),
        ],
        ROOT,
    )
    if cloned.returncode != 0:
        print(cloned.stdout + cloned.stderr)
        return 1
    head = _run(["git", "rev-parse", "HEAD"], CLONE).stdout.strip()

    cases = {
        "C11": "cases/software-engineering/C11/se-dependency-upgrade-v1/repository/manifest.json",
        "C13": "cases/software-engineering/C13/se-dependency-upgrade-v1/repository/manifest.json",
    }
    snapshots = {}
    for name, manifest in cases.items():
        completed = _run([sys.executable, "scripts/verify_repository_snapshot.py", manifest], CLONE)
        snapshots[name] = json.loads(completed.stdout)

    BASE_TEMP.mkdir(parents=True, exist_ok=True)
    pytest = _run(
        [sys.executable, "-m", "pytest", "tests", "-q", "--basetemp", str(BASE_TEMP)], CLONE
    )
    summary = [line for line in pytest.stdout.strip().splitlines() if line.strip()]
    release = _run([sys.executable, "scripts/c13_verify_release.py"], CLONE)

    payload = {
        "snapshot_C11": snapshots["C11"],
        "snapshot_C13": snapshots["C13"],
        "pytest_summary": summary[-1] if summary else "",
        "pytest_returncode": pytest.returncode,
        "commit": head,
        "release_verification": json.loads(release.stdout) if release.stdout.strip() else {},
        "note": (
            "Captured inside a fresh git clone of the feature branch, before writing this file. "
            "Release verification is expected to fail only on the missing Ubuntu 26.04 LTS Docker "
            "evidence until that evidence exists."
        ),
    }
    OUTPUT.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(payload, indent=2))
    shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
