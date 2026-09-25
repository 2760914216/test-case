from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from argparse import ArgumentParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCAL_REPO = ROOT
BRANCH = "feature/c32-action-open-independent-single-action"
ORIGIN = "git@ssh.github.com:2760914216/test-case.git"
OUTPUT = ROOT / "artifacts/verification/c32-fresh-clone.json"

CASES = {
    "C11": "cases/software-engineering/C11/se-dependency-upgrade-v1/repository/manifest.json",
    "C21": "cases/software-engineering/C21/se-dependency-upgrade-v1/repository/manifest.json",
    "C22": "cases/software-engineering/C22/se-dependency-upgrade-v1/repository/manifest.json",
    "C31": "cases/software-engineering/C31/se-dependency-upgrade-v1/repository/manifest.json",
    "C32": "cases/software-engineering/C32/se-dependency-upgrade-v1/repository/manifest.json",
}


def _run(
    command: list[str], cwd: Path, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False, env=env)


def _ssh_env() -> dict[str, str] | None:
    """Reuse the repository's configured SSH command for the nested clone.

    `git clone` does not always pick up `core.sshCommand` from the surrounding
    repository, so the value is forwarded through GIT_SSH_COMMAND instead.
    """
    import os

    configured = subprocess.run(
        ["git", "config", "--get", "core.sshCommand"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    if not configured:
        return None
    return {**os.environ, "GIT_SSH_COMMAND": configured}


def main() -> int:
    parser = ArgumentParser()
    parser.add_argument("--remote", action="store_true")
    args = parser.parse_args()
    source = ORIGIN if args.remote else str(LOCAL_REPO)

    scratch = Path(tempfile.mkdtemp(prefix="c32clone-"))
    clone = scratch / "clone"
    base_temp = scratch / "pt"
    cloned = _run(
        ["git", "-c", "core.longpaths=true", "clone", "--quiet", "--branch", BRANCH, source, str(clone)],
        ROOT,
        _ssh_env(),
    )
    if cloned.returncode != 0:
        print(cloned.stdout + cloned.stderr)
        return 1
    head = _run(["git", "rev-parse", "HEAD"], clone).stdout.strip()

    snapshots = {}
    for name, manifest in CASES.items():
        completed = _run([sys.executable, "scripts/verify_repository_snapshot.py", manifest], clone)
        snapshots[name] = json.loads(completed.stdout)

    base_temp.mkdir(parents=True, exist_ok=True)
    pytest = _run([sys.executable, "-m", "pytest", "tests", "-q", "--basetemp", str(base_temp)], clone)
    summary = [line for line in pytest.stdout.strip().splitlines() if line.strip()]
    release = _run([sys.executable, "scripts/c32_verify_release.py"], clone)

    payload = {
        "clone_source": source,
        "snapshots": snapshots,
        "pytest_summary": summary[-1] if summary else "",
        "pytest_returncode": pytest.returncode,
        "commit": head,
        "release_verification": json.loads(release.stdout) if release.stdout.strip() else {},
        "note": (
            "Captured inside a fresh git clone of the pushed branch, before writing this file. "
            "release_verification records the verifier output as observed for this commit."
        ),
    }
    OUTPUT.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8", newline=chr(10))
    print(json.dumps(payload, indent=2))
    shutil.rmtree(scratch, ignore_errors=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
