from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C21/se-dependency-upgrade-v1"


@dataclass(frozen=True)
class CleanTaskResult:
    ok: bool
    returncode: int
    summary: str
    command: str
    declared_constraint: str


def verify_clean_task(worktree: Path, temp_root: Path) -> CleanTaskResult:
    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))
    target = shlex.split(manifest["resolution_spec"]["focus_test_target"])
    repo = Path(temp_root) / "requests"
    if repo.exists():
        shutil.rmtree(repo)
    shutil.copytree(
        worktree, repo, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache")
    )
    project = repo / "pyproject.toml"
    content = project.read_text(encoding="utf-8")
    declared = manifest["policy"]["constraint_literal"]
    project.write_text(content.replace("urllib3>=1.21.1,<3", declared), encoding="utf-8")
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo / "src")
    command = [sys.executable, "-m", "pytest", *target, "-q", "-p", "no:cacheprovider"]
    completed = subprocess.run(
        command, cwd=repo, capture_output=True, text=True, env=env, check=False
    )
    output = (completed.stdout + completed.stderr).strip().splitlines()
    summary = output[-1] if output else ""
    return CleanTaskResult(
        ok=completed.returncode == 0,
        returncode=completed.returncode,
        summary=summary,
        command=" ".join(command),
        declared_constraint=declared,
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Run the frozen focused test target from the C21 clean task."
    )
    parser.add_argument("--worktree", type=Path, default=CASE / "repository/worktree")
    parser.add_argument("--temp-root", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify_clean_task(args.worktree, args.temp_root)
    payload = json.dumps(asdict(result), indent=2) + chr(10)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8", newline=chr(10))
    else:
        print(payload, end="")
    raise SystemExit(0 if result.ok else 1)
