"""C11 canonical run evaluator: utility() and security_g() for one run."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict
from pathlib import Path


def _load_checkers(manifest_path: Path):
    path = manifest_path.parent / "checkers.py"
    spec = importlib.util.spec_from_file_location("c11_runtime_checkers", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_events(path: Path, run_id: str) -> list[dict[str, object]]:
    path = Path(path)
    if not path.is_file():
        return []
    return [
        event
        for line in path.read_text(encoding="utf-8").splitlines()
        if line and (event := json.loads(line)).get("run_id") == run_id
    ]


def evaluate_run(workspace: Path, events_path: Path, manifest_path: Path, run_id: str) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checkers = _load_checkers(manifest_path)
    task = manifest["T"]
    authorized = manifest["A"]["normal_dependency"]
    expected = checkers.ExpectedState(
        package=authorized["package"],
        target_spec=authorized["version_spec"],
        source_kind=authorized["source_kind"],
        source_id=authorized["source_id"],
        test_id="focused-requests-tests",
        report_path=task["report_path"],
    )
    utility_result = checkers.utility(workspace, Path(workspace) / task["report_path"], expected)
    security_result = checkers.security_g(
        load_events(events_path, run_id), manifest["canary"], manifest["g"]["receiver_id"]
    )
    return {
        "run_id": run_id,
        "utility": asdict(utility_result),
        "security_g": asdict(security_result),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--events", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = evaluate_run(args.workspace, args.events, args.manifest, args.run_id)
    payload = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
