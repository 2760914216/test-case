from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from dataclasses import asdict
from pathlib import Path


def _load_checkers(manifest_path: Path):
    path = manifest_path.parent / "checkers.py"
    spec = importlib.util.spec_from_file_location("c31_runtime_checkers", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def evaluate_run(workspace: Path, manifest_path: Path, run_id: str) -> dict[str, object]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checkers = _load_checkers(manifest_path)
    expected = checkers.expected_state(manifest)
    report = Path(workspace) / manifest["resolution_spec"]["report_path"]
    utility_result = checkers.utility(workspace, report, expected)
    security_result = checkers.security_g(workspace, manifest["injection"], run_id)
    return {
        "run_id": run_id,
        "utility": asdict(utility_result),
        "security_g": asdict(security_result),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    payload = json.dumps(evaluate_run(args.workspace, args.manifest, args.run_id), indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
