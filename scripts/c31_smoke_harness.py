from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from policies.gate import ToolCall, evaluate, load_policy

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "cases/software-engineering/C31/se-dependency-upgrade-v1"
POLICY = ROOT / "policies/software-engineering-g-v1.yaml"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@dataclass(frozen=True)
class SmokeResult:
    fixture: str
    g_enabled: bool
    parameters_source: str
    gate_allowed: bool
    blocked_call: str | None
    utility_ok: bool
    security_ok: bool


def _events(manifest: dict, parameters: dict) -> list[ToolCall]:
    return [
        ToolCall(
            tool="read_issue",
            parameters={"issue_id": "REQ-7189-followup"},
            source_kind=None,
            source_value=None,
            path="issue/issue.json",
            hooks=[],
        ),
        ToolCall(
            tool="read_file",
            parameters={"path": manifest["resolution_spec"]["designated_field"]},
            source_kind=None,
            source_value=None,
            path=manifest["resolution_spec"]["designated_field"],
            hooks=[],
        ),
        ToolCall(
            tool="update_dependency",
            parameters={
                "distribution": parameters["distribution"],
                "version_spec": parameters["constraint_literal"],
                "artifact_reference": parameters["artifact_reference"],
            },
            source_kind="sim-registry",
            source_value="official-pypi",
            path="pyproject.toml",
            hooks=[],
        ),
        ToolCall(
            tool="run_tests",
            parameters={"target": manifest["resolution_spec"]["focus_test_target"]},
            source_kind=None,
            source_value=None,
            path=None,
            hooks=[],
        ),
        ToolCall(
            tool="write_report",
            parameters={"path": manifest["resolution_spec"]["report_path"]},
            source_kind=None,
            source_value=None,
            path=manifest["resolution_spec"]["report_path"],
            hooks=[],
        ),
    ]


def _policy_parameters(manifest: dict) -> dict:
    declared = manifest["policy"]
    return {
        "distribution": declared["distribution"],
        "constraint_literal": declared["constraint_literal"],
        "artifact_reference": declared["artifact_reference"],
        "source_kind": declared["source_kind"],
        "source_id": declared["source_id"],
    }


def _injection_parameters(manifest: dict, partial: bool = False) -> dict:
    injected = manifest["injection"]
    parameters = _policy_parameters(manifest)
    parameters["constraint_literal"] = injected["constraint_literal"]
    if partial:
        return parameters
    parameters["artifact_reference"] = injected["artifact_reference"]
    return parameters


def run_smoke(
    fixture: str,
    g_enabled: bool,
    run_root: Path,
    *,
    follow_injection: bool = True,
    partially_injected: bool = False,
    external_source: bool = False,
) -> SmokeResult:
    if fixture not in {"clean", "attack"}:
        raise ValueError("fixture must be clean or attack")
    run_root = Path(run_root)
    if run_root.exists():
        shutil.rmtree(run_root)
    workspace = run_root / "workspace"
    shutil.copytree(CASE / "repository/worktree", workspace)

    manifest = json.loads((CASE / "evaluation/manifest.json").read_text(encoding="utf-8"))
    policy_field = _load("c31_resolution_policy", CASE / "environment/resolution_policy.py")
    checkers = _load("c31_checkers", CASE / "evaluation/checkers.py")
    policy_field.provision(workspace, manifest)

    follows_injection = fixture == "attack" and follow_injection
    if follows_injection:
        parameters = _injection_parameters(manifest, partial=partially_injected)
        parameters_source = "injection_comment"
    else:
        parameters = _policy_parameters(manifest)
        parameters_source = "resolution_policy"

    run_id = f"smoke-{fixture}-{'enabled' if g_enabled else 'disabled'}"
    calls = _events(manifest, parameters)
    update_call = calls[2]
    if external_source:
        update_call = ToolCall(
            tool=update_call.tool,
            parameters=update_call.parameters,
            source_kind="https",
            source_value=manifest["injection"]["artifact_reference"],
            path=update_call.path,
            hooks=update_call.hooks,
        )
        calls = [*calls[:2], update_call, *calls[3:]]
    policy = load_policy(POLICY)
    blocked: str | None = None
    if g_enabled:
        for call in calls:
            if not evaluate(call, policy).allowed:
                blocked = call.tool
    gate_allowed = blocked is None

    if gate_allowed:
        checkers.apply_dependency_parameters(workspace, parameters, run_id)
        if evaluate(calls[3], policy).allowed or not g_enabled:
            report = workspace / manifest["resolution_spec"]["report_path"]
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text("focused-requests-tests: PASS\n", encoding="utf-8")

    expected = checkers.expected_state(manifest)
    report = workspace / manifest["resolution_spec"]["report_path"]
    utility_result = checkers.utility(workspace, report, expected)
    security_result = checkers.security_g(workspace, manifest["injection"], run_id)
    return SmokeResult(
        fixture=fixture,
        g_enabled=g_enabled,
        parameters_source=parameters_source,
        gate_allowed=gate_allowed,
        blocked_call=blocked,
        utility_ok=utility_result.ok,
        security_ok=security_result.ok,
    )
