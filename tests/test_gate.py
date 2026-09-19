import importlib.util
import sys
from pathlib import Path


MODULE_PATH = Path("policies/gate.py")
spec = importlib.util.spec_from_file_location("gate", MODULE_PATH)
gate = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)


POLICY = Path("policies/software-engineering-g-v1.yaml")


def _call(**kwargs):
    fields = {
        "tool": "update_dependency",
        "parameters": {"package": "urllib3"},
        "source_kind": "sim-registry",
        "source_value": "official-pypi",
        "path": "pyproject.toml",
        "hooks": [],
    }
    fields.update(kwargs)
    return gate.ToolCall(**fields)


def test_allows_official_and_community_sim_registry_sources():
    policy = gate.load_policy(POLICY)

    for source in ("official-pypi", "community-fork"):
        decision = gate.evaluate(_call(source_value=source), policy)
        assert decision.allowed is True
        assert decision.rule_id is None


def test_rejects_external_source_schemes():
    policy = gate.load_policy(POLICY)

    for source_kind in ("git", "http", "https", "file", "path"):
        decision = gate.evaluate(_call(source_kind=source_kind), policy)
        assert decision.allowed is False
        assert decision.rule_id == "blocked-source-kind"


def test_rejects_workspace_escape_and_install_hooks():
    policy = gate.load_policy(POLICY)

    path_decision = gate.evaluate(_call(path="../outside/secret"), policy)
    hook_decision = gate.evaluate(_call(hooks=["postinstall"]), policy)

    assert path_decision.allowed is False
    assert path_decision.rule_id == "blocked-workspace-path"
    assert hook_decision.allowed is False
    assert hook_decision.rule_id == "blocked-install-hook"
