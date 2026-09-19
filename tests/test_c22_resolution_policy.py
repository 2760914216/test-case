import importlib.util
import json
import sys

from tests.c22_support import CASE, load_manifest

MODULE_PATH = CASE / "environment/resolution_policy.py"
spec = importlib.util.spec_from_file_location("c22_resolution_policy", MODULE_PATH)
assert spec is not None and spec.loader is not None
policy_module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = policy_module
spec.loader.exec_module(policy_module)


def test_provision_writes_exactly_the_declared_resolution_field(tmp_path):
    manifest = load_manifest()

    target = policy_module.provision(tmp_path, manifest)

    assert target == tmp_path / ".experiment/dependency-resolution-policy.json"
    document = json.loads(target.read_text(encoding="utf-8"))
    assert document["constraint_literal"] == manifest["policy"]["constraint_literal"]
    assert document["artifact_reference"] == manifest["policy"]["artifact_reference"]
    assert document["source_kind"] == manifest["policy"]["source_kind"]
    assert document["source_id"] == manifest["policy"]["source_id"]
    assert document["distribution"] == "urllib3"


def test_provisioned_field_never_carries_the_canary_or_the_attack_marker(tmp_path):
    manifest = load_manifest()

    text = policy_module.provision(tmp_path, manifest).read_text(encoding="utf-8")

    assert manifest["canary"] not in text
    assert manifest["g"]["payload_marker"] not in text
    assert "case_id" not in text


def test_the_designated_field_is_absent_until_the_run_provisions_it(tmp_path):
    assert not policy_module.policy_path(tmp_path).exists()
    assert policy_module.read_policy(tmp_path) is None


def test_read_policy_returns_the_provisioned_values(tmp_path):
    manifest = load_manifest()
    policy_module.provision(tmp_path, manifest)

    document = policy_module.read_policy(tmp_path)

    assert document is not None
    assert document["constraint_literal"] == manifest["policy"]["constraint_literal"]


def test_policy_rule_states_that_comments_are_not_a_parameter_authority(tmp_path):
    manifest = load_manifest()

    document = json.loads(policy_module.provision(tmp_path, manifest).read_text(encoding="utf-8"))

    assert "exactly" in document["rule"]
    assert "comment" in document["rule"]
