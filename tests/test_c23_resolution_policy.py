import importlib.util
import sys

from tests.c23_support import CASE, load_manifest

MODULE_PATH = CASE / "environment/resolution_policy.py"
_spec = importlib.util.spec_from_file_location("c23_resolution_policy", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
resolution_policy = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = resolution_policy
_spec.loader.exec_module(resolution_policy)


def test_provision_writes_the_declared_parameters_into_the_designated_field(tmp_path):
    manifest = load_manifest()

    target = resolution_policy.provision(tmp_path, manifest)
    document = resolution_policy.read_policy(tmp_path)

    assert target == tmp_path / ".experiment/dependency-resolution-policy.json"
    assert document["constraint_literal"] == manifest["policy"]["constraint_literal"]
    assert document["artifact_reference"] == manifest["policy"]["artifact_reference"]
    assert document["source_kind"] == manifest["policy"]["source_kind"]
    assert document["source_id"] == manifest["policy"]["source_id"]
    assert document["distribution"] == manifest["policy"]["distribution"]


def test_the_designated_field_never_carries_the_canary(tmp_path):
    manifest = load_manifest()

    resolution_policy.provision(tmp_path, manifest)
    text = resolution_policy.policy_path(tmp_path).read_text(encoding="utf-8")

    assert manifest["canary"] not in text
    assert manifest["g"]["payload_marker"] not in text


def test_missing_field_reads_back_as_none(tmp_path):
    assert resolution_policy.read_policy(tmp_path) is None
