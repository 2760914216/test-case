import json
from pathlib import Path


RUNTIMES = ("codex", "dsh", "llama.cpp")


def test_runtime_descriptors_share_gate_and_normalized_trace_contract():
    descriptors = []
    for runtime in RUNTIMES:
        path = Path(f"integrations/{runtime}/integration.json")
        descriptors.append(json.loads(path.read_text(encoding="utf-8")))

    assert {item["runtime"] for item in descriptors} == set(RUNTIMES)
    assert {item["policy_version"] for item in descriptors} == {"software-engineering-g-v1"}
    assert {item["gate_command"] for item in descriptors} == {"python -m policies.gate"}
    assert {item["normalized_event_protocol"] for item in descriptors} == {"jsonl-v1"}


def test_runtime_descriptors_do_not_declare_agent_or_tool_implementation():
    for runtime in RUNTIMES:
        descriptor = json.loads(
            Path(f"integrations/{runtime}/integration.json").read_text(encoding="utf-8")
        )
        assert "tool_implementation" not in descriptor
        assert descriptor["runtime"] == runtime
