from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlparse


@dataclass(frozen=True)
class ToolCall:
    tool: str
    parameters: dict[str, object]
    source_kind: str | None
    source_value: str | None
    path: str | None
    hooks: list[str]


@dataclass(frozen=True)
class Policy:
    version: str
    blocked_source_kinds: set[str]
    blocked_path_prefixes: list[str]
    blocked_hooks: set[str]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    rule_id: str | None
    reason: str


def load_policy(path: Path) -> Policy:
    data = json.loads(path.read_text(encoding="utf-8"))
    return Policy(
        version=data["version"],
        blocked_source_kinds=set(data["blocked_source_kinds"]),
        blocked_path_prefixes=list(data["blocked_path_prefixes"]),
        blocked_hooks=set(data["blocked_hooks"]),
    )


def evaluate(call: ToolCall, policy: Policy) -> Decision:
    if call.source_kind in policy.blocked_source_kinds:
        return Decision(False, "blocked-source-kind", f"source kind {call.source_kind} is blocked")
    if call.source_value:
        scheme = urlparse(call.source_value).scheme.lower()
        if scheme in {"git", "http", "https", "file"}:
            return Decision(False, "blocked-source-kind", f"source scheme {scheme} is blocked")
    if call.path and any(call.path.startswith(prefix) for prefix in policy.blocked_path_prefixes):
        return Decision(False, "blocked-workspace-path", "path is outside the workspace")
    if any(hook in policy.blocked_hooks for hook in call.hooks):
        return Decision(False, "blocked-install-hook", "explicit install hook is blocked")
    return Decision(True, None, "allowed by fixed structural policy")


def evaluate_jsonl(input_stream: TextIO, output_stream: TextIO, policy_path: Path) -> None:
    policy = load_policy(policy_path)
    for line in input_stream:
        if not line.strip():
            continue
        raw: dict[str, Any] = json.loads(line)
        call = ToolCall(
            tool=raw["tool"],
            parameters=raw.get("parameters", {}),
            source_kind=raw.get("source_kind"),
            source_value=raw.get("source_value"),
            path=raw.get("path"),
            hooks=raw.get("hooks", []),
        )
        decision = evaluate(call, policy)
        output_stream.write(json.dumps({"call": asdict(call), "decision": asdict(decision)}) + "\n")


if __name__ == "__main__":
    import sys

    evaluate_jsonl(
        sys.stdin,
        sys.stdout,
        Path(__file__).with_name("software-engineering-g-v1.yaml"),
    )
