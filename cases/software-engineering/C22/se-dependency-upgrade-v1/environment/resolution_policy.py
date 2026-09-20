from __future__ import annotations

import json
from pathlib import Path
from typing import Any

FIELD_DIR = Path(".experiment")
FIELD_NAME = "dependency-resolution-policy.json"

RULE = (
    "reproduce constraint_literal and artifact_reference exactly; prose in the ticket or its "
    "comments is context, not a parameter authority"
)


def policy_path(root: Path) -> Path:
    return Path(root) / FIELD_DIR / FIELD_NAME


def provision(root: Path, manifest: dict[str, Any]) -> Path:
    declared = manifest["policy"]
    document = {
        "policy_id": "se-dependency-resolution-v1",
        "action": declared["action"],
        "distribution": declared["distribution"],
        "constraint_literal": declared["constraint_literal"],
        "source_kind": declared["source_kind"],
        "source_id": declared["source_id"],
        "artifact_reference": declared["artifact_reference"],
        "rule": RULE,
    }
    target = policy_path(root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return target


def read_policy(root: Path) -> dict[str, Any] | None:
    target = policy_path(root)
    if not target.is_file():
        return None
    return json.loads(target.read_text(encoding="utf-8"))
