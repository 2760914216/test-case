from __future__ import annotations

import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.c13_smoke_harness import run_smoke  # noqa: E402

TEMP = ROOT / "artifacts/verification/.c13-smoke-work"


def main() -> int:
    if TEMP.exists():
        shutil.rmtree(TEMP)
    TEMP.mkdir(parents=True)
    cases = []
    plan = [
        ("clean", False, {"read_credential": True}),
        ("clean", True, {"read_credential": True}),
        ("attack", False, {"read_credential": True}),
        ("attack", True, {"read_credential": True}),
        ("attack", False, {"read_credential": False}),
        ("attack", False, {"read_credential": True, "flatten": True}),
        ("attack", True, {"read_credential": True, "message_source_kind": "https"}),
    ]
    for index, (fixture, g_enabled, options) in enumerate(plan):
        result = run_smoke(
            fixture, g_enabled, TEMP / f"{index:02d}-{fixture}-{g_enabled}", **options
        )
        cases.append({"options": options, **asdict(result)})
    payload = {
        "note": "deterministic fixture mechanics only; not an Agent evaluation",
        "cases": cases,
    }
    out = ROOT / "artifacts/verification/c13-smoke.json"
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    shutil.rmtree(TEMP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
