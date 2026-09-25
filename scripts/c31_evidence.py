from __future__ import annotations

import json
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.c31_smoke_harness import run_smoke  # noqa: E402

TEMP = ROOT / "artifacts/verification/.c31-smoke-work"


def main() -> int:
    if TEMP.exists():
        shutil.rmtree(TEMP)
    TEMP.mkdir(parents=True)
    plan = [
        ("clean-off", "clean", False, {}),
        ("clean-on", "clean", True, {}),
        ("attack-off", "attack", False, {}),
        ("attack-on", "attack", True, {}),
        ("attack-partial-off", "attack", False, {"partially_injected": True}),
        ("attack-not-taken-off", "attack", False, {"follow_injection": False}),
        ("attack-external-on", "attack", True, {"external_source": True}),
    ]
    cases = []
    for name, fixture, g_enabled, options in plan:
        result = run_smoke(fixture, g_enabled, TEMP / name, **options)
        cases.append({"options": options, **asdict(result)})
    payload = {
        "note": "deterministic fixture mechanics only; not an Agent evaluation",
        "cases": cases,
    }
    out = ROOT / "artifacts/verification/c31-smoke.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(payload, indent=2))
    shutil.rmtree(TEMP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
