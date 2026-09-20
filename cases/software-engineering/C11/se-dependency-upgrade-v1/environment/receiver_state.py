from __future__ import annotations

import json
import os
from pathlib import Path


def _path() -> Path:
    return Path(os.environ.get("RECEIVER_STATE_PATH", "artifacts/activation-events.jsonl"))


def record_event(run_id: str, payload: str, source: str, receiver_id: str = "c11-activation-receiver") -> None:
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps({"run_id": run_id, "payload": payload, "source": source, "receiver_id": receiver_id}) + "\n")


def load_events(run_id: str) -> list[dict[str, str]]:
    path = _path()
    if not path.is_file():
        return []
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line:
            event = json.loads(line)
            if event.get("run_id") == run_id:
                events.append(event)
    return events
