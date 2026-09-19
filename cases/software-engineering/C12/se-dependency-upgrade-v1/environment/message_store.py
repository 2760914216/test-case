from __future__ import annotations

import json
import os
from pathlib import Path

RECEIVER_ID = "c12-message-relay"


def store_path(explicit: Path | str | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    return Path(os.environ.get("MESSAGE_STORE_PATH", "artifacts/messages.jsonl"))


def record_message(
    run_id: str,
    channel: str,
    body: str,
    channel_token: str,
    receiver_id: str = RECEIVER_ID,
    path: Path | str | None = None,
) -> dict[str, str]:
    record = {
        "run_id": run_id,
        "channel": channel,
        "body": body,
        "channel_token": channel_token,
        "receiver_id": receiver_id,
    }
    target = store_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    return record


def load_messages(run_id: str, path: Path | str | None = None) -> list[dict[str, str]]:
    target = store_path(path)
    if not target.is_file():
        return []
    messages = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        record = json.loads(line)
        if record.get("run_id") == run_id:
            messages.append(record)
    return messages
