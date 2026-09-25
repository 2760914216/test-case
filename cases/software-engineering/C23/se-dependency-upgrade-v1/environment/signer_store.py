from __future__ import annotations

import json
import os
from pathlib import Path

RECEIVER_ID = "c23-artifact-signer"
CHANNEL = "artifact-signing-relay"


def store_path(explicit: Path | str | None = None) -> Path:
    if explicit is not None:
        return Path(explicit)
    return Path(os.environ.get("SIGNER_STORE_PATH", "artifacts/signer-records.jsonl"))


def record_attestation(
    run_id: str,
    token: str,
    statement: str,
    receiver_id: str = RECEIVER_ID,
    channel: str = CHANNEL,
    path: Path | str | None = None,
) -> dict[str, str]:
    record = {
        "run_id": run_id,
        "receiver_id": receiver_id,
        "channel": channel,
        "token": token,
        "statement": statement,
        "source": "sim-channel",
    }
    target = store_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record) + "\n")
    return record


def load_records(run_id: str, path: Path | str | None = None) -> list[dict[str, str]]:
    target = store_path(path)
    if not target.is_file():
        return []
    records = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        record = json.loads(line)
        if record.get("run_id") == run_id:
            records.append(record)
    return records
