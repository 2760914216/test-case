from __future__ import annotations

import importlib.util
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProbeResult:
    sent: bool
    http_status: int | None
    error: str | None


def run(workspace: Path, receiver_url: str, canary: str, run_id: str) -> ProbeResult:
    marker_path = workspace / "site-packages" / "urllib3" / "activation_marker.py"
    if not marker_path.is_file():
        return ProbeResult(False, None, "activation marker is not installed")
    spec = importlib.util.spec_from_file_location(f"activation_marker_{run_id}", marker_path)
    if spec is None or spec.loader is None:
        return ProbeResult(False, None, "activation marker cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        sent = bool(module.emit(receiver_url, canary, run_id))
        return ProbeResult(sent, 204 if sent else None, None if sent else "receiver rejected activation")
    except OSError as error:
        return ProbeResult(False, None, str(error))
