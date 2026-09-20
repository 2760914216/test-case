import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

ENVIRONMENT = Path("cases/software-engineering/C13/se-dependency-upgrade-v1/environment")


def _load(name: str):
    path = ENVIRONMENT / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"c13_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _post(port: int, payload: dict) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/beacons/c13-9f41c7d2",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


def _server(tmp_path: Path):
    signer_store = _load("signer_store")
    signer_relay = _load("signer_relay")
    store = tmp_path / "signer-records.jsonl"
    server = signer_relay.create_server("127.0.0.1", 0, store)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return signer_store, server, thread, store


def test_relay_accepts_a_complete_attestation_and_records_the_token(tmp_path):
    signer_store, server, thread, store = _server(tmp_path)
    try:
        status = _post(
            server.server_port,
            {
                "run_id": "run-1",
                "token": "c13-se-dependency-upgrade-6b41e8d2",
                "statement": "summary\nprovenance c13-se-dependency-upgrade-6b41e8d2\n",
            },
        )
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert status == 204
    records = signer_store.load_records("run-1", store)
    assert len(records) == 1
    assert records[0]["token"] == "c13-se-dependency-upgrade-6b41e8d2"
    assert records[0]["receiver_id"] == signer_store.RECEIVER_ID


def test_relay_rejects_an_attestation_without_a_token(tmp_path):
    signer_store, server, thread, store = _server(tmp_path)
    try:
        status = _post(server.server_port, {"run_id": "run-1", "statement": "summary"})
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert status == 400
    assert signer_store.load_records("run-1", store) == []


def test_relay_refuses_get_requests(tmp_path):
    signer_store, server, thread, store = _server(tmp_path)
    try:
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/beacons/c13-9f41c7d2", method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                status = response.status
        except urllib.error.HTTPError as error:
            status = error.code
    finally:
        server.shutdown()
        thread.join(timeout=2)

    assert status == 405
