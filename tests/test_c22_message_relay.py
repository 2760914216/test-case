import importlib.util
import json
import sys
import threading
import urllib.error
import urllib.request

from tests.c22_support import CASE, load_manifest

ENV_DIR = CASE / "environment"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_saved_store = sys.modules.pop("message_store", None)
message_store = _load("message_store", ENV_DIR / "message_store.py")
relay = _load("c22_message_relay", ENV_DIR / "message_relay.py")
if _saved_store is not None:
    sys.modules["message_store"] = _saved_store
else:
    sys.modules.pop("message_store", None)


def _post(port: int, payload: bytes, path: str = "/messages"):
    request = urllib.request.Request(
        "http://127.0.0.1:" + str(port) + path,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status
    except urllib.error.HTTPError as error:
        return error.code


class _Relay:
    def __init__(self, store, token):
        self.server = relay.create_server("127.0.0.1", 0, store, token)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        return False


def test_relay_rejects_every_other_path(tmp_path):
    with _Relay(tmp_path / "messages.jsonl", "token") as service:
        assert _post(service.port, b"{}", path="/other") == 404


def test_relay_rejects_invalid_json(tmp_path):
    with _Relay(tmp_path / "messages.jsonl", "token") as service:
        assert _post(service.port, b"{") == 400


def test_relay_rejects_incomplete_payloads(tmp_path):
    with _Relay(tmp_path / "messages.jsonl", "token") as service:
        assert _post(service.port, json.dumps({"run_id": "r"}).encode("utf-8")) == 400


def test_relay_records_the_message_with_the_case_receiver_and_token(tmp_path):
    manifest = load_manifest()
    store = tmp_path / "messages.jsonl"

    with _Relay(store, manifest["canary"]) as service:
        status = _post(
            service.port,
            json.dumps(
                {
                    "run_id": "run-1",
                    "channel": manifest["g"]["channel"],
                    "body": "Change summary " + manifest["g"]["payload_marker"],
                }
            ).encode("utf-8"),
        )

    assert status == 204
    record = json.loads(store.read_text(encoding="utf-8").strip())
    assert record["run_id"] == "run-1"
    assert record["channel"] == manifest["g"]["channel"]
    assert record["channel_token"] == manifest["canary"]
    assert record["receiver_id"] == manifest["g"]["receiver_id"] == message_store.RECEIVER_ID


def test_load_messages_filters_by_run_id(tmp_path):
    store = tmp_path / "messages.jsonl"
    message_store.record_message("run-1", "c", "b", "t", "c22-message-relay", store)
    message_store.record_message("run-2", "c", "b", "t", "c22-message-relay", store)

    messages = message_store.load_messages("run-1", store)

    assert len(messages) == 1
    assert messages[0]["run_id"] == "run-1"
    assert message_store.load_messages("missing", store) == []


def test_the_relay_token_is_never_written_into_the_workspace(tmp_path):
    manifest = load_manifest()

    assert manifest["canary"] == manifest["channel_token"]
    assert manifest["canary"] not in (CASE / "fixtures/attack.json").read_text(encoding="utf-8")
