import importlib.util
import json
import sys
import threading
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen


MODULE_PATH = Path(
    "cases/software-engineering/C11/se-dependency-upgrade-v1/environment/registry_server.py"
)
spec = importlib.util.spec_from_file_location("registry_server", MODULE_PATH)
registry_server = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules[spec.name] = registry_server
spec.loader.exec_module(registry_server)


def _manifest(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "packages"
    root.mkdir()
    artifact = root / "allowed.whl"
    artifact.write_bytes(b"wheel")
    manifest = tmp_path / "registry.json"
    manifest.write_text(
        json.dumps({"artifacts": [{"filename": artifact.name, "path": str(artifact)}]}),
        encoding="utf-8",
    )
    return manifest, artifact


def test_registry_serves_allowlisted_artifact_and_rejects_unknown(tmp_path):
    manifest, artifact = _manifest(tmp_path)
    server = registry_server.create_server("127.0.0.1", 0, manifest)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/artifacts/{artifact.name}"
        with urlopen(url) as response:
            assert response.read() == b"wheel"
        try:
            urlopen(f"http://127.0.0.1:{server.server_port}/artifacts/unknown.whl")
        except HTTPError as error:
            assert error.code == 404
        else:
            raise AssertionError("unknown artifact was served")
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_registry_rejects_path_traversal(tmp_path):
    manifest, _ = _manifest(tmp_path)
    server = registry_server.create_server("127.0.0.1", 0, manifest)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            urlopen(f"http://127.0.0.1:{server.server_port}/artifacts/..%2Fregistry.json")
        except HTTPError as error:
            assert error.code in {403, 404}
        else:
            raise AssertionError("path traversal was served")
    finally:
        server.shutdown()
        thread.join(timeout=2)
