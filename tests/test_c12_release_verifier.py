import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = Path("scripts/c12_verify_release.py")
SPEC = importlib.util.spec_from_file_location("c12_verify_release_unit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
release_verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_verifier
SPEC.loader.exec_module(release_verifier)

EVIDENCE = Path("artifacts/verification/c12-ubuntu-26.04-docker.json")
SMOKE_SCRIPT = MODULE_PATH.parent / "c12_docker_smoke.py"
COMPLETE = {
    "os": "Ubuntu 26.04 LTS",
    "base_image_digest": "python@sha256:" + "0" * 64,
    "docker_version": "29.8.1",
    "compose_version": "5.5.1",
    "compose_config_ok": True,
    "registry_artifact_ok": True,
    "attack_message_ok": True,
    "clean_no_message_ok": True,
}
MISSING = ["Ubuntu 26.04 Docker verification evidence is missing"]
INCOMPLETE = ["Ubuntu 26.04 Docker verification evidence is incomplete"]


def _evidence(tmp_path: Path, **overrides) -> Path:
    payload = dict(COMPLETE)
    payload.update(overrides)
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_missing_evidence_blocks_the_release(tmp_path):
    assert release_verifier.verify_docker_evidence(tmp_path / "absent.json") == MISSING


def test_every_required_check_must_be_true(tmp_path):
    for key in (
        "compose_config_ok",
        "registry_artifact_ok",
        "attack_message_ok",
        "clean_no_message_ok",
    ):
        assert release_verifier.verify_docker_evidence(_evidence(tmp_path, **{key: False})) == INCOMPLETE


def test_unpinned_or_unversioned_evidence_blocks_the_release(tmp_path):
    assert release_verifier.verify_docker_evidence(
        _evidence(tmp_path, base_image_digest="python:3.12.11-slim")
    ) == INCOMPLETE
    assert release_verifier.verify_docker_evidence(_evidence(tmp_path, docker_version="")) == INCOMPLETE
    assert release_verifier.verify_docker_evidence(_evidence(tmp_path, compose_version="")) == INCOMPLETE
    assert release_verifier.verify_docker_evidence(_evidence(tmp_path, os="Debian GNU/Linux 13")) == INCOMPLETE


def test_ubuntu_26_04_point_releases_are_accepted(tmp_path):
    assert release_verifier.verify_docker_evidence(
        _evidence(tmp_path, os="Ubuntu 26.04.1 LTS")
    ) == []


def test_the_recorded_ubuntu_evidence_satisfies_the_release_gate():
    payload = json.loads(EVIDENCE.read_text(encoding="utf-8"))

    assert payload["os"].startswith("Ubuntu 26.04")
    assert release_verifier.verify_docker_evidence(EVIDENCE) == []


def test_docker_smoke_reads_the_real_os_release_and_stays_on_the_internal_network():
    script = SMOKE_SCRIPT.read_text(encoding="utf-8")

    assert 'release["VERSION_ID"] == "26.04"' in script
    assert '"os": release["PRETTY_NAME"]' in script
    assert "127.0.0.1:8090" not in script
    assert "127.0.0.1:8080" not in script
