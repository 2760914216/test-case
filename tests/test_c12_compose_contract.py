from pathlib import Path

CASE = "cases/software-engineering/C12/se-dependency-upgrade-v1"


def _compose() -> str:
    return Path("compose.c12.yaml").read_text(encoding="utf-8")


def test_c12_compose_defines_internal_services_without_host_ports():
    compose = _compose()

    for service in ("registry:", "relay:", "workspace:"):
        assert service in compose
    assert "internal: true" in compose
    assert "ports:" not in compose


def test_c12_compose_mounts_the_visible_fixture_but_never_the_hidden_manifest_in_the_workspace():
    compose = _compose()

    assert "fixtures/" in compose
    assert "FIXTURE:-clean" in compose
    assert ":/issue/issue.json:ro" in compose
    assert CASE + "/evaluation/manifest.json:/evaluation/manifest.json:ro" in compose
    assert CASE + "/evaluation/manifest.json:/workspace" not in compose
    assert CASE + "/evaluation/manifest.json:/issue" not in compose
    assert CASE + "/repository/worktree:/workspace:rw" not in compose
    assert ":/workspace:rw" in compose
    assert "RUN_WORKSPACE" in compose
    assert "C12_RUN_STATE" in compose


def test_c12_dockerfile_only_ships_the_scenario_environment():
    dockerfile = Path("Dockerfile.c12").read_text(encoding="utf-8")

    assert "COPY " + CASE + "/environment /app/environment" in dockerfile
    assert "evaluation" not in dockerfile
    assert "api_key" not in dockerfile.lower()


def test_c12_build_script_pins_the_base_image_digest():
    script = Path("scripts/c12_build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
    assert "c12-base-image.json" in script


def test_c12_run_case_script_uses_the_c12_compose_project():
    script = Path("scripts/c12_run_case.sh").read_text(encoding="utf-8")

    assert "docker compose -f compose.c12.yaml up -d registry relay workspace" in script
    assert CASE in script
    assert "c12_evaluate_run.py" in script


def test_c12_release_verifier_requires_docker_evidence_before_a_tag():
    script = Path("scripts/c12_verify_release.py").read_text(encoding="utf-8")

    assert "c12-ubuntu-26.04-docker.json" in script
    assert "require_docker_evidence: bool = True" in script
