from pathlib import Path

CASE = "cases/software-engineering/C23/se-dependency-upgrade-v1"


def _compose() -> str:
    return Path("compose.c23.yaml").read_text(encoding="utf-8")


def test_c23_compose_defines_internal_services_without_host_ports():
    compose = _compose()

    for service in ("registry:", "signer:", "workspace:"):
        assert service in compose
    assert "internal: true" in compose
    assert "ports:" not in compose


def test_c23_compose_mounts_the_visible_fixture_but_never_the_hidden_manifest():
    compose = _compose()

    assert "fixtures/" in compose
    assert "FIXTURE:-clean" in compose
    assert ":/issue/issue.json:ro" in compose
    assert CASE + "/evaluation/manifest.json" not in compose
    assert CASE + "/repository/worktree:/workspace:rw" not in compose
    assert ":/workspace:rw" in compose
    assert "RUN_WORKSPACE" in compose
    assert "C23_RUN_STATE" in compose
    assert "C23_RUN_CREDENTIALS" in compose
    assert ":/workspace/.config/release-engineering:rw" in compose


def test_c23_dockerfile_only_ships_the_scenario_environment():
    dockerfile = Path("Dockerfile.c23").read_text(encoding="utf-8")

    assert "COPY " + CASE + "/environment /app/environment" in dockerfile
    assert "evaluation" not in dockerfile
    assert "api_key" not in dockerfile.lower()


def test_c23_build_script_pins_the_base_image_digest():
    script = Path("scripts/c23_build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
    assert "c23-base-image.json" in script


def test_c23_run_case_script_uses_the_c23_compose_project():
    script = Path("scripts/c23_run_case.sh").read_text(encoding="utf-8")

    assert "docker compose -f compose.c23.yaml up -d registry signer workspace" in script
    assert CASE in script
    assert "c23_evaluate_run.py" in script
    assert 'service_entrypoint.py" provision' in script


def test_c23_release_verifier_requires_docker_evidence_before_a_tag():
    script = Path("scripts/c23_verify_release.py").read_text(encoding="utf-8")

    assert "c23-ubuntu-26.04-docker.json" in script
    assert "require_docker_evidence: bool = True" in script
