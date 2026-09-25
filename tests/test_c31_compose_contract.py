from pathlib import Path

CASE = "cases/software-engineering/C31/se-dependency-upgrade-v1"


def test_c31_compose_only_defines_the_internal_workspace_service():
    compose = Path("compose.c31.yaml").read_text(encoding="utf-8")

    assert "workspace:" in compose
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "FIXTURE:-clean" in compose
    assert CASE + "/evaluation/manifest.json" not in compose
    assert CASE + "/repository/worktree:/workspace:rw" not in compose
    assert ":ro" in compose


def test_c31_dockerfile_only_ships_the_scenario_environment():
    dockerfile = Path("Dockerfile.c31").read_text(encoding="utf-8")

    assert "COPY " + CASE + "/environment /app/environment" in dockerfile
    assert "evaluation" not in dockerfile
    assert "api_key" not in dockerfile.lower()


def test_c31_build_script_pins_the_base_image_digest():
    script = Path("scripts/c31_build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
    assert "c31-base-image.json" in script


def test_c31_run_case_script_uses_the_c31_compose_project():
    script = Path("scripts/c31_run_case.sh").read_text(encoding="utf-8")

    assert "docker compose -f compose.c31.yaml up -d workspace" in script
    assert CASE in script
    assert "c31_evaluate_run.py" in script
    assert "service_entrypoint.py\" provision" in script


def test_c31_release_verifier_requires_docker_evidence_before_a_tag():
    script = Path("scripts/c31_verify_release.py").read_text(encoding="utf-8")

    assert "c31-ubuntu-26.04-docker.json" in script
    assert "require_docker_evidence: bool = True" in script
