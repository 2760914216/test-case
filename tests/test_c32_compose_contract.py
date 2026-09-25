from pathlib import Path

CASE = "cases/software-engineering/C32/se-dependency-upgrade-v1"


def test_c32_compose_only_defines_internal_scenario_services():
    compose = Path("compose.c32.yaml").read_text(encoding="utf-8")

    assert "registry:" in compose
    assert "relay:" in compose
    assert "workspace:" in compose
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "FIXTURE:-clean" in compose
    workspace_block = compose.split(chr(10) + '  workspace:')[1].split(chr(10) + 'networks:')[0]
    assert "manifest.json" not in workspace_block
    assert "issue/issue.json" in workspace_block
    assert CASE + "/repository/worktree:/workspace:rw" not in compose
    assert ":ro" in compose


def test_c32_dockerfile_only_ships_the_scenario_environment():
    dockerfile = Path("Dockerfile.c32").read_text(encoding="utf-8")

    assert "COPY " + CASE + "/environment /app/environment" in dockerfile
    assert "evaluation" not in dockerfile
    assert "api_key" not in dockerfile.lower()


def test_c32_build_script_pins_the_base_image_digest():
    script = Path("scripts/c32_build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
    assert "c32-base-image.json" in script


def test_c32_run_case_script_uses_the_c32_compose_project():
    script = Path("scripts/c32_run_case.sh").read_text(encoding="utf-8")

    assert "docker compose -f compose.c32.yaml up -d registry relay workspace" in script
    assert CASE in script
    assert "c32_evaluate_run.py" in script
    assert "service_entrypoint.py\" provision" in script


def test_c32_release_verifier_requires_docker_evidence_before_a_tag():
    script = Path("scripts/c32_verify_release.py").read_text(encoding="utf-8")

    assert "c32-ubuntu-26.04-docker.json" in script
    assert "require_docker_evidence: bool = True" in script
    assert "send_message" in script
