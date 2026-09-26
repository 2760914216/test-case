from pathlib import Path

COMPOSE = Path("compose.c11.yaml")
DOCKERFILE = Path("Dockerfile.c11")


def test_compose_defines_internal_scenario_services_without_host_ports():
    compose = COMPOSE.read_text(encoding="utf-8")

    for service in ("registry:", "receiver:", "workspace:", "probe:"):
        assert service in compose
    assert "internal: true" in compose
    assert "ports:" not in compose
    assert "dockerfile: Dockerfile.c11" in compose


def test_compose_mounts_the_visible_fixture_but_not_the_hidden_manifest_as_a_carrier():
    compose = COMPOSE.read_text(encoding="utf-8")

    assert "fixtures/${FIXTURE:-clean}.json:/issue/issue.json:ro" in compose
    assert "${RUN_WORKSPACE:-./artifacts/manual-run/workspace}:/workspace:rw" in compose
    assert "evaluation/manifest.json:/evaluation/manifest.json:ro" in compose
    assert "evaluation/manifest.json:/issue" not in compose


def test_dockerfile_copies_only_the_c11_environment():
    text = DOCKERFILE.read_text(encoding="utf-8")

    assert "cases/software-engineering/C11/se-dependency-upgrade-v1/environment" in text
    assert "PYTHON_IMAGE" in text


def test_build_script_resolves_the_base_digest_and_writes_c11_evidence():
    script = Path("scripts/c11_build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
    assert "c11-base-image.json" in script
    assert "compose.c11.yaml" in script


def test_docker_smoke_covers_the_registry_the_probes_and_the_activation_event():
    script = Path("scripts/c11_docker_smoke.py").read_text(encoding="utf-8")

    assert "http://registry:8080/artifacts/" in script
    assert "clean-probe.json" in script
    assert "attack-probe.json" in script
    assert "activation-events.jsonl" in script
    assert "c11-ubuntu-26.04-docker.json" in script


def test_run_case_script_uses_the_c11_compose_file():
    script = Path("scripts/c11_run_case.sh").read_text(encoding="utf-8")

    assert "compose.c11.yaml" in script
    assert "cases/software-engineering/C11/se-dependency-upgrade-v1" in script
    assert "$case_dir/repository/worktree" in script
