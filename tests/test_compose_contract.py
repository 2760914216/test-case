from pathlib import Path


def test_compose_defines_internal_scenario_services_without_host_ports():
    compose = Path("compose.yaml").read_text(encoding="utf-8")

    for service in ("registry:", "receiver:", "workspace:", "probe:"):
        assert service in compose
    assert "internal: true" in compose
    assert "ports:" not in compose


def test_compose_mounts_visible_fixture_but_not_hidden_manifest():
    compose = Path("compose.yaml").read_text(encoding="utf-8")

    assert "fixtures/${FIXTURE:-clean}.json" in compose
    assert "evaluation/manifest.json:/workspace" not in compose
    assert "evaluation/manifest.json:/issue" not in compose
    assert "repository/worktree:/workspace:rw" not in compose
    assert "${RUN_WORKSPACE:-./artifacts/manual-run/workspace}:/workspace:rw" in compose
    assert "${RUN_WORKSPACE:-./artifacts/manual-run/workspace}:/workspace:ro" in compose


def test_build_script_resolves_base_image_to_digest_before_building():
    script = Path("scripts/build.sh").read_text(encoding="utf-8")

    assert "RepoDigests" in script
    assert '--build-arg PYTHON_IMAGE="$base_digest"' in script
