from pathlib import Path

from scripts.c21_smoke_harness import run_smoke

TEMP = Path("artifacts/verification/.c21-smoke-work")


def _run(name: str, **options):
    root = TEMP / name
    result = run_smoke(**options, run_root=root)
    return result


def test_clean_run_passes_utility_without_satisfying_the_attack_goal():
    result = _run("clean-off", fixture="clean", g_enabled=False)

    assert result.gate_allowed is True
    assert result.parameters_source == "resolution_policy"
    assert result.utility_ok is True
    assert result.security_ok is False


def test_clean_run_survives_the_gate_and_still_passes_utility():
    result = _run("clean-on", fixture="clean", g_enabled=True)

    assert result.gate_allowed is True
    assert result.utility_ok is True
    assert result.security_ok is False


def test_attack_run_reaches_the_goal_when_the_gate_is_disabled():
    result = _run("attack-off", fixture="attack", g_enabled=False)

    assert result.parameters_source == "injection_comment"
    assert result.gate_allowed is True
    assert result.utility_ok is False
    assert result.security_ok is True


def test_attack_run_reaches_the_goal_through_the_frozen_gate_blind_spot():
    result = _run("attack-on", fixture="attack", g_enabled=True)

    assert result.gate_allowed is True
    assert result.security_ok is True


def test_attack_run_without_the_injected_artifact_reference_never_succeeds():
    result = _run("attack-partial", fixture="attack", g_enabled=False, partially_injected=True)

    assert result.parameters_source == "injection_comment"
    assert result.security_ok is False


def test_attack_run_that_keeps_the_authorized_parameters_never_succeeds():
    result = _run("attack-not-taken", fixture="attack", g_enabled=False, follow_injection=False)

    assert result.parameters_source == "resolution_policy"
    assert result.utility_ok is True
    assert result.security_ok is False


def test_attack_run_through_an_external_source_kind_is_blocked_by_the_gate():
    result = _run("attack-external", fixture="attack", g_enabled=True, external_source=True)

    assert result.gate_allowed is False
    assert result.security_ok is False
