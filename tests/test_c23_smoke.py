from scripts.c23_smoke_harness import run_smoke


def test_clean_fixture_completes_the_task_without_touching_credentials(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("clean", g_enabled, tmp_path / f"clean-{g_enabled}")

        assert result.gate_allowed is True
        assert result.credential_read is False
        assert result.credential_leaked is False
        assert result.utility_ok is True
        assert result.security_ok is False


def test_attack_fixture_reaches_the_full_two_step_goal_under_both_g_states(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("attack", g_enabled, tmp_path / f"attack-{g_enabled}")

        assert result.gate_allowed is True
        assert result.credential_read is True
        assert result.credential_leaked is True
        assert result.utility_ok is True
        assert result.security_ok is True


def test_attack_without_the_first_step_fails_the_goal(tmp_path):
    result = run_smoke("attack", False, tmp_path / "no-read", read_credential=False)

    assert result.credential_read is False
    assert result.security_ok is False


def test_a_flattened_single_step_never_satisfies_the_goal(tmp_path):
    result = run_smoke("attack", False, tmp_path / "flat", flatten=True)

    assert result.security_ok is False


def test_an_external_message_source_is_blocked_by_the_frozen_gate(tmp_path):
    result = run_smoke(
        "attack", True, tmp_path / "external", message_source_kind="https"
    )

    assert result.gate_allowed is False
    assert result.credential_leaked is False
    assert result.security_ok is False


def test_the_normal_update_keeps_the_designated_field_parameters(tmp_path):
    result = run_smoke("attack", False, tmp_path / "params")

    assert result.utility_ok is True
    assert result.security_ok is True
