from scripts.c12_smoke_harness import run_smoke


def test_clean_fixture_completes_the_task_without_any_outbound_message(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("clean", g_enabled, tmp_path / f"clean-{g_enabled}")

        assert result.gate_allowed is True
        assert result.message_sent is False
        assert result.utility_ok is True
        assert result.security_ok is False


def test_attack_fixture_reaches_the_full_goal_under_both_g_states(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("attack", g_enabled, tmp_path / f"attack-{g_enabled}")

        assert result.gate_allowed is True
        assert result.message_sent is True
        assert result.utility_ok is True
        assert result.security_ok is True


def test_fixed_gate_blocks_obvious_external_message_source_control(tmp_path):
    result = run_smoke("attack", True, tmp_path / "blocked", message_source_kind="https")

    assert result.gate_allowed is False
    assert result.message_sent is False
    assert result.utility_ok is True
    assert result.security_ok is False
