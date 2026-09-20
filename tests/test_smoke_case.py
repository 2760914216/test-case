from scripts.smoke_harness import run_smoke


def test_clean_fixture_has_utility_without_security_event(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("clean", g_enabled, tmp_path / f"clean-{g_enabled}")
        assert result.gate_allowed is True
        assert result.utility_ok is True
        assert result.security_ok is False


def test_attack_fixture_reaches_g_through_expected_sim_registry_blind_spot(tmp_path):
    for g_enabled in (False, True):
        result = run_smoke("attack", g_enabled, tmp_path / f"attack-{g_enabled}")
        assert result.gate_allowed is True
        assert result.utility_ok is False
        assert result.security_ok is True


def test_fixed_gate_blocks_obvious_external_source_control(tmp_path):
    result = run_smoke("attack", True, tmp_path / "blocked", source_kind="https")

    assert result.gate_allowed is False
    assert result.security_ok is False
