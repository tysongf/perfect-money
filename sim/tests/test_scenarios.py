from pathlib import Path

from sim.engine.environment import run_episode


SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"


def test_determinism_identical_seed():
    r1 = run_episode(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml", seed=42)
    r2 = run_episode(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml", seed=42)
    assert r1.summary == r2.summary
    assert r1.telemetry == r2.telemetry


def test_scenario_01_oracle_cartel_bribe():
    res = run_episode(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml", seed=42)
    s = res.summary
    assert s.total_disputes >= 1
    assert s.cartel_net_roi < 0.0
    assert s.whistleblower_net_roi > 0.0
    assert s.unbacked_bad_debt_pm == 0.0
    assert s.min_coc_pfc_ratio >= 3.0 - 1e-6


def test_scenario_02_commodity_supply_shock():
    res = run_episode(SCENARIO_DIR / "02_commodity_supply_shock.yaml", seed=42)
    s = res.summary
    assert s.final_i_true > 1.13
    assert s.restored_within_14_days is True
    assert s.peg_error_at_day14_after_shock < 0.02
    assert s.unbacked_bad_debt_pm == 0.0
    assert s.min_coc_pfc_ratio >= 3.0 - 1e-6


def test_scenario_03_whale_bank_run():
    res = run_episode(SCENARIO_DIR / "03_whale_bank_run.yaml", seed=42)
    s = res.summary
    assert s.restored_within_14_days is True
    assert s.peg_error_at_day14_after_shock < 0.02
    assert s.unbacked_bad_debt_pm == 0.0
    assert s.eth_btc_redistributed_or_bad_debt == 0.0
    # Verify both Tier 1 Stability Pool and Tier 2 Insurance Reserve absorbed the -50% SOL crash
    assert s.sol_sp_offset_pm > 0.0
    assert s.sol_insurance_offset_pm > 0.0
    assert s.min_coc_pfc_ratio >= 3.0 - 1e-6


def test_scenario_04_hostile_state_short():
    patched = run_episode(SCENARIO_DIR / "04_hostile_state_short.yaml", seed=42)
    s = patched.summary
    # Under patched_decoupled mode, R(t) is immune to AMM spoofing (never exceeds basket bounds);
    # verify against legacy_spot_driven_r ablation on the exact same hostile episode.
    legacy = run_episode(
        SCENARIO_DIR / "04_hostile_state_short.yaml",
        seed=42,
        overrides={"peg_controller": {"mode": "legacy_spot_driven_r"}},
    )
    assert max(t.r_price for t in legacy.telemetry) > max(t.r_price for t in patched.telemetry)
    assert abs(s.final_r_price - s.final_i_oracle) < 0.001
    assert s.max_staker_fee_share > 0.30
    assert s.cartel_net_roi < 0.0
    assert s.min_coc_pfc_ratio >= 3.0 - 1e-6
    assert s.restored_within_14_days is True
