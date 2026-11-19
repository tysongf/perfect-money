from pathlib import Path

from sim.engine.environment import run_episode
from sim.engine.phase1_bridge import quantize_episode_deltas, verify_supply_deltas_with_phase1


SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"


def test_simulated_supply_deltas_verify_through_real_noir_circuits():
    res = run_episode(SCENARIO_DIR / "02_commodity_supply_shock.yaml", seed=42)
    mints, burns = quantize_episode_deltas(res.summary, scale=1_000)
    bridge = verify_supply_deltas_with_phase1(mints, burns)

    assert bridge.verified_shields == len(mints)
    assert bridge.verified_unshields >= len(burns)
    expected_supply = sum(mints) - sum(burns)
    assert bridge.total_issued_supply == expected_supply
    assert bridge.total_shielded_supply == expected_supply
    assert bridge.public_vault_balance == 0

