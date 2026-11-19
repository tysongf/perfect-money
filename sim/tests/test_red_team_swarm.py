import json
from pathlib import Path

import pytest

from sim.engine.environment import SimulationEnv, load_scenario_config
from sim.red_team_agents.base_agent import (
    ActionValidationError,
    AgentAction,
    BaseRedTeamAgent,
    LLMBackendConfig,
    parse_actions_json,
)
from sim.red_team_agents.covert_channel import CovertChannel
from sim.red_team_agents.personas import (
    ArbitrageurAgent,
    GreedyWhaleAgent,
    HonestOracleEnsembleAgent,
    HonestWhistleblowerAgent,
    OracleCartelAgent,
)
from sim.red_team_agents.runner import RedTeamRunner


SCENARIO_DIR = Path(__file__).resolve().parents[1] / "scenarios"


def test_action_schema_and_mock_llm_adapter():
    # Rejects malformed/negative/unknown actions
    with pytest.raises(ActionValidationError):
        parse_actions_json('{"actions": [{"action_type": "MINT_FREE_MONEY", "params": {}}]}')
    with pytest.raises(ActionValidationError):
        parse_actions_json('{"actions": [{"action_type": "AMM_SWAP_PM_TO_NUM", "params": {"pm_amount": -5}}]}')

    # Accepts strict JSON wrapped in markdown fences
    parsed = parse_actions_json(
        '```json\n{"actions": [{"action_type": "AMM_SWAP_PM_TO_NUM", "params": {"pm_amount": 250.0}}]}\n```'
    )
    assert len(parsed) == 1
    assert parsed[0].action_type == "AMM_SWAP_PM_TO_NUM"

    # Mock LLM valid vs malformed fallback -> NOOP without crashing
    valid_agent = BaseRedTeamAgent(
        agent_id="mock_valid",
        role="retail",
        llm_config=LLMBackendConfig(
            backend="mock_llm",
            checkpoint_hours=24,
            mock_transport=lambda _id, _sys, _usr: json.dumps(
                {"actions": [{"action_type": "AMM_SWAP_PM_TO_NUM", "params": {"pm_amount": 100.0}}]}
            ),
        ),
    )
    obs = {"hour": 24, "oracle_round": None}
    acts = valid_agent.decide(obs, [], __import__("random").Random(1))
    assert valid_agent.llm_client.llm_calls == 1
    assert valid_agent.llm_client.schema_violations == 0
    assert acts[0].action_type == "AMM_SWAP_PM_TO_NUM"

    bad_agent = BaseRedTeamAgent(
        agent_id="mock_bad",
        role="retail",
        llm_config=LLMBackendConfig(
            backend="mock_llm",
            checkpoint_hours=24,
            mock_transport=lambda _id, _sys, _usr: "NOT VALID JSON!!!",
        ),
    )
    fallback = bad_agent.decide(obs, [], __import__("random").Random(1))
    assert bad_agent.llm_client.schema_violations == 1
    assert fallback == [AgentAction("NOOP")]


def test_boiling_frog_ablation_naive_vs_epsilon_whistleblower():
    # Configure 49% cartel running stealth_boiling_frog (+1.0-1.1%) while honest_1 lags in round 1
    def _run_stealth(use_eps: bool):
        cfg = load_scenario_config(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml")
        cfg["duration_hours"] = 144
        cfg["basket_hourly_noise_sigma"] = 0.0
        ch = CovertChannel()
        agents = [
            HonestOracleEnsembleAgent(
                ("honest_1", "honest_2", "honest_dynamic"),
                outage_first_attack_round=True,
                attack_start_hour=48,
            ),
            OracleCartelAgent(
                ("cartel_core_1", "cartel_core_2", "cartel_outlier"),
                strategy="stealth_boiling_frog",
                attack_start_hour=48,
                attack_end_hour=52,
            ),
            HonestWhistleblowerAgent(
                use_epsilon_trigger=use_eps,
                epsilon_multiplier=1.05,
                naive_threshold=0.012,
            ),
            ArbitrageurAgent(),
        ]
        env = SimulationEnv(cfg, seed=77, custom_agents=agents, covert_channel=ch, replace_default_bots=True)
        return env, env.run()

    naive_env, naive_res = _run_stealth(use_eps=False)
    patched_env, patched_res = _run_stealth(use_eps=True)

    # Naive 1.2% whistleblower fails to catch stealth 1.1% creep -> honest reporter slashed, zero disputes!
    assert naive_res.summary.total_disputes == 0
    assert naive_env.oracle.nodes["honest_2"].slashed_pm > 0.0
    assert naive_env.oracle.nodes["cartel_core_1"].slashed_pm == 0.0

    # Patched 1.05 * frozen_epsilon whistleblower catches stealth creep, wins court, slashes cartel!
    assert patched_res.summary.total_disputes >= 1
    assert patched_env.oracle.nodes["cartel_core_1"].slashed_pm > 0.0
    assert patched_res.summary.cartel_net_roi < -0.02
    assert patched_res.summary.whistleblower_net_roi > 0.05
    assert patched_env.oracle.nodes["honest_2"].slashed_pm == 0.0


def test_covert_bribe_defection_and_irrational_accept():
    def _run_bribe(irrational_accept: bool):
        cfg = load_scenario_config(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml")
        cfg["duration_hours"] = 180
        cfg["basket_hourly_noise_sigma"] = 0.0
        # 44% cartel + 5% swing_voter vs 51% honest (including cold court staker)
        cfg["oracle"]["nodes"] = [
            {"node_id": "honest_1", "stake_pm": 140_000.0, "role": "honest", "is_court_voter": True},
            {"node_id": "honest_2", "stake_pm": 140_000.0, "role": "honest", "is_court_voter": True},
            {"node_id": "honest_cold_court", "stake_pm": 88_000.0, "role": "honest", "is_court_voter": True},
            {"node_id": "swing_voter", "stake_pm": 40_000.0, "role": "honest", "is_court_voter": True},
            {"node_id": "whistleblower", "stake_pm": 40_000.0, "role": "whistleblower", "is_court_voter": True},
            {"node_id": "cartel_core_1", "stake_pm": 160_000.0, "role": "cartel", "is_court_voter": True},
            {"node_id": "cartel_core_2", "stake_pm": 192_000.0, "role": "cartel", "is_court_voter": True},
        ]
        ch = CovertChannel()
        agents = [
            HonestOracleEnsembleAgent(
                ("honest_1", "honest_2", "honest_cold_court"),
                outage_first_attack_round=True,
                attack_start_hour=48,
                cold_court_only_nodes=("honest_cold_court",),
            ),
            OracleCartelAgent(
                ("cartel_core_1", "cartel_core_2"),
                strategy="bribe_swing_voter",
                attack_bias=0.10,
                attack_start_hour=48,
                attack_end_hour=120,
                bribe_offer_pm=12_000.0,
            ),
            GreedyWhaleAgent(
                swing_node_id="swing_voter",
                owned_node_ids=("swing_voter",),
                irrational_accept=irrational_accept,
            ),
            HonestWhistleblowerAgent(use_epsilon_trigger=True),
            ArbitrageurAgent(),
        ]
        env = SimulationEnv(cfg, seed=88, custom_agents=agents, covert_channel=ch, replace_default_bots=True)
        return env, ch, env.run()

    # Case 1: Rational swing voter defects to whistleblow for 20% bounty
    _, ch_def, res_def = _run_bribe(irrational_accept=False)
    assert ch_def.stats()["bribe_offers"] >= 1
    assert ch_def.stats()["defections_to_whistleblow"] >= 1
    assert res_def.summary.cartel_net_roi < 0.0

    # Case 2: Even if swing voter irrationally accepts bribe, honest whistleblower + 48h court defeats both
    env_acc, ch_acc, res_acc = _run_bribe(irrational_accept=True)
    assert ch_acc.stats()["bribes_accepted"] >= 1
    assert res_acc.summary.total_disputes >= 1
    assert res_acc.summary.cartel_net_roi < -0.50
    assert env_acc.oracle.nodes["swing_voter"].slashed_pm > 0.0


def test_red_team_120_episode_gate_matrix():
    runner = RedTeamRunner(episodes_per_regime=30, base_seed=1000)
    report = runner.run_suite()
    assert report["total_episodes"] == 120
    assert report["active_cartel_attack_episodes"] >= 50
    assert report["failed_episodes"] == 0, (
        f"Failed episodes: {[e for e in report['episodes'] if not e['passed_all_gates']][:3]}"
    )
    assert report["all_gates_passed"] is True


def test_mid_round_shock_toctou_griefing_defeated():
    """Mid-round +40% spot shock in R8 CHALLENGE window must not allow griefer to slash honest reporters."""
    cfg = load_scenario_config(SCENARIO_DIR / "02_commodity_supply_shock.yaml")
    cfg["shock_hour"] = 44
    cfg["shocks"] = [{"hour": 44, "basket_multipliers": {"electricity": 1.40, "oil_gas": 1.40}}]
    cfg["oracle"]["nodes"].append(
        {"node_id": "cartel_grief_1", "stake_pm": 80_000.0, "role": "cartel", "is_court_voter": True}
    )
    cfg["agent_pm_mints"]["cartel_trader"] = 15_000.0

    agents = [
        HonestOracleEnsembleAgent(("honest_1", "honest_2", "honest_dynamic")),
        OracleCartelAgent(
            ("cartel_grief_1",),
            strategy="liveness_grief_spam",
            attack_start_hour=44,
            attack_end_hour=140,
        ),
        HonestWhistleblowerAgent(use_epsilon_trigger=True),
        ArbitrageurAgent(),
    ]
    env = SimulationEnv(cfg, seed=1030, custom_agents=agents, covert_channel=CovertChannel(), replace_default_bots=True)
    res = env.run()
    s = res.summary
    assert s.total_disputes >= 1
    assert env.oracle.nodes["honest_1"].slashed_pm == 0.0
    assert env.oracle.nodes["honest_2"].slashed_pm == 0.0
    assert env.oracle.nodes["whistleblower"].slashed_pm == 0.0
    assert s.cartel_net_roi < -0.05
    assert s.min_coc_pfc_ratio >= 3.0 - 1e-6
    assert s.restored_within_14_days is True
    assert s.peg_error_at_day14_after_shock < 0.02
