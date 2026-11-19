"""120-episode adversarial swarm runner, randomized regime generator, and Phase 2 DoD auditor."""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import random
from typing import Any

from sim.engine.environment import EpisodeSummary, SimulationEnv, load_scenario_config

from .base_agent import LLMBackendConfig
from .covert_channel import CovertChannel
from .personas import (
    ArbitrageurAgent,
    GreedyWhaleAgent,
    HonestOracleEnsembleAgent,
    HonestWhistleblowerAgent,
    HostileStateAgent,
    OracleCartelAgent,
    RetailHerdAgent,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = REPO_ROOT / "sim" / "scenarios"


@dataclass(frozen=True)
class EpisodeAuditRecord:
    episode_idx: int
    regime: str
    seed: int
    cartel_strategy: str
    irrational_bribe_accept: bool
    tvl_scale: float
    cartel_attacked: bool
    cartel_net_roi: float
    whistleblower_net_roi: float
    max_oracle_manipulation_error: float
    unbacked_bad_debt_pm: float
    eth_btc_redistributed_or_bad_debt: float
    min_coc_pfc_ratio: float
    peg_error_at_day14_after_shock: float
    restored_within_14_days: bool
    recovery_hours_after_shock: int | None
    total_disputes: int
    cumulative_slash_burned_pm: float
    bribe_offers: int
    defections_to_whistleblow: int
    passed_all_gates: bool
    gate_failures: list[str]


def _percentile(sorted_vals: list[float], q: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int((len(sorted_vals) - 1) * q)))
    return float(sorted_vals[idx])


def _scale_config(cfg: dict[str, Any], tvl_scale: float) -> dict[str, Any]:
    out = dict(cfg)
    if "amm" in out:
        amm = dict(out["amm"])
        amm["pm_reserve"] = float(amm["pm_reserve"]) * tvl_scale
        amm["numeraire_reserve"] = float(amm["numeraire_reserve"]) * tvl_scale
        out["amm"] = amm
    if "initial_vaults" in out:
        out["initial_vaults"] = [
            {**v, "debt_pm": float(v["debt_pm"]) * tvl_scale}
            for v in out["initial_vaults"]
        ]
    if "agent_numeraire" in out:
        out["agent_numeraire"] = {k: float(v) * tvl_scale for k, v in out["agent_numeraire"].items()}
    if "agent_pm_mints" in out:
        out["agent_pm_mints"] = {k: float(v) * tvl_scale for k, v in out["agent_pm_mints"].items()}
    if "arbitrageur" in out:
        arb = dict(out["arbitrageur"])
        arb["vault_collateral_numeraire"] = float(arb.get("vault_collateral_numeraire", 500_000.0)) * tvl_scale
        arb["initial_debt_pm"] = float(arb.get("initial_debt_pm", 1_000.0)) * tvl_scale
        out["arbitrageur"] = arb
    if "oracle" in out:
        ocfg = dict(out["oracle"])
        ocfg["nodes"] = [{**n, "stake_pm": float(n["stake_pm"]) * tvl_scale} for n in ocfg.get("nodes", [])]
        ocfg["dispute_bond_min_pm"] = float(ocfg.get("dispute_bond_min_pm", 5000.0)) * max(1.0, min(tvl_scale, 5.0))
        out["oracle"] = ocfg
    return out


def build_regime_episode(
    episode_idx: int,
    regime: str,
    seed: int,
    llm_config: LLMBackendConfig,
) -> tuple[SimulationEnv, CovertChannel, dict[str, Any]]:
    rng = random.Random(seed + 10_000 * (episode_idx + 1))
    channel = CovertChannel()
    cartel_strategy = "none"
    irrational_accept = False
    tvl_scale = 1.0

    if regime == "cartel_stealth_and_bribe":
        cfg = load_scenario_config(SCENARIO_DIR / "01_oracle_cartel_bribe.yaml")
        strategies = (
            "aggressive_lie",
            "stealth_boiling_frog",
            "bribe_swing_voter",
            "liveness_grief_spam",
            "adaptive_capitulate",
        )
        cartel_strategy = strategies[episode_idx % len(strategies)]
        irrational_accept = cartel_strategy == "bribe_swing_voter" and (episode_idx % 2 == 1)
        cartel_frac = rng.uniform(0.36, 0.49)
        total_locked = 800_000.0

        # Ensure swing_voter node + extra 2-year locked cold court voters exist cleanly
        if cartel_strategy == "bribe_swing_voter":
            # 44% cartel + 5% swing_voter vs 51% honest (35% online honest + 11% cold court + 5% wb)
            c_tot = 0.44 * total_locked
            swing_stake = 0.05 * total_locked
            wb_stake = 0.05 * total_locked
            cold_stake = 0.11 * total_locked
            h_each = (total_locked - c_tot - swing_stake - wb_stake - cold_stake) / 2.0
            nodes = [
                {"node_id": "honest_1", "stake_pm": h_each, "role": "honest", "is_court_voter": True},
                {"node_id": "honest_2", "stake_pm": h_each, "role": "honest", "is_court_voter": True},
                {"node_id": "honest_cold_court", "stake_pm": cold_stake, "role": "honest", "is_court_voter": True},
                {"node_id": "swing_voter", "stake_pm": swing_stake, "role": "honest", "is_court_voter": True},
                {"node_id": "whistleblower", "stake_pm": wb_stake, "role": "whistleblower", "is_court_voter": True},
                {"node_id": "cartel_core_1", "stake_pm": 0.45 * c_tot, "role": "cartel", "is_court_voter": True},
                {"node_id": "cartel_core_2", "stake_pm": 0.40 * c_tot, "role": "cartel", "is_court_voter": True},
                {"node_id": "cartel_outlier", "stake_pm": 0.15 * c_tot, "role": "cartel", "is_court_voter": True},
            ]
            outage = True  # honest_1 outage in round 1 lets cartel+swing capture P_med
            cold_nodes = ("honest_cold_court",)
        else:
            c_tot = cartel_frac * total_locked
            wb_stake = 20_000.0
            dyn_stake = 20_000.0
            h_each = (total_locked - c_tot - wb_stake - dyn_stake) / 2.0
            nodes = [
                {"node_id": "honest_1", "stake_pm": h_each, "role": "honest", "is_court_voter": True},
                {"node_id": "honest_2", "stake_pm": h_each, "role": "honest", "is_court_voter": True},
                {"node_id": "honest_dynamic", "stake_pm": dyn_stake, "role": "honest", "is_court_voter": True},
                {"node_id": "whistleblower", "stake_pm": wb_stake, "role": "whistleblower", "is_court_voter": True},
                {"node_id": "cartel_core_1", "stake_pm": 0.42 * c_tot, "role": "cartel", "is_court_voter": True},
                {"node_id": "cartel_core_2", "stake_pm": 0.42 * c_tot, "role": "cartel", "is_court_voter": True},
                {"node_id": "cartel_outlier", "stake_pm": 0.16 * c_tot, "role": "cartel", "is_court_voter": True},
            ]
            outage = True
            cold_nodes = ()

        cfg["oracle"]["nodes"] = nodes
        cfg["agent_pm_mints"]["retail_herd"] = 30_000.0
        cfg["agent_numeraire"]["retail_herd"] = 30_000.0

        bias_sign = -1.0 if (episode_idx % 3 == 2 and cartel_strategy != "stealth_boiling_frog") else 1.0
        bias = bias_sign * rng.uniform(0.06, 0.14)
        start_h = rng.randint(24, 72)

        honest_ids = tuple(n["node_id"] for n in nodes if n["role"] == "honest")
        cartel_ids = tuple(n["node_id"] for n in nodes if n["role"] == "cartel")
        agents = [
            HonestOracleEnsembleAgent(
                honest_ids,
                outage_first_attack_round=outage,
                attack_start_hour=start_h,
                cold_court_only_nodes=cold_nodes,
            ),
            OracleCartelAgent(
                cartel_ids,
                strategy=cartel_strategy,
                attack_bias=bias,
                attack_start_hour=start_h,
                attack_end_hour=start_h + 192,
                bribe_offer_pm=12_000.0,
                llm_config=llm_config,
            ),
            HonestWhistleblowerAgent(use_epsilon_trigger=True, llm_config=llm_config),
            RetailHerdAgent(llm_config=llm_config),
            ArbitrageurAgent(llm_config=llm_config),
        ]
        if cartel_strategy == "bribe_swing_voter":
            agents.insert(
                2,
                GreedyWhaleAgent(
                    swing_node_id="swing_voter",
                    owned_node_ids=("swing_voter",),
                    irrational_accept=irrational_accept,
                    llm_config=llm_config,
                ),
            )

    elif regime == "commodity_energy_shocks":
        cfg = load_scenario_config(SCENARIO_DIR / "02_commodity_supply_shock.yaml")
        energy_mult = rng.uniform(1.25, 1.45)
        shock_h = rng.randint(24, 96)
        cfg["shock_hour"] = shock_h
        cfg["shocks"] = [{"hour": shock_h, "basket_multipliers": {"electricity": energy_mult, "oil_gas": energy_mult}}]
        cfg["agent_pm_mints"]["retail_herd"] = 25_000.0
        cfg["agent_numeraire"]["retail_herd"] = 25_000.0

        # Mix in a small griefing cartel (25%) during commodity shocks testing liveness under turmoil
        cfg["oracle"]["nodes"].append(
            {"node_id": "cartel_grief_1", "stake_pm": 80_000.0, "role": "cartel", "is_court_voter": True}
        )
        cfg["agent_pm_mints"]["cartel_trader"] = 15_000.0
        cartel_strategy = "liveness_grief_spam"

        agents = [
            HonestOracleEnsembleAgent(("honest_1", "honest_2", "honest_dynamic")),
            OracleCartelAgent(
                ("cartel_grief_1",),
                strategy="liveness_grief_spam",
                attack_start_hour=shock_h,
                attack_end_hour=shock_h + 96,
                llm_config=llm_config,
            ),
            HonestWhistleblowerAgent(use_epsilon_trigger=True, llm_config=llm_config),
            RetailHerdAgent(llm_config=llm_config),
            ArbitrageurAgent(llm_config=llm_config),
        ]

    elif regime == "whale_bank_run_and_crash":
        cfg = load_scenario_config(SCENARIO_DIR / "03_whale_bank_run.yaml")
        shock_h = rng.randint(24, 96)
        cfg["shock_hour"] = shock_h
        sol_mult = rng.uniform(0.45, 0.55)
        eth_mult = rng.uniform(0.75, 0.90)
        btc_mult = rng.uniform(0.75, 0.90)
        cfg["shocks"] = [
            {"hour": shock_h, "collateral_multipliers": {"SOL": sol_mult, "ETH": eth_mult, "BTC": btc_mult}}
        ]
        # Vary whale dump between 350k and 480k (~25% to 35% of circulating supply)
        cfg["agent_pm_mints"]["whale_seller"] = rng.uniform(350_000.0, 480_000.0)
        cfg["agent_pm_mints"]["retail_herd"] = 35_000.0
        cfg["agent_numeraire"]["retail_herd"] = 35_000.0
        wave_hours = rng.randint(6, 12)

        agents = [
            HonestOracleEnsembleAgent(("honest_1", "honest_2", "honest_dynamic")),
            HonestWhistleblowerAgent(use_epsilon_trigger=True, llm_config=llm_config),
            GreedyWhaleAgent(
                owned_node_ids=(),
                bank_run_enabled=True,
                bank_run_start_hour=shock_h,
                bank_run_wave_hours=wave_hours,
                llm_config=llm_config,
            ),
            RetailHerdAgent(llm_config=llm_config),
            ArbitrageurAgent(llm_config=llm_config),
        ]

    elif regime == "hostile_state_low_stake":
        base_cfg = load_scenario_config(SCENARIO_DIR / "04_hostile_state_short.yaml")
        tvl_scale = rng.choice([0.5, 1.0, 5.0, 20.0])
        cfg = _scale_config(base_cfg, tvl_scale)
        shock_h = rng.randint(36, 72)
        cfg["shock_hour"] = shock_h
        cartel_strategy = "aggressive_lie"
        bias = rng.uniform(0.06, 0.12)
        dump_amt = float(cfg["hostile_state"]["dump_pm_amount"]) * tvl_scale

        agents = [
            HonestOracleEnsembleAgent(("honest_1", "honest_2", "honest_dynamic")),
            OracleCartelAgent(
                ("cartel_core_1",),
                strategy="aggressive_lie",
                attack_bias=bias,
                attack_start_hour=shock_h + 12,
                attack_end_hour=shock_h + 144,
                llm_config=llm_config,
            ),
            HonestWhistleblowerAgent(
                use_epsilon_trigger=True,
                dispute_bond_pm=float(cfg["oracle"]["dispute_bond_min_pm"]),
                llm_config=llm_config,
            ),
            HostileStateAgent(
                start_hour=shock_h,
                end_hour=shock_h + 180,
                dump_interval_hours=12,
                dump_pm_amount=dump_amt,
                llm_config=llm_config,
            ),
            ArbitrageurAgent(llm_config=llm_config),
        ]
    else:
        raise ValueError(f"unknown red-team regime '{regime}'")

    env = SimulationEnv(cfg, seed=seed, custom_agents=agents, covert_channel=channel, replace_default_bots=True)
    meta = {
        "cartel_strategy": cartel_strategy,
        "irrational_accept": irrational_accept,
        "tvl_scale": tvl_scale,
    }
    return env, channel, meta


def audit_episode(
    episode_idx: int,
    regime: str,
    seed: int,
    summary: EpisodeSummary,
    channel: CovertChannel,
    meta: dict[str, Any],
) -> EpisodeAuditRecord:
    failures: list[str] = []
    if summary.cartel_attacked:
        if summary.cartel_net_roi >= 0.0:
            failures.append(f"cartel_net_roi={summary.cartel_net_roi:.4f} >= 0")
    elif summary.max_oracle_manipulation_error >= 0.01:
        failures.append(f"deterred manipulation error {summary.max_oracle_manipulation_error:.4f} >= 0.01")

    if not summary.restored_within_14_days or summary.peg_error_at_day14_after_shock >= 0.02:
        failures.append(
            f"peg_14d_failed(restored={summary.restored_within_14_days}, "
            f"err={summary.peg_error_at_day14_after_shock:.4f})"
        )
    if summary.unbacked_bad_debt_pm > 1e-6 or summary.eth_btc_redistributed_or_bad_debt > 1e-6:
        failures.append(
            f"solvency_failed(bad_debt={summary.unbacked_bad_debt_pm:.4f}, "
            f"contagion={summary.eth_btc_redistributed_or_bad_debt:.4f})"
        )
    if summary.min_coc_pfc_ratio < 3.0 - 1e-6:
        failures.append(f"coc_pfc_ratio={summary.min_coc_pfc_ratio:.4f} < 3.0")

    cstats = channel.stats()
    return EpisodeAuditRecord(
        episode_idx=episode_idx,
        regime=regime,
        seed=seed,
        cartel_strategy=str(meta["cartel_strategy"]),
        irrational_bribe_accept=bool(meta["irrational_accept"]),
        tvl_scale=float(meta["tvl_scale"]),
        cartel_attacked=summary.cartel_attacked,
        cartel_net_roi=summary.cartel_net_roi,
        whistleblower_net_roi=summary.whistleblower_net_roi,
        max_oracle_manipulation_error=summary.max_oracle_manipulation_error,
        unbacked_bad_debt_pm=summary.unbacked_bad_debt_pm,
        eth_btc_redistributed_or_bad_debt=summary.eth_btc_redistributed_or_bad_debt,
        min_coc_pfc_ratio=summary.min_coc_pfc_ratio,
        peg_error_at_day14_after_shock=summary.peg_error_at_day14_after_shock,
        restored_within_14_days=summary.restored_within_14_days,
        recovery_hours_after_shock=summary.recovery_hours_after_shock,
        total_disputes=summary.total_disputes,
        cumulative_slash_burned_pm=summary.cumulative_slash_burned_pm,
        bribe_offers=cstats["bribe_offers"],
        defections_to_whistleblow=cstats["defections_to_whistleblow"],
        passed_all_gates=len(failures) == 0,
        gate_failures=failures,
    )


class RedTeamRunner:
    """Executes the full 4-regime x N-seed randomized red-team audit matrix."""

    REGIMES = (
        "cartel_stealth_and_bribe",
        "commodity_energy_shocks",
        "whale_bank_run_and_crash",
        "hostile_state_low_stake",
    )

    def __init__(
        self,
        episodes_per_regime: int = 30,
        base_seed: int = 1000,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        self.episodes_per_regime = episodes_per_regime
        self.base_seed = base_seed
        self.llm_config = llm_config or LLMBackendConfig(backend="heuristic")

    def run_suite(self) -> dict[str, Any]:
        records: list[EpisodeAuditRecord] = []
        sampled_transcripts: dict[str, list[dict[str, Any]]] = {}

        idx = 0
        for regime in self.REGIMES:
            for ep in range(self.episodes_per_regime):
                seed = self.base_seed + idx
                env, channel, meta = build_regime_episode(ep, regime, seed, self.llm_config)
                res = env.run()
                rec = audit_episode(idx, regime, seed, res.summary, channel, meta)
                records.append(rec)
                if len(channel.transcript()) > 0 and regime not in sampled_transcripts:
                    sampled_transcripts[regime] = channel.transcript()
                idx += 1

        failed = [r for r in records if not r.passed_all_gates]
        active_cartel = [r for r in records if r.cartel_attacked]
        deterred_cartel = [r for r in records if not r.cartel_attacked and r.cartel_strategy != "none"]

        regime_stats: dict[str, Any] = {}
        for regime in self.REGIMES:
            sub = [r for r in records if r.regime == regime]
            d14_errs = sorted(r.peg_error_at_day14_after_shock for r in sub)
            rois = sorted(r.cartel_net_roi for r in sub if r.cartel_attacked)
            cocs = sorted(r.min_coc_pfc_ratio for r in sub)
            regime_stats[regime] = {
                "episodes": len(sub),
                "passed": sum(1 for r in sub if r.passed_all_gates),
                "active_cartel_episodes": len([r for r in sub if r.cartel_attacked]),
                "cartel_roi_p50": _percentile(rois, 0.50) if rois else 0.0,
                "cartel_roi_worst_max": max(rois) if rois else 0.0,
                "day14_err_p50": _percentile(d14_errs, 0.50),
                "day14_err_p95": _percentile(d14_errs, 0.95),
                "day14_err_worst_max": max(d14_errs),
                "min_coc_pfc_ratio": min(cocs),
                "max_bad_debt_pm": max(r.unbacked_bad_debt_pm for r in sub),
            }

        return {
            "total_episodes": len(records),
            "passed_episodes": len(records) - len(failed),
            "failed_episodes": len(failed),
            "active_cartel_attack_episodes": len(active_cartel),
            "deterred_capitulation_episodes": len(deterred_cartel),
            "all_gates_passed": len(failed) == 0,
            "backend": self.llm_config.backend,
            "regime_stats": regime_stats,
            "sampled_covert_transcripts": sampled_transcripts,
            "episodes": [asdict(r) for r in records],
        }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Phase 2 Step 2 adversarial red-team swarm suite.")
    parser.add_argument("--episodes-per-regime", type=int, default=30)
    parser.add_argument("--base-seed", type=int, default=1000)
    parser.add_argument(
        "--backend",
        choices=["heuristic", "openai", "gemini", "anthropic", "ollama"],
        default="heuristic",
    )
    parser.add_argument("--model", default="gpt-4o-mini")
    parser.add_argument("--checkpoint-hours", type=int, default=24)
    parser.add_argument("--report", default="target/phase2_red_team_report.json")
    args = parser.parse_args(argv)

    llm_cfg = LLMBackendConfig(
        backend=args.backend,
        model=args.model,
        checkpoint_hours=args.checkpoint_hours,
    )
    runner = RedTeamRunner(
        episodes_per_regime=args.episodes_per_regime,
        base_seed=args.base_seed,
        llm_config=llm_cfg,
    )
    report = runner.run_suite()

    report_path = Path(args.report)
    if not report_path.is_absolute():
        report_path = REPO_ROOT / report_path
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print(
        f"Red-Team Swarm Audit: total={report['total_episodes']}, "
        f"passed={report['passed_episodes']}, failed={report['failed_episodes']}, "
        f"active_cartel_attacks={report['active_cartel_attack_episodes']} "
        f"(backend={args.backend})"
    )
    hdr = (
        f"{'Regime':<27} | {'Pass':>6} | {'Atk':>3} | {'WorstROI':>9} | "
        f"{'D14 p50':>8} | {'D14 p95':>8} | {'D14 Max':>8} | {'MinCoC':>7} | {'BadDebt':>7}"
    )
    print(hdr)
    print("-" * len(hdr))
    for reg, st in report["regime_stats"].items():
        print(
            f"{reg:<27} | "
            f"{st['passed']:>2}/{st['episodes']:<3} | "
            f"{st['active_cartel_episodes']:>3} | "
            f"{st['cartel_roi_worst_max'] * 100:>8.1f}% | "
            f"{st['day14_err_p50'] * 100:>7.3f}% | "
            f"{st['day14_err_p95'] * 100:>7.3f}% | "
            f"{st['day14_err_worst_max'] * 100:>7.3f}% | "
            f"{st['min_coc_pfc_ratio']:>6.2f}x | "
            f"{st['max_bad_debt_pm']:>7.1f}"
        )
    print(f"Wrote red-team audit report to {report_path}")
    return 0 if report["all_gates_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

