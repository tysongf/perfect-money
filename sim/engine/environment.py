"""Deterministic 1-hour epoch simulation runner and conservation/security telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from pathlib import Path
import random
from typing import Any, Mapping

import yaml

from .amm_and_vaults import SpotAMM, VaultAndAmmSystem, default_collateral_branches
from .baselines import (
    ArbitrageurBot,
    BotContext,
    DynamicStakerBot,
    HostileStateShortBot,
    OracleParticipantStrategy,
    WhaleBankRunBot,
    WhistleblowerBot,
)
from .oracle_market import OracleMarket, OracleNode, OracleRound
from .peg_controller import (
    BasketSpec,
    DEFAULT_BASKET_WEIGHTS,
    DEFAULT_GENESIS_PRICES,
    PegController,
    compute_auto_throttle,
)


@dataclass(frozen=True)
class TickTelemetry:
    hour: int
    i_true: float
    i_oracle: float
    r_price: float
    m_spot: float
    e_spot_true: float
    e_spot_oracle: float
    min_borrow_rate_apr: float
    circulating_pm_supply: float
    active_debt_pm: float
    locked_pm: float
    coc_51_pm: float
    pfc_effective_pm: float
    coc_pfc_ratio: float
    max_epoch_delta: float
    challenge_hours: int
    staker_fee_share: float
    unbacked_bad_debt_pm: float


@dataclass(frozen=True)
class EpisodeSummary:
    scenario_name: str
    seed: int
    duration_hours: int
    shock_hour: int
    peg_mode: str
    final_i_true: float
    final_i_oracle: float
    final_r_price: float
    final_m_spot: float
    final_abs_peg_error: float
    max_abs_peg_error: float
    post_shock_max_abs_peg_error: float
    peg_error_at_day14_after_shock: float
    restored_within_14_days: bool
    recovery_hours_after_shock: int | None
    max_r_over_i_observed: float
    unbacked_bad_debt_pm: float
    eth_btc_redistributed_or_bad_debt: float
    sol_sp_offset_pm: float
    sol_insurance_offset_pm: float
    sol_redistributed_pm: float
    min_coc_pfc_ratio: float
    max_staker_fee_share: float
    cartel_initial_wealth: float
    cartel_final_wealth: float
    cartel_net_roi: float
    whistleblower_initial_wealth: float
    whistleblower_final_wealth: float
    whistleblower_net_roi: float
    cumulative_vault_mints_pm: float
    cumulative_vault_burns_pm: float
    cumulative_slash_burned_pm: float
    total_oracle_rounds_finalized: int
    total_disputes: int
    max_oracle_manipulation_error: float = 0.0
    cartel_attacked: bool = False


@dataclass
class EpisodeResult:
    summary: EpisodeSummary
    telemetry: list[TickTelemetry] = field(default_factory=list)
    config: dict[str, Any] = field(default_factory=dict)


class SimulationEnv:
    """Deterministic epoch environment enforcing 1h tick order and global accounting conservation."""

    def __init__(
        self,
        config: Mapping[str, Any],
        seed: int = 42,
        *,
        custom_agents: list[Any] | None = None,
        covert_channel: Any | None = None,
        replace_default_bots: bool = False,
    ) -> None:
        self.config: dict[str, Any] = dict(config)
        self.seed = seed
        self.rng = random.Random(seed)
        self.custom_agents: list[Any] = list(custom_agents or [])
        self.covert_channel = covert_channel
        self.replace_default_bots = replace_default_bots
        self._cartel_attacked = False
        self._max_oracle_manipulation_error = 0.0
        self.duration_hours = int(self.config.get("duration_hours", 504))
        self.shock_hour = int(self.config.get("shock_hour", 48))
        self.round_interval_hours = int(self.config.get("round_interval_hours", 6))

        weights = dict(self.config.get("basket_weights", DEFAULT_BASKET_WEIGHTS))
        genesis = dict(self.config.get("genesis_prices", DEFAULT_GENESIS_PRICES))
        self.basket = BasketSpec(weights=weights, genesis_prices=genesis)
        self.true_prices: dict[str, float] = dict(genesis)
        self.price_history_by_hour: dict[int, dict[str, float]] = {0: dict(self.true_prices)}

        peg_cfg = self.config.get("peg_controller", {})
        self.peg_controller = PegController(
            mode=str(peg_cfg.get("mode", "patched_decoupled")),
            u_max_per_day=float(peg_cfg.get("u_max_per_day", 0.03)),
            k_track_per_day=float(peg_cfg.get("k_track_per_day", 0.80)),
        )

        # Collateral branches & spot AMM
        branches = default_collateral_branches()
        for bname, bcfg in self.config.get("branches", {}).items():
            if bname in branches:
                b = branches[bname]
                b.mint_mcr = float(bcfg.get("mint_mcr", b.mint_mcr))
                b.liq_cr = float(bcfg.get("liq_cr", b.liq_cr))
                b.liq_discount = float(bcfg.get("liq_discount", b.liq_discount))
                b.price = float(bcfg.get("price", b.price))

        amm_cfg = self.config.get("amm", {})
        amm_pm = float(amm_cfg.get("pm_reserve", 400_000.0))
        amm_num = float(amm_cfg.get("numeraire_reserve", 400_000.0))
        self.system = VaultAndAmmSystem(
            branches=branches,
            amm=SpotAMM(pm_reserve=amm_pm, numeraire_reserve=amm_num, fee_rate=float(amm_cfg.get("fee_rate", 0.003))),
        )
        # Genesis AMM PM reserve is backed by an initial protocol LP vault so debt == supply at t=0.
        amm_lp_col = (amm_pm * 2.5) / self.system.branches["ETH"].price
        self.system.open_or_mint_vault(
            "protocol_lp",
            "ETH",
            amm_lp_col,
            amm_pm,
            0.05,
            1.0,
            skip_owner_collateral_deduct=True,
            initial_allocation_target="_amm_init_",
            vault_id="V_AMM_LP",
        )
        # AMM holds those initial `amm_pm` tokens directly; remove duplicate agent bucket
        self.system.agent_pm["_amm_init_"] = 0.0

        # Fund vaults & allocate genesis PM buckets (every PM created from an over-collateralized vault)
        for vcfg in self.config.get("initial_vaults", []):
            owner = str(vcfg["owner"])
            bname = str(vcfg["branch"])
            mint_pm = float(vcfg["debt_pm"])
            init_cr = float(vcfg["initial_cr"])
            rate = float(vcfg.get("borrow_rate_apr", 0.05))
            target_sp = vcfg.get("deposit_to_sp_branch")
            target_ins = bool(vcfg.get("deposit_to_insurance", False))
            col_qty = (mint_pm * init_cr) / self.system.branches[bname].price
            self.system.open_or_mint_vault(
                owner,
                bname,
                col_qty,
                mint_pm,
                rate,
                1.0,
                skip_owner_collateral_deduct=True,
                vault_id=vcfg.get("vault_id"),
            )
            if target_sp:
                self.system.deposit_to_stability_pool(owner, str(target_sp), mint_pm)
            elif target_ins:
                self.system.agent_pm[owner] -= mint_pm
                self.system.insurance_reserve_pm += mint_pm

        # Stability pool initial top-ups from liquid agent balances if requested
        for bname, sp_cfg in self.config.get("initial_sp", {}).items():
            depositor = str(sp_cfg.get("agent_id", "sp_provider"))
            amount = float(sp_cfg.get("pm_amount", 0.0))
            if amount > 0.0:
                if self.system.agent_pm.get(depositor, 0.0) < amount:
                    col_qty = (amount * 2.2) / self.system.branches["ETH"].price
                    self.system.open_or_mint_vault(
                        depositor,
                        "ETH",
                        col_qty,
                        amount,
                        0.05,
                        1.0,
                        skip_owner_collateral_deduct=True,
                    )
                self.system.deposit_to_stability_pool(depositor, bname, amount)

        # Agent external numeraire funding (Arb, Whistleblower, Cartel, Hostile State)
        for agent_id, num_amt in self.config.get("agent_numeraire", {}).items():
            self.system.ensure_agent(str(agent_id))
            self.system.agent_numeraire[str(agent_id)] += float(num_amt)

        # Arb vault headroom for ceiling arbitrage (mint + sell PM when M > R)
        arb_cfg = self.config.get("arbitrageur", {})
        arb_col_qty = float(arb_cfg.get("vault_collateral_numeraire", 500_000.0)) / self.system.branches["ETH"].price
        arb_init_debt = float(arb_cfg.get("initial_debt_pm", 1000.0))
        self.system.open_or_mint_vault(
            "arb",
            "ETH",
            arb_col_qty,
            arb_init_debt,
            0.06,
            1.0,
            skip_owner_collateral_deduct=True,
            vault_id="V_ARB_ETH",
        )

        # Oracle Market & staker nodes (minted/backed via backing vaults or existing PM balances)
        oracle_cfg = self.config.get("oracle", {})
        self.oracle = OracleMarket(
            initial_prices=genesis,
            s_min_pm=float(oracle_cfg.get("s_min_pm", 1000.0)),
            dispute_bond_min_pm=float(oracle_cfg.get("dispute_bond_min_pm", 5000.0)),
        )
        for ncfg in oracle_cfg.get("nodes", []):
            nid = str(ncfg["node_id"])
            stake = float(ncfg["stake_pm"])
            role = str(ncfg.get("role", "honest"))
            is_voter = bool(ncfg.get("is_court_voter", True))
            # Mint backed stake PM from an isolated backing vault if caller didn't pre-fund liquid PM
            avail = self.system.agent_pm.get(nid, 0.0)
            if avail < stake:
                need = stake - avail
                col_qty = (need * 2.5) / self.system.branches["ETH"].price
                self.system.open_or_mint_vault(
                    f"stake_vault_{nid}",
                    "ETH",
                    col_qty,
                    need,
                    0.05,
                    1.0,
                    skip_owner_collateral_deduct=True,
                    initial_allocation_target=nid,
                )
            self.system.agent_pm[nid] -= stake
            self.oracle.add_node(
                OracleNode(node_id=nid, stake_pm=stake, is_court_voter=is_voter, role=role)
            )

        # Optional liquid reserves held by cartel_trader / dynamic_staker / whistleblower / whale / hostile_state
        for agent_id, pm_amt in self.config.get("agent_pm_mints", {}).items():
            aid = str(agent_id)
            amt = float(pm_amt)
            if amt > 0.0:
                col_qty = (amt * 2.5) / self.system.branches["ETH"].price
                self.system.open_or_mint_vault(
                    f"vault_{aid}",
                    "ETH",
                    col_qty,
                    amt,
                    0.055,
                    1.0,
                    skip_owner_collateral_deduct=True,
                    initial_allocation_target=aid,
                )

        # Strategies
        self.arb_bot = ArbitrageurBot()
        self.dynamic_staker = DynamicStakerBot()
        wb_cfg = self.config.get("whistleblower", {})
        self.whistleblower_bot = (
            WhistleblowerBot(
                dispute_bond_pm=float(wb_cfg.get("dispute_bond_pm", 5000.0)),
                deviation_threshold=float(wb_cfg.get("deviation_threshold", 0.012)),
                use_epsilon_trigger=bool(wb_cfg.get("use_epsilon_trigger", True)),
                epsilon_multiplier=float(wb_cfg.get("epsilon_multiplier", 1.05)),
            )
            if bool(wb_cfg.get("enabled", True))
            else None
        )
        cartel_cfg = self.config.get("cartel_attack", {})
        self.oracle_strategy = OracleParticipantStrategy(
            cartel_bias_by_asset=cartel_cfg.get("bias_by_asset"),
            cartel_outlier_sybil_bias=float(cartel_cfg.get("outlier_sybil_bias", 0.0)),
            attack_start_hour=int(cartel_cfg.get("start_hour", 0)),
            attack_end_hour=int(cartel_cfg.get("end_hour", 10_000)),
            honest_outage_rounds=cartel_cfg.get("honest_outage_rounds"),
            outage_first_attack_round=bool(cartel_cfg.get("outage_first_attack_round", False)),
        )

        bank_cfg = self.config.get("bank_run", {})
        self.whale_bot = (
            WhaleBankRunBot(
                agent_id=str(bank_cfg.get("agent_id", "whale_seller")),
                start_hour=int(bank_cfg.get("start_hour", self.shock_hour)),
                wave_hours=int(bank_cfg.get("wave_hours", 8)),
            )
            if bool(bank_cfg.get("enabled", False))
            else None
        )

        hostile_cfg = self.config.get("hostile_state", {})
        self.hostile_bot = (
            HostileStateShortBot(
                agent_id=str(hostile_cfg.get("agent_id", "hostile_state")),
                start_hour=int(hostile_cfg.get("start_hour", self.shock_hour)),
                end_hour=int(hostile_cfg.get("end_hour", 240)),
                dump_interval_hours=int(hostile_cfg.get("dump_interval_hours", 12)),
                dump_pm_amount=float(hostile_cfg.get("dump_pm_amount", 25_000.0)),
            )
            if bool(hostile_cfg.get("enabled", False))
            else None
        )

        self.k_pfc = float(self.config.get("k_pfc", 1.5))

    def round_open_true_prices(self, rnd: OracleRound | None = None) -> dict[str, float]:
        if rnd is None:
            return dict(self.true_prices)
        return dict(self.price_history_by_hour.get(rnd.open_hour, self.true_prices))

    def _cartel_wealth(self, r_px: float) -> float:
        stake = sum(n.stake_pm for n in self.oracle.nodes.values() if n.role == "cartel")
        pending = (
            self.system.pending_dispute_bonds_pm
            if self.oracle.active_round is not None
            and self.oracle.active_round.disputed
            and self.oracle.active_round.challenger_id in ("cartel", "cartel_trader")
            else 0.0
        )
        liquid_pm = (
            sum(
                self.system.agent_pm.get(nid, 0.0)
                for nid, n in self.oracle.nodes.items()
                if n.role == "cartel"
            )
            + self.system.agent_pm.get("cartel_trader", 0.0)
            + self.system.agent_pm.get("cartel", 0.0)
            + pending
        )
        num = self.system.agent_numeraire.get("cartel_trader", 0.0)
        return (stake + liquid_pm) + (num / max(1e-9, r_px))

    def _whistleblower_wealth(self, r_px: float) -> float:
        stake = sum(n.stake_pm for n in self.oracle.nodes.values() if n.role == "whistleblower")
        pending = (
            self.system.pending_dispute_bonds_pm
            if self.oracle.active_round is not None
            and self.oracle.active_round.disputed
            and self.oracle.active_round.challenger_id == "whistleblower"
            else 0.0
        )
        liquid_pm = (
            sum(
                self.system.agent_pm.get(nid, 0.0)
                for nid, n in self.oracle.nodes.items()
                if n.role == "whistleblower"
            )
            + self.system.agent_pm.get("whistleblower", 0.0)
            + pending
        )
        num = self.system.agent_numeraire.get("whistleblower", 0.0)
        return (stake + liquid_pm) + (num / max(1e-9, r_px))

    def _apply_scheduled_shocks(self, hour: int) -> None:
        for shock in self.config.get("shocks", []):
            if int(shock["hour"]) != hour:
                continue
            for asset, mult in shock.get("basket_multipliers", {}).items():
                self.true_prices[str(asset)] *= float(mult)
            for bname, mult in shock.get("collateral_multipliers", {}).items():
                self.system.branches[str(bname)].price *= float(mult)

    def _apply_background_noise(self) -> None:
        vol_basket = float(self.config.get("basket_hourly_noise_sigma", 0.0))
        if vol_basket > 0.0:
            for asset in self.true_prices:
                self.true_prices[asset] *= math.exp(self.rng.gauss(0.0, vol_basket))
        vol_col = float(self.config.get("collateral_hourly_noise_sigma", 0.0))
        if vol_col > 0.0:
            for branch in self.system.branches.values():
                branch.price *= math.exp(self.rng.gauss(0.0, vol_col))

    def _settle_oracle_events(self, throttle: Any, hour: int) -> None:
        res, no_rev, _ = self.oracle.advance(hour, throttle, self.system.oracle_fee_pool_pm)
        if no_rev["total_slashed_pm"] > 0.0:
            if self.oracle.active_round is not None and any(
                self.oracle.nodes.get(nid) is not None and self.oracle.nodes[nid].role == "cartel"
                for nid in self.oracle.active_round.no_reveal_slashes
            ):
                self._cartel_attacked = True
            self.system.cumulative_slash_burned_pm += no_rev["burned_pm"]
            self.system.circulating_pm_supply -= no_rev["burned_pm"]
            self.system.insurance_reserve_pm += no_rev["insurance_pm"]

        if res is not None:
            i_or_fin = self.basket.index(res.finalized_prices)
            i_tr_ref = self.basket.index(self.round_open_true_prices(self.oracle.active_round))
            self._max_oracle_manipulation_error = max(
                self._max_oracle_manipulation_error,
                abs(i_or_fin - i_tr_ref) / max(1e-9, i_tr_ref),
            )
            if any(
                self.oracle.nodes.get(nid) is not None and self.oracle.nodes[nid].role == "cartel"
                for nid in res.node_slashes
            ):
                self._cartel_attacked = True
            paid_rewards = sum(res.reward_payouts.values())
            self.system.oracle_fee_pool_pm = (
                self.system.oracle_fee_pool_pm + res.bond_fee_pool_pm - paid_rewards
            )
            for nid, rew in res.reward_payouts.items():
                self.system.credit_pm(nid, rew)
            for cid, bounty in res.bounty_payouts.items():
                self.system.credit_pm(cid, bounty)
            for cid, refund in res.bond_refunds.items():
                self.system.pending_dispute_bonds_pm -= refund
                self.system.credit_pm(cid, refund)
            if res.was_disputed and not res.dispute_upheld_challenger:
                # Frivolous challenge bond was already split into burned + bond_fee_pool + insurance
                if self.oracle.active_round is not None:
                    self.system.pending_dispute_bonds_pm -= self.oracle.active_round.dispute_bond_pm
            self.system.cumulative_slash_burned_pm += res.burned_pm
            self.system.circulating_pm_supply -= res.burned_pm
            self.system.insurance_reserve_pm += res.insurance_pm

    def transfer_pm(self, sender_id: str, recipient_id: str, amount: float) -> float:
        """Conservation-preserving transfer of liquid PM between two accounts."""
        self.system.ensure_agent(sender_id)
        self.system.ensure_agent(recipient_id)
        amt = min(max(0.0, float(amount)), self.system.agent_pm.get(sender_id, 0.0))
        if amt <= 0.0:
            return 0.0
        self.system.agent_pm[sender_id] -= amt
        self.system.agent_pm[recipient_id] += amt
        return amt

    def challenge_oracle_round(self, challenger_id: str, bond_pm: float, hour: int) -> bool:
        """Posts dispute bond and escalates current CHALLENGE round to 48h COURT."""
        rnd = self.oracle.active_round
        if rnd is None or rnd.phase != "CHALLENGE" or rnd.disputed:
            return False
        bond = max(float(bond_pm), self.oracle.dispute_bond_min_pm)
        avail = self.system.agent_pm.get(challenger_id, 0.0)
        if avail + 1e-12 < bond:
            return False
        self.system.agent_pm[challenger_id] = max(0.0, avail - bond)
        self.system.pending_dispute_bonds_pm += bond
        self.oracle.challenge_round(challenger_id, bond, hour)
        return True

    def lock_oracle_stake(self, agent_id: str, node_id: str, amount: float) -> float:
        """Locks liquid PM from `agent_id` into an existing oracle node's stake."""
        node = self.oracle.nodes.get(node_id)
        if node is None:
            return 0.0
        self.system.ensure_agent(agent_id)
        add = min(max(0.0, float(amount)), self.system.agent_pm.get(agent_id, 0.0))
        if add <= 0.0:
            return 0.0
        self.system.agent_pm[agent_id] -= add
        node.stake_pm += add
        return add

    def build_agent_observation(
        self,
        agent: Any,
        hour: int,
        peg_res: PegStepResult,
        throttle: ThrottleState,
    ) -> dict[str, Any]:
        """Constructs strict JSON-serializable state observation for a pluggable Step 2 agent."""
        rnd = self.oracle.active_round
        owned_nodes = sorted(getattr(agent, "owned_node_ids", ()))
        owned_accts = sorted(getattr(agent, "owned_accounts", (agent.agent_id,)))
        total_locked = self.oracle.total_locked_stake()
        cartel_stake = sum(n.stake_pm for n in self.oracle.nodes.values() if n.role == "cartel")
        round_info = None
        if rnd is not None:
            round_info = {
                "round_id": rnd.round_id,
                "open_hour": rnd.open_hour,
                "phase": rnd.phase,
                "phase_end_hour": rnd.phase_end_hour,
                "frozen_epsilons": dict(rnd.frozen_epsilons),
                "open_true_prices": self.round_open_true_prices(rnd),
                "p_med": dict(rnd.p_med),
                "disputed": rnd.disputed,
                "is_drastic": rnd.is_drastic,
                "committed_nodes": sorted(rnd.commits.keys()),
                "revealed_nodes": sorted(rnd.reveals.keys()),
                "court_voted_nodes": sorted(rnd.court_reveals.keys()),
            }
        return {
            "hour": hour,
            "duration_hours": self.duration_hours,
            "shock_hour": self.shock_hour,
            "true_prices": dict(self.true_prices),
            "last_finalized_prices": dict(self.oracle.last_finalized_prices),
            "branch_prices": {k: b.price for k, b in self.system.branches.items()},
            "i_oracle": peg_res.i_oracle,
            "r_price": peg_res.r_price,
            "m_spot": peg_res.m_spot,
            "e_spot": peg_res.e_spot,
            "min_borrow_rate_apr": peg_res.min_borrow_rate_apr,
            "redemption_fee": self.system.current_redemption_fee(hour),
            "circulating_pm_supply": self.system.circulating_pm_supply,
            "active_debt_pm": self.system.active_vault_debt(),
            "amm_pm_reserve": self.system.amm.pm_reserve,
            "amm_numeraire_reserve": self.system.amm.numeraire_reserve,
            "amm_fee_rate": self.system.amm.fee_rate,
            "throttle": {
                "locked_pm": throttle.locked_pm,
                "max_epoch_delta": throttle.max_epoch_delta,
                "challenge_hours": throttle.challenge_hours,
                "staker_fee_share": throttle.staker_fee_share,
                "coc_pfc_ratio": throttle.coc_pfc_ratio,
                "deficit_frac": throttle.deficit_frac,
            },
            "oracle_round": round_info,
            "dispute_bond_min_pm": self.oracle.dispute_bond_min_pm,
            "total_locked_stake_pm": total_locked,
            "cartel_stake_pm": cartel_stake,
            "balances_pm": {a: self.system.agent_pm.get(a, 0.0) for a in owned_accts},
            "balances_numeraire": {a: self.system.agent_numeraire.get(a, 0.0) for a in owned_accts},
            "node_stakes": {
                nid: {
                    "stake_pm": self.oracle.nodes[nid].stake_pm,
                    "role": self.oracle.nodes[nid].role,
                    "jailed": self.oracle.nodes[nid].jailed,
                }
                for nid in owned_nodes
                if nid in self.oracle.nodes
            },
        }

    def apply_agent_action(
        self,
        agent: Any,
        action: Any,
        hour: int,
        peg_res: PegStepResult,
        throttle: ThrottleState,
    ) -> bool:
        """Executes one validated AgentAction against simulator state with ownership checks."""
        atype = action.action_type
        params = action.params
        if atype == "NOOP":
            return True

        owned_nodes = set(getattr(agent, "owned_node_ids", ()))
        owned_accts = set(getattr(agent, "owned_accounts", (agent.agent_id,)))
        sender = str(params.get("account_id", agent.agent_id))
        if sender not in owned_accts and atype not in (
            "ORACLE_COMMIT",
            "ORACLE_REVEAL",
            "ORACLE_COURT_VOTE",
            "COVERT_SEND",
        ):
            return False

        is_cartel_agent = getattr(agent, "role", "") == "cartel"

        if atype == "ORACLE_COMMIT":
            nid = str(params["node_id"])
            if nid not in owned_nodes:
                return False
            rnd = self.oracle.active_round
            if rnd is None or rnd.phase != "COMMIT" or nid in rnd.commits:
                return False
            prices = {a: float(params["prices"][a]) for a in self.true_prices}
            salt = str(params["salt"])
            self.oracle.submit_commit(nid, prices, salt)
            if nid in rnd.commits:
                ref_px = self.round_open_true_prices(rnd)
                if is_cartel_agent and any(
                    abs(prices[a] - ref_px[a]) / ref_px[a] > 0.5 * rnd.frozen_epsilons[a]
                    for a in self.true_prices
                ):
                    self._cartel_attacked = True
                return True
            return False

        if atype == "ORACLE_REVEAL":
            nid = str(params["node_id"])
            if nid not in owned_nodes:
                return False
            rnd = self.oracle.active_round
            if rnd is None or rnd.phase != "REVEAL" or nid in rnd.reveals:
                return False
            prices = {a: float(params["prices"][a]) for a in self.true_prices}
            salt = str(params["salt"])
            ok = self.oracle.submit_reveal(nid, prices, salt)
            ref_px = self.round_open_true_prices(rnd)
            if ok and is_cartel_agent and any(
                abs(prices[a] - ref_px[a]) / ref_px[a] > 0.5 * rnd.frozen_epsilons[a]
                for a in self.true_prices
            ):
                self._cartel_attacked = True
            return ok

        if atype == "ORACLE_COURT_VOTE":
            nid = str(params["node_id"])
            if nid not in owned_nodes:
                return False
            rnd = self.oracle.active_round
            if rnd is None or rnd.phase != "COURT" or nid in rnd.court_reveals:
                return False
            prices = {a: float(params["prices"][a]) for a in self.true_prices}
            salt = str(params["salt"])
            self.oracle.submit_court_vote(nid, prices, salt)
            ref_px = self.round_open_true_prices(rnd)
            if (
                nid in rnd.court_reveals
                and is_cartel_agent
                and any(
                    abs(prices[a] - ref_px[a]) / ref_px[a] > 0.5 * rnd.frozen_epsilons[a]
                    for a in self.true_prices
                )
            ):
                self._cartel_attacked = True
            return nid in rnd.court_reveals

        if atype == "ORACLE_CHALLENGE":
            bond = float(params.get("bond_pm", self.oracle.dispute_bond_min_pm))
            if is_cartel_agent:
                self._cartel_attacked = True
            return self.challenge_oracle_round(sender, bond, hour)

        if atype == "AMM_SWAP_PM_TO_NUM":
            amt = min(float(params["pm_amount"]), self.system.agent_pm.get(sender, 0.0))
            if amt <= 1.0:
                return False
            self.system.swap_pm_for_numeraire(sender, amt)
            if is_cartel_agent:
                self._cartel_attacked = True
            return True

        if atype == "AMM_SWAP_NUM_TO_PM":
            amt = min(float(params["numeraire_amount"]), self.system.agent_numeraire.get(sender, 0.0))
            if amt <= 1.0:
                return False
            self.system.swap_numeraire_for_pm(sender, amt)
            if is_cartel_agent:
                self._cartel_attacked = True
            return True

        if atype == "REDEEM_PM":
            amt = min(
                float(params["pm_amount"]),
                self.system.agent_pm.get(sender, 0.0),
                self.system.active_vault_debt(),
            )
            if amt <= 1.0:
                return False
            receipt = self.system.redeem_pm(sender, amt, peg_res.r_price, hour, convert_to_numeraire=True)
            return receipt.pm_redeemed > 0.0

        if atype == "MINT_AND_SELL":
            vid = str(params["vault_id"])
            vault = self.system.vaults.get(vid)
            if vault is None or vault.owner not in owned_accts:
                return False
            branch = self.system.branches[vault.branch]
            max_debt = (vault.collateral_qty * branch.price) / (branch.mint_mcr * peg_res.r_price * 1.02)
            headroom = max(0.0, max_debt - vault.debt_pm)
            mint_amt = min(float(params["mint_pm"]), headroom)
            if mint_amt <= 1.0:
                return False
            rate = max(float(params.get("borrow_rate_apr", 0.06)), peg_res.min_borrow_rate_apr)
            self.system.open_or_mint_vault(
                vault.owner,
                vault.branch,
                0.0,
                mint_amt,
                rate,
                peg_res.r_price,
                peg_res.min_borrow_rate_apr,
                vault_id=vid,
            )
            self.system.swap_pm_for_numeraire(vault.owner, mint_amt)
            return True

        if atype == "LOCK_STAKE":
            nid = str(params["node_id"])
            if nid not in owned_nodes:
                return False
            return self.lock_oracle_stake(sender, nid, float(params["pm_amount"])) > 0.0

        if atype == "COVERT_SEND":
            if self.covert_channel is None:
                return False
            rnd = self.oracle.active_round
            rid = rnd.round_id if rnd is not None else None
            self.covert_channel.send(
                hour=hour,
                round_id=rid,
                sender=agent.agent_id,
                recipients=list(params["recipients"]),
                msg_type=str(params["msg_type"]),
                payload=dict(params.get("payload", {})),
            )
            return True

        if atype == "PAY_BRIBE":
            recipient = str(params["recipient_id"])
            paid = self.transfer_pm(sender, recipient, float(params["pm_amount"]))
            if paid > 0.0 and is_cartel_agent:
                self._cartel_attacked = True
            return paid > 0.0

        return False

    def run(self) -> EpisodeResult:
        cartel_init = self._cartel_wealth(1.0)
        wb_init = self._whistleblower_wealth(1.0)
        telemetry: list[TickTelemetry] = []
        max_r_over_i = 1.0

        for hour in range(self.duration_hours):
            self._apply_scheduled_shocks(hour)
            if hour > 0:
                self._apply_background_noise()
            self.price_history_by_hour[hour] = dict(self.true_prices)

            # Compute current security throttle snapshot
            locked_pm = self.oracle.total_locked_stake()
            throttle = compute_auto_throttle(
                locked_pm=locked_pm,
                amm_liquidity_pm=self.system.amm.liquidity_pm_equiv,
                total_pm_supply=self.system.circulating_pm_supply,
                k_pfc=self.k_pfc,
            )

            # Accrue hourly vault interest + liquidate any underwater branches
            self.system.accrue_hourly_interest(
                throttle=throttle,
                min_borrow_rate_apr=self.peg_controller.min_borrow_rate_apr,
                dt_years=1.0 / 8760.0,
            )
            for bname in self.system.branches:
                self.system.liquidate_branch(bname, self.peg_controller.r_price)

            # Start new oracle round when idle and cadence matches
            if (
                (self.oracle.active_round is None or self.oracle.active_round.phase == "FINALIZED")
                and hour % self.round_interval_hours == 0
            ):
                self.oracle.start_round(hour)

            # Advance oracle state deadlines first, then allow strategies to submit commits/reveals/challenges
            self._settle_oracle_events(throttle, hour)

            i_oracle = self.basket.index(self.oracle.last_finalized_prices)
            i_true = self.basket.index(self.true_prices)
            peg_res = self.peg_controller.step(i_oracle, self.system.amm.spot_price, dt_days=1.0 / 24.0)
            max_r_over_i = max(max_r_over_i, peg_res.r_price / max(1e-9, i_oracle))

            ctx = BotContext(
                hour=hour,
                rng=self.rng,
                true_prices=dict(self.true_prices),
                system=self.system,
                oracle=self.oracle,
                peg=peg_res,
                throttle=throttle,
                config=self.config,
                round_open_true_prices=self.round_open_true_prices(self.oracle.active_round),
            )

            if self.custom_agents and self.replace_default_bots:
                for agent in self.custom_agents:
                    obs = self.build_agent_observation(agent, hour, peg_res, throttle)
                    inbox = (
                        self.covert_channel.poll(agent.agent_id)
                        if self.covert_channel is not None
                        else []
                    )
                    actions = agent.decide(obs, inbox, self.rng)
                    for act in actions:
                        self.apply_agent_action(agent, act, hour, peg_res, throttle)
                self.dynamic_staker.step(ctx)
            else:
                self.oracle_strategy.step(ctx)
                if self.whistleblower_bot is not None:
                    self.whistleblower_bot.step(ctx)
                if self.whale_bot is not None:
                    self.whale_bot.step(ctx)
                if self.hostile_bot is not None:
                    self.hostile_bot.step(ctx)
                self.dynamic_staker.step(ctx)
                self.arb_bot.step(ctx)
                for agent in self.custom_agents:
                    obs = self.build_agent_observation(agent, hour, peg_res, throttle)
                    inbox = (
                        self.covert_channel.poll(agent.agent_id)
                        if self.covert_channel is not None
                        else []
                    )
                    for act in agent.decide(obs, inbox, self.rng):
                        self.apply_agent_action(agent, act, hour, peg_res, throttle)

            # Recompute throttle & assert strict conservation invariants every hour
            locked_after = self.oracle.total_locked_stake()
            self.system.assert_conservation(locked_after)
            throttle_after = compute_auto_throttle(
                locked_pm=locked_after,
                amm_liquidity_pm=self.system.amm.liquidity_pm_equiv,
                total_pm_supply=self.system.circulating_pm_supply,
                k_pfc=self.k_pfc,
            )

            m_spot = self.system.amm.spot_price
            e_spot_true = (i_true - m_spot) / i_true
            e_spot_oracle = (i_oracle - m_spot) / i_oracle

            telemetry.append(
                TickTelemetry(
                    hour=hour,
                    i_true=i_true,
                    i_oracle=i_oracle,
                    r_price=peg_res.r_price,
                    m_spot=m_spot,
                    e_spot_true=e_spot_true,
                    e_spot_oracle=e_spot_oracle,
                    min_borrow_rate_apr=peg_res.min_borrow_rate_apr,
                    circulating_pm_supply=self.system.circulating_pm_supply,
                    active_debt_pm=self.system.active_vault_debt(),
                    locked_pm=locked_after,
                    coc_51_pm=throttle_after.coc_51_pm,
                    pfc_effective_pm=throttle_after.pfc_effective_pm,
                    coc_pfc_ratio=throttle_after.coc_pfc_ratio,
                    max_epoch_delta=throttle_after.max_epoch_delta,
                    challenge_hours=throttle_after.challenge_hours,
                    staker_fee_share=throttle_after.staker_fee_share,
                    unbacked_bad_debt_pm=self.system.unbacked_bad_debt_pm,
                )
            )

        last = telemetry[-1]
        max_abs_err = max(abs(t.e_spot_true) for t in telemetry)
        post_shock = [t for t in telemetry if t.hour >= self.shock_hour]
        post_shock_max = max(abs(t.e_spot_true) for t in post_shock) if post_shock else max_abs_err

        day14_hour = min(self.duration_hours - 1, self.shock_hour + 336)
        day14_err = abs(telemetry[day14_hour].e_spot_true)

        # Compute earliest hour post-shock after which |e_spot_true| remains < 2% through day 14
        window_14d = [t for t in telemetry if self.shock_hour <= t.hour <= day14_hour]
        recovery_hours: int | None = None
        if window_14d:
            for idx, item in enumerate(window_14d):
                if all(abs(x.e_spot_true) < 0.02 for x in window_14d[idx:]):
                    recovery_hours = item.hour - self.shock_hour
                    break
        restored_14d = recovery_hours is not None and day14_err < 0.02

        cartel_final = self._cartel_wealth(last.r_price)
        wb_final = self._whistleblower_wealth(last.r_price)
        cartel_roi = 0.0 if cartel_init <= 1e-9 else (cartel_final - cartel_init) / cartel_init
        wb_roi = 0.0 if wb_init <= 1e-9 else (wb_final - wb_init) / wb_init

        eth_b = self.system.branches["ETH"]
        btc_b = self.system.branches["BTC"]
        sol_b = self.system.branches["SOL"]
        eth_btc_bad = (
            eth_b.total_redistributed_debt_pm
            + eth_b.unbacked_bad_debt_pm
            + btc_b.total_redistributed_debt_pm
            + btc_b.unbacked_bad_debt_pm
        )

        summary = EpisodeSummary(
            scenario_name=str(self.config.get("name", "unnamed")),
            seed=self.seed,
            duration_hours=self.duration_hours,
            shock_hour=self.shock_hour,
            peg_mode=self.peg_controller.mode,
            final_i_true=last.i_true,
            final_i_oracle=last.i_oracle,
            final_r_price=last.r_price,
            final_m_spot=last.m_spot,
            final_abs_peg_error=abs(last.e_spot_true),
            max_abs_peg_error=max_abs_err,
            post_shock_max_abs_peg_error=post_shock_max,
            peg_error_at_day14_after_shock=day14_err,
            restored_within_14_days=restored_14d,
            recovery_hours_after_shock=recovery_hours,
            max_r_over_i_observed=max_r_over_i,
            unbacked_bad_debt_pm=self.system.unbacked_bad_debt_pm,
            eth_btc_redistributed_or_bad_debt=eth_btc_bad,
            sol_sp_offset_pm=sol_b.total_sp_offset_pm,
            sol_insurance_offset_pm=sol_b.total_insurance_offset_pm,
            sol_redistributed_pm=sol_b.total_redistributed_debt_pm,
            min_coc_pfc_ratio=min(t.coc_pfc_ratio for t in telemetry),
            max_staker_fee_share=max(t.staker_fee_share for t in telemetry),
            cartel_initial_wealth=cartel_init,
            cartel_final_wealth=cartel_final,
            cartel_net_roi=cartel_roi,
            whistleblower_initial_wealth=wb_init,
            whistleblower_final_wealth=wb_final,
            whistleblower_net_roi=wb_roi,
            cumulative_vault_mints_pm=self.system.cumulative_vault_mints_pm,
            cumulative_vault_burns_pm=self.system.cumulative_vault_burns_pm,
            cumulative_slash_burned_pm=self.system.cumulative_slash_burned_pm,
            total_oracle_rounds_finalized=len(self.oracle.history),
            total_disputes=sum(1 for h in self.oracle.history if h.was_disputed),
            max_oracle_manipulation_error=self._max_oracle_manipulation_error,
            cartel_attacked=self._cartel_attacked,
        )
        return EpisodeResult(summary=summary, telemetry=telemetry, config=self.config)


def load_scenario_config(scenario_path: str | Path) -> dict[str, Any]:
    with open(scenario_path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"invalid scenario YAML at {scenario_path}")
    return data


def _deep_merge(base: dict[str, Any], patch: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for k, v in patch.items():
        if isinstance(v, Mapping) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def run_episode(
    scenario_path: str | Path,
    seed: int = 42,
    overrides: Mapping[str, Any] | None = None,
) -> EpisodeResult:
    cfg = load_scenario_config(scenario_path)
    if overrides:
        cfg = _deep_merge(cfg, overrides)
    return SimulationEnv(cfg, seed=seed).run()
