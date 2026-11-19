"""Deterministic baseline and adversarial bot strategies for Phase 2 Step 1."""

from __future__ import annotations

from dataclasses import dataclass, field
import random
from typing import Mapping

from .amm_and_vaults import VaultAndAmmSystem
from .oracle_market import OracleMarket, OracleNode
from .peg_controller import PegStepResult, ThrottleState


@dataclass
class BotContext:
    hour: int
    rng: random.Random
    true_prices: dict[str, float]
    system: VaultAndAmmSystem
    oracle: OracleMarket
    peg: PegStepResult
    throttle: ThrottleState
    config: Mapping[str, object]


class ArbitrageurBot:
    """Maintains ceiling (mint+sell) and floor (buy+hard-redeem) arbitrage against R(t)."""

    def __init__(self, agent_id: str = "arb", arb_vault_id: str = "V_ARB_ETH", borrow_rate_apr: float = 0.06) -> None:
        self.agent_id = agent_id
        self.arb_vault_id = arb_vault_id
        self.borrow_rate_apr = borrow_rate_apr
        self.total_redeemed_pm = 0.0
        self.total_minted_pm = 0.0

    def step(self, ctx: BotContext) -> None:
        sys = ctx.system
        r_px = ctx.peg.r_price
        f_redeem = sys.current_redemption_fee(ctx.hour)
        eff_floor = r_px * (1.0 - f_redeem)

        # Floor arb: buy PM on AMM and hard-redeem when M(t) < R(t) * (1 - f_redeem) * (1 - fee)
        opt_num = sys.amm.optimal_numeraire_in_for_target_price(eff_floor)
        avail_num = sys.agent_numeraire.get(self.agent_id, 0.0)
        # Do not buy more PM than vaults can redeem across active debt
        active_debt = sys.active_vault_debt()
        spend_num = min(opt_num, avail_num, 0.85 * active_debt * eff_floor)
        if spend_num > 1.0:
            pm_bought = sys.swap_numeraire_for_pm(self.agent_id, spend_num)
            receipt = sys.redeem_pm(
                self.agent_id,
                pm_bought,
                r_px,
                ctx.hour,
                convert_to_numeraire=True,
            )
            self.total_redeemed_pm += receipt.pm_redeemed
            # If excess PM remained unredeemed (capped), sell it back or keep as small inventory.
            return

        # Ceiling arb: mint PM at R(t) and sell on AMM when M(t) * (1 - swap_fee) > R(t)
        opt_pm = sys.amm.optimal_pm_in_for_target_price(r_px)
        if opt_pm > 1.0:
            vault = sys.vaults.get(self.arb_vault_id)
            if vault is not None:
                branch = sys.branches[vault.branch]
                max_debt = (vault.collateral_qty * branch.price) / (branch.mint_mcr * r_px * 1.02)
                headroom = max(0.0, max_debt - vault.debt_pm)
                mint_amt = min(opt_pm, headroom)
                rate = max(self.borrow_rate_apr, ctx.peg.min_borrow_rate_apr)
                if mint_amt > 1.0:
                    sys.open_or_mint_vault(
                        self.agent_id,
                        vault.branch,
                        0.0,
                        mint_amt,
                        rate,
                        r_px,
                        ctx.peg.min_borrow_rate_apr,
                        vault_id=self.arb_vault_id,
                    )
                    self.total_minted_pm += mint_amt
                    sys.swap_pm_for_numeraire(self.agent_id, mint_amt)


class DynamicStakerBot:
    """Locks additional unshielded PM into oracle/court pool when yield rises under low stake."""

    def __init__(self, staker_agent_id: str = "dynamic_staker", node_id: str = "honest_dynamic") -> None:
        self.staker_agent_id = staker_agent_id
        self.node_id = node_id
        self.locked_total = 0.0

    def step(self, ctx: BotContext) -> None:
        sys = ctx.system
        node = ctx.oracle.nodes.get(self.node_id)
        if node is None:
            return
        avail = sys.agent_pm.get(self.staker_agent_id, 0.0)
        if avail <= 1.0:
            return
        # When CoC_51 < 3.0 * PfC_unthrottled (deficit_frac > 0), elevated staker_fee_share draws lockups in
        if ctx.throttle.deficit_frac > 0.01:
            needed = max(0.0, (3.05 * ctx.throttle.pfc_unthrottled_pm / 0.51) - ctx.oracle.total_locked_stake())
            # Realistic gradual lockup rate (up to 10% of deficit per hour, capped at available liquid PM)
            add = min(avail, max(0.0, 0.12 * needed))
            if add > 1.0:
                sys.agent_pm[self.staker_agent_id] -= add
                node.stake_pm += add
                self.locked_total += add


class WhistleblowerBot:
    """Challenges any oracle median deviating materially from observable true market prices."""

    def __init__(
        self,
        agent_id: str = "whistleblower",
        dispute_bond_pm: float = 5000.0,
        deviation_threshold: float = 0.012,
    ) -> None:
        self.agent_id = agent_id
        self.dispute_bond_pm = dispute_bond_pm
        self.deviation_threshold = deviation_threshold
        self.challenges_launched = 0

    def step(self, ctx: BotContext) -> None:
        rnd = ctx.oracle.active_round
        if rnd is None or rnd.phase != "CHALLENGE" or rnd.disputed:
            return
        max_dev = max(
            abs(rnd.p_med[a] - ctx.true_prices[a]) / ctx.true_prices[a]
            for a in ctx.true_prices
        )
        if max_dev > self.deviation_threshold:
            avail = ctx.system.agent_pm.get(self.agent_id, 0.0)
            if avail >= self.dispute_bond_pm:
                ctx.system.agent_pm[self.agent_id] -= self.dispute_bond_pm
                ctx.system.pending_dispute_bonds_pm += self.dispute_bond_pm
                ctx.oracle.challenge_round(self.agent_id, self.dispute_bond_pm, ctx.hour)
                self.challenges_launched += 1


class OracleParticipantStrategy:
    """Drives commits, reveals, and 48h court votes for honest and cartel oracle nodes."""

    def __init__(
        self,
        cartel_bias_by_asset: Mapping[str, float] | None = None,
        cartel_outlier_sybil_bias: float = 0.0,
        attack_start_hour: int = 0,
        attack_end_hour: int = 10_000,
        cartel_trader_id: str = "cartel_trader",
        honest_outage_rounds: list[int] | None = None,
        outage_first_attack_round: bool = False,
    ) -> None:
        self.cartel_bias_by_asset = dict(cartel_bias_by_asset or {})
        self.cartel_outlier_sybil_bias = cartel_outlier_sybil_bias
        self.attack_start_hour = attack_start_hour
        self.attack_end_hour = attack_end_hour
        self.cartel_trader_id = cartel_trader_id
        self.honest_outage_rounds = set(int(r) for r in (honest_outage_rounds or []))
        self.outage_first_attack_round = outage_first_attack_round
        self._outage_triggered_round: int | None = None
        self._round_quotes: dict[int, dict[str, tuple[dict[str, float], str]]] = {}
        self._traded_rounds: set[int] = set()

    def _build_quote(self, node: OracleNode, ctx: BotContext, round_id: int) -> dict[str, float]:
        attack_active = self.attack_start_hour <= ctx.hour <= self.attack_end_hour
        if node.role == "cartel" and attack_active:
            if self.cartel_outlier_sybil_bias != 0.0 and node.node_id.endswith("_outlier"):
                return {
                    a: px * (1.0 + self.cartel_outlier_sybil_bias)
                    for a, px in ctx.true_prices.items()
                }
            return {
                a: px * (1.0 + self.cartel_bias_by_asset.get(a, 0.0))
                for a, px in ctx.true_prices.items()
            }
        # Honest / whistleblower reporters quote true prices with tiny observational jitter (< 0.04%)
        return {
            a: px * (1.0 + ctx.rng.uniform(-0.0004, 0.0004))
            for a, px in ctx.true_prices.items()
        }

    def step(self, ctx: BotContext) -> None:
        rnd = ctx.oracle.active_round
        if rnd is None:
            return

        if rnd.phase == "COMMIT":
            attack_active = self.attack_start_hour <= ctx.hour <= self.attack_end_hour
            if self.outage_first_attack_round and attack_active and self._outage_triggered_round is None:
                self._outage_triggered_round = rnd.round_id
            outage_now = rnd.round_id in self.honest_outage_rounds or (
                self._outage_triggered_round == rnd.round_id
            )
            quotes = self._round_quotes.setdefault(rnd.round_id, {})
            for node in ctx.oracle.active_reporter_nodes():
                if outage_now and node.role == "honest" and node.node_id == "honest_1":
                    continue
                if node.node_id not in rnd.commits:
                    px_map = self._build_quote(node, ctx, rnd.round_id)
                    salt = f"salt_{rnd.round_id}_{node.node_id}"
                    quotes[node.node_id] = (px_map, salt)
                    ctx.oracle.submit_commit(node.node_id, px_map, salt)

            # Cartel trader takes a front-running position against its own manipulated direction
            attack_active = self.attack_start_hour <= ctx.hour <= self.attack_end_hour
            if self.cartel_bias_by_asset and attack_active and rnd.round_id not in self._traded_rounds:
                self._traded_rounds.add(rnd.round_id)
                net_bias = sum(self.cartel_bias_by_asset.values()) / max(1, len(self.cartel_bias_by_asset))
                if net_bias > 0.01:
                    avail_num = ctx.system.agent_numeraire.get(self.cartel_trader_id, 0.0)
                    trade_num = min(avail_num * 0.25, 10_000.0)
                    if trade_num > 10.0:
                        ctx.system.swap_numeraire_for_pm(self.cartel_trader_id, trade_num)
                elif net_bias < -0.01:
                    avail_pm = ctx.system.agent_pm.get(self.cartel_trader_id, 0.0)
                    trade_pm = min(avail_pm * 0.25, 10_000.0)
                    if trade_pm > 10.0:
                        ctx.system.swap_pm_for_numeraire(self.cartel_trader_id, trade_pm)
        elif rnd.phase == "REVEAL":
            quotes = self._round_quotes.get(rnd.round_id, {})
            for node in ctx.oracle.active_reporter_nodes():
                if node.node_id not in rnd.reveals and node.node_id in quotes:
                    px_map, salt = quotes[node.node_id]
                    ctx.oracle.submit_reveal(node.node_id, px_map, salt)
        elif rnd.phase == "COURT":
            for node in ctx.oracle.court_voter_nodes():
                if node.node_id not in rnd.court_reveals:
                    # 2-year locked court voters vote true market value if honest, biased if cartel
                    px_map = self._build_quote(node, ctx, rnd.round_id)
                    salt = f"court_{rnd.round_id}_{node.node_id}"
                    ctx.oracle.submit_court_vote(node.node_id, px_map, salt)


class WhaleBankRunBot:
    """Executes a coordinated PM dump wave against the AMM starting at `start_hour`."""

    def __init__(
        self,
        agent_id: str = "whale_seller",
        start_hour: int = 48,
        wave_hours: int = 8,
    ) -> None:
        self.agent_id = agent_id
        self.start_hour = start_hour
        self.wave_hours = max(1, wave_hours)
        self.total_dumped_pm = 0.0
        self._remaining_hours_scheduled = False
        self._per_hour_dump = 0.0

    def step(self, ctx: BotContext) -> None:
        if ctx.hour < self.start_hour or ctx.hour >= self.start_hour + self.wave_hours:
            return
        avail_pm = ctx.system.agent_pm.get(self.agent_id, 0.0)
        if not self._remaining_hours_scheduled:
            self._per_hour_dump = avail_pm / self.wave_hours
            self._remaining_hours_scheduled = True
        sell_amt = min(avail_pm, self._per_hour_dump * 1.05)
        if sell_amt > 1.0:
            ctx.system.swap_pm_for_numeraire(self.agent_id, sell_amt)
            self.total_dumped_pm += sell_amt


class HostileStateShortBot:
    """Repeatedly dumps PM onto thin AMM spots to spoof e_spot while attempting redemptions & bribes."""

    def __init__(
        self,
        agent_id: str = "hostile_state",
        start_hour: int = 48,
        end_hour: int = 240,
        dump_interval_hours: int = 12,
        dump_pm_amount: float = 25_000.0,
    ) -> None:
        self.agent_id = agent_id
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.dump_interval_hours = dump_interval_hours
        self.dump_pm_amount = dump_pm_amount
        self.max_r_over_i_observed = 0.0
        self.numeraire_spent = 0.0
        self.numeraire_recovered = 0.0

    def step(self, ctx: BotContext) -> None:
        r_over_i = ctx.peg.r_price / max(1e-9, ctx.peg.i_oracle)
        if r_over_i > self.max_r_over_i_observed:
            self.max_r_over_i_observed = r_over_i

        if not (self.start_hour <= ctx.hour <= self.end_hour):
            return
        if (ctx.hour - self.start_hour) % self.dump_interval_hours == 0:
            avail_pm = ctx.system.agent_pm.get(self.agent_id, 0.0)
            sell = min(avail_pm, self.dump_pm_amount)
            if sell > 1.0:
                num_out = ctx.system.swap_pm_for_numeraire(self.agent_id, sell)
                self.numeraire_recovered += num_out
                # Try to exploit depressed M(t) by buying cheap PM + hard-redeeming if profitable
                opt_num = ctx.system.amm.optimal_numeraire_in_for_target_price(ctx.peg.r_price)
                buy_num = min(opt_num, ctx.system.agent_numeraire.get(self.agent_id, 0.0) * 0.5)
                if buy_num > 10.0:
                    self.numeraire_spent += buy_num
                    pm_back = ctx.system.swap_numeraire_for_pm(self.agent_id, buy_num)
                    receipt = ctx.system.redeem_pm(
                        self.agent_id,
                        pm_back,
                        ctx.peg.r_price,
                        ctx.hour,
                        convert_to_numeraire=True,
                    )
                    self.numeraire_recovered += receipt.collateral_numeraire_received
