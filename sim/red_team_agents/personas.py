"""Six adversarial & defensive red-team personas using strict JSON actions + covert collusion."""

from __future__ import annotations

import random
from typing import Any

from .base_agent import AgentAction, BaseRedTeamAgent, LLMBackendConfig
from .covert_channel import CovertMessage


def _oracle_commit_and_reveal(
    rnd: dict[str, Any],
    node_id: str,
    prices: dict[str, float],
    salt_cache: dict[tuple[int, str], tuple[dict[str, float], str]],
    salt_tag: str,
) -> AgentAction | None:
    rid = int(rnd["round_id"])
    phase = str(rnd["phase"])
    if phase == "COMMIT" and node_id not in rnd["committed_nodes"]:
        salt = f"{salt_tag}_{rid}_{node_id}"
        px_copy = {a: float(v) for a, v in prices.items()}
        salt_cache[(rid, node_id)] = (px_copy, salt)
        return AgentAction(
            "ORACLE_COMMIT",
            {"node_id": node_id, "prices": px_copy, "salt": salt},
        )
    if phase == "REVEAL" and node_id not in rnd["revealed_nodes"] and (rid, node_id) in salt_cache:
        px_copy, salt = salt_cache[(rid, node_id)]
        return AgentAction(
            "ORACLE_REVEAL",
            {"node_id": node_id, "prices": px_copy, "salt": salt},
        )
    return None


class HonestOracleEnsembleAgent(BaseRedTeamAgent):
    """Coordinates honest stakers across COMMIT, REVEAL, and 48h COURT blind votes."""

    def __init__(
        self,
        owned_node_ids: tuple[str, ...],
        *,
        outage_first_attack_round: bool = False,
        attack_start_hour: int = 48,
        outage_node_id: str = "honest_1",
        cold_court_only_nodes: tuple[str, ...] = (),
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(
            agent_id="honest_ensemble",
            role="honest",
            owned_node_ids=owned_node_ids,
            llm_config=llm_config,
        )
        self.outage_first_attack_round = outage_first_attack_round
        self.attack_start_hour = attack_start_hour
        self.outage_node_id = outage_node_id
        self.cold_court_only_nodes = set(cold_court_only_nodes)
        self._outage_round_id: int | None = None
        self._quotes: dict[tuple[int, str], tuple[dict[str, float], str]] = {}

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        rnd = obs.get("oracle_round")
        if rnd is None:
            return [AgentAction("NOOP")]

        hour = int(obs["hour"])
        rid = int(rnd["round_id"])
        phase = str(rnd["phase"])
        true_px: dict[str, float] = obs["true_prices"]

        if (
            self.outage_first_attack_round
            and phase == "COMMIT"
            and hour >= self.attack_start_hour
            and self._outage_round_id is None
        ):
            self._outage_round_id = rid

        actions: list[AgentAction] = []
        for nid in self.owned_node_ids:
            info = obs["node_stakes"].get(nid)
            if info is None or info["jailed"] or info["stake_pm"] <= 0.0:
                continue
            if phase in ("COMMIT", "REVEAL"):
                if nid in self.cold_court_only_nodes:
                    continue
                if rid == self._outage_round_id and nid == self.outage_node_id:
                    continue
                noisy = {a: px * (1.0 + rng.uniform(-0.0003, 0.0003)) for a, px in true_px.items()}
                act = _oracle_commit_and_reveal(rnd, nid, noisy, self._quotes, "honest")
                if act is not None:
                    actions.append(act)
            elif phase == "COURT" and nid not in rnd["court_voted_nodes"]:
                court_ref = rnd.get("open_true_prices") or true_px
                vote_px = {a: px * (1.0 + rng.uniform(-0.0002, 0.0002)) for a, px in court_ref.items()}
                actions.append(
                    AgentAction(
                        "ORACLE_COURT_VOTE",
                        {"node_id": nid, "prices": vote_px, "salt": f"hcourt_{rid}_{nid}"},
                    )
                )
        return actions or [AgentAction("NOOP")]


class OracleCartelAgent(BaseRedTeamAgent):
    """Adaptive colluding cartel testing aggressive, stealth boiling-frog, bribe, grief & capitulation."""

    def __init__(
        self,
        owned_node_ids: tuple[str, ...],
        *,
        strategy: str = "aggressive_lie",
        attack_bias: float = 0.10,
        outlier_sybil_bias: float = 0.45,
        attack_start_hour: int = 48,
        attack_end_hour: int = 360,
        bribe_offer_pm: float = 12_000.0,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(
            agent_id="cartel",
            role="cartel",
            owned_node_ids=owned_node_ids,
            owned_accounts=("cartel", "cartel_trader", *owned_node_ids),
            llm_config=llm_config,
            persona_prompt=(
                "You are an adversarial Oracle Cartel maximizing profit via coordinated oracle "
                "manipulation, bribes, or spot front-running. Output strict JSON actions."
            ),
        )
        self.strategy = strategy
        self.attack_bias = attack_bias
        self.outlier_sybil_bias = outlier_sybil_bias
        self.attack_start_hour = attack_start_hour
        self.attack_end_hour = attack_end_hour
        self.bribe_offer_pm = bribe_offer_pm
        self.capitulated = False
        self._initial_stake: float | None = None
        self._quotes: dict[tuple[int, str], tuple[dict[str, float], str]] = {}
        self._traded_rounds: set[int] = set()
        self._bribed_rounds: set[int] = set()
        self._grief_rounds: set[int] = set()

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        hour = int(obs["hour"])
        rnd = obs.get("oracle_round")
        true_px: dict[str, float] = obs["true_prices"]
        cur_stake = sum(info["stake_pm"] for info in obs["node_stakes"].values())
        if self._initial_stake is None:
            self._initial_stake = cur_stake

        # Check adaptive capitulation trigger if previously slashed or defeated in court
        if self.strategy == "adaptive_capitulate" and cur_stake + 1e-6 < self._initial_stake:
            self.capitulated = True

        actions: list[AgentAction] = []
        swing_accepted = False
        for msg in covert_inbox:
            if msg.msg_type == "BRIBE_ACCEPT":
                swing_accepted = True

        if swing_accepted and not self.capitulated:
            avail_pm = obs["balances_pm"].get("cartel_trader", 0.0)
            pay = min(avail_pm, self.bribe_offer_pm)
            if pay > 1.0:
                actions.append(
                    AgentAction(
                        "PAY_BRIBE",
                        {"account_id": "cartel_trader", "recipient_id": "swing_voter", "pm_amount": pay},
                    )
                )

        if rnd is None:
            return actions or [AgentAction("NOOP")]

        rid = int(rnd["round_id"])
        phase = str(rnd["phase"])
        attack_window = (self.attack_start_hour <= hour <= self.attack_end_hour) and not self.capitulated

        # Compute attack quote factor per strategy
        if not attack_window:
            bias = 0.0
        elif self.strategy == "stealth_boiling_frog":
            avg_eps = sum(rnd["frozen_epsilons"].values()) / max(1, len(rnd["frozen_epsilons"]))
            # Probe right inside naive 1.2% thresholds yet outside frozen epsilon
            bias = max(1.15 * avg_eps, min(0.011, 1.85 * avg_eps))
        elif self.strategy == "liveness_grief_spam":
            bias = 0.0
        else:
            bias = self.attack_bias

        if phase == "COMMIT":
            if attack_window and self.strategy == "bribe_swing_voter" and rid not in self._bribed_rounds:
                self._bribed_rounds.add(rid)
                actions.append(
                    AgentAction(
                        "COVERT_SEND",
                        {
                            "recipients": ["swing_voter"],
                            "msg_type": "BRIBE_OFFER",
                            "payload": {"bribe_pm": self.bribe_offer_pm, "target_bias": bias},
                        },
                    )
                )
            if attack_window and abs(bias) > 0.005 and rid not in self._traded_rounds:
                self._traded_rounds.add(rid)
                if bias > 0.0:
                    num = obs["balances_numeraire"].get("cartel_trader", 0.0)
                    trade = min(num * 0.25, 10_000.0)
                    if trade > 10.0:
                        actions.append(
                            AgentAction(
                                "AMM_SWAP_NUM_TO_PM",
                                {"account_id": "cartel_trader", "numeraire_amount": trade},
                            )
                        )
                else:
                    pm_bal = obs["balances_pm"].get("cartel_trader", 0.0)
                    trade = min(pm_bal * 0.25, 10_000.0)
                    if trade > 10.0:
                        actions.append(
                            AgentAction(
                                "AMM_SWAP_PM_TO_NUM",
                                {"account_id": "cartel_trader", "pm_amount": trade},
                            )
                        )

            for nid in self.owned_node_ids:
                info = obs["node_stakes"].get(nid)
                if info is None or info["jailed"] or info["stake_pm"] <= 0.0:
                    continue
                if nid.endswith("_outlier") and attack_window and self.outlier_sybil_bias != 0.0 and self.strategy == "aggressive_lie":
                    q = {a: px * (1.0 + self.outlier_sybil_bias) for a, px in true_px.items()}
                else:
                    q = {a: px * (1.0 + bias) for a, px in true_px.items()}
                act = _oracle_commit_and_reveal(rnd, nid, q, self._quotes, "cartel")
                if act is not None:
                    actions.append(act)

        elif phase == "REVEAL":
            for nid in self.owned_node_ids:
                info = obs["node_stakes"].get(nid)
                if info is None or info["jailed"] or info["stake_pm"] <= 0.0:
                    continue
                if attack_window and self.strategy == "liveness_grief_spam":
                    # Grief reveal by withholding reveal on core node to burn 10% no-reveal slash testing liveness
                    if nid.endswith("_1") or nid == self.owned_node_ids[0]:
                        continue
                q = {a: px * (1.0 + bias) for a, px in true_px.items()}
                act = _oracle_commit_and_reveal(rnd, nid, q, self._quotes, "cartel")
                if act is not None:
                    actions.append(act)

        elif phase == "CHALLENGE":
            if (
                attack_window
                and self.strategy == "liveness_grief_spam"
                and not rnd["disputed"]
                and rid not in self._grief_rounds
            ):
                avail = obs["balances_pm"].get("cartel_trader", 0.0)
                bond = float(obs["dispute_bond_min_pm"])
                if avail >= bond:
                    self._grief_rounds.add(rid)
                    actions.append(
                        AgentAction(
                            "ORACLE_CHALLENGE",
                            {"account_id": "cartel_trader", "bond_pm": bond},
                        )
                    )

        elif phase == "COURT":
            court_ref = rnd.get("open_true_prices") or true_px
            for nid in self.owned_node_ids:
                info = obs["node_stakes"].get(nid)
                if info is None or info["jailed"] or info["stake_pm"] <= 0.0:
                    continue
                if nid not in rnd["court_voted_nodes"]:
                    q = {a: px * (1.0 + bias) for a, px in court_ref.items()}
                    actions.append(
                        AgentAction(
                            "ORACLE_COURT_VOTE",
                            {"node_id": nid, "prices": q, "salt": f"ccourt_{rid}_{nid}"},
                        )
                    )

        return actions or [AgentAction("NOOP")]


class HonestWhistleblowerAgent(BaseRedTeamAgent):
    """Polices oracle medians using 1.05 * frozen_epsilon trigger and covert defection tips."""

    def __init__(
        self,
        *,
        owned_node_ids: tuple[str, ...] = ("whistleblower",),
        use_epsilon_trigger: bool = True,
        epsilon_multiplier: float = 1.05,
        naive_threshold: float = 0.012,
        dispute_bond_pm: float = 5000.0,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(
            agent_id="whistleblower",
            role="whistleblower",
            owned_node_ids=owned_node_ids,
            owned_accounts=("whistleblower", *owned_node_ids),
            llm_config=llm_config,
        )
        self.use_epsilon_trigger = use_epsilon_trigger
        self.epsilon_multiplier = epsilon_multiplier
        self.naive_threshold = naive_threshold
        self.dispute_bond_pm = dispute_bond_pm
        self.challenges_launched = 0
        self._quotes: dict[tuple[int, str], tuple[dict[str, float], str]] = {}
        self._defection_tip_rounds: set[int] = set()

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        for msg in covert_inbox:
            if msg.msg_type == "BRIBE_DEFECT_WHISTLEBLOW" and msg.round_id is not None:
                self._defection_tip_rounds.add(int(msg.round_id))

        rnd = obs.get("oracle_round")
        if rnd is None:
            return [AgentAction("NOOP")]

        rid = int(rnd["round_id"])
        phase = str(rnd["phase"])
        true_px: dict[str, float] = obs["true_prices"]
        actions: list[AgentAction] = []

        if phase in ("COMMIT", "REVEAL"):
            for nid in self.owned_node_ids:
                info = obs["node_stakes"].get(nid)
                if info is not None and not info["jailed"] and info["stake_pm"] > 0.0:
                    noisy = {a: px * (1.0 + rng.uniform(-0.0002, 0.0002)) for a, px in true_px.items()}
                    act = _oracle_commit_and_reveal(rnd, nid, noisy, self._quotes, "wb")
                    if act is not None:
                        actions.append(act)

        elif phase == "CHALLENGE" and not rnd["disputed"]:
            ref_px = rnd.get("open_true_prices") or true_px
            trigger = False
            for asset, tpx in ref_px.items():
                rel_dev = abs(rnd["p_med"][asset] - tpx) / tpx
                limit = (
                    self.epsilon_multiplier * rnd["frozen_epsilons"][asset]
                    if self.use_epsilon_trigger
                    else self.naive_threshold
                )
                if rel_dev > limit:
                    trigger = True
                    break
                if rid in self._defection_tip_rounds and rel_dev > 0.85 * rnd["frozen_epsilons"][asset]:
                    trigger = True
                    break
            if trigger and obs["balances_pm"].get("whistleblower", 0.0) >= self.dispute_bond_pm:
                self.challenges_launched += 1
                actions.append(AgentAction("ORACLE_CHALLENGE", {"bond_pm": self.dispute_bond_pm}))

        elif phase == "COURT":
            court_ref = rnd.get("open_true_prices") or true_px
            for nid in self.owned_node_ids:
                info = obs["node_stakes"].get(nid)
                if info is not None and not info["jailed"] and info["stake_pm"] > 0.0:
                    if nid not in rnd["court_voted_nodes"]:
                        actions.append(
                            AgentAction(
                                "ORACLE_COURT_VOTE",
                                {"node_id": nid, "prices": dict(court_ref), "salt": f"wbcourt_{rid}_{nid}"},
                            )
                        )
        return actions or [AgentAction("NOOP")]


class GreedyWhaleAgent(BaseRedTeamAgent):
    """Rational swing voter evaluating Bribe EV vs 20% Defection Bounty, plus whale dump waves."""

    def __init__(
        self,
        *,
        swing_node_id: str = "swing_voter",
        whale_account_id: str = "whale_seller",
        owned_node_ids: tuple[str, ...] = ("swing_voter",),
        irrational_accept: bool = False,
        bank_run_enabled: bool = False,
        bank_run_start_hour: int = 48,
        bank_run_wave_hours: int = 8,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(
            agent_id=swing_node_id,
            role="whale_swing",
            owned_node_ids=owned_node_ids,
            owned_accounts=(swing_node_id, whale_account_id),
            llm_config=llm_config,
        )
        self.swing_node_id = swing_node_id
        self.whale_account_id = whale_account_id
        self.irrational_accept = irrational_accept
        self.bank_run_enabled = bank_run_enabled
        self.bank_run_start_hour = bank_run_start_hour
        self.bank_run_wave_hours = max(1, bank_run_wave_hours)
        self._quotes: dict[tuple[int, str], tuple[dict[str, float], str]] = {}
        self._accepted_rounds: dict[int, float] = {}
        self._per_hour_dump: float | None = None

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        hour = int(obs["hour"])
        rnd = obs.get("oracle_round")
        true_px: dict[str, float] = obs["true_prices"]
        actions: list[AgentAction] = []

        # Bank run dump wave if enabled
        if self.bank_run_enabled and self.bank_run_start_hour <= hour < self.bank_run_start_hour + self.bank_run_wave_hours:
            bal = obs["balances_pm"].get(self.whale_account_id, 0.0)
            if self._per_hour_dump is None:
                self._per_hour_dump = bal / self.bank_run_wave_hours
            sell = min(bal, self._per_hour_dump * 1.05)
            if sell > 1.0:
                actions.append(
                    AgentAction(
                        "AMM_SWAP_PM_TO_NUM",
                        {"account_id": self.whale_account_id, "pm_amount": sell},
                    )
                )

        # Evaluate incoming covert cartel bribe offers
        for msg in covert_inbox:
            if msg.msg_type == "BRIBE_OFFER":
                bribe_pm = float(msg.payload.get("bribe_pm", 0.0))
                target_bias = float(msg.payload.get("target_bias", 0.0))
                my_stake = obs["node_stakes"].get(self.swing_node_id, {}).get("stake_pm", 0.0)
                ev_cooperate = bribe_pm - my_stake
                ev_defect = 0.20 * float(obs.get("cartel_stake_pm", 0.0))
                if self.irrational_accept or (ev_cooperate > ev_defect and bribe_pm > my_stake):
                    if rnd is not None:
                        self._accepted_rounds[int(rnd["round_id"])] = target_bias
                    actions.append(
                        AgentAction(
                            "COVERT_SEND",
                            {
                                "recipients": [msg.sender],
                                "msg_type": "BRIBE_ACCEPT",
                                "payload": {"round_id": rnd["round_id"] if rnd else None},
                            },
                        )
                    )
                else:
                    actions.append(
                        AgentAction(
                            "COVERT_SEND",
                            {
                                "recipients": ["whistleblower"],
                                "msg_type": "BRIBE_DEFECT_WHISTLEBLOW",
                                "payload": {
                                    "briber": msg.sender,
                                    "bribe_pm": bribe_pm,
                                    "ev_defect": ev_defect,
                                },
                            },
                        )
                    )

        if rnd is not None and self.swing_node_id in self.owned_node_ids:
            info = obs["node_stakes"].get(self.swing_node_id)
            if info is not None and not info["jailed"] and info["stake_pm"] > 0.0:
                rid = int(rnd["round_id"])
                phase = str(rnd["phase"])
                bias = self._accepted_rounds.get(rid, 0.0)
                if phase in ("COMMIT", "REVEAL"):
                    q = {a: px * (1.0 + bias) for a, px in true_px.items()}
                    act = _oracle_commit_and_reveal(rnd, self.swing_node_id, q, self._quotes, "swing")
                    if act is not None:
                        actions.append(act)
                elif phase == "COURT" and self.swing_node_id not in rnd["court_voted_nodes"]:
                    court_ref = rnd.get("open_true_prices") or true_px
                    q = {a: px * (1.0 + bias) for a, px in court_ref.items()}
                    actions.append(
                        AgentAction(
                            "ORACLE_COURT_VOTE",
                            {"node_id": self.swing_node_id, "prices": q, "salt": f"scourt_{rid}"},
                        )
                    )

        return actions or [AgentAction("NOOP")]


class RetailHerdAgent(BaseRedTeamAgent):
    """Momentum panic seller/buyer reacting to de-pegs and collateral crashes."""

    def __init__(
        self,
        agent_id: str = "retail_herd",
        max_sell_fraction: float = 0.25,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(agent_id=agent_id, role="retail", llm_config=llm_config)
        self.max_sell_fraction = max_sell_fraction
        self._init_sol_px: float | None = None

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        sol_px = float(obs["branch_prices"].get("SOL", 180.0))
        if self._init_sol_px is None:
            self._init_sol_px = sol_px
        e_spot = float(obs["e_spot"])
        sol_drawdown = (self._init_sol_px - sol_px) / self._init_sol_px

        pm_bal = obs["balances_pm"].get(self.agent_id, 0.0)
        num_bal = obs["balances_numeraire"].get(self.agent_id, 0.0)
        if (e_spot > 0.015 or sol_drawdown > 0.20) and pm_bal > 100.0:
            sell = min(pm_bal, max(500.0, pm_bal * self.max_sell_fraction * 0.5))
            if sell > 10.0:
                return [AgentAction("AMM_SWAP_PM_TO_NUM", {"pm_amount": sell})]
        if abs(e_spot) < 0.005 and num_bal > 100.0:
            buy = min(num_bal * 0.10, 2000.0)
            if buy > 10.0:
                return [AgentAction("AMM_SWAP_NUM_TO_PM", {"numeraire_amount": buy})]
        return [AgentAction("NOOP")]


class HostileStateAgent(BaseRedTeamAgent):
    """Sustained spot-AMM dumping spoofing attacker trying to bait R(t) and drain vaults."""

    def __init__(
        self,
        agent_id: str = "hostile_state",
        start_hour: int = 48,
        end_hour: int = 240,
        dump_interval_hours: int = 12,
        dump_pm_amount: float = 25_000.0,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(agent_id=agent_id, role="hostile_state", llm_config=llm_config)
        self.start_hour = start_hour
        self.end_hour = end_hour
        self.dump_interval_hours = max(1, dump_interval_hours)
        self.dump_pm_amount = dump_pm_amount

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        hour = int(obs["hour"])
        if not (self.start_hour <= hour <= self.end_hour):
            return [AgentAction("NOOP")]
        if (hour - self.start_hour) % self.dump_interval_hours != 0:
            return [AgentAction("NOOP")]

        pm_bal = obs["balances_pm"].get(self.agent_id, 0.0)
        sell = min(pm_bal, self.dump_pm_amount)
        if sell <= 10.0:
            return [AgentAction("NOOP")]

        actions = [AgentAction("AMM_SWAP_PM_TO_NUM", {"pm_amount": sell})]
        num_bal = obs["balances_numeraire"].get(self.agent_id, 0.0)
        if num_bal > 1_000.0:
            buy = min(num_bal * 0.20, sell * float(obs["m_spot"]) * 0.5)
            if buy > 10.0:
                gamma = 1.0 - float(obs["amm_fee_rate"])
                eff_in = buy * gamma
                pm_est = (float(obs["amm_pm_reserve"]) * eff_in) / (float(obs["amm_numeraire_reserve"]) + eff_in)
                actions.append(AgentAction("AMM_SWAP_NUM_TO_PM", {"numeraire_amount": buy}))
                actions.append(AgentAction("REDEEM_PM", {"pm_amount": pm_est * 0.99}))
        return actions


class ArbitrageurAgent(BaseRedTeamAgent):
    """Exact CP-AMM closed-form arbitrage agent defending peg floor and ceiling."""

    def __init__(
        self,
        agent_id: str = "arb",
        arb_vault_id: str = "V_ARB_ETH",
        borrow_rate_apr: float = 0.06,
        llm_config: LLMBackendConfig | None = None,
    ) -> None:
        super().__init__(agent_id=agent_id, role="arbitrageur", llm_config=llm_config)
        self.arb_vault_id = arb_vault_id
        self.borrow_rate_apr = borrow_rate_apr

    def heuristic_decide(
        self,
        obs: dict[str, Any],
        covert_inbox: list[CovertMessage],
        rng: random.Random,
    ) -> list[AgentAction]:
        r_px = float(obs["r_price"])
        f_redeem = float(obs["redemption_fee"])
        eff_floor = r_px * (1.0 - f_redeem)
        pm_res = float(obs["amm_pm_reserve"])
        num_res = float(obs["amm_numeraire_reserve"])
        gamma = 1.0 - float(obs["amm_fee_rate"])
        spot = num_res / pm_res

        if spot < eff_floor * gamma:
            num_after = (eff_floor * gamma * pm_res * num_res) ** 0.5
            opt_num = max(0.0, (num_after - num_res) / gamma)
            avail_num = obs["balances_numeraire"].get(self.agent_id, 0.0)
            active_debt = float(obs["active_debt_pm"])
            spend_num = min(opt_num, avail_num, 0.85 * active_debt * eff_floor)
            if spend_num > 1.0:
                eff_in = spend_num * gamma
                pm_out = (pm_res * eff_in) / (num_res + eff_in)
                return [
                    AgentAction("AMM_SWAP_NUM_TO_PM", {"numeraire_amount": spend_num}),
                    AgentAction("REDEEM_PM", {"pm_amount": pm_out * 0.999999}),
                ]

        if spot * gamma > r_px:
            pm_after = ((num_res * gamma * pm_res) / r_px) ** 0.5
            opt_pm = max(0.0, (pm_after - pm_res) / gamma)
            if opt_pm > 1.0:
                return [
                    AgentAction(
                        "MINT_AND_SELL",
                        {
                            "vault_id": self.arb_vault_id,
                            "mint_pm": opt_pm,
                            "borrow_rate_apr": max(self.borrow_rate_apr, float(obs["min_borrow_rate_apr"])),
                        },
                    )
                ]
        return [AgentAction("NOOP")]
