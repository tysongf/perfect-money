"""One-token Schelling-point commit-reveal oracle, lagged-EWMA slashing, and 48h dispute court."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from typing import Mapping

from .peg_controller import ThrottleState, clamp


def weighted_median(pairs: list[tuple[float, float]]) -> float:
    """Computes stake-weighted median over (value, weight) pairs."""
    valid = [(v, w) for v, w in pairs if w > 0.0]
    if not valid:
        raise ValueError("cannot take weighted_median of empty or zero-weight set")
    valid.sort(key=lambda item: item[0])
    total_w = sum(w for _, w in valid)
    half = 0.5 * total_w
    acc = 0.0
    for val, w in valid:
        acc += w
        if acc >= half - 1e-12:
            return val
    return valid[-1][0]


def make_oracle_commit(
    round_id: int,
    asset: str,
    price: float,
    salt: str,
    node_id: str,
) -> str:
    payload = f"PM_ORACLE_V1|{round_id}|{asset}|{price:.8f}|{salt}|{node_id}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class OracleNode:
    """Reporter and/or 2-year locked court voter staking unshielded PM."""

    node_id: str
    stake_pm: float
    is_court_voter: bool = True
    role: str = "honest"
    rewards_pm: float = 0.0
    slashed_pm: float = 0.0
    jailed: bool = False


@dataclass
class OracleCommit:
    node_id: str
    asset_hashes: dict[str, str]


@dataclass
class OracleReveal:
    node_id: str
    prices: dict[str, float]
    salt: str


@dataclass
class OracleFinalizeResult:
    round_id: int
    finalized_prices: dict[str, float]
    p_med: dict[str, float]
    was_disputed: bool
    dispute_upheld_challenger: bool
    is_drastic: bool
    epsilon_by_asset: dict[str, float]
    burned_pm: float
    insurance_pm: float
    bond_fee_pool_pm: float
    bounty_payouts: dict[str, float]
    bond_refunds: dict[str, float]
    reward_payouts: dict[str, float]
    node_slashes: dict[str, float]


@dataclass
class OracleRound:
    round_id: int
    open_hour: int
    phase: str = "COMMIT"
    phase_end_hour: int = 1
    frozen_epsilons: dict[str, float] = field(default_factory=dict)
    commits: dict[str, OracleCommit] = field(default_factory=dict)
    reveals: dict[str, OracleReveal] = field(default_factory=dict)
    no_reveal_slashed_pm: float = 0.0
    no_reveal_slashes: dict[str, float] = field(default_factory=dict)
    p_med: dict[str, float] = field(default_factory=dict)
    is_drastic: bool = False
    challenge_hours_assigned: int = 2
    disputed: bool = False
    challenger_id: str | None = None
    dispute_bond_pm: float = 0.0
    court_commits: dict[str, dict[str, str]] = field(default_factory=dict)
    court_reveals: dict[str, OracleReveal] = field(default_factory=dict)
    final_result: OracleFinalizeResult | None = None


@dataclass
class OracleMarket:
    """Epoch commit -> reveal -> challenge -> (optional 48h court) -> finalize engine."""

    initial_prices: dict[str, float]
    nodes: dict[str, OracleNode] = field(default_factory=dict)
    s_min_pm: float = 1000.0
    dispute_bond_min_pm: float = 5000.0
    slash_no_reveal_rate: float = 0.10
    ewma_alpha: float = 0.10
    ewma_min: float = 0.002
    ewma_max: float = 0.03
    epsilon_floor: float = 0.005
    sigma_hist_ewma: dict[str, float] = field(default_factory=dict)
    last_finalized_prices: dict[str, float] = field(default_factory=dict)
    active_round: OracleRound | None = None
    next_round_id: int = 1
    history: list[OracleFinalizeResult] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.last_finalized_prices = dict(self.initial_prices)
        if not self.sigma_hist_ewma:
            self.sigma_hist_ewma = {asset: 0.004 for asset in self.initial_prices}

    def add_node(self, node: OracleNode) -> None:
        self.nodes[node.node_id] = node

    def total_locked_stake(self) -> float:
        return sum(n.stake_pm for n in self.nodes.values() if n.stake_pm > 0.0)

    def active_reporter_nodes(self) -> list[OracleNode]:
        return [
            n
            for n in self.nodes.values()
            if not n.jailed and n.stake_pm >= self.s_min_pm
        ]

    def court_voter_nodes(self) -> list[OracleNode]:
        return [
            n
            for n in self.nodes.values()
            if n.is_court_voter and not n.jailed and n.stake_pm >= self.s_min_pm
        ]

    def current_epsilons(self) -> dict[str, float]:
        return {
            asset: max(self.epsilon_floor, 1.5 * self.sigma_hist_ewma[asset])
            for asset in self.initial_prices
        }

    def start_round(self, hour: int) -> OracleRound:
        if self.active_round is not None and self.active_round.phase != "FINALIZED":
            raise RuntimeError(f"cannot start round while round {self.active_round.round_id} is active")
        rnd = OracleRound(
            round_id=self.next_round_id,
            open_hour=hour,
            phase="COMMIT",
            phase_end_hour=hour + 1,
            frozen_epsilons=self.current_epsilons(),
        )
        self.next_round_id += 1
        self.active_round = rnd
        return rnd

    def submit_commit(self, node_id: str, prices: Mapping[str, float], salt: str) -> None:
        rnd = self._require_phase("COMMIT")
        node = self.nodes.get(node_id)
        if node is None or node.jailed or node.stake_pm < self.s_min_pm:
            return
        hashes = {
            asset: make_oracle_commit(rnd.round_id, asset, float(prices[asset]), salt, node_id)
            for asset in self.initial_prices
        }
        rnd.commits[node_id] = OracleCommit(node_id=node_id, asset_hashes=hashes)

    def submit_reveal(self, node_id: str, prices: Mapping[str, float], salt: str) -> bool:
        rnd = self._require_phase("REVEAL")
        commit = rnd.commits.get(node_id)
        if commit is None:
            return False
        for asset, expected_hash in commit.asset_hashes.items():
            px = prices.get(asset)
            if px is None or px <= 0.0:
                return False
            actual_hash = make_oracle_commit(rnd.round_id, asset, float(px), salt, node_id)
            if actual_hash != expected_hash:
                return False
        rnd.reveals[node_id] = OracleReveal(
            node_id=node_id,
            prices={asset: float(prices[asset]) for asset in self.initial_prices},
            salt=salt,
        )
        return True

    def challenge_round(self, challenger_id: str, bond_pm: float, hour: int) -> float:
        rnd = self._require_phase("CHALLENGE")
        if rnd.disputed:
            raise ValueError("round already disputed")
        if bond_pm < self.dispute_bond_min_pm:
            raise ValueError(
                f"dispute bond {bond_pm} below minimum {self.dispute_bond_min_pm}"
            )
        rnd.disputed = True
        rnd.challenger_id = challenger_id
        rnd.dispute_bond_pm = bond_pm
        rnd.phase = "COURT"
        rnd.phase_end_hour = hour + 48
        return bond_pm

    def submit_court_vote(self, node_id: str, prices: Mapping[str, float], salt: str) -> None:
        rnd = self._require_phase("COURT")
        node = self.nodes.get(node_id)
        if node is None or not node.is_court_voter or node.jailed or node.stake_pm < self.s_min_pm:
            return
        rnd.court_commits[node_id] = {
            asset: make_oracle_commit(rnd.round_id, f"COURT_{asset}", float(prices[asset]), salt, node_id)
            for asset in self.initial_prices
        }
        rnd.court_reveals[node_id] = OracleReveal(
            node_id=node_id,
            prices={asset: float(prices[asset]) for asset in self.initial_prices},
            salt=salt,
        )

    def advance(
        self,
        hour: int,
        throttle: ThrottleState,
        oracle_fee_pool_pm: float,
    ) -> tuple[OracleFinalizeResult | None, dict[str, float], float]:
        """Advances round phase if deadline reached.

        Returns `(finalize_result_or_none, no_reveal_event_dict, round_insurance_or_burn_adjust)`.
        """
        no_reveal_info = {"burned_pm": 0.0, "insurance_pm": 0.0, "total_slashed_pm": 0.0}
        rnd = self.active_round
        if rnd is None or rnd.phase == "FINALIZED":
            return None, no_reveal_info, 0.0

        if hour < rnd.phase_end_hour:
            return None, no_reveal_info, 0.0

        if rnd.phase == "COMMIT":
            rnd.phase = "REVEAL"
            rnd.phase_end_hour = hour + 1
            return None, no_reveal_info, 0.0

        if rnd.phase == "REVEAL":
            no_reveal_info = self._resolve_reveal_and_enter_challenge(rnd, hour, throttle)
            return None, no_reveal_info, 0.0

        if rnd.phase in ("CHALLENGE", "COURT"):
            res = self._finalize_round(rnd, throttle, oracle_fee_pool_pm)
            return res, no_reveal_info, 0.0

        return None, no_reveal_info, 0.0

    def _resolve_reveal_and_enter_challenge(
        self,
        rnd: OracleRound,
        hour: int,
        throttle: ThrottleState,
    ) -> dict[str, float]:
        total_no_reveal_slash = 0.0
        for node_id in list(rnd.commits.keys()):
            if node_id not in rnd.reveals:
                node = self.nodes[node_id]
                slash = min(node.stake_pm, node.stake_pm * self.slash_no_reveal_rate)
                node.stake_pm -= slash
                node.slashed_pm += slash
                rnd.no_reveal_slashed_pm += slash
                rnd.no_reveal_slashes[node_id] = rnd.no_reveal_slashes.get(node_id, 0.0) + slash
                total_no_reveal_slash += slash

        p_med: dict[str, float] = {}
        for asset in self.initial_prices:
            pairs = [
                (rev.prices[asset], self.nodes[nid].stake_pm)
                for nid, rev in rnd.reveals.items()
                if self.nodes[nid].stake_pm > 0.0
            ]
            if pairs:
                p_med[asset] = weighted_median(pairs)
            else:
                p_med[asset] = self.last_finalized_prices[asset]

        rnd.p_med = p_med
        max_rel_shift = max(
            abs(p_med[a] - self.last_finalized_prices[a]) / self.last_finalized_prices[a]
            for a in self.initial_prices
        )
        rnd.is_drastic = max_rel_shift > 0.02
        base_window = 48 if rnd.is_drastic else 2
        rnd.challenge_hours_assigned = max(base_window, throttle.challenge_hours)
        rnd.phase = "CHALLENGE"
        rnd.phase_end_hour = hour + rnd.challenge_hours_assigned

        # Conservation: no challenger wins no-reveal fee -> 90% burned, 10% insurance reserve
        burned = 0.90 * total_no_reveal_slash
        insurance = 0.10 * total_no_reveal_slash
        return {
            "burned_pm": burned,
            "insurance_pm": insurance,
            "total_slashed_pm": total_no_reveal_slash,
        }

    def _finalize_round(
        self,
        rnd: OracleRound,
        throttle: ThrottleState,
        oracle_fee_pool_pm: float,
    ) -> OracleFinalizeResult:
        epsilons = rnd.frozen_epsilons
        bounty_payouts: dict[str, float] = {}
        bond_refunds: dict[str, float] = {}
        reward_payouts: dict[str, float] = {}
        node_slashes: dict[str, float] = {}
        burned_pm = 0.0
        insurance_pm = 0.0
        bond_fee_pool_pm = 0.0

        court_confirmed = False
        dispute_upheld_challenger = False

        if rnd.disputed:
            p_court: dict[str, float] = {}
            for asset in self.initial_prices:
                pairs = [
                    (rev.prices[asset], self.nodes[nid].stake_pm)
                    for nid, rev in rnd.court_reveals.items()
                    if self.nodes[nid].stake_pm > 0.0
                ]
                if pairs:
                    p_court[asset] = weighted_median(pairs)
                else:
                    p_court[asset] = self.last_finalized_prices[asset]

            court_confirmed = True
            overturned = any(
                abs(p_court[a] - rnd.p_med[a]) / max(1e-12, p_court[a]) > epsilons[a]
                for a in self.initial_prices
            )
            if overturned:
                dispute_upheld_challenger = True
                raw_p_star = p_court
                if rnd.challenger_id is not None:
                    bond_refunds[rnd.challenger_id] = rnd.dispute_bond_pm
            else:
                # Frivolous challenge: slash challenger's dispute bond (70% burn, 20% fee pool, 10% ins)
                raw_p_star = dict(rnd.p_med)
                bond = rnd.dispute_bond_pm
                burned_pm += 0.70 * bond
                bond_fee_pool_pm = 0.20 * bond
                oracle_fee_pool_pm += bond_fee_pool_pm
                insurance_pm += 0.10 * bond
        else:
            raw_p_star = dict(rnd.p_med)

        # Apply epoch delta clamp unless confirmed by 48h court or full uncontested 48h+ drastic window
        # when CoC_51 covers unthrottled exposure (if low-stake throttled & unchallenged by court, throttle caps it).
        allow_full_jump = court_confirmed or (rnd.is_drastic and throttle.deficit_frac < 1e-9)
        finalized_prices: dict[str, float] = {}
        for asset in self.initial_prices:
            prev_px = self.last_finalized_prices[asset]
            target_px = raw_p_star[asset]
            if allow_full_jump:
                finalized_prices[asset] = target_px
            else:
                lo = prev_px * (1.0 - throttle.max_epoch_delta)
                hi = prev_px * (1.0 + throttle.max_epoch_delta)
                finalized_prices[asset] = clamp(target_px, lo, hi)

        # Asymmetric slashing against finalized P* using FROZEN pre-round epsilons
        coherent_nodes: list[OracleNode] = []
        total_reporter_slashed = 0.0

        for node_id, rev in rnd.reveals.items():
            node = self.nodes[node_id]
            if node.stake_pm <= 0.0:
                continue
            max_ratio = 0.0
            for asset in self.initial_prices:
                p_star = finalized_prices[asset]
                d_k = abs(rev.prices[asset] - p_star) / p_star
                ratio = d_k / epsilons[asset]
                if ratio > max_ratio:
                    max_ratio = ratio

            if max_ratio <= 1.0:
                coherent_nodes.append(node)
            elif max_ratio <= 3.0:
                # d_k in (eps, 3*eps] => max_ratio in (1, 3]
                slash_rate = 0.25 * (((max_ratio - 1.0) / 2.0) ** 2)
                slash = node.stake_pm * slash_rate
                node.stake_pm -= slash
                node.slashed_pm += slash
                node_slashes[node_id] = slash
                total_reporter_slashed += slash
            else:
                slash = node.stake_pm
                node.stake_pm = 0.0
                node.slashed_pm += slash
                node.jailed = True
                node_slashes[node_id] = slash
                total_reporter_slashed += slash

        # Distribute reporter slashes cleanly (70% burn, 20% whistleblower if upheld else burn, 10% insurance)
        if total_reporter_slashed > 0.0:
            burned_pm += 0.70 * total_reporter_slashed
            insurance_pm += 0.10 * total_reporter_slashed
            if dispute_upheld_challenger and rnd.challenger_id is not None:
                bounty = 0.20 * total_reporter_slashed
                bounty_payouts[rnd.challenger_id] = bounty_payouts.get(rnd.challenger_id, 0.0) + bounty
            else:
                burned_pm += 0.20 * total_reporter_slashed

        # Distribute oracle fee pool across coherent nodes (includes court voters if coherent)
        coherent_voters: dict[str, OracleNode] = {n.node_id: n for n in coherent_nodes}
        if rnd.disputed:
            for node_id, rev in rnd.court_reveals.items():
                node = self.nodes[node_id]
                if node.stake_pm <= 0.0:
                    continue
                within_band = all(
                    abs(rev.prices[a] - finalized_prices[a]) / finalized_prices[a] <= epsilons[a]
                    for a in self.initial_prices
                )
                if within_band:
                    coherent_voters[node_id] = node

        total_coherent_stake = sum(n.stake_pm for n in coherent_voters.values())
        if total_coherent_stake > 0.0 and oracle_fee_pool_pm > 0.0:
            for nid, node in coherent_voters.items():
                reward = oracle_fee_pool_pm * (node.stake_pm / total_coherent_stake)
                node.rewards_pm += reward
                reward_payouts[nid] = reward

        # Update lagged sigma_hist_ewma AFTER finalization for the NEXT round
        for asset in self.initial_prices:
            prev_px = self.last_finalized_prices[asset]
            new_px = finalized_prices[asset]
            rel_move = abs(new_px - prev_px) / prev_px
            updated_ewma = (1.0 - self.ewma_alpha) * self.sigma_hist_ewma[asset] + self.ewma_alpha * rel_move
            self.sigma_hist_ewma[asset] = clamp(updated_ewma, self.ewma_min, self.ewma_max)

        self.last_finalized_prices = dict(finalized_prices)
        rnd.phase = "FINALIZED"

        result = OracleFinalizeResult(
            round_id=rnd.round_id,
            finalized_prices=finalized_prices,
            p_med=dict(rnd.p_med),
            was_disputed=rnd.disputed,
            dispute_upheld_challenger=dispute_upheld_challenger,
            is_drastic=rnd.is_drastic,
            epsilon_by_asset=dict(epsilons),
            burned_pm=burned_pm,
            insurance_pm=insurance_pm,
            bond_fee_pool_pm=bond_fee_pool_pm,
            bounty_payouts=bounty_payouts,
            bond_refunds=bond_refunds,
            reward_payouts=reward_payouts,
            node_slashes=node_slashes,
        )
        rnd.final_result = result
        self.history.append(result)
        return result

    def _require_phase(self, expected_phase: str) -> OracleRound:
        if self.active_round is None or self.active_round.phase != expected_phase:
            actual = None if self.active_round is None else self.active_round.phase
            raise RuntimeError(f"expected oracle phase {expected_phase}, got {actual}")
        return self.active_round
