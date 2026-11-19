"""Basket peg mathematics, decoupled target tracker, spot PID, and auto-throttling."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Mapping


DEFAULT_BASKET_WEIGHTS: dict[str, float] = {
    "electricity": 0.25,
    "oil_gas": 0.15,
    "grain": 0.20,
    "metals": 0.15,
    "housing": 0.10,
    "datacenter_power": 0.15,
}

DEFAULT_GENESIS_PRICES: dict[str, float] = {
    "electricity": 100.0,
    "oil_gas": 80.0,
    "grain": 250.0,
    "metals": 8000.0,
    "housing": 2000.0,
    "datacenter_power": 120.0,
}


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


@dataclass
class BasketSpec:
    """Purchasing-power basket weights and genesis reference prices."""

    weights: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_BASKET_WEIGHTS))
    genesis_prices: dict[str, float] = field(default_factory=lambda: dict(DEFAULT_GENESIS_PRICES))
    i0: float = 1.0
    max_annual_weight_shift: float = 0.02

    def __post_init__(self) -> None:
        self._validate_weights(self.weights)
        if set(self.weights.keys()) != set(self.genesis_prices.keys()):
            raise ValueError("weights and genesis_prices must share identical asset keys")
        if self.i0 <= 0.0:
            raise ValueError("i0 must be positive")
        for asset, px in self.genesis_prices.items():
            if px <= 0.0:
                raise ValueError(f"genesis price for {asset} must be positive")

    @staticmethod
    def _validate_weights(weights: Mapping[str, float]) -> None:
        if not weights:
            raise ValueError("weights cannot be empty")
        for asset, w in weights.items():
            if w < 0.0:
                raise ValueError(f"weight for {asset} cannot be negative: {w}")
        total = sum(weights.values())
        if abs(total - 1.0) > 1e-9:
            raise ValueError(f"basket weights must sum to 1.0, got {total}")

    def update_weights(self, new_weights: Mapping[str, float], elapsed_years: float = 1.0) -> None:
        """Updates weights subject to the constitutional <= 2%/year per-component shift cap."""
        if elapsed_years < 0.0:
            raise ValueError("elapsed_years must be non-negative")
        if set(new_weights.keys()) != set(self.weights.keys()):
            raise ValueError("new_weights keys must match existing basket components")
        self._validate_weights(new_weights)
        max_shift = self.max_annual_weight_shift * elapsed_years + 1e-12
        for asset, w_new in new_weights.items():
            delta = abs(w_new - self.weights[asset])
            if delta > max_shift:
                raise ValueError(
                    f"weight shift for {asset} ({delta:.6f}) exceeds constitutional cap {max_shift:.6f}"
                )
        self.weights = dict(new_weights)

    def index(self, prices: Mapping[str, float]) -> float:
        return compute_geometric_index(prices, self.genesis_prices, self.weights, i0=self.i0)


def compute_geometric_index(
    prices: Mapping[str, float],
    genesis_prices: Mapping[str, float],
    weights: Mapping[str, float],
    i0: float = 1.0,
) -> float:
    """Computes I(t) = I_0 * prod_i (P_i(t) / P_i(0)) ^ w_i."""
    if set(prices.keys()) != set(weights.keys()) or set(genesis_prices.keys()) != set(weights.keys()):
        raise ValueError("prices, genesis_prices, and weights must have identical component keys")
    if i0 <= 0.0:
        raise ValueError("i0 must be positive")
    prod_val = 1.0
    for asset, w in weights.items():
        p_t = prices[asset]
        p_0 = genesis_prices[asset]
        if p_t <= 0.0 or p_0 <= 0.0:
            raise ValueError(f"non-positive price for {asset}: P_t={p_t}, P_0={p_0}")
        prod_val *= math.pow(p_t / p_0, w)
    return i0 * prod_val


@dataclass(frozen=True)
class ThrottleState:
    """Closed-form CoC >= 3.0 * PfC security, throttling, and fee-routing snapshot."""

    locked_pm: float
    amm_liquidity_pm: float
    total_pm_supply: float
    exposure_pm: float
    coc_51_pm: float
    pfc_unthrottled_pm: float
    pfc_effective_pm: float
    coc_pfc_ratio: float
    max_epoch_delta: float
    challenge_hours: int
    staker_fee_share: float
    sp_fee_share: float
    insurance_fee_share: float
    deficit_frac: float


def compute_auto_throttle(
    locked_pm: float,
    amm_liquidity_pm: float,
    total_pm_supply: float,
    *,
    k_pfc: float = 1.5,
    baseline_max_delta: float = 0.05,
    floor_max_delta: float = 0.005,
    base_challenge_hours: int = 2,
    max_challenge_hours: int = 168,
    base_staker_fee_share: float = 0.25,
    max_staker_fee_share: float = 0.40,
    insurance_fee_share: float = 0.10,
) -> ThrottleState:
    """Computes observable PfC and stacked auto-throttling + dynamic fee routing."""
    exposure = max(1e-9, amm_liquidity_pm + total_pm_supply)
    coc_51 = 0.51 * max(0.0, locked_pm)
    pfc_unthrottled = k_pfc * baseline_max_delta * exposure
    raw_delta = coc_51 / (3.0 * k_pfc * exposure)
    max_epoch_delta = clamp(raw_delta, floor_max_delta, baseline_max_delta)
    pfc_effective = max(1e-9, k_pfc * max_epoch_delta * exposure)
    coc_pfc_ratio = coc_51 / pfc_effective

    req_coc_unthrottled = max(1e-9, 3.0 * pfc_unthrottled)
    deficit_frac = clamp(1.0 - (coc_51 / req_coc_unthrottled), 0.0, 1.0)
    challenge_hours = int(
        round(base_challenge_hours + deficit_frac * (max_challenge_hours - base_challenge_hours))
    )
    staker_fee_share = base_staker_fee_share + deficit_frac * (
        max_staker_fee_share - base_staker_fee_share
    )
    sp_fee_share = max(0.0, 1.0 - staker_fee_share - insurance_fee_share)

    return ThrottleState(
        locked_pm=locked_pm,
        amm_liquidity_pm=amm_liquidity_pm,
        total_pm_supply=total_pm_supply,
        exposure_pm=exposure,
        coc_51_pm=coc_51,
        pfc_unthrottled_pm=pfc_unthrottled,
        pfc_effective_pm=pfc_effective,
        coc_pfc_ratio=coc_pfc_ratio,
        max_epoch_delta=max_epoch_delta,
        challenge_hours=challenge_hours,
        staker_fee_share=staker_fee_share,
        sp_fee_share=sp_fee_share,
        insurance_fee_share=insurance_fee_share,
        deficit_frac=deficit_frac,
    )


@dataclass(frozen=True)
class PegStepResult:
    r_price: float
    i_oracle: float
    m_spot: float
    e_spot: float
    e_target: float
    min_borrow_rate_apr: float
    u_r_applied: float


@dataclass
class PegController:
    """Tracks R(t) against finalized I(t) (patched_decoupled) and modulates min borrow APR via spot PID."""

    mode: str = "patched_decoupled"
    r_price: float = 1.0
    deadband: float = 0.0025
    u_max_per_day: float = 0.03
    k_track_per_day: float = 0.80

    min_rate_base_apr: float = 0.005
    min_rate_max_apr: float = 0.25
    k_p_rate: float = 1.5
    k_i_rate: float = 0.30
    k_d_rate: float = 0.05
    i_max_rate: float = 0.10

    # Legacy spot-driven R(t) parameters (used only in AMM-spoofing ablation tests)
    k_p_legacy: float = 0.40
    k_i_legacy: float = 0.05
    k_d_legacy: float = 0.02
    u_max_legacy_per_day: float = 0.015
    i_max_legacy: float = 0.05

    i_term: float = 0.0
    prev_error: float | None = None
    min_borrow_rate_apr: float = 0.005

    def __post_init__(self) -> None:
        if self.mode not in ("patched_decoupled", "legacy_spot_driven_r"):
            raise ValueError(f"unsupported PegController mode: {self.mode}")

    def step(self, i_oracle: float, m_spot: float, dt_days: float = 1.0 / 24.0) -> PegStepResult:
        if i_oracle <= 0.0 or m_spot <= 0.0:
            raise ValueError(f"prices must be positive: i_oracle={i_oracle}, m_spot={m_spot}")

        e_spot = (i_oracle - m_spot) / i_oracle
        e_target = (i_oracle - self.r_price) / i_oracle

        if self.mode == "patched_decoupled":
            # 1. Hard-redemption target R(t) tracks finalized oracle basket I(t) monotonically.
            u_r = 0.0
            if abs(e_target) > 1e-12:
                u_r = clamp(self.k_track_per_day * e_target, -self.u_max_per_day, self.u_max_per_day)
                r_candidate = self.r_price * (1.0 + u_r * dt_days)
                lo = min(self.r_price, i_oracle)
                hi = max(self.r_price, i_oracle)
                self.r_price = clamp(r_candidate, lo, hi)

            # 2. Spot error modulates bounded minimum borrow-rate floor (never inflates R(t)).
            if abs(e_spot) < self.deadband:
                self.i_term *= max(0.0, 1.0 - 0.5 * dt_days)
                self.min_borrow_rate_apr = self.min_rate_base_apr
            else:
                p_term = self.k_p_rate * e_spot
                self.i_term = clamp(
                    self.i_term + self.k_i_rate * e_spot * dt_days,
                    -self.i_max_rate,
                    self.i_max_rate,
                )
                d_term = (
                    0.0
                    if self.prev_error is None
                    else self.k_d_rate * (e_spot - self.prev_error) / max(1e-9, dt_days)
                )
                pid_out = p_term + self.i_term + d_term
                self.min_borrow_rate_apr = clamp(
                    self.min_rate_base_apr + pid_out,
                    self.min_rate_base_apr,
                    self.min_rate_max_apr,
                )
            self.prev_error = e_spot

            return PegStepResult(
                r_price=self.r_price,
                i_oracle=i_oracle,
                m_spot=m_spot,
                e_spot=e_spot,
                e_target=(i_oracle - self.r_price) / i_oracle,
                min_borrow_rate_apr=self.min_borrow_rate_apr,
                u_r_applied=u_r,
            )

        # Legacy mode: spot error directly drives R(t) (vulnerable to AMM-spoofing).
        if abs(e_spot) < self.deadband:
            u_legacy = 0.0
        else:
            p_term = self.k_p_legacy * e_spot
            self.i_term = clamp(
                self.i_term + self.k_i_legacy * e_spot * dt_days,
                -self.i_max_legacy,
                self.i_max_legacy,
            )
            d_term = (
                0.0
                if self.prev_error is None
                else self.k_d_legacy * (e_spot - self.prev_error) / max(1e-9, dt_days)
            )
            u_legacy = clamp(
                p_term + self.i_term + d_term,
                -self.u_max_legacy_per_day,
                self.u_max_legacy_per_day,
            )
        self.prev_error = e_spot
        self.r_price = max(1e-6, self.r_price * (1.0 + u_legacy * dt_days))
        self.min_borrow_rate_apr = self.min_rate_base_apr
        return PegStepResult(
            r_price=self.r_price,
            i_oracle=i_oracle,
            m_spot=m_spot,
            e_spot=e_spot,
            e_target=(i_oracle - self.r_price) / i_oracle,
            min_borrow_rate_apr=self.min_borrow_rate_apr,
            u_r_applied=u_legacy,
        )

