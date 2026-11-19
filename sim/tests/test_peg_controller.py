import pytest

from sim.engine.peg_controller import (
    BasketSpec,
    DEFAULT_BASKET_WEIGHTS,
    DEFAULT_GENESIS_PRICES,
    PegController,
    compute_auto_throttle,
    compute_geometric_index,
)


def test_basket_weights_validation_and_annual_shift_clamp():
    basket = BasketSpec()
    bad_sum = dict(DEFAULT_BASKET_WEIGHTS)
    bad_sum["electricity"] += 0.05
    with pytest.raises(ValueError, match="sum to 1.0"):
        BasketSpec(weights=bad_sum)

    too_big_shift = dict(DEFAULT_BASKET_WEIGHTS)
    too_big_shift["electricity"] += 0.03
    too_big_shift["oil_gas"] -= 0.03
    with pytest.raises(ValueError, match="constitutional cap"):
        basket.update_weights(too_big_shift, elapsed_years=1.0)

    valid_shift = dict(DEFAULT_BASKET_WEIGHTS)
    valid_shift["electricity"] += 0.02
    valid_shift["oil_gas"] -= 0.02
    basket.update_weights(valid_shift, elapsed_years=1.0)
    assert abs(sum(basket.weights.values()) - 1.0) < 1e-12


def test_geometric_index_dimensional_invariance():
    # Changing numeraire from USD to Yen (155x) or gold grams (0.012x) cancels identically
    curr_usd = dict(DEFAULT_GENESIS_PRICES)
    curr_usd["electricity"] *= 1.40
    curr_usd["grain"] *= 1.12

    idx_usd = compute_geometric_index(curr_usd, DEFAULT_GENESIS_PRICES, DEFAULT_BASKET_WEIGHTS)
    for scale in (155.0, 0.012, 3.14159):
        scaled_curr = {k: v * scale for k, v in curr_usd.items()}
        scaled_gen = {k: v * scale for k, v in DEFAULT_GENESIS_PRICES.items()}
        idx_scaled = compute_geometric_index(scaled_curr, scaled_gen, DEFAULT_BASKET_WEIGHTS)
        assert abs(idx_usd - idx_scaled) < 1e-12


def test_auto_throttle_closed_form_across_liquidity_tiers():
    # Across liquidity scales from $100k to $1B, >=5% exposure locked guarantees CoC_51 / PfC_effective >= 3.0
    for supply in (100_000.0, 1_000_000.0, 50_000_000.0, 1_000_000_000.0):
        amm_liq = 0.4 * supply
        exposure = amm_liq + supply

        # Low-stake tier (10% of exposure locked): throttles max_epoch_delta, widens challenge, boosts staker share
        low = compute_auto_throttle(locked_pm=0.10 * exposure, amm_liquidity_pm=amm_liq, total_pm_supply=supply)
        assert low.coc_pfc_ratio >= 3.0 - 1e-9
        assert low.max_epoch_delta < 0.05
        assert low.challenge_hours > 2
        assert low.staker_fee_share > 0.25

        # Healthy-stake tier (50% of exposure locked): hits baseline 5% unthrottled cap cleanly
        high = compute_auto_throttle(locked_pm=0.50 * exposure, amm_liquidity_pm=amm_liq, total_pm_supply=supply)
        assert high.coc_pfc_ratio >= 3.0 - 1e-9
        assert abs(high.max_epoch_delta - 0.05) < 1e-12
        assert high.challenge_hours == 2
        assert abs(high.staker_fee_share - 0.25) < 1e-12


def test_amm_spoofing_ablation_patched_vs_legacy():
    patched = PegController(mode="patched_decoupled")
    legacy = PegController(mode="legacy_spot_driven_r")

    # Simulate an attacker temporarily spoofing spot AMM price M(t) down 15% (0.85) while I(t) stays 1.00
    for _ in range(48):
        p_res = patched.step(i_oracle=1.0, m_spot=0.85, dt_days=1.0 / 24.0)
        l_res = legacy.step(i_oracle=1.0, m_spot=0.85, dt_days=1.0 / 24.0)

    # Patched decoupled R(t) never inflates above I(t), blocking hard-redemption vault extraction!
    assert p_res.r_price == pytest.approx(1.0, abs=1e-12)
    assert p_res.min_borrow_rate_apr > 0.20

    # Unpatched legacy mode lets spoofing push R(t) above $1.00, subsidizing attacker redemptions
    assert l_res.r_price > 1.02

