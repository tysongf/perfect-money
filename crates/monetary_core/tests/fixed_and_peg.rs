use std::collections::BTreeMap;

use monetary_core::{
    BasketSpec, MonetaryError, PegController, PegMode, SCALE, ThrottleConfig, WAD,
    compute_auto_throttle, compute_geometric_index, decay_half_life, default_basket_weights,
    default_genesis_prices, exp_wad, isqrt_u256, ln_wad, mul_div_ceil, mul_div_floor,
    mul_div_round, mul_div_signed_trunc, mul_u128_wide, pm_from_whole, scale_from_bps,
};

#[test]
fn test_256_bit_mul_div_and_isqrt() {
    // Intermediate 2^100 * 2^60 overflows u128, but result fits cleanly
    let q = mul_div_floor(1u128 << 100, 1u128 << 60, 1u128 << 80).unwrap();
    assert_eq!(q, 1u128 << 80);

    assert_eq!(mul_div_floor(10, 1, 3).unwrap(), 3);
    assert_eq!(mul_div_ceil(10, 1, 3).unwrap(), 4);
    assert_eq!(mul_div_round(10, 1, 3).unwrap(), 3);
    assert_eq!(mul_div_round(11, 1, 3).unwrap(), 4);
    assert_eq!(mul_div_round(5, 1, 2).unwrap(), 3);

    assert_eq!(mul_div_floor(1, 1, 0), Err(MonetaryError::DivisionByZero));
    assert_eq!(
        mul_div_floor(u128::MAX, 2, 1),
        Err(MonetaryError::MathOverflow)
    );

    assert_eq!(mul_div_signed_trunc(-7, 3, 2).unwrap(), -10);
    assert_eq!(mul_div_signed_trunc(-7, -3, 2).unwrap(), 10);

    let (hi, lo) = mul_u128_wide(1_000_000_000_000_000, 1_000_000_000_000_000);
    assert_eq!(isqrt_u256(hi, lo), 1_000_000_000_000_000);
    assert_eq!(isqrt_u256(0, 0), 0);
    assert_eq!(isqrt_u256(u128::MAX, u128::MAX), u128::MAX);
}

#[test]
fn test_ln_exp_and_half_life_precision() {
    assert_eq!(ln_wad(WAD).unwrap(), 0);
    assert_eq!(exp_wad(0).unwrap(), WAD);
    assert!(ln_wad(0).is_err());

    // Roundtrip exp(ln(x)) within 1e-12 relative error
    for factor_milli in [50u128, 500, 1_000, 1_400, 2_718, 10_000] {
        let x = (factor_milli * WAD) / 1_000;
        let lx = ln_wad(x).unwrap();
        let ex = exp_wad(lx).unwrap();
        let err = ex.abs_diff(x);
        assert!(
            err * 1_000_000_000_000 <= x.max(WAD),
            "roundtrip error too large for x={x}: got={ex}, err={err}"
        );
    }

    // Half-life exact & fractional checks
    assert_eq!(decay_half_life(10_000_000, 6, 6).unwrap(), 5_000_000);
    assert_eq!(decay_half_life(10_000_000, 12, 6).unwrap(), 2_500_000);
    let half_step = decay_half_life(10_000_000, 3, 6).unwrap();
    assert!(half_step.abs_diff(7_071_068) <= 1);
}

#[test]
fn test_basket_weights_validation_and_annual_shift_clamp() {
    let mut basket = BasketSpec::default();
    let mut bad_sum = default_basket_weights();
    *bad_sum.get_mut("electricity").unwrap() += 50_000_000;
    assert!(matches!(
        BasketSpec::new(bad_sum, default_genesis_prices(), SCALE, scale_from_bps(200)),
        Err(MonetaryError::InvalidBasketWeights(_))
    ));

    let mut too_big = default_basket_weights();
    *too_big.get_mut("electricity").unwrap() += 30_000_000;
    *too_big.get_mut("oil_gas").unwrap() -= 30_000_000;
    assert!(matches!(
        basket.update_weights(too_big, 365),
        Err(MonetaryError::WeightShiftExceedsCap { .. })
    ));

    let mut valid_shift = default_basket_weights();
    *valid_shift.get_mut("electricity").unwrap() += 20_000_000;
    *valid_shift.get_mut("oil_gas").unwrap() -= 20_000_000;
    basket.update_weights(valid_shift, 365).unwrap();
    assert_eq!(basket.weights.values().sum::<u128>(), SCALE);
}

#[test]
fn test_geometric_index_dimensional_invariance() {
    let genesis = default_genesis_prices();
    let weights = default_basket_weights();
    let mut curr = genesis.clone();
    *curr.get_mut("electricity").unwrap() = (curr["electricity"] * 140) / 100;
    *curr.get_mut("grain").unwrap() = (curr["grain"] * 112) / 100;

    let idx_usd = compute_geometric_index(&curr, &genesis, &weights, SCALE).unwrap();
    for (num, den) in [(155u128, 1u128), (12, 1000), (314_159, 100_000)] {
        let scaled_curr: BTreeMap<String, u128> = curr
            .iter()
            .map(|(k, &v)| (k.clone(), (v * num) / den))
            .collect();
        let scaled_gen: BTreeMap<String, u128> = genesis
            .iter()
            .map(|(k, &v)| (k.clone(), (v * num) / den))
            .collect();
        let idx_scaled =
            compute_geometric_index(&scaled_curr, &scaled_gen, &weights, SCALE).unwrap();
        assert!(
            idx_usd.abs_diff(idx_scaled) <= 2,
            "dimensional invariance mismatch: base={idx_usd}, scaled={idx_scaled}"
        );
    }
}

#[test]
fn test_auto_throttle_closed_form_across_liquidity_tiers() {
    let cfg = ThrottleConfig::default();
    for whole_supply in [100_000u64, 1_000_000, 50_000_000, 1_000_000_000] {
        let supply = pm_from_whole(whole_supply);
        let amm_liq = (supply * 4) / 10;
        let exposure = amm_liq + supply;

        let low = compute_auto_throttle(exposure / 10, amm_liq, supply, &cfg).unwrap();
        assert!(low.coc_pfc_ratio >= 3 * SCALE - 1);
        assert!(low.max_epoch_delta < 50_000_000);
        assert!(low.challenge_hours > 2);
        assert!(low.staker_fee_share > 250_000_000);
        assert_eq!(
            low.staker_fee_share + low.sp_fee_share + low.insurance_fee_share,
            SCALE
        );

        let high = compute_auto_throttle(exposure / 2, amm_liq, supply, &cfg).unwrap();
        assert!(high.coc_pfc_ratio >= 3 * SCALE);
        assert_eq!(high.max_epoch_delta, 50_000_000);
        assert_eq!(high.challenge_hours, 2);
        assert_eq!(high.staker_fee_share, 250_000_000);
    }
}

#[test]
fn test_amm_spoofing_ablation_patched_vs_legacy() {
    let mut patched = PegController::default();
    let mut legacy = PegController {
        mode: PegMode::LegacySpotDrivenR,
        ..PegController::default()
    };

    let mut p_res = None;
    let mut l_res = None;
    for _ in 0..48 {
        p_res = Some(patched.step(SCALE, 850_000_000, 1).unwrap());
        l_res = Some(legacy.step(SCALE, 850_000_000, 1).unwrap());
    }
    let p_res = p_res.unwrap();
    let l_res = l_res.unwrap();

    // Patched decoupled R(t) never inflates above I(t) under spot AMM spoofing
    assert_eq!(p_res.r_price, SCALE);
    assert!(p_res.min_borrow_rate_apr > 200_000_000);

    // Unpatched legacy mode lets spoofing push R(t) above 1.02
    assert!(l_res.r_price > 1_020_000_000);
}

