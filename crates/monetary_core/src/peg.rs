use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::MonetaryError;
use crate::fixed::{
    SCALE, SCALE_I128, WAD, exp_wad, ln_wad, mul_div_ceil, mul_div_floor, mul_div_round,
    mul_div_signed_trunc, scale_from_bps,
};

pub fn default_basket_weights() -> BTreeMap<String, u128> {
    BTreeMap::from([
        ("electricity".to_string(), 250_000_000),
        ("oil_gas".to_string(), 150_000_000),
        ("grain".to_string(), 200_000_000),
        ("metals".to_string(), 150_000_000),
        ("housing".to_string(), 100_000_000),
        ("datacenter_power".to_string(), 150_000_000),
    ])
}

pub fn default_genesis_prices() -> BTreeMap<String, u128> {
    BTreeMap::from([
        ("electricity".to_string(), 100 * SCALE),
        ("oil_gas".to_string(), 80 * SCALE),
        ("grain".to_string(), 250 * SCALE),
        ("metals".to_string(), 8_000 * SCALE),
        ("housing".to_string(), 2_000 * SCALE),
        ("datacenter_power".to_string(), 120 * SCALE),
    ])
}

/// Purchasing-power basket weights and genesis reference prices (`SCALE = 1e9`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasketSpec {
    pub weights: BTreeMap<String, u128>,
    pub genesis_prices: BTreeMap<String, u128>,
    pub i0: u128,
    pub max_annual_weight_shift: u128,
}

impl Default for BasketSpec {
    fn default() -> Self {
        Self::new(
            default_basket_weights(),
            default_genesis_prices(),
            SCALE,
            scale_from_bps(200),
        )
        .expect("default basket spec is valid")
    }
}

impl BasketSpec {
    pub fn new(
        weights: BTreeMap<String, u128>,
        genesis_prices: BTreeMap<String, u128>,
        i0: u128,
        max_annual_weight_shift: u128,
    ) -> Result<Self, MonetaryError> {
        let spec = Self {
            weights,
            genesis_prices,
            i0,
            max_annual_weight_shift,
        };
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<(), MonetaryError> {
        validate_weights(&self.weights)?;
        if self.weights.len() != self.genesis_prices.len()
            || !self
                .weights
                .keys()
                .all(|k| self.genesis_prices.contains_key(k))
        {
            return Err(MonetaryError::InvalidBasketWeights(
                "weights and genesis_prices must share identical asset keys".to_string(),
            ));
        }
        if self.i0 == 0 {
            return Err(MonetaryError::InvalidParameter(
                "basket i0 must be positive".to_string(),
            ));
        }
        for (asset, &px) in &self.genesis_prices {
            if px == 0 {
                return Err(MonetaryError::NonPositivePrice(asset.clone()));
            }
        }
        Ok(())
    }

    /// Updates component weights subject to constitutional `<= max_annual_weight_shift / year` cap.
    pub fn update_weights(
        &mut self,
        new_weights: BTreeMap<String, u128>,
        elapsed_days: u64,
    ) -> Result<(), MonetaryError> {
        if new_weights.len() != self.weights.len()
            || !new_weights.keys().all(|k| self.weights.contains_key(k))
        {
            return Err(MonetaryError::InvalidBasketWeights(
                "new_weights keys must match existing basket components".to_string(),
            ));
        }
        validate_weights(&new_weights)?;
        let max_shift = mul_div_floor(self.max_annual_weight_shift, elapsed_days as u128, 365)?;
        for (asset, &w_new) in &new_weights {
            let delta = w_new.abs_diff(self.weights[asset]);
            if delta > max_shift {
                return Err(MonetaryError::WeightShiftExceedsCap {
                    asset: asset.clone(),
                    delta,
                    max_shift,
                });
            }
        }
        self.weights = new_weights;
        Ok(())
    }

    pub fn index(&self, prices: &BTreeMap<String, u128>) -> Result<u128, MonetaryError> {
        compute_geometric_index(prices, &self.genesis_prices, &self.weights, self.i0)
    }
}

fn validate_weights(weights: &BTreeMap<String, u128>) -> Result<(), MonetaryError> {
    if weights.is_empty() {
        return Err(MonetaryError::InvalidBasketWeights(
            "weights cannot be empty".to_string(),
        ));
    }
    let total: u128 = weights.values().copied().sum();
    if total != SCALE {
        return Err(MonetaryError::InvalidBasketWeights(format!(
            "basket weights must sum to {SCALE}, got {total}"
        )));
    }
    Ok(())
}

/// Computes `I(t) = I_0 * prod_i (P_i(t) / P_i(0)) ^ w_i` in deterministic integer math.
pub fn compute_geometric_index(
    prices: &BTreeMap<String, u128>,
    genesis_prices: &BTreeMap<String, u128>,
    weights: &BTreeMap<String, u128>,
    i0: u128,
) -> Result<u128, MonetaryError> {
    if i0 == 0 {
        return Err(MonetaryError::InvalidParameter(
            "i0 must be positive".to_string(),
        ));
    }
    validate_weights(weights)?;
    if prices.len() != weights.len()
        || genesis_prices.len() != weights.len()
        || !weights
            .keys()
            .all(|k| prices.contains_key(k) && genesis_prices.contains_key(k))
    {
        return Err(MonetaryError::InvalidBasketWeights(
            "prices, genesis_prices, and weights must have identical keys".to_string(),
        ));
    }

    let mut sum_ln_wad: i128 = 0;
    for (asset, &w) in weights {
        let p_t = prices[asset];
        let p_0 = genesis_prices[asset];
        if p_t == 0 || p_0 == 0 {
            return Err(MonetaryError::NonPositivePrice(asset.clone()));
        }
        let ratio_wad = mul_div_round(p_t, WAD, p_0)?;
        let ln_ratio = ln_wad(ratio_wad)?;
        let weighted = mul_div_signed_trunc(ln_ratio, w as i128, SCALE)?;
        sum_ln_wad = sum_ln_wad
            .checked_add(weighted)
            .ok_or(MonetaryError::MathOverflow)?;
    }

    let factor_wad = exp_wad(sum_ln_wad)?;
    mul_div_round(i0, factor_wad, WAD)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrottleConfig {
    pub k_pfc: u128,
    pub baseline_max_delta: u128,
    pub floor_max_delta: u128,
    pub base_challenge_hours: u64,
    pub max_challenge_hours: u64,
    pub base_staker_fee_share: u128,
    pub max_staker_fee_share: u128,
    pub insurance_fee_share: u128,
}

impl Default for ThrottleConfig {
    fn default() -> Self {
        Self {
            k_pfc: 1_500_000_000,               // 1.5
            baseline_max_delta: 50_000_000,     // 5.0%
            floor_max_delta: 5_000_000,         // 0.5%
            base_challenge_hours: 2,
            max_challenge_hours: 168,
            base_staker_fee_share: 250_000_000, // 25%
            max_staker_fee_share: 400_000_000,  // 40%
            insurance_fee_share: 100_000_000,   // 10%
        }
    }
}

/// Closed-form `CoC_51 >= 3.0 * PfC_effective` security, throttling, and fee-routing snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThrottleState {
    pub locked_pm: u128,
    pub amm_liquidity_pm: u128,
    pub total_pm_supply: u128,
    pub exposure_pm: u128,
    pub coc_51_pm: u128,
    pub pfc_unthrottled_pm: u128,
    pub pfc_effective_pm: u128,
    pub coc_pfc_ratio: u128,
    pub max_epoch_delta: u128,
    pub challenge_hours: u64,
    pub staker_fee_share: u128,
    pub sp_fee_share: u128,
    pub insurance_fee_share: u128,
    pub deficit_frac: u128,
}

/// Computes observable PfC, closed-form auto-throttling bounds, and dynamic staker fee share.
pub fn compute_auto_throttle(
    locked_pm: u128,
    amm_liquidity_pm: u128,
    total_pm_supply: u128,
    cfg: &ThrottleConfig,
) -> Result<ThrottleState, MonetaryError> {
    let exposure_pm = amm_liquidity_pm.saturating_add(total_pm_supply).max(1);
    let coc_51_pm = mul_div_floor(locked_pm, 51, 100)?;
    let exp_k = mul_div_floor(exposure_pm, cfg.k_pfc, SCALE)?;
    let pfc_unthrottled_pm = mul_div_floor(exp_k, cfg.baseline_max_delta, SCALE)?;

    let denom_scaled = mul_div_ceil(exposure_pm.saturating_mul(3), cfg.k_pfc, SCALE)?.max(1);
    let raw_delta = mul_div_floor(coc_51_pm, SCALE, denom_scaled)?;
    let max_epoch_delta = raw_delta.clamp(cfg.floor_max_delta, cfg.baseline_max_delta);

    let pfc_effective_pm = mul_div_floor(exp_k, max_epoch_delta, SCALE)?.max(1);
    let coc_pfc_ratio = mul_div_floor(coc_51_pm, SCALE, pfc_effective_pm)?;

    let req_coc_unthrottled = pfc_unthrottled_pm.saturating_mul(3).max(1);
    let deficit_frac = if coc_51_pm >= req_coc_unthrottled {
        0
    } else {
        SCALE - mul_div_floor(coc_51_pm, SCALE, req_coc_unthrottled)?
    };

    let hour_span = cfg.max_challenge_hours.saturating_sub(cfg.base_challenge_hours) as u128;
    let challenge_hours = cfg.base_challenge_hours
        + mul_div_round(deficit_frac, hour_span, SCALE)? as u64;

    let fee_span = cfg
        .max_staker_fee_share
        .saturating_sub(cfg.base_staker_fee_share);
    let staker_fee_share =
        cfg.base_staker_fee_share + mul_div_floor(deficit_frac, fee_span, SCALE)?;
    let sp_fee_share = SCALE
        .saturating_sub(staker_fee_share)
        .saturating_sub(cfg.insurance_fee_share);

    Ok(ThrottleState {
        locked_pm,
        amm_liquidity_pm,
        total_pm_supply,
        exposure_pm,
        coc_51_pm,
        pfc_unthrottled_pm,
        pfc_effective_pm,
        coc_pfc_ratio,
        max_epoch_delta,
        challenge_hours,
        staker_fee_share,
        sp_fee_share,
        insurance_fee_share: cfg.insurance_fee_share,
        deficit_frac,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PegMode {
    #[default]
    PatchedDecoupled,
    LegacySpotDrivenR,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegStepResult {
    pub r_price: u128,
    pub i_oracle: u128,
    pub m_spot: u128,
    pub e_spot: i128,
    pub e_target: i128,
    pub min_borrow_rate_apr: u128,
    pub u_r_applied: i128,
}

/// Decoupled redemption target `R(t)` tracker (`I(t)` only) and spot-error borrow-rate PID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegController {
    pub mode: PegMode,
    pub r_price: u128,
    pub deadband: u128,
    pub u_max_per_day: u128,
    pub k_track_per_day: u128,

    pub min_rate_base_apr: u128,
    pub min_rate_max_apr: u128,
    pub k_p_rate: u128,
    pub k_i_rate: u128,
    pub k_d_rate: u128,
    pub i_max_rate: u128,

    pub k_p_legacy: u128,
    pub k_i_legacy: u128,
    pub k_d_legacy: u128,
    pub u_max_legacy_per_day: u128,
    pub i_max_legacy: u128,

    pub i_term: i128,
    pub prev_error: Option<i128>,
    pub min_borrow_rate_apr: u128,
}

impl Default for PegController {
    fn default() -> Self {
        Self {
            mode: PegMode::PatchedDecoupled,
            r_price: SCALE,
            deadband: 2_500_000,         // 0.0025 (25 bps)
            u_max_per_day: 30_000_000,   // 3.0%/day
            k_track_per_day: 800_000_000,

            min_rate_base_apr: 5_000_000,   // 0.5% APR
            min_rate_max_apr: 250_000_000,  // 25.0% APR
            k_p_rate: 1_500_000_000,
            k_i_rate: 300_000_000,
            k_d_rate: 50_000_000,
            i_max_rate: 100_000_000,

            k_p_legacy: 400_000_000,
            k_i_legacy: 50_000_000,
            k_d_legacy: 20_000_000,
            u_max_legacy_per_day: 15_000_000,
            i_max_legacy: 50_000_000,

            i_term: 0,
            prev_error: None,
            min_borrow_rate_apr: 5_000_000,
        }
    }
}

impl PegController {
    pub fn step(
        &mut self,
        i_oracle: u128,
        m_spot: u128,
        dt_hours: u64,
    ) -> Result<PegStepResult, MonetaryError> {
        if i_oracle == 0 || m_spot == 0 {
            return Err(MonetaryError::InvalidParameter(
                "i_oracle and m_spot must be positive".to_string(),
            ));
        }
        let dt_h = dt_hours.max(1);
        let e_spot = mul_div_signed_trunc((i_oracle as i128) - (m_spot as i128), SCALE_I128, i_oracle)?;
        let e_target =
            mul_div_signed_trunc((i_oracle as i128) - (self.r_price as i128), SCALE_I128, i_oracle)?;

        match self.mode {
            PegMode::PatchedDecoupled => {
                let mut u_r: i128 = 0;
                if e_target != 0 {
                    let raw_u = mul_div_signed_trunc(self.k_track_per_day as i128, e_target, SCALE)?;
                    let max_u = self.u_max_per_day as i128;
                    u_r = raw_u.clamp(-max_u, max_u);
                    let u_dt = mul_div_signed_trunc(u_r, dt_h as i128, 24)?;
                    let r_delta = mul_div_signed_trunc(self.r_price as i128, u_dt, SCALE)?;
                    let r_candidate = (self.r_price as i128 + r_delta).max(1) as u128;
                    let lo = self.r_price.min(i_oracle);
                    let hi = self.r_price.max(i_oracle);
                    self.r_price = r_candidate.clamp(lo, hi);
                }

                if e_spot.unsigned_abs() < self.deadband {
                    if dt_h >= 48 {
                        self.i_term = 0;
                    } else {
                        self.i_term =
                            mul_div_signed_trunc(self.i_term, (48 - dt_h) as i128, 48)?;
                    }
                    self.min_borrow_rate_apr = self.min_rate_base_apr;
                } else {
                    let p_term = mul_div_signed_trunc(self.k_p_rate as i128, e_spot, SCALE)?;
                    let e_dt = mul_div_signed_trunc(e_spot, dt_h as i128, 24)?;
                    let i_delta = mul_div_signed_trunc(self.k_i_rate as i128, e_dt, SCALE)?;
                    let max_i = self.i_max_rate as i128;
                    self.i_term = (self.i_term + i_delta).clamp(-max_i, max_i);
                    let d_term = match self.prev_error {
                        None => 0,
                        Some(prev) => mul_div_signed_trunc(
                            self.k_d_rate as i128,
                            (e_spot - prev) * 24,
                            SCALE * (dt_h as u128),
                        )?,
                    };
                    let raw_rate = self.min_rate_base_apr as i128 + p_term + self.i_term + d_term;
                    let clamped = raw_rate
                        .max(self.min_rate_base_apr as i128)
                        .min(self.min_rate_max_apr as i128);
                    self.min_borrow_rate_apr = clamped as u128;
                }
                self.prev_error = Some(e_spot);

                let final_e_target = mul_div_signed_trunc(
                    (i_oracle as i128) - (self.r_price as i128),
                    SCALE_I128,
                    i_oracle,
                )?;
                Ok(PegStepResult {
                    r_price: self.r_price,
                    i_oracle,
                    m_spot,
                    e_spot,
                    e_target: final_e_target,
                    min_borrow_rate_apr: self.min_borrow_rate_apr,
                    u_r_applied: u_r,
                })
            }
            PegMode::LegacySpotDrivenR => {
                let u_legacy = if e_spot.unsigned_abs() < self.deadband {
                    0
                } else {
                    let p_term = mul_div_signed_trunc(self.k_p_legacy as i128, e_spot, SCALE)?;
                    let e_dt = mul_div_signed_trunc(e_spot, dt_h as i128, 24)?;
                    let i_delta = mul_div_signed_trunc(self.k_i_legacy as i128, e_dt, SCALE)?;
                    let max_i = self.i_max_legacy as i128;
                    self.i_term = (self.i_term + i_delta).clamp(-max_i, max_i);
                    let d_term = match self.prev_error {
                        None => 0,
                        Some(prev) => mul_div_signed_trunc(
                            self.k_d_legacy as i128,
                            (e_spot - prev) * 24,
                            SCALE * (dt_h as u128),
                        )?,
                    };
                    let max_u = self.u_max_legacy_per_day as i128;
                    (p_term + self.i_term + d_term).clamp(-max_u, max_u)
                };
                self.prev_error = Some(e_spot);
                let u_dt = mul_div_signed_trunc(u_legacy, dt_h as i128, 24)?;
                let r_delta = mul_div_signed_trunc(self.r_price as i128, u_dt, SCALE)?;
                self.r_price = (self.r_price as i128 + r_delta).max(1_000) as u128;
                self.min_borrow_rate_apr = self.min_rate_base_apr;
                let final_e_target = mul_div_signed_trunc(
                    (i_oracle as i128) - (self.r_price as i128),
                    SCALE_I128,
                    i_oracle,
                )?;
                Ok(PegStepResult {
                    r_price: self.r_price,
                    i_oracle,
                    m_spot,
                    e_spot,
                    e_target: final_e_target,
                    min_borrow_rate_apr: self.min_borrow_rate_apr,
                    u_r_applied: u_legacy,
                })
            }
        }
    }
}

