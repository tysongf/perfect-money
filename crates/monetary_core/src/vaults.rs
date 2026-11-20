use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::MonetaryError;
use crate::fixed::{
    PM_SCALE, SCALE, SCALE_TO_PM, decay_half_life, isqrt_u256, mul_div_ceil, mul_div_floor,
    mul_u128_wide, scale_from_bps,
};
use crate::peg::ThrottleState;

/// Isolated collateral branch with independent MCR, liquidation threshold, and Stability Pool.
///
/// Quantities `stability_pool_collateral` use `SCALE` (`1e9`); `price`, `mint_mcr`, `liq_cr`, and
/// `liq_discount` use `SCALE` (`1e9`); PM debt and pools use `PM_SCALE` (`1e6`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollateralBranch {
    pub name: String,
    pub mint_mcr: u128,
    pub liq_cr: u128,
    pub liq_discount: u128,
    pub price: u128,
    pub stability_pool_pm: u128,
    pub stability_pool_collateral: u128,
    pub total_liquidated_debt_pm: u128,
    pub total_redistributed_debt_pm: u128,
    pub total_sp_offset_pm: u128,
    pub total_insurance_offset_pm: u128,
    pub unbacked_bad_debt_pm: u128,
}

pub fn default_collateral_branches() -> BTreeMap<String, CollateralBranch> {
    BTreeMap::from([
        (
            "ETH".to_string(),
            CollateralBranch {
                name: "ETH".to_string(),
                mint_mcr: 1_500_000_000,
                liq_cr: 1_150_000_000,
                liq_discount: 50_000_000,
                price: 3_000 * SCALE,
                stability_pool_pm: 0,
                stability_pool_collateral: 0,
                total_liquidated_debt_pm: 0,
                total_redistributed_debt_pm: 0,
                total_sp_offset_pm: 0,
                total_insurance_offset_pm: 0,
                unbacked_bad_debt_pm: 0,
            },
        ),
        (
            "BTC".to_string(),
            CollateralBranch {
                name: "BTC".to_string(),
                mint_mcr: 1_500_000_000,
                liq_cr: 1_150_000_000,
                liq_discount: 50_000_000,
                price: 90_000 * SCALE,
                stability_pool_pm: 0,
                stability_pool_collateral: 0,
                total_liquidated_debt_pm: 0,
                total_redistributed_debt_pm: 0,
                total_sp_offset_pm: 0,
                total_insurance_offset_pm: 0,
                unbacked_bad_debt_pm: 0,
            },
        ),
        (
            "SOL".to_string(),
            CollateralBranch {
                name: "SOL".to_string(),
                mint_mcr: 1_750_000_000,
                liq_cr: 1_250_000_000,
                liq_discount: 80_000_000,
                price: 180 * SCALE,
                stability_pool_pm: 0,
                stability_pool_collateral: 0,
                total_liquidated_debt_pm: 0,
                total_redistributed_debt_pm: 0,
                total_sp_offset_pm: 0,
                total_insurance_offset_pm: 0,
                unbacked_bad_debt_pm: 0,
            },
        ),
    ])
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vault {
    pub vault_id: String,
    pub owner: String,
    pub branch: String,
    pub collateral_qty: u128,
    pub debt_pm: u128,
    pub borrow_rate_apr: u128,
}

impl Vault {
    pub fn collateral_ratio(
        &self,
        collateral_price: u128,
        r_price: u128,
    ) -> Result<u128, MonetaryError> {
        compute_cr(self.collateral_qty, collateral_price, self.debt_pm, r_price)
    }
}

pub fn compute_cr(
    collateral_qty: u128,
    collateral_price: u128,
    debt_pm: u128,
    r_price: u128,
) -> Result<u128, MonetaryError> {
    if debt_pm == 0 {
        return Ok(u128::MAX);
    }
    if r_price == 0 {
        return Err(MonetaryError::DivisionByZero);
    }
    if let (Some(col_scaled), Some(debt_times_r)) =
        (collateral_qty.checked_mul(PM_SCALE), debt_pm.checked_mul(r_price))
    {
        return mul_div_floor(col_scaled, collateral_price, debt_times_r);
    }
    let col_val_pm = mul_div_floor(collateral_qty, collateral_price, SCALE * SCALE_TO_PM)?;
    let debt_val_pm = mul_div_ceil(debt_pm, r_price, SCALE)?.max(1);
    mul_div_floor(col_val_pm, SCALE, debt_val_pm)
}

/// Constant-product PM / numeraire spot AMM (`pm_reserve` and `numeraire_reserve` in `PM_SCALE`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpotAmm {
    pub pm_reserve: u128,
    pub numeraire_reserve: u128,
    pub fee_rate: u128,
}

impl Default for SpotAmm {
    fn default() -> Self {
        Self {
            pm_reserve: 250_000 * PM_SCALE,
            numeraire_reserve: 250_000 * PM_SCALE,
            fee_rate: scale_from_bps(30), // 0.30%
        }
    }
}

impl SpotAmm {
    pub fn new(pm_reserve: u128, numeraire_reserve: u128, fee_rate: u128) -> Result<Self, MonetaryError> {
        if pm_reserve == 0 || numeraire_reserve == 0 {
            return Err(MonetaryError::InvalidParameter(
                "AMM reserves must be strictly positive".to_string(),
            ));
        }
        if fee_rate >= SCALE {
            return Err(MonetaryError::InvalidParameter(
                "AMM fee_rate must be < 1.0".to_string(),
            ));
        }
        Ok(Self {
            pm_reserve,
            numeraire_reserve,
            fee_rate,
        })
    }

    pub fn spot_price(&self) -> Result<u128, MonetaryError> {
        mul_div_floor(self.numeraire_reserve, SCALE, self.pm_reserve)
    }

    pub fn liquidity_pm_equiv(&self) -> u128 {
        self.pm_reserve.saturating_mul(2)
    }

    pub fn quote_numeraire_to_pm(&self, numeraire_in: u128) -> Result<u128, MonetaryError> {
        if numeraire_in == 0 {
            return Ok(0);
        }
        let eff_in = mul_div_floor(numeraire_in, SCALE - self.fee_rate, SCALE)?;
        mul_div_floor(self.pm_reserve, eff_in, self.numeraire_reserve + eff_in)
    }

    pub fn quote_pm_to_numeraire(&self, pm_in: u128) -> Result<u128, MonetaryError> {
        if pm_in == 0 {
            return Ok(0);
        }
        let eff_in = mul_div_floor(pm_in, SCALE - self.fee_rate, SCALE)?;
        mul_div_floor(self.numeraire_reserve, eff_in, self.pm_reserve + eff_in)
    }

    pub fn swap_numeraire_for_pm(&mut self, numeraire_in: u128) -> Result<u128, MonetaryError> {
        if numeraire_in == 0 {
            return Err(MonetaryError::InvalidParameter(
                "numeraire_in must be positive".to_string(),
            ));
        }
        let pm_out = self.quote_numeraire_to_pm(numeraire_in)?;
        self.numeraire_reserve += numeraire_in;
        self.pm_reserve -= pm_out;
        Ok(pm_out)
    }

    pub fn swap_pm_for_numeraire(&mut self, pm_in: u128) -> Result<u128, MonetaryError> {
        if pm_in == 0 {
            return Err(MonetaryError::InvalidParameter(
                "pm_in must be positive".to_string(),
            ));
        }
        let num_out = self.quote_pm_to_numeraire(pm_in)?;
        self.pm_reserve += pm_in;
        self.numeraire_reserve -= num_out;
        Ok(num_out)
    }

    pub fn optimal_numeraire_in_for_target_price(
        &self,
        effective_target_price: u128,
    ) -> Result<u128, MonetaryError> {
        if effective_target_price == 0 {
            return Ok(0);
        }
        let gamma = SCALE - self.fee_rate;
        let threshold = mul_div_floor(effective_target_price, gamma, SCALE)?;
        if self.spot_price()? >= threshold {
            return Ok(0);
        }
        let eff_factor = mul_div_floor(effective_target_price, gamma, SCALE)?;
        let a = mul_div_floor(self.pm_reserve, eff_factor, SCALE)?;
        let (hi, lo) = mul_u128_wide(a, self.numeraire_reserve);
        let num_after = isqrt_u256(hi, lo);
        if num_after <= self.numeraire_reserve {
            return Ok(0);
        }
        mul_div_floor(num_after - self.numeraire_reserve, SCALE, gamma)
    }

    pub fn optimal_pm_in_for_target_price(&self, r_price: u128) -> Result<u128, MonetaryError> {
        if r_price == 0 {
            return Err(MonetaryError::DivisionByZero);
        }
        let gamma = SCALE - self.fee_rate;
        if mul_div_floor(self.spot_price()?, gamma, SCALE)? <= r_price {
            return Ok(0);
        }
        let num_scaled = mul_div_floor(self.numeraire_reserve, gamma, r_price)?;
        let (hi, lo) = mul_u128_wide(num_scaled, self.pm_reserve);
        let pm_after = isqrt_u256(hi, lo);
        if pm_after <= self.pm_reserve {
            return Ok(0);
        }
        mul_div_floor(pm_after - self.pm_reserve, SCALE, gamma)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedemptionReceipt {
    pub pm_redeemed: u128,
    pub collateral_numeraire_received: u128,
    pub fee_rate: u128,
    pub fee_total_numeraire: u128,
    pub fee_to_vaults_numeraire: u128,
    pub fee_to_insurance_numeraire: u128,
    pub collateral_received_by_branch: BTreeMap<String, u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiquidationReport {
    pub branch: String,
    pub liquidated_vaults: usize,
    pub debt_cleared_pm: u128,
    pub sp_offset_pm: u128,
    pub insurance_offset_pm: u128,
    pub redistributed_debt_pm: u128,
    pub unbacked_bad_debt_pm: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultAndAmmSystem {
    pub branches: BTreeMap<String, CollateralBranch>,
    pub amm: SpotAmm,
    pub vaults: BTreeMap<String, Vault>,
    pub agent_pm: BTreeMap<String, u128>,
    pub agent_numeraire: BTreeMap<String, u128>,
    pub agent_collateral: BTreeMap<String, BTreeMap<String, u128>>,

    pub insurance_reserve_pm: u128,
    pub insurance_collateral_numeraire: u128,
    pub oracle_fee_pool_pm: u128,
    pub pending_dispute_bonds_pm: u128,
    /// PM minted out into Phase 1 `ledger_core::LedgerState` via the vault bridge.
    pub ledger_bridge_pm: u128,

    pub circulating_pm_supply: u128,
    pub cumulative_slash_burned_pm: u128,
    pub unbacked_bad_debt_pm: u128,
    pub cumulative_vault_mints_pm: u128,
    pub cumulative_vault_burns_pm: u128,

    pub redemption_base_rate: u128,
    pub last_redemption_hour: u64,
    pub redemption_floor_fee: u128,
    pub redemption_cap_fee: u128,
    pub redemption_halflife_hours: u64,

    pub next_vault_num: u64,
}

impl Default for VaultAndAmmSystem {
    fn default() -> Self {
        Self::new(default_collateral_branches(), SpotAmm::default())
    }
}

impl VaultAndAmmSystem {
    pub fn new(branches: BTreeMap<String, CollateralBranch>, amm: SpotAmm) -> Self {
        Self {
            branches,
            amm,
            vaults: BTreeMap::new(),
            agent_pm: BTreeMap::new(),
            agent_numeraire: BTreeMap::new(),
            agent_collateral: BTreeMap::new(),
            insurance_reserve_pm: 0,
            insurance_collateral_numeraire: 0,
            oracle_fee_pool_pm: 0,
            pending_dispute_bonds_pm: 0,
            ledger_bridge_pm: 0,
            circulating_pm_supply: 0,
            cumulative_slash_burned_pm: 0,
            unbacked_bad_debt_pm: 0,
            cumulative_vault_mints_pm: 0,
            cumulative_vault_burns_pm: 0,
            redemption_base_rate: 0,
            last_redemption_hour: 0,
            redemption_floor_fee: 5_000_000, // 0.5%
            redemption_cap_fee: 50_000_000,  // 5.0%
            redemption_halflife_hours: 6,
            next_vault_num: 1,
        }
    }

    /// Creates a genesis-backed system whose `amm.pm_reserve` is backed by a `protocol_lp` ETH vault.
    pub fn new_backed(
        branches: BTreeMap<String, CollateralBranch>,
        amm: SpotAmm,
    ) -> Result<Self, MonetaryError> {
        let mut sys = Self::new(branches, amm);
        let eth_px = sys
            .branches
            .get("ETH")
            .ok_or_else(|| MonetaryError::UnknownBranch("ETH".to_string()))?
            .price;
        let amm_pm = sys.amm.pm_reserve;
        let col_qty = mul_div_ceil(amm_pm * 25, SCALE * SCALE_TO_PM, 10 * eth_px)?;
        sys.vaults.insert(
            "V_AMM_LP".to_string(),
            Vault {
                vault_id: "V_AMM_LP".to_string(),
                owner: "protocol_lp".to_string(),
                branch: "ETH".to_string(),
                collateral_qty: col_qty,
                debt_pm: amm_pm,
                borrow_rate_apr: 50_000_000,
            },
        );
        sys.ensure_agent("protocol_lp");
        sys.circulating_pm_supply = amm_pm;
        sys.cumulative_vault_mints_pm = amm_pm;
        sys.assert_conservation(0)?;
        Ok(sys)
    }

    pub fn ensure_agent(&mut self, agent_id: &str) {
        self.agent_pm.entry(agent_id.to_string()).or_insert(0);
        self.agent_numeraire
            .entry(agent_id.to_string())
            .or_insert(0);
        let col_map = self
            .agent_collateral
            .entry(agent_id.to_string())
            .or_default();
        for b in self.branches.keys() {
            col_map.entry(b.clone()).or_insert(0);
        }
    }

    pub fn credit_pm(&mut self, agent_id: &str, amount: u128) {
        self.ensure_agent(agent_id);
        *self.agent_pm.get_mut(agent_id).expect("ensured") += amount;
    }

    pub fn credit_collateral(&mut self, agent_id: &str, branch_name: &str, qty: u128) -> Result<(), MonetaryError> {
        if !self.branches.contains_key(branch_name) {
            return Err(MonetaryError::UnknownBranch(branch_name.to_string()));
        }
        self.ensure_agent(agent_id);
        *self
            .agent_collateral
            .get_mut(agent_id)
            .expect("ensured")
            .entry(branch_name.to_string())
            .or_insert(0) += qty;
        Ok(())
    }

    pub fn active_vault_debt(&self) -> u128 {
        self.vaults.values().map(|v| v.debt_pm).sum()
    }

    pub fn total_sp_pm(&self) -> u128 {
        self.branches.values().map(|b| b.stability_pool_pm).sum()
    }

    pub fn current_redemption_fee(&self, current_hour: u64) -> Result<u128, MonetaryError> {
        let elapsed = current_hour.saturating_sub(self.last_redemption_hour);
        let decayed = decay_half_life(
            self.redemption_base_rate,
            elapsed,
            self.redemption_halflife_hours,
        )?;
        Ok(self.redemption_cap_fee.min(self.redemption_floor_fee + decayed))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_or_mint_vault(
        &mut self,
        owner: &str,
        branch_name: &str,
        add_collateral_qty: u128,
        mint_pm: u128,
        borrow_rate_apr: u128,
        r_price: u128,
        min_borrow_rate_apr: u128,
        vault_id: Option<&str>,
        skip_owner_collateral_deduct: bool,
        initial_allocation_target: Option<&str>,
    ) -> Result<Vault, MonetaryError> {
        let vault = self.apply_vault_mint_inner(
            owner,
            branch_name,
            add_collateral_qty,
            mint_pm,
            borrow_rate_apr,
            r_price,
            min_borrow_rate_apr,
            vault_id,
            skip_owner_collateral_deduct,
        )?;
        if mint_pm > 0 {
            let recipient = initial_allocation_target.unwrap_or(owner);
            self.credit_pm(recipient, mint_pm);
            self.circulating_pm_supply += mint_pm;
            self.cumulative_vault_mints_pm += mint_pm;
        }
        Ok(vault)
    }

    /// Mints vault debt directly into `ledger_bridge_pm` for atomic `LedgerState` supply issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_vault_to_bridge(
        &mut self,
        owner: &str,
        branch_name: &str,
        add_collateral_qty: u128,
        mint_pm: u128,
        borrow_rate_apr: u128,
        r_price: u128,
        min_borrow_rate_apr: u128,
        vault_id: Option<&str>,
        skip_owner_collateral_deduct: bool,
    ) -> Result<Vault, MonetaryError> {
        if mint_pm == 0 {
            return Err(MonetaryError::InvalidParameter(
                "mint_pm to ledger bridge must be > 0".to_string(),
            ));
        }
        let vault = self.apply_vault_mint_inner(
            owner,
            branch_name,
            add_collateral_qty,
            mint_pm,
            borrow_rate_apr,
            r_price,
            min_borrow_rate_apr,
            vault_id,
            skip_owner_collateral_deduct,
        )?;
        self.ledger_bridge_pm += mint_pm;
        self.circulating_pm_supply += mint_pm;
        self.cumulative_vault_mints_pm += mint_pm;
        Ok(vault)
    }

    #[allow(clippy::too_many_arguments)]
    fn apply_vault_mint_inner(
        &mut self,
        owner: &str,
        branch_name: &str,
        add_collateral_qty: u128,
        mint_pm: u128,
        borrow_rate_apr: u128,
        r_price: u128,
        min_borrow_rate_apr: u128,
        vault_id: Option<&str>,
        skip_owner_collateral_deduct: bool,
    ) -> Result<Vault, MonetaryError> {
        let branch = self
            .branches
            .get(branch_name)
            .ok_or_else(|| MonetaryError::UnknownBranch(branch_name.to_string()))?
            .clone();
        if borrow_rate_apr < min_borrow_rate_apr {
            return Err(MonetaryError::BorrowRateBelowFloor {
                rate: borrow_rate_apr,
                floor: min_borrow_rate_apr,
            });
        }
        self.ensure_agent(owner);
        if !skip_owner_collateral_deduct && add_collateral_qty > 0 {
            let avail = self.agent_collateral[owner][branch_name];
            if avail < add_collateral_qty {
                return Err(MonetaryError::InsufficientBalance {
                    kind: "collateral",
                    requested: add_collateral_qty,
                    available: avail,
                });
            }
        }

        let (mut vault, existed) = if let Some(vid) = vault_id {
            if let Some(existing) = self.vaults.get(vid) {
                if existing.owner != owner || existing.branch != branch_name {
                    return Err(MonetaryError::VaultOwnerOrBranchMismatch);
                }
                (existing.clone(), true)
            } else {
                (
                    Vault {
                        vault_id: vid.to_string(),
                        owner: owner.to_string(),
                        branch: branch_name.to_string(),
                        collateral_qty: 0,
                        debt_pm: 0,
                        borrow_rate_apr,
                    },
                    false,
                )
            }
        } else {
            let vid = format!("V_{branch_name}_{}", self.next_vault_num);
            (
                Vault {
                    vault_id: vid,
                    owner: owner.to_string(),
                    branch: branch_name.to_string(),
                    collateral_qty: 0,
                    debt_pm: 0,
                    borrow_rate_apr,
                },
                false,
            )
        };

        let new_col = vault
            .collateral_qty
            .checked_add(add_collateral_qty)
            .ok_or(MonetaryError::MathOverflow)?;
        let new_debt = vault
            .debt_pm
            .checked_add(mint_pm)
            .ok_or(MonetaryError::MathOverflow)?;
        if new_debt > 0 {
            let cr = compute_cr(new_col, branch.price, new_debt, r_price)?;
            if cr < branch.mint_mcr {
                return Err(MonetaryError::CollateralRatioBelowMcr {
                    branch: branch_name.to_string(),
                    cr,
                    mcr: branch.mint_mcr,
                });
            }
        }

        if !skip_owner_collateral_deduct && add_collateral_qty > 0 {
            *self
                .agent_collateral
                .get_mut(owner)
                .expect("ensured")
                .get_mut(branch_name)
                .expect("ensured") -= add_collateral_qty;
        }
        if !existed && vault_id.is_none() {
            self.next_vault_num += 1;
        }
        vault.collateral_qty = new_col;
        vault.debt_pm = new_debt;
        vault.borrow_rate_apr = borrow_rate_apr;
        self.vaults.insert(vault.vault_id.clone(), vault.clone());
        Ok(vault)
    }

    pub fn add_collateral(
        &mut self,
        owner: &str,
        vault_id: &str,
        add_collateral_qty: u128,
    ) -> Result<Vault, MonetaryError> {
        let branch = {
            let v = self
                .vaults
                .get(vault_id)
                .ok_or_else(|| MonetaryError::UnknownVault(vault_id.to_string()))?;
            if v.owner != owner {
                return Err(MonetaryError::VaultOwnerOrBranchMismatch);
            }
            v.branch.clone()
        };
        self.ensure_agent(owner);
        let avail = self.agent_collateral[owner][&branch];
        if avail < add_collateral_qty {
            return Err(MonetaryError::InsufficientBalance {
                kind: "collateral",
                requested: add_collateral_qty,
                available: avail,
            });
        }
        *self
            .agent_collateral
            .get_mut(owner)
            .expect("ensured")
            .get_mut(&branch)
            .expect("ensured") -= add_collateral_qty;
        let v = self.vaults.get_mut(vault_id).expect("checked");
        v.collateral_qty += add_collateral_qty;
        Ok(v.clone())
    }

    pub fn withdraw_collateral(
        &mut self,
        owner: &str,
        vault_id: &str,
        withdraw_qty: u128,
        r_price: u128,
    ) -> Result<Vault, MonetaryError> {
        let (branch_name, cur_col, debt_pm) = {
            let v = self
                .vaults
                .get(vault_id)
                .ok_or_else(|| MonetaryError::UnknownVault(vault_id.to_string()))?;
            if v.owner != owner {
                return Err(MonetaryError::VaultOwnerOrBranchMismatch);
            }
            (v.branch.clone(), v.collateral_qty, v.debt_pm)
        };
        if cur_col < withdraw_qty {
            return Err(MonetaryError::InsufficientBalance {
                kind: "vault_collateral",
                requested: withdraw_qty,
                available: cur_col,
            });
        }
        let branch = self.branches[&branch_name].clone();
        let new_col = cur_col - withdraw_qty;
        if debt_pm > 0 {
            let cr = compute_cr(new_col, branch.price, debt_pm, r_price)?;
            if cr < branch.mint_mcr {
                return Err(MonetaryError::CollateralRatioBelowMcr {
                    branch: branch_name,
                    cr,
                    mcr: branch.mint_mcr,
                });
            }
        }
        let v = self.vaults.get_mut(vault_id).expect("checked");
        v.collateral_qty = new_col;
        let updated = v.clone();
        self.credit_collateral(owner, &updated.branch, withdraw_qty)?;
        Ok(updated)
    }

    pub fn deposit_to_stability_pool(
        &mut self,
        agent_id: &str,
        branch_name: &str,
        pm_amount: u128,
    ) -> Result<(), MonetaryError> {
        if !self.branches.contains_key(branch_name) {
            return Err(MonetaryError::UnknownBranch(branch_name.to_string()));
        }
        self.ensure_agent(agent_id);
        let avail = self.agent_pm[agent_id];
        if avail < pm_amount {
            return Err(MonetaryError::InsufficientBalance {
                kind: "pm",
                requested: pm_amount,
                available: avail,
            });
        }
        *self.agent_pm.get_mut(agent_id).expect("ensured") -= pm_amount;
        self.branches.get_mut(branch_name).expect("checked").stability_pool_pm += pm_amount;
        Ok(())
    }

    pub fn withdraw_from_stability_pool(
        &mut self,
        agent_id: &str,
        branch_name: &str,
        pm_amount: u128,
    ) -> Result<u128, MonetaryError> {
        let sp_avail = self
            .branches
            .get(branch_name)
            .ok_or_else(|| MonetaryError::UnknownBranch(branch_name.to_string()))?
            .stability_pool_pm;
        let actual = sp_avail.min(pm_amount);
        self.branches
            .get_mut(branch_name)
            .expect("checked")
            .stability_pool_pm -= actual;
        self.credit_pm(agent_id, actual);
        Ok(actual)
    }

    pub fn repay_vault(&mut self, vault_id: &str, repay_pm: u128) -> Result<u128, MonetaryError> {
        let (owner, debt) = {
            let v = self
                .vaults
                .get(vault_id)
                .ok_or_else(|| MonetaryError::UnknownVault(vault_id.to_string()))?;
            (v.owner.clone(), v.debt_pm)
        };
        self.ensure_agent(&owner);
        let actual = repay_pm.min(debt).min(self.agent_pm[&owner]);
        if actual == 0 {
            return Ok(0);
        }
        *self.agent_pm.get_mut(&owner).expect("ensured") -= actual;
        self.vaults.get_mut(vault_id).expect("checked").debt_pm -= actual;
        self.circulating_pm_supply -= actual;
        self.cumulative_vault_burns_pm += actual;
        Ok(actual)
    }

    pub fn repay_vault_from_bridge(
        &mut self,
        vault_id: &str,
        repay_pm: u128,
    ) -> Result<u128, MonetaryError> {
        let debt = self
            .vaults
            .get(vault_id)
            .ok_or_else(|| MonetaryError::UnknownVault(vault_id.to_string()))?
            .debt_pm;
        let actual = repay_pm.min(debt).min(self.ledger_bridge_pm);
        if actual == 0 {
            return Ok(0);
        }
        self.ledger_bridge_pm -= actual;
        self.vaults.get_mut(vault_id).expect("checked").debt_pm -= actual;
        self.circulating_pm_supply -= actual;
        self.cumulative_vault_burns_pm += actual;
        Ok(actual)
    }

    pub fn swap_numeraire_for_pm(
        &mut self,
        agent_id: &str,
        numeraire_in: u128,
    ) -> Result<u128, MonetaryError> {
        self.ensure_agent(agent_id);
        let avail = self.agent_numeraire[agent_id];
        if numeraire_in == 0 || avail < numeraire_in {
            return Err(MonetaryError::InsufficientBalance {
                kind: "numeraire",
                requested: numeraire_in,
                available: avail,
            });
        }
        *self.agent_numeraire.get_mut(agent_id).expect("ensured") -= numeraire_in;
        let pm_out = self.amm.swap_numeraire_for_pm(numeraire_in)?;
        *self.agent_pm.get_mut(agent_id).expect("ensured") += pm_out;
        Ok(pm_out)
    }

    pub fn swap_pm_for_numeraire(
        &mut self,
        agent_id: &str,
        pm_in: u128,
    ) -> Result<u128, MonetaryError> {
        self.ensure_agent(agent_id);
        let avail = self.agent_pm[agent_id];
        if pm_in == 0 || avail < pm_in {
            return Err(MonetaryError::InsufficientBalance {
                kind: "pm",
                requested: pm_in,
                available: avail,
            });
        }
        *self.agent_pm.get_mut(agent_id).expect("ensured") -= pm_in;
        let num_out = self.amm.swap_pm_for_numeraire(pm_in)?;
        *self.agent_numeraire.get_mut(agent_id).expect("ensured") += num_out;
        Ok(num_out)
    }

    pub fn accrue_hourly_interest(
        &mut self,
        throttle: &ThrottleState,
        min_borrow_rate_apr: u128,
        dt_hours: u64,
    ) -> Result<u128, MonetaryError> {
        if dt_hours == 0 {
            return Ok(0);
        }
        let mut total_interest = 0u128;
        for vault in self.vaults.values_mut() {
            if vault.debt_pm == 0 {
                continue;
            }
            let effective_rate = vault.borrow_rate_apr.max(min_borrow_rate_apr);
            vault.borrow_rate_apr = effective_rate;
            let interest =
                mul_div_floor(vault.debt_pm, effective_rate * (dt_hours as u128), SCALE * 8_760)?;
            if interest == 0 {
                continue;
            }
            vault.debt_pm += interest;
            total_interest += interest;

            let staker_part = mul_div_floor(interest, throttle.staker_fee_share, SCALE)?;
            let ins_part = mul_div_floor(interest, throttle.insurance_fee_share, SCALE)?;
            let sp_part = interest - staker_part - ins_part;

            self.oracle_fee_pool_pm += staker_part;
            self.insurance_reserve_pm += ins_part;
            self.branches
                .get_mut(&vault.branch)
                .expect("vault branch exists")
                .stability_pool_pm += sp_part;
        }
        self.circulating_pm_supply += total_interest;
        self.cumulative_vault_mints_pm += total_interest;
        Ok(total_interest)
    }

    pub fn redeem_pm(
        &mut self,
        redeemer: &str,
        pm_amount: u128,
        r_price: u128,
        current_hour: u64,
        convert_to_numeraire: bool,
    ) -> Result<RedemptionReceipt, MonetaryError> {
        self.ensure_agent(redeemer);
        let max_avail = pm_amount
            .min(self.agent_pm[redeemer])
            .min(self.active_vault_debt());
        self.redeem_pm_inner(
            redeemer,
            max_avail,
            r_price,
            current_hour,
            convert_to_numeraire,
            false,
        )
    }

    pub fn redeem_pm_from_bridge(
        &mut self,
        redeemer: &str,
        pm_amount: u128,
        r_price: u128,
        current_hour: u64,
        convert_to_numeraire: bool,
    ) -> Result<RedemptionReceipt, MonetaryError> {
        self.ensure_agent(redeemer);
        let max_avail = pm_amount
            .min(self.ledger_bridge_pm)
            .min(self.active_vault_debt());
        self.redeem_pm_inner(
            redeemer,
            max_avail,
            r_price,
            current_hour,
            convert_to_numeraire,
            true,
        )
    }

    fn redeem_pm_inner(
        &mut self,
        redeemer: &str,
        max_avail: u128,
        r_price: u128,
        current_hour: u64,
        convert_to_numeraire: bool,
        from_bridge: bool,
    ) -> Result<RedemptionReceipt, MonetaryError> {
        if r_price == 0 {
            return Err(MonetaryError::DivisionByZero);
        }
        if max_avail == 0 {
            return Ok(RedemptionReceipt {
                pm_redeemed: 0,
                collateral_numeraire_received: 0,
                fee_rate: self.current_redemption_fee(current_hour)?,
                fee_total_numeraire: 0,
                fee_to_vaults_numeraire: 0,
                fee_to_insurance_numeraire: 0,
                collateral_received_by_branch: BTreeMap::new(),
            });
        }

        let dt_h = current_hour.saturating_sub(self.last_redemption_hour);
        self.redemption_base_rate =
            decay_half_life(self.redemption_base_rate, dt_h, self.redemption_halflife_hours)?;
        self.last_redemption_hour = current_hour;

        let f_redeem = self
            .redemption_cap_fee
            .min(self.redemption_floor_fee + self.redemption_base_rate);

        let mut candidates: Vec<(u128, u128, String)> = Vec::new();
        for v in self.vaults.values() {
            if v.debt_pm == 0 {
                continue;
            }
            let cr = v.collateral_ratio(self.branches[&v.branch].price, r_price)?;
            candidates.push((v.borrow_rate_apr, cr, v.vault_id.clone()));
        }
        candidates.sort();

        let eff_r = mul_div_ceil(r_price, SCALE - (f_redeem / 2), SCALE)?.max(1);
        let mut remaining = max_avail;
        let mut total_redeemed = 0u128;
        let mut total_col_received_val = 0u128;
        let mut total_fee_val = 0u128;
        let mut total_vault_fee_val = 0u128;
        let mut total_ins_fee_val = 0u128;
        let mut by_branch: BTreeMap<String, u128> = BTreeMap::new();

        for (_, _, vid) in candidates {
            if remaining == 0 {
                break;
            }
            let (col_qty, debt_pm, branch_name) = {
                let v = &self.vaults[&vid];
                (v.collateral_qty, v.debt_pm, v.branch.clone())
            };
            let col_px = self.branches[&branch_name].price;
            let max_pm_by_col = mul_div_floor(col_qty, col_px, eff_r * SCALE_TO_PM)?;
            let d_pm = remaining.min(debt_pm).min(max_pm_by_col);
            if d_pm == 0 {
                continue;
            }

            let gross_val = mul_div_floor(d_pm, r_price, SCALE)?;
            let fee_val = mul_div_floor(gross_val, f_redeem, SCALE)?;
            let ins_fee_val = fee_val / 2;
            let vault_keep_val = fee_val - ins_fee_val;
            let redeemer_val = gross_val - fee_val;

            let redeemer_col_qty = mul_div_floor(redeemer_val * SCALE_TO_PM, SCALE, col_px)?;
            let ins_col_qty = mul_div_floor(ins_fee_val * SCALE_TO_PM, SCALE, col_px)?;
            let total_deduct_qty = (redeemer_col_qty + ins_col_qty).min(col_qty);

            self.vaults.get_mut(&vid).expect("exists").collateral_qty -= total_deduct_qty;
            self.vaults.get_mut(&vid).expect("exists").debt_pm -= d_pm;

            if from_bridge {
                self.ledger_bridge_pm -= d_pm;
            } else {
                *self.agent_pm.get_mut(redeemer).expect("ensured") -= d_pm;
            }
            self.circulating_pm_supply -= d_pm;
            self.cumulative_vault_burns_pm += d_pm;

            total_redeemed += d_pm;
            total_col_received_val += redeemer_val;
            total_fee_val += fee_val;
            total_vault_fee_val += vault_keep_val;
            total_ins_fee_val += ins_fee_val;
            self.insurance_collateral_numeraire += ins_fee_val;
            *by_branch.entry(branch_name.clone()).or_insert(0) += redeemer_col_qty;

            if convert_to_numeraire {
                *self.agent_numeraire.get_mut(redeemer).expect("ensured") += redeemer_val;
            } else {
                self.credit_collateral(redeemer, &branch_name, redeemer_col_qty)?;
            }
            remaining -= d_pm;
        }

        if total_redeemed > 0 {
            let denom = (self.circulating_pm_supply + total_redeemed).max(1);
            let add_rate = mul_div_floor(total_redeemed, SCALE / 2, denom)?;
            let cap_base = self.redemption_cap_fee.saturating_sub(self.redemption_floor_fee);
            self.redemption_base_rate = cap_base.min(self.redemption_base_rate + add_rate);
        }

        Ok(RedemptionReceipt {
            pm_redeemed: total_redeemed,
            collateral_numeraire_received: total_col_received_val,
            fee_rate: f_redeem,
            fee_total_numeraire: total_fee_val,
            fee_to_vaults_numeraire: total_vault_fee_val,
            fee_to_insurance_numeraire: total_ins_fee_val,
            collateral_received_by_branch: by_branch,
        })
    }

    /// Hybrid A3 3-tier liquidation waterfall isolated strictly to `branch_name`.
    pub fn liquidate_branch(
        &mut self,
        branch_name: &str,
        r_price: u128,
    ) -> Result<LiquidationReport, MonetaryError> {
        let branch_snap = self
            .branches
            .get(branch_name)
            .ok_or_else(|| MonetaryError::UnknownBranch(branch_name.to_string()))?
            .clone();
        let col_px = branch_snap.price;
        if col_px == 0 || r_price == 0 {
            return Err(MonetaryError::DivisionByZero);
        }

        let mut under_ids = Vec::new();
        for (vid, v) in &self.vaults {
            if v.branch == branch_name && v.debt_pm > 0 {
                let cr = v.collateral_ratio(col_px, r_price)?;
                if cr < branch_snap.liq_cr {
                    under_ids.push(vid.clone());
                }
            }
        }
        if under_ids.is_empty() {
            return Ok(LiquidationReport {
                branch: branch_name.to_string(),
                liquidated_vaults: 0,
                debt_cleared_pm: 0,
                sp_offset_pm: 0,
                insurance_offset_pm: 0,
                redistributed_debt_pm: 0,
                unbacked_bad_debt_pm: 0,
            });
        }

        let r_with_disc = mul_div_floor(r_price, SCALE + branch_snap.liq_discount, SCALE)?;
        let mut debt_cleared_total = 0u128;
        let mut sp_offset_total = 0u128;
        let mut ins_offset_total = 0u128;
        let mut redistributed_total = 0u128;
        let mut bad_debt_total = 0u128;

        for vid in &under_ids {
            let initial_debt = self.vaults[vid].debt_pm;
            let owner = self.vaults[vid].owner.clone();

            // Tier 1: Branch-local Stability Pool instant offset
            let sp_avail = self.branches[branch_name].stability_pool_pm;
            let cur_debt = self.vaults[vid].debt_pm;
            let sp_offset = sp_avail.min(cur_debt);
            if sp_offset > 0 {
                self.branches.get_mut(branch_name).expect("exists").stability_pool_pm -= sp_offset;
                self.vaults.get_mut(vid).expect("exists").debt_pm -= sp_offset;
                self.circulating_pm_supply -= sp_offset;
                self.cumulative_vault_burns_pm += sp_offset;
                sp_offset_total += sp_offset;
                self.branches
                    .get_mut(branch_name)
                    .expect("exists")
                    .total_sp_offset_pm += sp_offset;

                let desired_seize = mul_div_floor(sp_offset * SCALE_TO_PM, r_with_disc, col_px)?;
                let v = self.vaults.get_mut(vid).expect("exists");
                let seize_qty = v.collateral_qty.min(desired_seize);
                v.collateral_qty -= seize_qty;
                self.branches
                    .get_mut(branch_name)
                    .expect("exists")
                    .stability_pool_collateral += seize_qty;
            }

            // Tier 2: Protocol Insurance Reserve
            let rem_after_sp = self.vaults[vid].debt_pm;
            if rem_after_sp > 0 {
                if self.insurance_reserve_pm < rem_after_sp && self.insurance_collateral_numeraire > 0
                {
                    let needed_num =
                        mul_div_ceil(rem_after_sp, r_price * 11, 10 * SCALE)?;
                    let num_spend = self.insurance_collateral_numeraire.min(needed_num);
                    if num_spend > 0 {
                        self.insurance_collateral_numeraire -= num_spend;
                        let bought = self.amm.swap_numeraire_for_pm(num_spend)?;
                        self.insurance_reserve_pm += bought;
                    }
                }
                let ins_offset = self.insurance_reserve_pm.min(rem_after_sp);
                if ins_offset > 0 {
                    self.insurance_reserve_pm -= ins_offset;
                    self.vaults.get_mut(vid).expect("exists").debt_pm -= ins_offset;
                    self.circulating_pm_supply -= ins_offset;
                    self.cumulative_vault_burns_pm += ins_offset;
                    ins_offset_total += ins_offset;
                    self.branches
                        .get_mut(branch_name)
                        .expect("exists")
                        .total_insurance_offset_pm += ins_offset;

                    let desired_seize =
                        mul_div_floor(ins_offset * SCALE_TO_PM, r_with_disc, col_px)?;
                    let v = self.vaults.get_mut(vid).expect("exists");
                    let seize_qty = v.collateral_qty.min(desired_seize);
                    v.collateral_qty -= seize_qty;
                    self.insurance_collateral_numeraire +=
                        mul_div_floor(seize_qty, col_px, SCALE * SCALE_TO_PM)?;
                }
            }

            if self.vaults[vid].debt_pm == 0 {
                let rem_col = self.vaults[vid].collateral_qty;
                if rem_col > 0 {
                    self.vaults.get_mut(vid).expect("exists").collateral_qty = 0;
                    self.credit_collateral(&owner, branch_name, rem_col)?;
                }
                debt_cleared_total += initial_debt;
                self.branches
                    .get_mut(branch_name)
                    .expect("exists")
                    .total_liquidated_debt_pm += initial_debt;
                continue;
            }

            // Tier 3: Branch-isolated pro-rata redistribution across healthy surviving vaults
            let rem_debt = self.vaults[vid].debt_pm;
            let rem_col = self.vaults[vid].collateral_qty;
            let survivors: Vec<(String, u128)> = self
                .vaults
                .values()
                .filter(|sv| {
                    sv.branch == branch_name
                        && !under_ids.iter().any(|u| u == &sv.vault_id)
                        && sv.debt_pm > 0
                })
                .map(|sv| (sv.vault_id.clone(), sv.debt_pm))
                .collect();
            let total_surv_debt: u128 = survivors.iter().map(|(_, d)| *d).sum();

            if !survivors.is_empty() && total_surv_debt > 0 {
                let mut alloc_debt = 0u128;
                let mut alloc_col = 0u128;
                let last_idx = survivors.len() - 1;
                for (idx, (sv_id, sv_debt)) in survivors.iter().enumerate() {
                    let (add_debt, add_col) = if idx == last_idx {
                        (rem_debt - alloc_debt, rem_col - alloc_col)
                    } else {
                        let ad = mul_div_floor(rem_debt, *sv_debt, total_surv_debt)?;
                        let ac = mul_div_floor(rem_col, *sv_debt, total_surv_debt)?;
                        alloc_debt += ad;
                        alloc_col += ac;
                        (ad, ac)
                    };
                    let sv = self.vaults.get_mut(sv_id).expect("survivor exists");
                    sv.debt_pm += add_debt;
                    sv.collateral_qty += add_col;
                }
                redistributed_total += rem_debt;
                self.branches
                    .get_mut(branch_name)
                    .expect("exists")
                    .total_redistributed_debt_pm += rem_debt;
                let v = self.vaults.get_mut(vid).expect("exists");
                v.debt_pm = 0;
                v.collateral_qty = 0;
            } else {
                bad_debt_total += rem_debt;
                self.branches
                    .get_mut(branch_name)
                    .expect("exists")
                    .unbacked_bad_debt_pm += rem_debt;
                self.unbacked_bad_debt_pm += rem_debt;
                let v = self.vaults.get_mut(vid).expect("exists");
                v.debt_pm = 0;
                if rem_col > 0 {
                    v.collateral_qty = 0;
                    self.insurance_collateral_numeraire +=
                        mul_div_floor(rem_col, col_px, SCALE * SCALE_TO_PM)?;
                }
            }

            debt_cleared_total += initial_debt;
            self.branches
                .get_mut(branch_name)
                .expect("exists")
                .total_liquidated_debt_pm += initial_debt;
        }

        Ok(LiquidationReport {
            branch: branch_name.to_string(),
            liquidated_vaults: under_ids.len(),
            debt_cleared_pm: debt_cleared_total,
            sp_offset_pm: sp_offset_total,
            insurance_offset_pm: ins_offset_total,
            redistributed_debt_pm: redistributed_total,
            unbacked_bad_debt_pm: bad_debt_total,
        })
    }

    /// Enforces exact `u128` conservation across all PM buckets and vault liabilities.
    pub fn assert_conservation(&self, oracle_locked_stake_pm: u128) -> Result<(), MonetaryError> {
        let all_agent_pm: u128 = self.agent_pm.values().copied().sum();
        let all_buckets = all_agent_pm
            + self.amm.pm_reserve
            + self.total_sp_pm()
            + self.insurance_reserve_pm
            + self.oracle_fee_pool_pm
            + self.pending_dispute_bonds_pm
            + self.ledger_bridge_pm
            + oracle_locked_stake_pm;
        if all_buckets != self.circulating_pm_supply {
            return Err(MonetaryError::ConservationViolation(format!(
                "PM bucket conservation violated: buckets={all_buckets} != circulating={}",
                self.circulating_pm_supply
            )));
        }
        let liability = self.active_vault_debt() + self.unbacked_bad_debt_pm;
        let accounted = self.circulating_pm_supply + self.cumulative_slash_burned_pm;
        if liability != accounted {
            return Err(MonetaryError::ConservationViolation(format!(
                "PM backing conservation violated: debt+bad_debt={liability} != circulating+burned={accounted}"
            )));
        }
        Ok(())
    }
}

