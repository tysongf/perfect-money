use ledger_core::LedgerState;
use serde::{Deserialize, Serialize};

use crate::error::MonetaryError;
use crate::oracle::{OracleFinalizeResult, OracleMarket, OracleNode, OracleRole};
use crate::peg::{BasketSpec, PegController, ThrottleConfig, ThrottleState, compute_auto_throttle};
use crate::vaults::{LiquidationReport, RedemptionReceipt, SpotAmm, Vault, VaultAndAmmSystem, default_collateral_branches};

/// Unified fixed-point monetary, vault, AMM, and commit-reveal oracle state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonetaryEngine {
    pub basket: BasketSpec,
    pub throttle_config: ThrottleConfig,
    pub peg: PegController,
    pub oracle: OracleMarket,
    pub vaults: VaultAndAmmSystem,
    pub current_hour: u64,
}

impl MonetaryEngine {
    pub fn new(
        basket: BasketSpec,
        throttle_config: ThrottleConfig,
        peg: PegController,
        oracle: OracleMarket,
        vaults: VaultAndAmmSystem,
    ) -> Result<Self, MonetaryError> {
        let engine = Self {
            basket,
            throttle_config,
            peg,
            oracle,
            vaults,
            current_hour: 0,
        };
        engine.assert_conservation()?;
        Ok(engine)
    }

    pub fn new_default() -> Result<Self, MonetaryError> {
        let basket = BasketSpec::default();
        let oracle = OracleMarket::new(basket.genesis_prices.clone())?;
        let vaults =
            VaultAndAmmSystem::new_backed(default_collateral_branches(), SpotAmm::default())?;
        Self::new(
            basket,
            ThrottleConfig::default(),
            PegController::default(),
            oracle,
            vaults,
        )
    }

    pub fn throttle_state(&self) -> Result<ThrottleState, MonetaryError> {
        compute_auto_throttle(
            self.oracle.total_locked_stake(),
            self.vaults.amm.liquidity_pm_equiv(),
            self.vaults.circulating_pm_supply,
            &self.throttle_config,
        )
    }

    /// Moves liquid `agent_pm` into `oracle.nodes[node_id].stake_pm`, creating the node if absent.
    pub fn stake_oracle_pm(
        &mut self,
        agent_id: &str,
        node_id: &str,
        amount_pm: u128,
        is_court_voter: bool,
        role: OracleRole,
    ) -> Result<(), MonetaryError> {
        self.vaults.ensure_agent(agent_id);
        let avail = self.vaults.agent_pm[agent_id];
        if avail < amount_pm {
            return Err(MonetaryError::InsufficientBalance {
                kind: "pm",
                requested: amount_pm,
                available: avail,
            });
        }
        *self.vaults.agent_pm.get_mut(agent_id).expect("ensured") -= amount_pm;
        match self.oracle.nodes.get_mut(node_id) {
            Some(node) => node.stake_pm += amount_pm,
            None => {
                self.oracle.add_node(OracleNode::new(
                    node_id.to_string(),
                    amount_pm,
                    is_court_voter,
                    role,
                ));
            }
        }
        self.assert_conservation()
    }

    pub fn unstake_oracle_pm(
        &mut self,
        agent_id: &str,
        node_id: &str,
        amount_pm: u128,
    ) -> Result<(), MonetaryError> {
        let stake_avail = self.oracle.nodes.get(node_id).map(|n| n.stake_pm).unwrap_or(0);
        if stake_avail < amount_pm {
            return Err(MonetaryError::InsufficientBalance {
                kind: "oracle_stake",
                requested: amount_pm,
                available: stake_avail,
            });
        }
        self.oracle
            .nodes
            .get_mut(node_id)
            .expect("checked")
            .stake_pm -= amount_pm;
        self.vaults.credit_pm(agent_id, amount_pm);
        self.assert_conservation()
    }

    pub fn challenge_round_with_bond(
        &mut self,
        challenger_id: &str,
        bond_pm: u128,
        hour: u64,
    ) -> Result<u128, MonetaryError> {
        let min_bond = self.oracle.dispute_bond_min_pm;
        let bond = bond_pm.max(min_bond);
        self.vaults.ensure_agent(challenger_id);
        let avail = self.vaults.agent_pm[challenger_id];
        if avail < bond {
            return Err(MonetaryError::InsufficientBalance {
                kind: "pm",
                requested: bond,
                available: avail,
            });
        }
        *self.vaults.agent_pm.get_mut(challenger_id).expect("ensured") -= bond;
        self.vaults.pending_dispute_bonds_pm += bond;
        if let Err(err) = self.oracle.challenge_round(challenger_id, bond, hour) {
            self.vaults.pending_dispute_bonds_pm -= bond;
            *self.vaults.agent_pm.get_mut(challenger_id).expect("ensured") += bond;
            return Err(err);
        }
        self.assert_conservation()?;
        Ok(bond)
    }

    /// Advances engine clock to `target_hour`, accruing vault interest, settling oracle events,
    /// and stepping `PegController` atomically while preserving exact `u128` conservation.
    pub fn advance_hour(
        &mut self,
        target_hour: u64,
    ) -> Result<Option<OracleFinalizeResult>, MonetaryError> {
        if target_hour < self.current_hour {
            return Err(MonetaryError::InvalidParameter(format!(
                "cannot rewind hour {} -> {}",
                self.current_hour, target_hour
            )));
        }
        let dt_hours = target_hour - self.current_hour;
        let throttle = self.throttle_state()?;
        if dt_hours > 0 {
            self.vaults
                .accrue_hourly_interest(&throttle, self.peg.min_borrow_rate_apr, dt_hours)?;
        }

        let (finalized_opt, no_rev) =
            self.oracle
                .advance(target_hour, &throttle, self.vaults.oracle_fee_pool_pm)?;
        if no_rev.total_slashed_pm > 0 {
            self.vaults.cumulative_slash_burned_pm += no_rev.burned_pm;
            self.vaults.circulating_pm_supply -= no_rev.burned_pm;
            self.vaults.insurance_reserve_pm += no_rev.insurance_pm;
        }

        if let Some(res) = &finalized_opt {
            self.vaults.oracle_fee_pool_pm = self.vaults.oracle_fee_pool_pm
                + res.bond_fee_pool_pm
                - res.total_rewards_paid_pm;
            for (nid, &rew) in &res.reward_payouts {
                self.vaults.credit_pm(nid, rew);
            }
            for (cid, &bounty) in &res.bounty_payouts {
                self.vaults.credit_pm(cid, bounty);
            }
            for (cid, &refund) in &res.bond_refunds {
                self.vaults.pending_dispute_bonds_pm -= refund;
                self.vaults.credit_pm(cid, refund);
            }
            if res.forfeited_bond_pm > 0 {
                self.vaults.pending_dispute_bonds_pm -= res.forfeited_bond_pm;
            }
            self.vaults.cumulative_slash_burned_pm += res.burned_pm;
            self.vaults.circulating_pm_supply -= res.burned_pm;
            self.vaults.insurance_reserve_pm += res.insurance_pm;
        }

        let i_oracle = self.basket.index(&self.oracle.last_finalized_prices)?;
        let m_spot = self.vaults.amm.spot_price()?;
        self.peg.step(i_oracle, m_spot, dt_hours.max(1))?;
        self.current_hour = target_hour;
        self.assert_conservation()?;
        Ok(finalized_opt)
    }

    pub fn liquidate_branch(&mut self, branch_name: &str) -> Result<LiquidationReport, MonetaryError> {
        let rep = self.vaults.liquidate_branch(branch_name, self.peg.r_price)?;
        self.assert_conservation()?;
        Ok(rep)
    }

    /// Mints vault debt against collateral directly into Phase 1 `LedgerState` unshielded supply.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_vault_to_ledger(
        &mut self,
        ledger: &mut LedgerState,
        owner: &str,
        branch_name: &str,
        add_collateral_qty: u128,
        mint_pm: u64,
        borrow_rate_apr: u128,
        vault_id: Option<&str>,
        skip_owner_collateral_deduct: bool,
    ) -> Result<Vault, MonetaryError> {
        let vault = self.vaults.mint_vault_to_bridge(
            owner,
            branch_name,
            add_collateral_qty,
            mint_pm as u128,
            borrow_rate_apr,
            self.peg.r_price,
            self.peg.min_borrow_rate_apr,
            vault_id,
            skip_owner_collateral_deduct,
        )?;
        ledger.mint_vault_supply(mint_pm)?;
        self.assert_ledger_bridge_conservation(ledger)?;
        Ok(vault)
    }

    /// Burns unshielded PM from `LedgerState` public vault balance to repay a vault's debt.
    pub fn repay_vault_from_ledger(
        &mut self,
        ledger: &mut LedgerState,
        vault_id: &str,
        repay_pm: u64,
    ) -> Result<u64, MonetaryError> {
        if ledger.public_vault_balance < repay_pm as u128 {
            return Err(MonetaryError::InsufficientBalance {
                kind: "ledger_public_vault",
                requested: repay_pm as u128,
                available: ledger.public_vault_balance,
            });
        }
        let actual = self.vaults.repay_vault_from_bridge(vault_id, repay_pm as u128)?;
        let actual_u64 = u64::try_from(actual).map_err(|_| MonetaryError::MathOverflow)?;
        if actual_u64 > 0 {
            ledger.burn_vault_supply(actual_u64)?;
        }
        self.assert_ledger_bridge_conservation(ledger)?;
        Ok(actual_u64)
    }

    /// Burns unshielded PM from `LedgerState` to hard-redeem lowest-rate vault collateral.
    pub fn redeem_pm_from_ledger(
        &mut self,
        ledger: &mut LedgerState,
        redeemer: &str,
        pm_amount: u64,
        convert_to_numeraire: bool,
    ) -> Result<RedemptionReceipt, MonetaryError> {
        if ledger.public_vault_balance < pm_amount as u128 {
            return Err(MonetaryError::InsufficientBalance {
                kind: "ledger_public_vault",
                requested: pm_amount as u128,
                available: ledger.public_vault_balance,
            });
        }
        let receipt = self.vaults.redeem_pm_from_bridge(
            redeemer,
            pm_amount as u128,
            self.peg.r_price,
            self.current_hour,
            convert_to_numeraire,
        )?;
        let redeemed_u64 =
            u64::try_from(receipt.pm_redeemed).map_err(|_| MonetaryError::MathOverflow)?;
        if redeemed_u64 > 0 {
            ledger.burn_vault_supply(redeemed_u64)?;
        }
        self.assert_ledger_bridge_conservation(ledger)?;
        Ok(receipt)
    }

    pub fn assert_conservation(&self) -> Result<(), MonetaryError> {
        self.vaults
            .assert_conservation(self.oracle.total_locked_stake())
    }

    pub fn assert_ledger_bridge_conservation(&self, ledger: &LedgerState) -> Result<(), MonetaryError> {
        self.assert_conservation()?;
        if self.vaults.ledger_bridge_pm != ledger.total_issued_supply {
            return Err(MonetaryError::ConservationViolation(format!(
                "ledger bridge mismatch: monetary ledger_bridge_pm={} != ledger.total_issued_supply={}",
                self.vaults.ledger_bridge_pm, ledger.total_issued_supply
            )));
        }
        Ok(())
    }
}

