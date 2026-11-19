use std::collections::BTreeMap;

use ledger_core::{LedgerState, ProofVerifier, ShieldTx, UnshieldTx};
use p256::ecdsa::VerifyingKey;

use crate::crypto::{
    compute_pocket_fund_binding_hash, compute_pocket_reclaim_binding_hash,
    compute_voucher_settle_binding_hash,
};
use crate::error::VoucherError;
use crate::types::{
    AttestationTrustStore, CloseStatement, EquivocationFraudProof, HardwareAttestation,
    OfflineVoucher, PocketId, PocketPolicy, UncooperativeDrainRequest, VoucherBundle,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocketStatus {
    Active,
    CooperativeClosed {
        final_counter: u64,
        final_cumulative_spent: u64,
        in_flight_expires_at: u64,
    },
    DrainingUncooperative {
        unlock_at: u64,
    },
    RevokedCompromised,
}

#[derive(Debug, Clone)]
pub struct PocketAccount {
    pub pocket_id: PocketId,
    pub attestation: HardwareAttestation,
    pub recovery_pk: [u8; 33],
    pub total_funded: u64,
    pub escrow_balance: u64,
    pub total_settled: u64,
    pub settled_counters: BTreeMap<u64, OfflineVoucher>,
    pub status: PocketStatus,
}

/// Online escrow & settlement registry bridging Phase 1 Noir proofs and Phase 3 P-256 pockets.
#[derive(Debug, Clone)]
pub struct PocketRegistry {
    pub policy: PocketPolicy,
    pub trust_store: AttestationTrustStore,
    pub pockets: BTreeMap<PocketId, PocketAccount>,
    pub victim_compensation_pool_pm: u128,
}

impl PocketRegistry {
    pub fn new(
        policy: PocketPolicy,
        trust_store: AttestationTrustStore,
    ) -> Result<Self, VoucherError> {
        policy.validate()?;
        Ok(Self {
            policy,
            trust_store,
            pockets: BTreeMap::new(),
            victim_compensation_pool_pm: 0,
        })
    }

    pub fn fund_pocket_from_shielded(
        &mut self,
        ledger: &mut LedgerState,
        verifier: &dyn ProofVerifier,
        unshield_tx: &UnshieldTx,
        attestation: &HardwareAttestation,
        recovery_pk: [u8; 33],
        now_secs: u64,
    ) -> Result<PocketId, VoucherError> {
        self.policy.validate()?;
        if unshield_tx.burn_amount == 0 {
            return Err(VoucherError::ZeroAmount);
        }
        VerifyingKey::from_sec1_bytes(&recovery_pk).map_err(|_| VoucherError::InvalidPublicKey)?;
        let pocket_id =
            self.trust_store
                .verify_attestation(attestation, self.policy.chain_id, now_secs)?;

        let expected_bind = compute_pocket_fund_binding_hash(
            self.policy.chain_id,
            &pocket_id,
            &attestation.device_pk,
            unshield_tx.burn_amount,
        );
        if unshield_tx.tx_binding_hash != expected_bind {
            return Err(VoucherError::TxBindingHashMismatch);
        }

        let new_funded = if let Some(acct) = self.pockets.get(&pocket_id) {
            if acct.attestation.device_pk != attestation.device_pk
                || acct.recovery_pk != recovery_pk
            {
                return Err(VoucherError::DeviceKeyMismatch);
            }
            match acct.status {
                PocketStatus::Active => {}
                PocketStatus::CooperativeClosed { .. } => return Err(VoucherError::PocketClosed),
                PocketStatus::DrainingUncooperative { .. } => {
                    return Err(VoucherError::PocketDraining);
                }
                PocketStatus::RevokedCompromised => return Err(VoucherError::PocketRevoked),
            }
            acct.total_funded as u128 + unshield_tx.burn_amount as u128
        } else {
            unshield_tx.burn_amount as u128
        };

        if new_funded > self.policy.max_pocket_balance as u128 {
            return Err(VoucherError::CapExceeded {
                requested: new_funded,
                cap: self.policy.max_pocket_balance,
            });
        }

        ledger.apply_unshield(unshield_tx, verifier)?;
        ledger.lock_to_pocket_escrow(unshield_tx.burn_amount)?;

        match self.pockets.get_mut(&pocket_id) {
            Some(acct) => {
                acct.attestation = attestation.clone();
                acct.total_funded = new_funded as u64;
                acct.escrow_balance += unshield_tx.burn_amount;
            }
            None => {
                self.pockets.insert(
                    pocket_id,
                    PocketAccount {
                        pocket_id,
                        attestation: attestation.clone(),
                        recovery_pk,
                        total_funded: unshield_tx.burn_amount,
                        escrow_balance: unshield_tx.burn_amount,
                        total_settled: 0,
                        settled_counters: BTreeMap::new(),
                        status: PocketStatus::Active,
                    },
                );
            }
        }

        self.assert_escrow_conservation(ledger);
        Ok(pocket_id)
    }

    pub fn settle_voucher_to_shielded(
        &mut self,
        ledger: &mut LedgerState,
        verifier: &dyn ProofVerifier,
        bundle: &VoucherBundle,
        shield_tx: &ShieldTx,
        recipient_pk: [u8; 33],
        now_secs: u64,
    ) -> Result<u32, VoucherError> {
        self.policy.validate()?;
        let derived_pid = self.trust_store.verify_attestation(
            &bundle.attestation,
            self.policy.chain_id,
            now_secs,
        )?;
        let v = &bundle.voucher;
        if v.pocket_id != derived_pid {
            return Err(VoucherError::PocketIdMismatch);
        }

        let device_pk = {
            let acct = self
                .pockets
                .get(&v.pocket_id)
                .ok_or(VoucherError::PocketNotFound)?;
            if acct.status == PocketStatus::RevokedCompromised {
                return Err(VoucherError::PocketRevoked);
            }
            if acct.attestation.device_pk != bundle.attestation.device_pk {
                return Err(VoucherError::DeviceKeyMismatch);
            }
            acct.attestation.device_pk
        };

        v.verify_common(&self.policy, now_secs)?;
        v.verify_signature(&device_pk)?;
        let final_holder =
            bundle.verify_hop_chain(&self.policy, self.policy.max_hops_allowed, now_secs)?;
        if final_holder != recipient_pk {
            return Err(VoucherError::RecipientMismatch);
        }

        if shield_tx.mint_amount != v.amount {
            return Err(VoucherError::SettlementAmountMismatch {
                expected: v.amount,
                got: shield_tx.mint_amount,
            });
        }
        let expected_bind = compute_voucher_settle_binding_hash(
            self.policy.chain_id,
            &v.hash(),
            &recipient_pk,
            shield_tx.out_commitment,
        );
        if shield_tx.tx_binding_hash != expected_bind {
            return Err(VoucherError::TxBindingHashMismatch);
        }

        // Check replay / equivocation BEFORE debiting escrow
        let existing = self
            .pockets
            .get(&v.pocket_id)
            .and_then(|a| a.settled_counters.get(&v.counter).cloned());
        if let Some(prev) = existing {
            if prev.hash() == v.hash() {
                return Err(VoucherError::VoucherAlreadySettled(v.counter));
            }
            self.revoke_and_slash_account(v.pocket_id);
            self.assert_escrow_conservation(ledger);
            return Err(VoucherError::EquivocationDetected { counter: v.counter });
        }

        {
            let acct = self
                .pockets
                .get(&v.pocket_id)
                .ok_or(VoucherError::PocketNotFound)?;
            if acct.escrow_balance < v.amount {
                return Err(VoucherError::InsufficientPocketBalance {
                    requested: v.amount,
                    available: acct.escrow_balance,
                });
            }
            if let PocketStatus::CooperativeClosed {
                final_cumulative_spent,
                ..
            } = acct.status
            {
                if v.counter == 0
                    || acct.total_settled.saturating_add(v.amount) > final_cumulative_spent
                {
                    return Err(VoucherError::InsufficientPocketBalance {
                        requested: v.amount,
                        available: final_cumulative_spent.saturating_sub(acct.total_settled),
                    });
                }
            }
        }

        let leaf_idx = release_and_shield(ledger, verifier, shield_tx)?;
        let acct = self
            .pockets
            .get_mut(&v.pocket_id)
            .ok_or(VoucherError::PocketNotFound)?;
        acct.escrow_balance -= v.amount;
        acct.total_settled += v.amount;
        acct.settled_counters.insert(v.counter, v.clone());

        self.assert_escrow_conservation(ledger);
        Ok(leaf_idx)
    }

    pub fn submit_equivocation_fraud_proof(
        &mut self,
        proof: &EquivocationFraudProof,
    ) -> Result<u64, VoucherError> {
        let a = &proof.voucher_a;
        let b = &proof.voucher_b;
        if a.chain_id != self.policy.chain_id
            || b.chain_id != self.policy.chain_id
            || a.pocket_id != b.pocket_id
            || a.counter != b.counter
            || a.hash() == b.hash()
        {
            return Err(VoucherError::InvalidEquivocationProof);
        }
        let device_pk = self
            .pockets
            .get(&a.pocket_id)
            .ok_or(VoucherError::PocketNotFound)?
            .attestation
            .device_pk;
        a.verify_signature(&device_pk)
            .map_err(|_| VoucherError::InvalidEquivocationProof)?;
        b.verify_signature(&device_pk)
            .map_err(|_| VoucherError::InvalidEquivocationProof)?;

        let slashed = self.revoke_and_slash_account(a.pocket_id);
        Ok(slashed)
    }

    pub fn claim_victim_compensation(
        &mut self,
        ledger: &mut LedgerState,
        verifier: &dyn ProofVerifier,
        shield_tx: &ShieldTx,
    ) -> Result<u32, VoucherError> {
        if shield_tx.mint_amount == 0 {
            return Err(VoucherError::ZeroAmount);
        }
        let req = shield_tx.mint_amount as u128;
        if self.victim_compensation_pool_pm < req {
            return Err(VoucherError::InsufficientVictimCompensation {
                requested: shield_tx.mint_amount,
                available: self.victim_compensation_pool_pm,
            });
        }
        let leaf_idx = release_and_shield(ledger, verifier, shield_tx)?;
        self.victim_compensation_pool_pm -= req;
        self.assert_escrow_conservation(ledger);
        Ok(leaf_idx)
    }

    pub fn cooperative_close_pocket(
        &mut self,
        ledger: &mut LedgerState,
        verifier: &dyn ProofVerifier,
        close_stmt: &CloseStatement,
        reclaim_shield_tx: Option<&ShieldTx>,
        now_secs: u64,
    ) -> Result<u64, VoucherError> {
        if close_stmt.chain_id != self.policy.chain_id {
            return Err(VoucherError::ChainIdMismatch {
                expected: self.policy.chain_id,
                got: close_stmt.chain_id,
            });
        }
        let (device_pk, total_funded, escrow_balance, total_settled) = {
            let acct = self
                .pockets
                .get(&close_stmt.pocket_id)
                .ok_or(VoucherError::PocketNotFound)?;
            match acct.status {
                PocketStatus::Active => {}
                PocketStatus::CooperativeClosed { .. } => return Err(VoucherError::PocketClosed),
                PocketStatus::DrainingUncooperative { .. } => {
                    return Err(VoucherError::PocketDraining);
                }
                PocketStatus::RevokedCompromised => return Err(VoucherError::PocketRevoked),
            }
            (
                acct.attestation.device_pk,
                acct.total_funded,
                acct.escrow_balance,
                acct.total_settled,
            )
        };

        close_stmt.verify_signature(&device_pk)?;
        if close_stmt.final_cumulative_spent < total_settled {
            return Err(VoucherError::CloseSpentRegression);
        }
        if close_stmt.final_cumulative_spent > total_funded {
            return Err(VoucherError::CapExceeded {
                requested: close_stmt.final_cumulative_spent as u128,
                cap: total_funded,
            });
        }

        let unspent_safe = total_funded
            .saturating_sub(close_stmt.final_cumulative_spent)
            .min(escrow_balance);

        if unspent_safe > 0 {
            let tx = reclaim_shield_tx.ok_or(VoucherError::SettlementAmountMismatch {
                expected: unspent_safe,
                got: 0,
            })?;
            verify_reclaim_tx(
                self.policy.chain_id,
                &close_stmt.pocket_id,
                unspent_safe,
                tx,
            )?;
            release_and_shield(ledger, verifier, tx)?;
        }

        let acct = self
            .pockets
            .get_mut(&close_stmt.pocket_id)
            .ok_or(VoucherError::PocketNotFound)?;
        acct.escrow_balance -= unspent_safe;
        acct.status = PocketStatus::CooperativeClosed {
            final_counter: close_stmt.final_counter,
            final_cumulative_spent: close_stmt.final_cumulative_spent,
            in_flight_expires_at: now_secs.saturating_add(self.policy.max_voucher_ttl_secs),
        };

        self.assert_escrow_conservation(ledger);
        Ok(unspent_safe)
    }

    pub fn initiate_uncooperative_drain(
        &mut self,
        req: &UncooperativeDrainRequest,
        now_secs: u64,
    ) -> Result<u64, VoucherError> {
        if req.chain_id != self.policy.chain_id {
            return Err(VoucherError::ChainIdMismatch {
                expected: self.policy.chain_id,
                got: req.chain_id,
            });
        }
        let acct = self
            .pockets
            .get_mut(&req.pocket_id)
            .ok_or(VoucherError::PocketNotFound)?;
        match acct.status {
            PocketStatus::Active => {}
            PocketStatus::CooperativeClosed { .. } => return Err(VoucherError::PocketClosed),
            PocketStatus::DrainingUncooperative { .. } => return Err(VoucherError::PocketDraining),
            PocketStatus::RevokedCompromised => return Err(VoucherError::PocketRevoked),
        }
        req.verify_signature(&acct.recovery_pk)?;
        let unlock_at = now_secs.saturating_add(self.policy.uncooperative_drain_delay_secs);
        acct.status = PocketStatus::DrainingUncooperative { unlock_at };
        Ok(unlock_at)
    }

    pub fn finalize_drain(
        &mut self,
        ledger: &mut LedgerState,
        verifier: &dyn ProofVerifier,
        pocket_id: &PocketId,
        reclaim_shield_tx: Option<&ShieldTx>,
        now_secs: u64,
    ) -> Result<u64, VoucherError> {
        let (escrow_balance, unlock_at) = {
            let acct = self
                .pockets
                .get(pocket_id)
                .ok_or(VoucherError::PocketNotFound)?;
            match acct.status {
                PocketStatus::DrainingUncooperative { unlock_at } => (acct.escrow_balance, unlock_at),
                PocketStatus::CooperativeClosed {
                    in_flight_expires_at,
                    ..
                } => (acct.escrow_balance, in_flight_expires_at),
                PocketStatus::Active => return Err(VoucherError::PocketNotDraining),
                PocketStatus::RevokedCompromised => return Err(VoucherError::PocketRevoked),
            }
        };

        if now_secs < unlock_at {
            return Err(VoucherError::DrainCooldownActive {
                unlock_at,
                now: now_secs,
            });
        }

        if escrow_balance > 0 {
            let tx = reclaim_shield_tx.ok_or(VoucherError::SettlementAmountMismatch {
                expected: escrow_balance,
                got: 0,
            })?;
            verify_reclaim_tx(self.policy.chain_id, pocket_id, escrow_balance, tx)?;
            release_and_shield(ledger, verifier, tx)?;
        }

        let acct = self
            .pockets
            .get_mut(pocket_id)
            .ok_or(VoucherError::PocketNotFound)?;
        acct.escrow_balance = 0;
        acct.status = PocketStatus::CooperativeClosed {
            final_counter: acct.settled_counters.keys().next_back().copied().unwrap_or(0),
            final_cumulative_spent: acct.total_settled,
            in_flight_expires_at: unlock_at,
        };
        self.assert_escrow_conservation(ledger);
        Ok(escrow_balance)
    }

    pub fn assert_escrow_conservation(&self, ledger: &LedgerState) {
        let sum_escrow: u128 = self.pockets.values().map(|p| p.escrow_balance as u128).sum();
        assert_eq!(
            sum_escrow + self.victim_compensation_pool_pm,
            ledger.total_pocket_escrow,
            "pocket escrow conservation violated"
        );
        ledger.assert_conservation_invariant();
    }

    fn revoke_and_slash_account(&mut self, pocket_id: PocketId) -> u64 {
        self.trust_store.revoke_pocket(pocket_id);
        let Some(acct) = self.pockets.get_mut(&pocket_id) else {
            return 0;
        };
        let slashed = acct.escrow_balance;
        acct.escrow_balance = 0;
        acct.status = PocketStatus::RevokedCompromised;
        self.victim_compensation_pool_pm += slashed as u128;
        slashed
    }
}

fn verify_reclaim_tx(
    chain_id: u64,
    pocket_id: &PocketId,
    expected_amount: u64,
    shield_tx: &ShieldTx,
) -> Result<(), VoucherError> {
    if shield_tx.mint_amount != expected_amount {
        return Err(VoucherError::SettlementAmountMismatch {
            expected: expected_amount,
            got: shield_tx.mint_amount,
        });
    }
    let expected_bind = compute_pocket_reclaim_binding_hash(
        chain_id,
        pocket_id,
        expected_amount,
        shield_tx.out_commitment,
    );
    if shield_tx.tx_binding_hash != expected_bind {
        return Err(VoucherError::TxBindingHashMismatch);
    }
    Ok(())
}

fn release_and_shield(
    ledger: &mut LedgerState,
    verifier: &dyn ProofVerifier,
    shield_tx: &ShieldTx,
) -> Result<u32, VoucherError> {
    ledger.release_from_pocket_escrow(shield_tx.mint_amount)?;
    match ledger.apply_shield(shield_tx, verifier) {
        Ok(idx) => Ok(idx),
        Err(err) => {
            ledger
                .lock_to_pocket_escrow(shield_tx.mint_amount)
                .expect("escrow rollback after failed shield cannot fail");
            Err(VoucherError::Ledger(err))
        }
    }
}

