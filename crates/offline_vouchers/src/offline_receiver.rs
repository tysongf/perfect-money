use std::collections::BTreeMap;

use crate::error::VoucherError;
use crate::types::{
    AttestationTrustStore, EquivocationFraudProof, OfflineVoucher, PocketId, PocketPolicy,
    VoucherBundle, WebAuthnAssertion, check_webauthn_sign_count_monotonic,
};

/// Air-gapped merchant/receiver wallet performing offline hardware attestation,
/// bounded hop verification, CRL checking, and double-spend/equivocation detection.
#[derive(Debug, Clone)]
pub struct OfflineMerchantWallet {
    pub merchant_pk: [u8; 33],
    pub trust_store: AttestationTrustStore,
    pub policy: PocketPolicy,
    pub max_accepted_hops: u8,
    pub seen_vouchers: BTreeMap<(PocketId, u64), (OfflineVoucher, Option<WebAuthnAssertion>)>,
    pub detected_equivocations: Vec<EquivocationFraudProof>,
    pub accepted_bundles: Vec<VoucherBundle>,
}

impl OfflineMerchantWallet {
    pub fn new(
        merchant_pk: [u8; 33],
        trust_store: AttestationTrustStore,
        policy: PocketPolicy,
        max_accepted_hops: Option<u8>,
    ) -> Result<Self, VoucherError> {
        policy.validate()?;
        let hops = max_accepted_hops.unwrap_or(policy.default_merchant_max_hops);
        if hops == 0 || hops > policy.max_hops_allowed {
            return Err(VoucherError::InvalidPolicy(
                "merchant max_accepted_hops out of policy bounds".to_string(),
            ));
        }
        Ok(Self {
            merchant_pk,
            trust_store,
            policy,
            max_accepted_hops: hops,
            seen_vouchers: BTreeMap::new(),
            detected_equivocations: Vec::new(),
            accepted_bundles: Vec::new(),
        })
    }

    pub fn sync_crl(&mut self, latest_trust_store: &AttestationTrustStore) {
        self.trust_store = latest_trust_store.clone();
    }

    pub fn verify_and_accept_offline(
        &mut self,
        bundle: &VoucherBundle,
        now_secs: u64,
    ) -> Result<[u8; 32], VoucherError> {
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
        v.verify_common(&self.policy, now_secs)?;
        let sign_count_opt =
            bundle.verify_voucher_signature(&bundle.attestation.device_pk, &self.policy)?;

        let final_holder = bundle.verify_hop_chain(&self.policy, self.max_accepted_hops, now_secs)?;
        if final_holder != self.merchant_pk {
            return Err(VoucherError::RecipientMismatch);
        }

        if let Some((prev, prev_wa)) = self.seen_vouchers.get(&(v.pocket_id, v.counter)) {
            if prev.hash() == v.hash() {
                return Err(VoucherError::VoucherAlreadySettled(v.counter));
            }
            self.detected_equivocations.push(EquivocationFraudProof {
                voucher_a: prev.clone(),
                voucher_b: v.clone(),
                webauthn_a: prev_wa.clone(),
                webauthn_b: bundle.webauthn_assertion.clone(),
            });
            return Err(VoucherError::EquivocationDetected { counter: v.counter });
        }

        if let Some(sc) = sign_count_opt {
            check_webauthn_sign_count_monotonic(
                v.counter,
                sc,
                self.seen_vouchers
                    .iter()
                    .filter(|((pid, _), _)| pid == &v.pocket_id)
                    .map(|((_, ctr), (_, wa))| (*ctr, wa.as_ref())),
            )?;
        }

        for ((pid, seen_ctr), (seen_v, _)) in &self.seen_vouchers {
            if pid != &v.pocket_id {
                continue;
            }
            if *seen_ctr < v.counter
                && v.cumulative_spent < seen_v.cumulative_spent.saturating_add(v.amount)
            {
                return Err(VoucherError::CumulativeSpentRegression);
            }
            if *seen_ctr > v.counter
                && seen_v.cumulative_spent < v.cumulative_spent.saturating_add(seen_v.amount)
            {
                return Err(VoucherError::CumulativeSpentRegression);
            }
        }

        let vhash = v.hash();
        self.seen_vouchers.insert(
            (v.pocket_id, v.counter),
            (v.clone(), bundle.webauthn_assertion.clone()),
        );
        self.accepted_bundles.push(bundle.clone());
        Ok(vhash)
    }
}

