use crate::crypto::{
    DOMAIN_HW_ATTEST, DOMAIN_OFFLINE_VOUCHER, DOMAIN_POCKET_CLOSE, DOMAIN_POCKET_DRAIN,
    DOMAIN_VOUCHER_HOP, compressed_pk, derive_pocket_id, sign_low_s,
};
use crate::error::VoucherError;
use crate::types::{
    CloseStatement, HardwareAttestation, HopEndorsement, OfflineVoucher, PocketId, PocketPolicy,
    SecurityLevel, UncooperativeDrainRequest, VOUCHER_FORMAT_VERSION, VoucherBundle,
};
use p256::ecdsa::SigningKey;

/// Hardware vendor certificate authority issuing P-256 device attestations.
#[derive(Clone)]
pub struct VendorCa {
    pub vendor_id: String,
    signing_key: SigningKey,
}

impl VendorCa {
    pub fn new(vendor_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            vendor_id: vendor_id.into(),
            signing_key,
        }
    }

    pub fn public_key(&self) -> [u8; 33] {
        compressed_pk(&self.signing_key)
    }

    pub fn issue_attestation(
        &self,
        device_pk: [u8; 33],
        security_level: SecurityLevel,
        issued_at: u64,
        expires_at: u64,
        cert_serial: [u8; 16],
    ) -> HardwareAttestation {
        let mut att = HardwareAttestation {
            vendor_id: self.vendor_id.clone(),
            device_pk,
            security_level,
            issued_at,
            expires_at,
            cert_serial,
            ca_sig: [0u8; 64],
        };
        att.ca_sig = sign_low_s(&self.signing_key, DOMAIN_HW_ATTEST, &att.signing_bytes());
        att
    }
}

/// Abstract hardware security boundary (Secure Enclave / StrongBox) owning the P-256 spend key.
pub trait SecureEnclave {
    fn attestation(&self) -> &HardwareAttestation;
    fn pocket_id(&self) -> PocketId;
    fn counter(&self) -> u64;
    fn cumulative_spent(&self) -> u64;
    fn remaining_balance(&self) -> u64;
    fn is_closed(&self) -> bool;
    fn credit_funding(&mut self, amount: u64) -> Result<(), VoucherError>;
    fn issue_voucher(
        &mut self,
        recipient_pk: [u8; 33],
        amount: u64,
        now_secs: u64,
        ttl_secs: u64,
        nonce: [u8; 16],
    ) -> Result<VoucherBundle, VoucherError>;
    fn cooperative_close(&mut self, now_secs: u64) -> Result<CloseStatement, VoucherError>;
}

/// Signs a bounded offline hop re-endorsement from the current holder `holder_sk`.
pub fn sign_hop_endorsement(
    holder_sk: &SigningKey,
    bundle: &VoucherBundle,
    to_pk: [u8; 33],
    expires_at: u64,
    nonce: [u8; 16],
) -> Result<VoucherBundle, VoucherError> {
    let from_pk = compressed_pk(holder_sk);
    let expected_holder = bundle.final_holder_pk();
    if from_pk != expected_holder {
        return Err(VoucherError::InvalidHopChain(
            "holder key does not match current voucher holder".to_string(),
        ));
    }
    let hop_index = u8::try_from(bundle.hops.len() + 1)
        .map_err(|_| VoucherError::InvalidHopChain("hop_index overflow".to_string()))?;
    let mut hop = HopEndorsement {
        voucher_hash: bundle.voucher.hash(),
        hop_index,
        from_pk,
        to_pk,
        expires_at: expires_at.min(bundle.voucher.expires_at),
        nonce,
        sig: [0u8; 64],
    };
    hop.sig = sign_low_s(holder_sk, DOMAIN_VOUCHER_HOP, &hop.signing_bytes());
    let mut out = bundle.clone();
    out.hops.push(hop);
    Ok(out)
}

/// Signs an owner recovery request to begin the uncooperative drain cooldown.
pub fn sign_uncooperative_drain_request(
    recovery_sk: &SigningKey,
    chain_id: u64,
    pocket_id: PocketId,
    requested_at: u64,
) -> UncooperativeDrainRequest {
    let mut req = UncooperativeDrainRequest {
        chain_id,
        pocket_id,
        requested_at,
        sig: [0u8; 64],
    };
    req.sig = sign_low_s(recovery_sk, DOMAIN_POCKET_DRAIN, &req.signing_bytes());
    req
}

/// Honest Secure Enclave / StrongBox simulator enforcing cap, monotonic counters, and close lock.
pub struct SoftwareMockEnclave {
    signing_key: SigningKey,
    attestation: HardwareAttestation,
    policy: PocketPolicy,
    pocket_id: PocketId,
    total_funded: u64,
    counter: u64,
    cumulative_spent: u64,
    last_voucher_hash: [u8; 32],
    closed: bool,
}

impl SoftwareMockEnclave {
    pub fn new(
        signing_key: SigningKey,
        ca: &VendorCa,
        security_level: SecurityLevel,
        policy: PocketPolicy,
        cert_issued_at: u64,
        cert_expires_at: u64,
        cert_serial: [u8; 16],
    ) -> Result<Self, VoucherError> {
        policy.validate()?;
        let pk = compressed_pk(&signing_key);
        let pocket_id = derive_pocket_id(policy.chain_id, &pk);
        let attestation = ca.issue_attestation(
            pk,
            security_level,
            cert_issued_at,
            cert_expires_at,
            cert_serial,
        );
        Ok(Self {
            signing_key,
            attestation,
            policy,
            pocket_id,
            total_funded: 0,
            counter: 0,
            cumulative_spent: 0,
            last_voucher_hash: [0u8; 32],
            closed: false,
        })
    }

    pub fn device_pk(&self) -> [u8; 33] {
        self.attestation.device_pk
    }
}

impl SecureEnclave for SoftwareMockEnclave {
    fn attestation(&self) -> &HardwareAttestation {
        &self.attestation
    }

    fn pocket_id(&self) -> PocketId {
        self.pocket_id
    }

    fn counter(&self) -> u64 {
        self.counter
    }

    fn cumulative_spent(&self) -> u64 {
        self.cumulative_spent
    }

    fn remaining_balance(&self) -> u64 {
        self.total_funded.saturating_sub(self.cumulative_spent)
    }

    fn is_closed(&self) -> bool {
        self.closed
    }

    fn credit_funding(&mut self, amount: u64) -> Result<(), VoucherError> {
        if self.closed {
            return Err(VoucherError::PocketClosed);
        }
        if amount == 0 {
            return Err(VoucherError::ZeroAmount);
        }
        let next = self.total_funded as u128 + amount as u128;
        if next > self.policy.max_pocket_balance as u128 {
            return Err(VoucherError::CapExceeded {
                requested: next,
                cap: self.policy.max_pocket_balance,
            });
        }
        self.total_funded = next as u64;
        Ok(())
    }

    fn issue_voucher(
        &mut self,
        recipient_pk: [u8; 33],
        amount: u64,
        now_secs: u64,
        ttl_secs: u64,
        nonce: [u8; 16],
    ) -> Result<VoucherBundle, VoucherError> {
        if self.closed {
            return Err(VoucherError::PocketClosed);
        }
        if amount == 0 {
            return Err(VoucherError::ZeroAmount);
        }
        let avail = self.remaining_balance();
        if amount > avail {
            return Err(VoucherError::InsufficientPocketBalance {
                requested: amount,
                available: avail,
            });
        }
        if ttl_secs == 0 || ttl_secs > self.policy.max_voucher_ttl_secs {
            return Err(VoucherError::VoucherTtlTooLong);
        }

        let next_counter = self.counter + 1;
        let next_spent = self.cumulative_spent + amount;
        let mut voucher = OfflineVoucher {
            version: VOUCHER_FORMAT_VERSION,
            chain_id: self.policy.chain_id,
            pocket_id: self.pocket_id,
            counter: next_counter,
            amount,
            cumulative_spent: next_spent,
            recipient_pk,
            prev_voucher_hash: self.last_voucher_hash,
            issued_at: now_secs,
            expires_at: now_secs.saturating_add(ttl_secs),
            nonce,
            sig: [0u8; 64],
        };
        voucher.sig = sign_low_s(
            &self.signing_key,
            DOMAIN_OFFLINE_VOUCHER,
            &voucher.signing_bytes(),
        );
        self.counter = next_counter;
        self.cumulative_spent = next_spent;
        self.last_voucher_hash = voucher.hash();

        Ok(VoucherBundle {
            voucher,
            attestation: self.attestation.clone(),
            hops: Vec::new(),
        })
    }

    fn cooperative_close(&mut self, now_secs: u64) -> Result<CloseStatement, VoucherError> {
        self.closed = true;
        let mut stmt = CloseStatement {
            chain_id: self.policy.chain_id,
            pocket_id: self.pocket_id,
            final_counter: self.counter,
            final_cumulative_spent: self.cumulative_spent,
            closed_at: now_secs,
            sig: [0u8; 64],
        };
        stmt.sig = sign_low_s(&self.signing_key, DOMAIN_POCKET_CLOSE, &stmt.signing_bytes());
        Ok(stmt)
    }
}

#[derive(Clone)]
pub struct CompromisedSnapshot {
    counter: u64,
    cumulative_spent: u64,
    last_voucher_hash: [u8; 32],
}

/// Adversarial test enclave capable of FIB state rollback and arbitrary counter/amount spoofing.
pub struct CompromisedTestEnclave {
    signing_key: SigningKey,
    attestation: HardwareAttestation,
    chain_id: u64,
    pocket_id: PocketId,
    pub counter: u64,
    pub cumulative_spent: u64,
    pub last_voucher_hash: [u8; 32],
}

impl CompromisedTestEnclave {
    pub fn from_signing_key(
        signing_key: SigningKey,
        attestation: HardwareAttestation,
        chain_id: u64,
    ) -> Self {
        let pocket_id = attestation.pocket_id(chain_id);
        Self {
            signing_key,
            attestation,
            chain_id,
            pocket_id,
            counter: 0,
            cumulative_spent: 0,
            last_voucher_hash: [0u8; 32],
        }
    }

    pub fn snapshot(&self) -> CompromisedSnapshot {
        CompromisedSnapshot {
            counter: self.counter,
            cumulative_spent: self.cumulative_spent,
            last_voucher_hash: self.last_voucher_hash,
        }
    }

    pub fn rollback(&mut self, snap: CompromisedSnapshot) {
        self.counter = snap.counter;
        self.cumulative_spent = snap.cumulative_spent;
        self.last_voucher_hash = snap.last_voucher_hash;
    }

    pub fn issue_voucher_unchecked(
        &mut self,
        recipient_pk: [u8; 33],
        amount: u64,
        cumulative_spent: u64,
        counter: u64,
        now_secs: u64,
        ttl_secs: u64,
        nonce: [u8; 16],
    ) -> VoucherBundle {
        let mut voucher = OfflineVoucher {
            version: VOUCHER_FORMAT_VERSION,
            chain_id: self.chain_id,
            pocket_id: self.pocket_id,
            counter,
            amount,
            cumulative_spent,
            recipient_pk,
            prev_voucher_hash: self.last_voucher_hash,
            issued_at: now_secs,
            expires_at: now_secs.saturating_add(ttl_secs),
            nonce,
            sig: [0u8; 64],
        };
        voucher.sig = sign_low_s(
            &self.signing_key,
            DOMAIN_OFFLINE_VOUCHER,
            &voucher.signing_bytes(),
        );
        self.counter = counter;
        self.cumulative_spent = cumulative_spent;
        self.last_voucher_hash = voucher.hash();
        VoucherBundle {
            voucher,
            attestation: self.attestation.clone(),
            hops: Vec::new(),
        }
    }
}

