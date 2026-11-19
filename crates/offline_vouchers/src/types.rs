use std::collections::{BTreeMap, BTreeSet};

use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};

use crate::crypto::{
    DOMAIN_HW_ATTEST, DOMAIN_OFFLINE_VOUCHER, DOMAIN_POCKET_CLOSE, DOMAIN_POCKET_DRAIN,
    DOMAIN_VOUCHER_HOP, derive_pocket_id, serde_hex_33, serde_hex_64, sha256_domain, verify_low_s,
};
use crate::error::VoucherError;

pub const VOUCHER_FORMAT_VERSION: u16 = 1;
pub const DEFAULT_CHAIN_ID: u64 = 1;
pub const DEFAULT_MAX_POCKET_BALANCE: u64 = 500_000_000;
pub const CONSTITUTIONAL_HARD_CAP: u64 = 1_000_000_000;
pub const DEFAULT_MAX_VOUCHER_TTL_SECS: u64 = 604_800;
pub const DEFAULT_MAX_CLOCK_SKEW_SECS: u64 = 300;
pub const DEFAULT_MAX_HOPS_ALLOWED: u8 = 3;
pub const DEFAULT_MERCHANT_MAX_HOPS: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PocketId(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PocketPolicy {
    pub chain_id: u64,
    pub max_pocket_balance: u64,
    pub constitutional_hard_cap: u64,
    pub max_voucher_ttl_secs: u64,
    pub uncooperative_drain_delay_secs: u64,
    pub max_clock_skew_secs: u64,
    pub max_hops_allowed: u8,
    pub default_merchant_max_hops: u8,
}

impl Default for PocketPolicy {
    fn default() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID,
            max_pocket_balance: DEFAULT_MAX_POCKET_BALANCE,
            constitutional_hard_cap: CONSTITUTIONAL_HARD_CAP,
            max_voucher_ttl_secs: DEFAULT_MAX_VOUCHER_TTL_SECS,
            uncooperative_drain_delay_secs: DEFAULT_MAX_VOUCHER_TTL_SECS,
            max_clock_skew_secs: DEFAULT_MAX_CLOCK_SKEW_SECS,
            max_hops_allowed: DEFAULT_MAX_HOPS_ALLOWED,
            default_merchant_max_hops: DEFAULT_MERCHANT_MAX_HOPS,
        }
    }
}

impl PocketPolicy {
    pub fn validate(&self) -> Result<(), VoucherError> {
        if self.constitutional_hard_cap == 0 {
            return Err(VoucherError::InvalidPolicy(
                "constitutional_hard_cap must be > 0".to_string(),
            ));
        }
        if self.max_pocket_balance == 0 || self.max_pocket_balance > self.constitutional_hard_cap {
            return Err(VoucherError::InvalidPolicy(format!(
                "max_pocket_balance ({}) must be in 1..={}",
                self.max_pocket_balance, self.constitutional_hard_cap
            )));
        }
        if self.max_voucher_ttl_secs == 0 {
            return Err(VoucherError::InvalidPolicy(
                "max_voucher_ttl_secs must be > 0".to_string(),
            ));
        }
        if self.uncooperative_drain_delay_secs < self.max_voucher_ttl_secs {
            return Err(VoucherError::InvalidPolicy(
                "uncooperative_drain_delay_secs must be >= max_voucher_ttl_secs".to_string(),
            ));
        }
        if self.max_hops_allowed == 0 || self.default_merchant_max_hops > self.max_hops_allowed {
            return Err(VoucherError::InvalidPolicy(
                "invalid hop policy bounds".to_string(),
            ));
        }
        Ok(())
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    SecureEnclave = 1,
    StrongBox = 2,
    Fido2Hardware = 3,
}

impl SecurityLevel {
    pub fn from_u8(val: u8) -> Result<Self, VoucherError> {
        match val {
            1 => Ok(Self::SecureEnclave),
            2 => Ok(Self::StrongBox),
            3 => Ok(Self::Fido2Hardware),
            _ => Err(VoucherError::WireError(format!(
                "unknown security_level {val}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareAttestation {
    pub vendor_id: String,
    #[serde(with = "serde_hex_33")]
    pub device_pk: [u8; 33],
    pub security_level: SecurityLevel,
    pub issued_at: u64,
    pub expires_at: u64,
    pub cert_serial: [u8; 16],
    #[serde(with = "serde_hex_64")]
    pub ca_sig: [u8; 64],
}

impl HardwareAttestation {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let vendor_bytes = self.vendor_id.as_bytes();
        let mut out = Vec::with_capacity(2 + vendor_bytes.len() + 33 + 1 + 8 + 8 + 16);
        out.extend_from_slice(&(vendor_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(vendor_bytes);
        out.extend_from_slice(&self.device_pk);
        out.push(self.security_level as u8);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.cert_serial);
        out
    }

    pub fn pocket_id(&self, chain_id: u64) -> PocketId {
        derive_pocket_id(chain_id, &self.device_pk)
    }

    pub fn verify(
        &self,
        trust_store: &AttestationTrustStore,
        chain_id: u64,
        now_secs: u64,
    ) -> Result<PocketId, VoucherError> {
        trust_store.verify_attestation(self, chain_id, now_secs)
    }
}

#[derive(Debug, Clone, Default)]
pub struct AttestationTrustStore {
    pub vendor_cas: BTreeMap<String, [u8; 33]>,
    pub revoked_pockets: BTreeSet<PocketId>,
    pub revoked_cert_serials: BTreeSet<[u8; 16]>,
    pub crl_version: u64,
}

impl AttestationTrustStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_ca(&mut self, vendor_id: impl Into<String>, ca_pk: [u8; 33]) -> Result<(), VoucherError> {
        VerifyingKey::from_sec1_bytes(&ca_pk).map_err(|_| VoucherError::InvalidPublicKey)?;
        self.vendor_cas.insert(vendor_id.into(), ca_pk);
        Ok(())
    }

    pub fn revoke_pocket(&mut self, pocket_id: PocketId) {
        if self.revoked_pockets.insert(pocket_id) {
            self.crl_version += 1;
        }
    }

    pub fn revoke_cert(&mut self, serial: [u8; 16]) {
        if self.revoked_cert_serials.insert(serial) {
            self.crl_version += 1;
        }
    }

    pub fn verify_attestation(
        &self,
        att: &HardwareAttestation,
        chain_id: u64,
        now_secs: u64,
    ) -> Result<PocketId, VoucherError> {
        VerifyingKey::from_sec1_bytes(&att.device_pk).map_err(|_| VoucherError::InvalidPublicKey)?;
        let ca_pk = self
            .vendor_cas
            .get(&att.vendor_id)
            .ok_or_else(|| VoucherError::UntrustedVendorCa(att.vendor_id.clone()))?;
        if self.revoked_cert_serials.contains(&att.cert_serial) {
            return Err(VoucherError::CertificateRevoked);
        }
        let pocket_id = att.pocket_id(chain_id);
        if self.revoked_pockets.contains(&pocket_id) {
            return Err(VoucherError::PocketRevoked);
        }
        if now_secs < att.issued_at {
            return Err(VoucherError::AttestationNotYetValid);
        }
        if now_secs > att.expires_at {
            return Err(VoucherError::AttestationExpired);
        }
        verify_low_s(ca_pk, DOMAIN_HW_ATTEST, &att.signing_bytes(), &att.ca_sig)?;
        Ok(pocket_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineVoucher {
    pub version: u16,
    pub chain_id: u64,
    pub pocket_id: PocketId,
    pub counter: u64,
    pub amount: u64,
    pub cumulative_spent: u64,
    #[serde(with = "serde_hex_33")]
    pub recipient_pk: [u8; 33],
    pub prev_voucher_hash: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 16],
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl OfflineVoucher {
    pub const WIRE_SIZE: usize = 227;

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(163);
        out.extend_from_slice(&self.version.to_le_bytes());
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.pocket_id.0);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&self.amount.to_le_bytes());
        out.extend_from_slice(&self.cumulative_spent.to_le_bytes());
        out.extend_from_slice(&self.recipient_pk);
        out.extend_from_slice(&self.prev_voucher_hash);
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn hash(&self) -> [u8; 32] {
        sha256_domain(DOMAIN_OFFLINE_VOUCHER, &self.signing_bytes())
    }

    pub fn verify_common(&self, policy: &PocketPolicy, now_secs: u64) -> Result<(), VoucherError> {
        if self.version != VOUCHER_FORMAT_VERSION {
            return Err(VoucherError::InvalidVersion(self.version));
        }
        if self.chain_id != policy.chain_id {
            return Err(VoucherError::ChainIdMismatch {
                expected: policy.chain_id,
                got: self.chain_id,
            });
        }
        if self.counter == 0 {
            return Err(VoucherError::InvalidCounter(0));
        }
        if self.amount == 0 {
            return Err(VoucherError::ZeroAmount);
        }
        if self.cumulative_spent < self.amount
            || self.cumulative_spent > policy.max_pocket_balance
            || self.amount > policy.max_pocket_balance
        {
            return Err(VoucherError::CapExceeded {
                requested: self.cumulative_spent.max(self.amount) as u128,
                cap: policy.max_pocket_balance,
            });
        }
        if self.expires_at < self.issued_at
            || self.expires_at - self.issued_at > policy.max_voucher_ttl_secs
        {
            return Err(VoucherError::VoucherTtlTooLong);
        }
        if self.issued_at > now_secs.saturating_add(policy.max_clock_skew_secs) {
            return Err(VoucherError::VoucherNotYetValid {
                issued_at: self.issued_at,
                now: now_secs,
            });
        }
        if now_secs > self.expires_at {
            return Err(VoucherError::VoucherExpired {
                expires_at: self.expires_at,
                now: now_secs,
            });
        }
        VerifyingKey::from_sec1_bytes(&self.recipient_pk)
            .map_err(|_| VoucherError::InvalidPublicKey)?;
        Ok(())
    }

    pub fn verify_signature(&self, device_pk: &[u8; 33]) -> Result<(), VoucherError> {
        verify_low_s(
            device_pk,
            DOMAIN_OFFLINE_VOUCHER,
            &self.signing_bytes(),
            &self.sig,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopEndorsement {
    pub voucher_hash: [u8; 32],
    pub hop_index: u8,
    #[serde(with = "serde_hex_33")]
    pub from_pk: [u8; 33],
    #[serde(with = "serde_hex_33")]
    pub to_pk: [u8; 33],
    pub expires_at: u64,
    pub nonce: [u8; 16],
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl HopEndorsement {
    pub const WIRE_SIZE: usize = 187;

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(123);
        out.extend_from_slice(&self.voucher_hash);
        out.push(self.hop_index);
        out.extend_from_slice(&self.from_pk);
        out.extend_from_slice(&self.to_pk);
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    pub fn verify_signature(&self) -> Result<(), VoucherError> {
        VerifyingKey::from_sec1_bytes(&self.to_pk).map_err(|_| VoucherError::InvalidPublicKey)?;
        verify_low_s(
            &self.from_pk,
            DOMAIN_VOUCHER_HOP,
            &self.signing_bytes(),
            &self.sig,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VoucherBundle {
    pub voucher: OfflineVoucher,
    pub attestation: HardwareAttestation,
    pub hops: Vec<HopEndorsement>,
}

impl VoucherBundle {
    pub fn final_holder_pk(&self) -> [u8; 33] {
        self.hops
            .last()
            .map(|h| h.to_pk)
            .unwrap_or(self.voucher.recipient_pk)
    }

    pub fn verify_hop_chain(
        &self,
        policy: &PocketPolicy,
        max_accepted_hops: u8,
        now_secs: u64,
    ) -> Result<[u8; 33], VoucherError> {
        let total_hops = 1usize + self.hops.len();
        let allowed = usize::from(max_accepted_hops.min(policy.max_hops_allowed));
        if total_hops > allowed {
            return Err(VoucherError::HopLimitExceeded {
                hops: total_hops,
                max_hops: allowed,
            });
        }
        let vhash = self.voucher.hash();
        let mut current_holder = self.voucher.recipient_pk;
        for (idx, hop) in self.hops.iter().enumerate() {
            let expected_idx = (idx + 1) as u8;
            if hop.hop_index != expected_idx {
                return Err(VoucherError::InvalidHopChain(format!(
                    "expected hop_index {expected_idx}, got {}",
                    hop.hop_index
                )));
            }
            if hop.voucher_hash != vhash {
                return Err(VoucherError::InvalidHopChain(
                    "hop voucher_hash mismatch".to_string(),
                ));
            }
            if hop.from_pk != current_holder {
                return Err(VoucherError::InvalidHopChain(
                    "broken hop holder continuity".to_string(),
                ));
            }
            if hop.expires_at > self.voucher.expires_at || now_secs > hop.expires_at {
                return Err(VoucherError::InvalidHopChain(
                    "hop expired or exceeds base voucher expiry".to_string(),
                ));
            }
            hop.verify_signature()?;
            current_holder = hop.to_pk;
        }
        Ok(current_holder)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloseStatement {
    pub chain_id: u64,
    pub pocket_id: PocketId,
    pub final_counter: u64,
    pub final_cumulative_spent: u64,
    pub closed_at: u64,
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl CloseStatement {
    pub const WIRE_SIZE: usize = 128;

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.pocket_id.0);
        out.extend_from_slice(&self.final_counter.to_le_bytes());
        out.extend_from_slice(&self.final_cumulative_spent.to_le_bytes());
        out.extend_from_slice(&self.closed_at.to_le_bytes());
        out
    }

    pub fn verify_signature(&self, device_pk: &[u8; 33]) -> Result<(), VoucherError> {
        verify_low_s(
            device_pk,
            DOMAIN_POCKET_CLOSE,
            &self.signing_bytes(),
            &self.sig,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncooperativeDrainRequest {
    pub chain_id: u64,
    pub pocket_id: PocketId,
    pub requested_at: u64,
    #[serde(with = "serde_hex_64")]
    pub sig: [u8; 64],
}

impl UncooperativeDrainRequest {
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.pocket_id.0);
        out.extend_from_slice(&self.requested_at.to_le_bytes());
        out
    }

    pub fn verify_signature(&self, recovery_pk: &[u8; 33]) -> Result<(), VoucherError> {
        verify_low_s(
            recovery_pk,
            DOMAIN_POCKET_DRAIN,
            &self.signing_bytes(),
            &self.sig,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EquivocationFraudProof {
    pub voucher_a: OfflineVoucher,
    pub voucher_b: OfflineVoucher,
}

