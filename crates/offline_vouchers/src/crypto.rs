use acir::{AcirField, FieldElement};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{Deserialize, Deserializer, Serializer};
use sha2::{Digest, Sha256};

use crate::error::VoucherError;
use crate::types::PocketId;

pub const DOMAIN_POCKET_ID: &[u8] = b"PM_POCKET_ID_V1";
pub const DOMAIN_HW_ATTEST: &[u8] = b"PM_HW_ATTEST_V1";
pub const DOMAIN_OFFLINE_VOUCHER: &[u8] = b"PM_OFFLINE_VOUCHER_V1";
pub const DOMAIN_VOUCHER_HOP: &[u8] = b"PM_VOUCHER_HOP_V1";
pub const DOMAIN_POCKET_CLOSE: &[u8] = b"PM_POCKET_CLOSE_V1";
pub const DOMAIN_POCKET_DRAIN: &[u8] = b"PM_POCKET_DRAIN_V1";
pub const DOMAIN_POCKET_FUND_BIND: &[u8] = b"PM_POCKET_FUND_BIND_V1";
pub const DOMAIN_VOUCHER_SETTLE_BIND: &[u8] = b"PM_VOUCHER_SETTLE_BIND_V1";
pub const DOMAIN_POCKET_RECLAIM_BIND: &[u8] = b"PM_POCKET_RECLAIM_BIND_V1";

pub fn sha256_raw(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

pub fn sha256_domain(domain: &[u8], payload: &[u8]) -> [u8; 32] {
    sha256_raw(&[domain, b"|", payload])
}

pub fn derive_pocket_id(chain_id: u64, device_pk: &[u8; 33]) -> PocketId {
    let mut payload = Vec::with_capacity(8 + 33);
    payload.extend_from_slice(&chain_id.to_le_bytes());
    payload.extend_from_slice(device_pk);
    PocketId(sha256_domain(DOMAIN_POCKET_ID, &payload))
}

pub fn compressed_pk(sk: &SigningKey) -> [u8; 33] {
    let pt = sk.verifying_key().to_sec1_point(true);
    let mut out = [0u8; 33];
    out.copy_from_slice(pt.as_bytes());
    out
}

pub fn signing_key_from_seed(seed_tag: &[u8]) -> SigningKey {
    let mut counter: u64 = 0;
    loop {
        let digest = sha256_raw(&[b"PM_KEY_SEED_V1|", seed_tag, &counter.to_le_bytes()]);
        if let Ok(sk) = SigningKey::from_bytes(&digest.into()) {
            return sk;
        }
        counter += 1;
    }
}

pub fn sign_low_s(sk: &SigningKey, domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let digest = sha256_domain(domain, payload);
    let sig: Signature = sk
        .sign_prehash(&digest)
        .expect("P-256 prehash signing should not fail");
    let canonical = sig.normalize_s();
    let mut out = [0u8; 64];
    out.copy_from_slice(canonical.to_bytes().as_slice());
    out
}

pub fn verify_low_s(
    pk_bytes: &[u8; 33],
    domain: &[u8],
    payload: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), VoucherError> {
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| VoucherError::InvalidPublicKey)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| VoucherError::InvalidSignature)?;
    if sig.normalize_s() != sig {
        return Err(VoucherError::NonCanonicalHighS);
    }
    let digest = sha256_domain(domain, payload);
    vk.verify_prehash(&digest, &sig)
        .map_err(|_| VoucherError::InvalidSignature)
}

/// Flips canonical low-S signature into malleable high-S `(r, n - s)` for adversarial tests.
pub fn malleate_to_high_s(sig_bytes: &[u8; 64]) -> Result<[u8; 64], VoucherError> {
    let sig = Signature::from_slice(sig_bytes).map_err(|_| VoucherError::InvalidSignature)?;
    let s_neg = -sig.s();
    let mal = Signature::from_scalars(sig.r().to_bytes(), s_neg.to_bytes())
        .map_err(|_| VoucherError::InvalidSignature)?;
    let mut out = [0u8; 64];
    out.copy_from_slice(mal.to_bytes().as_slice());
    Ok(out)
}

fn digest_to_nonzero_field(digest: [u8; 32]) -> FieldElement {
    let f = FieldElement::from_be_bytes_reduce(&digest);
    if f.is_zero() {
        FieldElement::one()
    } else {
        f
    }
}

pub fn compute_pocket_fund_binding_hash(
    chain_id: u64,
    pocket_id: &PocketId,
    device_pk: &[u8; 33],
    amount: u64,
) -> FieldElement {
    let mut payload = Vec::with_capacity(8 + 32 + 33 + 8);
    payload.extend_from_slice(&chain_id.to_le_bytes());
    payload.extend_from_slice(&pocket_id.0);
    payload.extend_from_slice(device_pk);
    payload.extend_from_slice(&amount.to_le_bytes());
    digest_to_nonzero_field(sha256_domain(DOMAIN_POCKET_FUND_BIND, &payload))
}

pub fn compute_voucher_settle_binding_hash(
    chain_id: u64,
    voucher_hash: &[u8; 32],
    recipient_pk: &[u8; 33],
    out_commitment: FieldElement,
) -> FieldElement {
    let mut payload = Vec::with_capacity(8 + 32 + 33 + 32);
    payload.extend_from_slice(&chain_id.to_le_bytes());
    payload.extend_from_slice(voucher_hash);
    payload.extend_from_slice(recipient_pk);
    payload.extend_from_slice(&out_commitment.to_be_bytes());
    digest_to_nonzero_field(sha256_domain(DOMAIN_VOUCHER_SETTLE_BIND, &payload))
}

pub fn compute_pocket_reclaim_binding_hash(
    chain_id: u64,
    pocket_id: &PocketId,
    amount: u64,
    out_commitment: FieldElement,
) -> FieldElement {
    let mut payload = Vec::with_capacity(8 + 32 + 8 + 32);
    payload.extend_from_slice(&chain_id.to_le_bytes());
    payload.extend_from_slice(&pocket_id.0);
    payload.extend_from_slice(&amount.to_le_bytes());
    payload.extend_from_slice(&out_commitment.to_be_bytes());
    digest_to_nonzero_field(sha256_domain(DOMAIN_POCKET_RECLAIM_BIND, &payload))
}

pub mod serde_hex_33 {
    use super::*;

    pub fn serialize<S: Serializer>(val: &[u8; 33], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 33], D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 33];
        if raw.len() != 33 {
            return Err(serde::de::Error::custom("expected 33 bytes"));
        }
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

pub mod serde_hex_64 {
    use super::*;

    pub fn serialize<S: Serializer>(val: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(val))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(d)?;
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        let mut out = [0u8; 64];
        if raw.len() != 64 {
            return Err(serde::de::Error::custom("expected 64 bytes"));
        }
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

