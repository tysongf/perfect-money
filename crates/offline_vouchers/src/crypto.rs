use acir::{AcirField, FieldElement};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use p256::ecdsa::{
    Signature, SigningKey, VerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use serde::{Deserialize, Deserializer, Serializer};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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

pub fn fill_os_random(dst: &mut [u8]) -> Result<(), VoucherError> {
    getrandom::fill(dst)
        .map_err(|e| VoucherError::TransportError(format!("OS CSPRNG failure: {e}")))
}

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

pub fn sign_prehash_low_s(sk: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
    let sig: Signature = sk
        .sign_prehash(digest)
        .expect("P-256 prehash signing should not fail");
    let canonical = sig.normalize_s();
    let mut out = [0u8; 64];
    out.copy_from_slice(canonical.to_bytes().as_slice());
    out
}

pub fn sign_low_s(sk: &SigningKey, domain: &[u8], payload: &[u8]) -> [u8; 64] {
    let digest = sha256_domain(domain, payload);
    sign_prehash_low_s(sk, &digest)
}

pub fn verify_prehash_low_s(
    pk_bytes: &[u8; 33],
    digest: &[u8; 32],
    sig_bytes: &[u8; 64],
) -> Result<(), VoucherError> {
    let vk = VerifyingKey::from_sec1_bytes(pk_bytes).map_err(|_| VoucherError::InvalidPublicKey)?;
    let sig = Signature::from_slice(sig_bytes).map_err(|_| VoucherError::InvalidSignature)?;
    if sig.normalize_s() != sig {
        return Err(VoucherError::NonCanonicalHighS);
    }
    vk.verify_prehash(digest, &sig)
        .map_err(|_| VoucherError::InvalidSignature)
}

pub fn verify_low_s(
    pk_bytes: &[u8; 33],
    domain: &[u8],
    payload: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<(), VoucherError> {
    let digest = sha256_domain(domain, payload);
    verify_prehash_low_s(pk_bytes, &digest, sig_bytes)
}

/// Verifies a W3C WebAuthn / Passkey P-256 assertion bound to `expected_challenge`.
pub fn verify_webauthn_p256_low_s(
    pk_bytes: &[u8; 33],
    expected_challenge: &[u8; 32],
    expected_rp_id: Option<&str>,
    require_uv: bool,
    authenticator_data: &[u8],
    client_data_json: &[u8],
    sig_bytes: &[u8; 64],
) -> Result<u32, VoucherError> {
    if authenticator_data.len() < 37 {
        return Err(VoucherError::InvalidWebAuthnAssertion(
            "authenticatorData shorter than 37 bytes".to_string(),
        ));
    }
    if let Some(rp_id) = expected_rp_id {
        let expected_rp_hash = sha256_raw(&[rp_id.as_bytes()]);
        if !bool::from(authenticator_data[0..32].ct_eq(&expected_rp_hash)) {
            return Err(VoucherError::WebAuthnRpIdMismatch);
        }
    }
    let flags = authenticator_data[32];
    if (flags & 0x01) == 0 {
        return Err(VoucherError::InvalidWebAuthnAssertion(
            "missing UP flag in authenticatorData".to_string(),
        ));
    }
    if require_uv && (flags & 0x04) == 0 {
        return Err(VoucherError::WebAuthnUserVerificationRequired);
    }

    let client_val: serde_json::Value = serde_json::from_slice(client_data_json)
        .map_err(|e| VoucherError::InvalidWebAuthnAssertion(format!("clientDataJSON parse: {e}")))?;
    if client_val.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(VoucherError::InvalidWebAuthnAssertion(
            "clientDataJSON.type must be 'webauthn.get'".to_string(),
        ));
    }
    if !client_val
        .get("origin")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty())
    {
        return Err(VoucherError::InvalidWebAuthnAssertion(
            "clientDataJSON.origin missing or empty".to_string(),
        ));
    }
    if client_val.get("crossOrigin").and_then(|v| v.as_bool()) == Some(true) {
        return Err(VoucherError::InvalidWebAuthnAssertion(
            "clientDataJSON.crossOrigin must not be true".to_string(),
        ));
    }
    let expected_challenge_b64 = URL_SAFE_NO_PAD.encode(expected_challenge);
    let actual_challenge = client_val
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VoucherError::WebAuthnChallengeMismatch)?;
    if !bool::from(
        actual_challenge
            .as_bytes()
            .ct_eq(expected_challenge_b64.as_bytes()),
    ) {
        return Err(VoucherError::WebAuthnChallengeMismatch);
    }

    let client_hash = sha256_raw(&[client_data_json]);
    let signed_digest = sha256_raw(&[authenticator_data, &client_hash]);
    verify_prehash_low_s(pk_bytes, &signed_digest, sig_bytes)?;

    Ok(u32::from_be_bytes([
        authenticator_data[33],
        authenticator_data[34],
        authenticator_data[35],
        authenticator_data[36],
    ]))
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

