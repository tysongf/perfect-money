use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ledger_core::{
    DOMAIN_DIVERSIFIER, DiversifiedAddress, GrumpkinPoint, crypto::is_on_grumpkin, poseidon2_hash,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const ADDRESS_PREFIX: &str = "pm1";
const ADDRESS_BODY_BYTES: usize = 129;
const ADDRESS_TOTAL_BYTES: usize = 133;

/// Diversified Grumpkin shielded payment address (`pm1...`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAddress {
    pub diversifier: FieldElement,
    pub nonce: u8,
    pub g_d: GrumpkinPoint,
    pub pk_d: GrumpkinPoint,
}

fn field_from_be_exact(bytes: &[u8]) -> Result<FieldElement> {
    if bytes.len() != 32 {
        bail!("expected 32-byte field element, got {}", bytes.len());
    }
    let f = FieldElement::from_be_bytes_reduce(bytes);
    if f.to_be_bytes().as_slice() != bytes {
        bail!("non-canonical field element encoding");
    }
    Ok(f)
}

fn address_checksum(body: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(b"PM_ADDR_V1|");
    hasher.update(body);
    let digest = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

impl PaymentAddress {
    pub fn from_diversified(addr: DiversifiedAddress) -> Self {
        Self {
            diversifier: addr.diversifier,
            nonce: addr.nonce,
            g_d: addr.g_d,
            pk_d: addr.pk_d,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected_gx = poseidon2_hash(&[
            FieldElement::from(DOMAIN_DIVERSIFIER),
            self.diversifier,
            FieldElement::from(self.nonce as u64),
        ]);
        if self.g_d.x != expected_gx {
            bail!("payment address g_d.x does not match diversifier + nonce");
        }
        if !is_on_grumpkin(self.g_d.x, self.g_d.y) {
            bail!("payment address g_d is not on Grumpkin curve");
        }
        if !is_on_grumpkin(self.pk_d.x, self.pk_d.y) {
            bail!("payment address pk_d is not on Grumpkin curve");
        }
        Ok(())
    }

    pub fn encode(&self) -> String {
        let mut raw = Vec::with_capacity(ADDRESS_TOTAL_BYTES);
        raw.extend_from_slice(&self.diversifier.to_be_bytes());
        raw.push(self.nonce);
        raw.extend_from_slice(&self.g_d.y.to_be_bytes());
        raw.extend_from_slice(&self.pk_d.x.to_be_bytes());
        raw.extend_from_slice(&self.pk_d.y.to_be_bytes());
        debug_assert_eq!(raw.len(), ADDRESS_BODY_BYTES);
        let csum = address_checksum(&raw);
        raw.extend_from_slice(&csum);
        format!("{ADDRESS_PREFIX}{}", URL_SAFE_NO_PAD.encode(raw))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let b64 = encoded
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("payment address must start with '{ADDRESS_PREFIX}'"))?;
        let raw = URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| anyhow::anyhow!("invalid base64 in payment address: {e}"))?;
        if raw.len() != ADDRESS_TOTAL_BYTES {
            bail!(
                "invalid payment address length: expected {ADDRESS_TOTAL_BYTES}, got {}",
                raw.len()
            );
        }
        let body = &raw[..ADDRESS_BODY_BYTES];
        let expected_csum = address_checksum(body);
        if raw[ADDRESS_BODY_BYTES..] != expected_csum {
            bail!("payment address checksum mismatch");
        }
        let diversifier = field_from_be_exact(&body[0..32])?;
        let nonce = body[32];
        let g_d_y = field_from_be_exact(&body[33..65])?;
        let pk_d_x = field_from_be_exact(&body[65..97])?;
        let pk_d_y = field_from_be_exact(&body[97..129])?;
        let g_d_x = poseidon2_hash(&[
            FieldElement::from(DOMAIN_DIVERSIFIER),
            diversifier,
            FieldElement::from(nonce as u64),
        ]);
        let addr = Self {
            diversifier,
            nonce,
            g_d: GrumpkinPoint { x: g_d_x, y: g_d_y },
            pk_d: GrumpkinPoint {
                x: pk_d_x,
                y: pk_d_y,
            },
        };
        addr.validate()?;
        Ok(addr)
    }
}

