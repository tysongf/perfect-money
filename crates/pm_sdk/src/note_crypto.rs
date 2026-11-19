use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use ledger_core::{
    GrumpkinPoint, Note, compute_note_commitment,
    crypto::{grumpkin_scalar_mul, is_on_grumpkin},
    derive_diversified_address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::address::PaymentAddress;

type HmacSha256 = Hmac<Sha256>;

const FIXED_PLAINTEXT_HEAD: usize = 75; // value(8) + blinding(32) + diversifier(32) + nonce(1) + memo_len(2)

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedNote {
    pub epk_x_hex: String,
    pub epk_y_hex: String,
    pub ciphertext_hex: String,
    pub tag_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedNote {
    pub note: Note,
    pub diversifier: FieldElement,
    pub nonce: u8,
    pub g_d_y: FieldElement,
    pub memo: String,
}

impl EncryptedNote {
    pub fn epk_point(&self) -> Result<GrumpkinPoint> {
        let x = field_from_hex(&self.epk_x_hex)?;
        let y = field_from_hex(&self.epk_y_hex)?;
        Ok(GrumpkinPoint { x, y })
    }
}

pub fn field_to_hex(f: FieldElement) -> String {
    format!("0x{}", f.to_hex())
}

pub fn field_from_hex(s: &str) -> Result<FieldElement> {
    FieldElement::from_hex(s).ok_or_else(|| anyhow::anyhow!("invalid field hex: {s}"))
}

fn derive_ecdh_keys(shared: &GrumpkinPoint, epk: &GrumpkinPoint) -> ([u8; 32], [u8; 32]) {
    let mut enc_h = Sha256::new();
    enc_h.update(b"PM_NOTE_ENC_V1|");
    enc_h.update(shared.x.to_be_bytes());
    enc_h.update(shared.y.to_be_bytes());
    enc_h.update(epk.x.to_be_bytes());
    enc_h.update(epk.y.to_be_bytes());
    let enc_key: [u8; 32] = enc_h.finalize().into();

    let mut mac_h = Sha256::new();
    mac_h.update(b"PM_NOTE_MAC_V1|");
    mac_h.update(shared.x.to_be_bytes());
    mac_h.update(shared.y.to_be_bytes());
    mac_h.update(epk.x.to_be_bytes());
    mac_h.update(epk.y.to_be_bytes());
    let mac_key: [u8; 32] = mac_h.finalize().into();

    (enc_key, mac_key)
}

pub(crate) fn sha256_ctr_xor(key: &[u8; 32], nonce_tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (idx, chunk) in data.chunks(32).enumerate() {
        let mut h = Sha256::new();
        h.update(b"PM_CTR_V1|");
        h.update(key);
        h.update(nonce_tag);
        h.update((idx as u64).to_le_bytes());
        let mask = h.finalize();
        for (i, b) in chunk.iter().enumerate() {
            out.push(b ^ mask[i]);
        }
    }
    out
}

fn note_hmac_tag(
    mac_key: &[u8; 32],
    cm: FieldElement,
    epk: &GrumpkinPoint,
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(mac_key).expect("32-byte key");
    mac.update(b"PM_NOTE_TAG_V1|");
    mac.update(&cm.to_be_bytes());
    mac.update(&epk.x.to_be_bytes());
    mac.update(&epk.y.to_be_bytes());
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

pub fn encrypt_note(
    recipient: &PaymentAddress,
    note: &Note,
    esk: FieldElement,
    cm: FieldElement,
    memo: &str,
) -> Result<EncryptedNote> {
    recipient.validate()?;
    if esk.is_zero() {
        bail!("ephemeral secret esk cannot be zero");
    }
    if note.owner_pk_x != recipient.pk_d.x || note.owner_pk_y != recipient.pk_d.y {
        bail!("note owner_pk does not match recipient pk_d");
    }
    if compute_note_commitment(note) != cm {
        bail!("note commitment mismatch during encrypt_note");
    }
    let memo_bytes = memo.as_bytes();
    if memo_bytes.len() > u16::MAX as usize {
        bail!("memo too long");
    }

    let epk = grumpkin_scalar_mul(recipient.g_d, esk)?;
    let shared = grumpkin_scalar_mul(recipient.pk_d, esk)?;
    let (enc_key, mac_key) = derive_ecdh_keys(&shared, &epk);

    let mut plain = Vec::with_capacity(FIXED_PLAINTEXT_HEAD + memo_bytes.len());
    plain.extend_from_slice(&note.value.to_le_bytes());
    plain.extend_from_slice(&note.blinding.to_be_bytes());
    plain.extend_from_slice(&recipient.diversifier.to_be_bytes());
    plain.push(recipient.nonce);
    plain.extend_from_slice(&(memo_bytes.len() as u16).to_le_bytes());
    plain.extend_from_slice(memo_bytes);

    let ciphertext = sha256_ctr_xor(&enc_key, &cm.to_be_bytes(), &plain);
    let tag = note_hmac_tag(&mac_key, cm, &epk, &ciphertext);

    Ok(EncryptedNote {
        epk_x_hex: field_to_hex(epk.x),
        epk_y_hex: field_to_hex(epk.y),
        ciphertext_hex: hex::encode(ciphertext),
        tag_hex: hex::encode(tag),
    })
}

pub fn try_decrypt_note(
    ivk: FieldElement,
    cm: FieldElement,
    enc: &EncryptedNote,
) -> Option<DecryptedNote> {
    if ivk.is_zero() {
        return None;
    }
    let epk = enc.epk_point().ok()?;
    if !is_on_grumpkin(epk.x, epk.y) {
        return None;
    }
    let ciphertext = hex::decode(&enc.ciphertext_hex).ok()?;
    let tag = hex::decode(&enc.tag_hex).ok()?;
    if ciphertext.len() < FIXED_PLAINTEXT_HEAD || tag.len() != 32 {
        return None;
    }

    let shared = grumpkin_scalar_mul(epk, ivk).ok()?;
    let (enc_key, mac_key) = derive_ecdh_keys(&shared, &epk);

    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&mac_key).ok()?;
    mac.update(b"PM_NOTE_TAG_V1|");
    mac.update(&cm.to_be_bytes());
    mac.update(&epk.x.to_be_bytes());
    mac.update(&epk.y.to_be_bytes());
    mac.update(&ciphertext);
    mac.verify_slice(&tag).ok()?;

    let plain = sha256_ctr_xor(&enc_key, &cm.to_be_bytes(), &ciphertext);
    if plain.len() < FIXED_PLAINTEXT_HEAD {
        return None;
    }
    let value = u64::from_le_bytes(plain[0..8].try_into().ok()?);
    let blinding = FieldElement::from_be_bytes_reduce(&plain[8..40]);
    let diversifier = FieldElement::from_be_bytes_reduce(&plain[40..72]);
    let nonce = plain[72];
    let memo_len = u16::from_le_bytes([plain[73], plain[74]]) as usize;
    if plain.len() != FIXED_PLAINTEXT_HEAD + memo_len {
        return None;
    }
    let memo = String::from_utf8(plain[75..].to_vec()).ok()?;

    let addr = derive_diversified_address(ivk, diversifier).ok()?;
    if addr.nonce != nonce {
        return None;
    }
    let note = Note {
        value,
        owner_pk_x: addr.pk_d.x,
        owner_pk_y: addr.pk_d.y,
        blinding,
    };
    if compute_note_commitment(&note) != cm {
        return None;
    }

    Some(DecryptedNote {
        note,
        diversifier,
        nonce,
        g_d_y: addr.g_d.y,
        memo,
    })
}

fn digest_to_nonzero_field(digest: [u8; 32]) -> FieldElement {
    let f = FieldElement::from_be_bytes_reduce(&digest);
    if f.is_zero() {
        FieldElement::one()
    } else {
        f
    }
}

fn hash_encrypted_note_into(hasher: &mut Sha256, enc: &EncryptedNote) {
    hasher.update(enc.epk_x_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(enc.epk_y_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(enc.ciphertext_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(enc.tag_hex.as_bytes());
}

pub fn compute_shield_tx_binding_hash(chain_id: u64, enc: &EncryptedNote) -> FieldElement {
    let mut h = Sha256::new();
    h.update(b"PM_SHIELD_BIND_V1|");
    h.update(chain_id.to_le_bytes());
    hash_encrypted_note_into(&mut h, enc);
    digest_to_nonzero_field(h.finalize().into())
}

pub fn compute_transfer_tx_binding_hash(chain_id: u64, encs: &[EncryptedNote; 2]) -> FieldElement {
    let mut h = Sha256::new();
    h.update(b"PM_TRANSFER_BIND_V1|");
    h.update(chain_id.to_le_bytes());
    hash_encrypted_note_into(&mut h, &encs[0]);
    h.update(b"||");
    hash_encrypted_note_into(&mut h, &encs[1]);
    digest_to_nonzero_field(h.finalize().into())
}

pub fn compute_unshield_change_binding_hash(
    chain_id: u64,
    change_enc: &EncryptedNote,
) -> FieldElement {
    let mut h = Sha256::new();
    h.update(b"PM_UNSHIELD_BIND_V1|");
    h.update(chain_id.to_le_bytes());
    hash_encrypted_note_into(&mut h, change_enc);
    digest_to_nonzero_field(h.finalize().into())
}

