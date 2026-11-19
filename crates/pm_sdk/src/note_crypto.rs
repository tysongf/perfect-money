use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use ledger_core::{
    GrumpkinPoint, Note, compute_note_commitment,
    crypto::{grumpkin_scalar_mul, is_on_grumpkin},
    derive_diversified_address,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::address::PaymentAddress;

const FIXED_PLAINTEXT_HEAD: usize = 75; // value(8) + blinding(32) + diversifier(32) + nonce(1) + memo_len(2)

/// Authenticated Grumpkin ECDH + XChaCha20-Poly1305 note ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedNote {
    pub epk_x_hex: String,
    pub epk_y_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
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

fn derive_note_aead_key(shared: &GrumpkinPoint, epk: &GrumpkinPoint) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(128));
    ikm.extend_from_slice(&shared.x.to_be_bytes());
    ikm.extend_from_slice(&shared.y.to_be_bytes());
    ikm.extend_from_slice(&epk.x.to_be_bytes());
    ikm.extend_from_slice(&epk.y.to_be_bytes());
    let hk = Hkdf::<Sha256>::new(Some(b"PM_NOTE_AEAD_V2"), &ikm);
    let mut key = Zeroizing::new([0u8; 32]);
    hk.expand(b"xchacha20poly1305-key", &mut *key)
        .expect("32-byte HKDF expand cannot fail");
    key
}

fn note_aad(cm: FieldElement, epk: &GrumpkinPoint) -> Vec<u8> {
    let mut aad = Vec::with_capacity(15 + 96);
    aad.extend_from_slice(b"PM_NOTE_AAD_V2|");
    aad.extend_from_slice(&cm.to_be_bytes());
    aad.extend_from_slice(&epk.x.to_be_bytes());
    aad.extend_from_slice(&epk.y.to_be_bytes());
    aad
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
    let key = derive_note_aead_key(&shared, &epk);

    let mut plain = Zeroizing::new(Vec::with_capacity(FIXED_PLAINTEXT_HEAD + memo_bytes.len()));
    plain.extend_from_slice(&note.value.to_le_bytes());
    plain.extend_from_slice(&note.blinding.to_be_bytes());
    plain.extend_from_slice(&recipient.diversifier.to_be_bytes());
    plain.push(recipient.nonce);
    plain.extend_from_slice(&(memo_bytes.len() as u16).to_le_bytes());
    plain.extend_from_slice(memo_bytes);

    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce)
        .map_err(|e| anyhow::anyhow!("OS CSPRNG note nonce failure: {e}"))?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = note_aad(cm, &epk);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plain.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("note XChaCha20-Poly1305 encryption failed"))?;

    Ok(EncryptedNote {
        epk_x_hex: field_to_hex(epk.x),
        epk_y_hex: field_to_hex(epk.y),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
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
    let nonce: [u8; 24] = hex::decode(&enc.nonce_hex).ok()?.try_into().ok()?;
    let ciphertext = hex::decode(&enc.ciphertext_hex).ok()?;
    if ciphertext.len() < FIXED_PLAINTEXT_HEAD + 16 {
        return None;
    }

    let shared = grumpkin_scalar_mul(epk, ivk).ok()?;
    let key = derive_note_aead_key(&shared, &epk);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = note_aad(cm, &epk);
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .ok()?,
    );

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
    hasher.update(enc.nonce_hex.as_bytes());
    hasher.update(b"|");
    hasher.update(enc.ciphertext_hex.as_bytes());
}

pub fn compute_shield_tx_binding_hash(chain_id: u64, enc: &EncryptedNote) -> FieldElement {
    let mut h = Sha256::new();
    h.update(b"PM_SHIELD_BIND_V2|");
    h.update(chain_id.to_le_bytes());
    hash_encrypted_note_into(&mut h, enc);
    digest_to_nonzero_field(h.finalize().into())
}

pub fn compute_transfer_tx_binding_hash(chain_id: u64, encs: &[EncryptedNote; 2]) -> FieldElement {
    let mut h = Sha256::new();
    h.update(b"PM_TRANSFER_BIND_V2|");
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
    h.update(b"PM_UNSHIELD_BIND_V2|");
    h.update(chain_id.to_le_bytes());
    hash_encrypted_note_into(&mut h, change_enc);
    digest_to_nonzero_field(h.finalize().into())
}
