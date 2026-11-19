use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use hmac::{Hmac, KeyInit, Mac};
use offline_vouchers::{PersistedEnclaveState, PocketId, VoucherBundle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::note_crypto::sha256_ctr_xor;

type HmacSha256 = Hmac<Sha256>;

pub const KEYSTORE_VERSION: u16 = 1;
pub const DEFAULT_KDF_ROUNDS: u32 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedNoteRecord {
    pub leaf_index: u32,
    pub value: u64,
    pub owner_pk_x_hex: String,
    pub owner_pk_y_hex: String,
    pub blinding_hex: String,
    pub diversifier_hex: String,
    pub g_d_nonce: u8,
    pub g_d_y_hex: String,
    pub commitment_hex: String,
    pub nullifier_hex: String,
    pub memo: String,
    pub spent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSnapshot {
    pub chain_id: u64,
    pub ask_hex: String,
    pub next_diversifier: u64,
    pub notes: Vec<OwnedNoteRecord>,
    pub enclave_state: PersistedEnclaveState,
    pub recovery_sk_hex: String,
    pub merchant_sk_hex: String,
    pub pending_merchant_bundles: Vec<VoucherBundle>,
    pub vendor_cas: Vec<(String, String)>,
    pub revoked_pockets: Vec<PocketId>,
    pub revoked_certs: Vec<[u8; 16]>,
    pub crl_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeystoreFile {
    pub version: u16,
    pub kdf_rounds: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub mac_hex: String,
}

fn derive_keystore_keys(passphrase: &str, salt: &[u8; 16], rounds: u32) -> ([u8; 32], [u8; 32]) {
    let mut h_init = Sha256::new();
    h_init.update(b"PM_KDF_V1|");
    h_init.update(salt);
    h_init.update(passphrase.as_bytes());
    let mut state: [u8; 32] = h_init.finalize().into();

    for round in 0..rounds {
        let mut mac = <HmacSha256 as KeyInit>::new_from_slice(&state).expect("32-byte key");
        mac.update(salt);
        mac.update(&round.to_le_bytes());
        state = mac.finalize().into_bytes().into();
    }

    let mut enc_h = Sha256::new();
    enc_h.update(b"PM_KS_ENC|");
    enc_h.update(state);
    let enc_key: [u8; 32] = enc_h.finalize().into();

    let mut mac_h = Sha256::new();
    mac_h.update(b"PM_KS_MAC|");
    mac_h.update(state);
    let mac_key: [u8; 32] = mac_h.finalize().into();

    (enc_key, mac_key)
}

fn keystore_mac_tag(
    mac_key: &[u8; 32],
    version: u16,
    kdf_rounds: u32,
    salt: &[u8; 16],
    nonce: &[u8; 16],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(mac_key).expect("32-byte key");
    mac.update(b"PM_KS_TAG_V1|");
    mac.update(&version.to_le_bytes());
    mac.update(&kdf_rounds.to_le_bytes());
    mac.update(salt);
    mac.update(nonce);
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

pub fn save_encrypted_wallet(
    path: &Path,
    snapshot: &WalletSnapshot,
    passphrase: &str,
) -> Result<()> {
    let json_bytes = serde_json::to_vec(snapshot)?;
    let mut salt_h = Sha256::new();
    salt_h.update(b"PM_KS_SALT_V1|");
    salt_h.update(&snapshot.ask_hex);
    salt_h.update(&json_bytes);
    let salt_digest: [u8; 32] = salt_h.finalize().into();
    let salt: [u8; 16] = salt_digest[0..16].try_into().unwrap();
    let nonce: [u8; 16] = salt_digest[16..32].try_into().unwrap();

    let (enc_key, mac_key) = derive_keystore_keys(passphrase, &salt, DEFAULT_KDF_ROUNDS);
    let ciphertext = sha256_ctr_xor(&enc_key, &nonce, &json_bytes);
    let tag = keystore_mac_tag(
        &mac_key,
        KEYSTORE_VERSION,
        DEFAULT_KDF_ROUNDS,
        &salt,
        &nonce,
        &ciphertext,
    );

    let file = EncryptedKeystoreFile {
        version: KEYSTORE_VERSION,
        kdf_rounds: DEFAULT_KDF_ROUNDS,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
        mac_hex: hex::encode(tag),
    };
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, serde_json::to_vec_pretty(&file)?)?;
    fs::rename(&tmp_path, path)?;
    Ok(())
}

pub fn load_encrypted_wallet(path: &Path, passphrase: &str) -> Result<WalletSnapshot> {
    let raw = fs::read(path)?;
    let file: EncryptedKeystoreFile = serde_json::from_slice(&raw)?;
    if file.version != KEYSTORE_VERSION {
        bail!("unsupported keystore version {}", file.version);
    }
    let salt: [u8; 16] = hex::decode(&file.salt_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid salt len"))?;
    let nonce: [u8; 16] = hex::decode(&file.nonce_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid nonce len"))?;
    let ciphertext = hex::decode(&file.ciphertext_hex)?;
    let tag = hex::decode(&file.mac_hex)?;

    let (enc_key, mac_key) = derive_keystore_keys(passphrase, &salt, file.kdf_rounds);
    let expected_mac = keystore_mac_tag(
        &mac_key,
        file.version,
        file.kdf_rounds,
        &salt,
        &nonce,
        &ciphertext,
    );
    if tag.as_slice() != expected_mac.as_slice() {
        bail!("invalid passphrase or corrupted wallet keystore");
    }
    let plaintext = sha256_ctr_xor(&enc_key, &nonce, &ciphertext);
    let snapshot: WalletSnapshot = serde_json::from_slice(&plaintext)?;
    Ok(snapshot)
}

