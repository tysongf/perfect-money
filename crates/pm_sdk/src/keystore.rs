use std::fs;
use std::path::Path;

use anyhow::{Result, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use offline_vouchers::{PersistedEnclaveState, PocketId, VoucherBundle};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const KEYSTORE_VERSION: u16 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Argon2Params {
    /// OWASP-aligned interactive/wallet Argon2id parameters (19 MiB, 2 passes, 1 lane).
    pub fn production() -> Self {
        Self {
            m_cost_kib: 19_456,
            t_cost: 2,
            p_cost: 1,
        }
    }

    /// Lightweight Argon2id parameters strictly for rapid automated CLI smoke tests.
    pub fn fast_test() -> Self {
        Self {
            m_cost_kib: 1_024,
            t_cost: 1,
            p_cost: 1,
        }
    }
}

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
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub salt_hex: String,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
}

fn derive_argon2id_key(
    passphrase: &str,
    salt: &[u8; 16],
    params: Argon2Params,
) -> Result<Zeroizing<[u8; 32]>> {
    if params.m_cost_kib < 128 || params.t_cost == 0 || params.p_cost == 0 {
        bail!("invalid Argon2id parameters");
    }
    let a2_params = Params::new(params.m_cost_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| anyhow::anyhow!("Argon2id params error: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut *key)
        .map_err(|e| anyhow::anyhow!("Argon2id derivation error: {e}"))?;
    Ok(key)
}

fn keystore_aad(
    version: u16,
    params: Argon2Params,
    salt: &[u8; 16],
    nonce: &[u8; 24],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(13 + 2 + 12 + 16 + 24);
    aad.extend_from_slice(b"PM_KS_AAD_V2|");
    aad.extend_from_slice(&version.to_le_bytes());
    aad.extend_from_slice(&params.m_cost_kib.to_le_bytes());
    aad.extend_from_slice(&params.t_cost.to_le_bytes());
    aad.extend_from_slice(&params.p_cost.to_le_bytes());
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);
    aad
}

pub fn save_encrypted_wallet(
    path: &Path,
    snapshot: &WalletSnapshot,
    passphrase: &str,
) -> Result<()> {
    save_encrypted_wallet_with_params(path, snapshot, passphrase, Argon2Params::production())
}

pub fn save_encrypted_wallet_with_params(
    path: &Path,
    snapshot: &WalletSnapshot,
    passphrase: &str,
    params: Argon2Params,
) -> Result<()> {
    let json_bytes = Zeroizing::new(serde_json::to_vec(snapshot)?);
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut salt).map_err(|e| anyhow::anyhow!("OS CSPRNG salt failure: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("OS CSPRNG nonce failure: {e}"))?;

    let key = derive_argon2id_key(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = keystore_aad(KEYSTORE_VERSION, params, &salt, &nonce);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: json_bytes.as_ref(),
                aad: &aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("keystore XChaCha20-Poly1305 encryption failed"))?;

    let file = EncryptedKeystoreFile {
        version: KEYSTORE_VERSION,
        m_cost_kib: params.m_cost_kib,
        t_cost: params.t_cost,
        p_cost: params.p_cost,
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
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
    let nonce: [u8; 24] = hex::decode(&file.nonce_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid nonce len"))?;
    let ciphertext = hex::decode(&file.ciphertext_hex)?;
    let params = Argon2Params {
        m_cost_kib: file.m_cost_kib,
        t_cost: file.t_cost,
        p_cost: file.p_cost,
    };

    let key = derive_argon2id_key(passphrase, &salt, params)?;
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = keystore_aad(file.version, params, &salt, &nonce);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                (&nonce).into(),
                Payload {
                    msg: ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("invalid passphrase or corrupted wallet keystore"))?,
    );
    let snapshot: WalletSnapshot = serde_json::from_slice(&plaintext)?;
    Ok(snapshot)
}
