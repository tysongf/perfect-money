use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
pub use bip39::{Language, Mnemonic, WordCount};
use hkdf::Hkdf;
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicWords {
    Words12,
    Words24,
}

impl From<MnemonicWords> for WordCount {
    fn from(w: MnemonicWords) -> Self {
        match w {
            MnemonicWords::Words12 => WordCount::Words12,
            MnemonicWords::Words24 => WordCount::Words24,
        }
    }
}

pub struct DerivedWalletSecrets {
    pub ask: FieldElement,
    pub device_sk: SigningKey,
    pub recovery_sk: SigningKey,
    pub merchant_sk: SigningKey,
    pub cert_serial: [u8; 16],
}

pub fn generate_mnemonic(words: MnemonicWords) -> Result<Mnemonic> {
    let entropy_len = match words {
        MnemonicWords::Words12 => 16,
        MnemonicWords::Words24 => 32,
    };
    let mut entropy = Zeroizing::new(vec![0u8; entropy_len]);
    getrandom::fill(&mut entropy)
        .map_err(|e| anyhow::anyhow!("OS CSPRNG entropy failure: {e}"))?;
    Ok(Mnemonic::from_entropy_in(Language::English, &entropy)?)
}

pub fn parse_mnemonic(phrase: &str) -> Result<Mnemonic> {
    Ok(Mnemonic::parse_in(Language::English, phrase.trim())?)
}

fn hkdf_expand_nonzero_field(hk: &Hkdf<Sha256>, label: &[u8]) -> Result<FieldElement> {
    for ctr in 0u32..256 {
        let mut info = Vec::with_capacity(label.len() + 4);
        info.extend_from_slice(label);
        info.extend_from_slice(&ctr.to_le_bytes());
        let mut okm = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut *okm)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        let f = FieldElement::from_be_bytes_reduce(&*okm);
        if !f.is_zero() {
            return Ok(f);
        }
    }
    bail!("failed to derive non-zero field element from HKDF")
}

fn hkdf_expand_p256_sk(hk: &Hkdf<Sha256>, label: &[u8]) -> Result<SigningKey> {
    for ctr in 0u32..256 {
        let mut info = Vec::with_capacity(label.len() + 4);
        info.extend_from_slice(label);
        info.extend_from_slice(&ctr.to_le_bytes());
        let mut raw = Zeroizing::new([0u8; 32]);
        hk.expand(&info, &mut *raw)
            .map_err(|_| anyhow::anyhow!("HKDF expand failed"))?;
        let mut digest = Zeroizing::new(Sha256::digest(&*raw));
        if let Ok(sk) = SigningKey::from_bytes(&(*digest).into()) {
            return Ok(sk);
        }
        // Fallback stretch if digest happens to be outside [1, n-1]
        let mut d2 = Zeroizing::new(Sha256::digest(&*digest));
        *digest = *d2;
        d2.iter_mut().for_each(|b| *b = 0);
        if let Ok(sk) = SigningKey::from_bytes(&(*digest).into()) {
            return Ok(sk);
        }
    }
    bail!("failed to derive valid P-256 signing key from HKDF")
}

pub fn derive_wallet_secrets(
    mnemonic: &Mnemonic,
    bip39_passphrase: &str,
) -> Result<DerivedWalletSecrets> {
    let seed = Zeroizing::new(mnemonic.to_seed(bip39_passphrase));
    let hk = Hkdf::<Sha256>::new(Some(b"PM_BIP39_ROOT_V1"), seed.as_ref());

    let ask = hkdf_expand_nonzero_field(&hk, b"pm/v1/shielded/ask")?;
    let device_sk = hkdf_expand_p256_sk(&hk, b"pm/v1/pocket/device_p256")?;
    let recovery_sk = hkdf_expand_p256_sk(&hk, b"pm/v1/pocket/recovery_p256")?;
    let merchant_sk = hkdf_expand_p256_sk(&hk, b"pm/v1/merchant/settle_p256")?;

    let mut serial_okm = Zeroizing::new([0u8; 16]);
    hk.expand(b"pm/v1/pocket/cert_serial", &mut *serial_okm)
        .map_err(|_| anyhow::anyhow!("HKDF serial expand failed"))?;

    Ok(DerivedWalletSecrets {
        ask,
        device_sk,
        recovery_sk,
        merchant_sk,
        cert_serial: *serial_okm,
    })
}

