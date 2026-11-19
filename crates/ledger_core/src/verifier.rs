use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail};
use tempfile::TempDir;

/// Supported circuit verification keys in `ledger_core`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitKind {
    Shield,
    ShieldedTransfer,
    Unshield,
}

/// Encodes `FieldElement` public inputs as concatenated 32-byte big-endian words
/// matching Barretenberg's binary `public_inputs` layout.
pub fn encode_public_inputs(inputs: &[FieldElement]) -> Vec<u8> {
    let mut out = Vec::with_capacity(inputs.len() * 32);
    for f in inputs {
        let be = f.to_be_bytes();
        debug_assert_eq!(be.len(), 32);
        out.extend_from_slice(&be);
    }
    out
}

/// Abstraction for verifying UltraHonk proofs against circuit-specific verification keys.
pub trait ProofVerifier {
    fn verify_proof(
        &self,
        kind: CircuitKind,
        proof: &[u8],
        public_inputs: &[FieldElement],
    ) -> Result<()>;
}

/// Barretenberg (`bb verify`) verifier backed by precomputed VK files on disk.
#[derive(Debug, Clone)]
pub struct BbVerifier {
    bb_bin: PathBuf,
    shield_vk: PathBuf,
    transfer_vk: PathBuf,
    unshield_vk: PathBuf,
}

impl BbVerifier {
    pub fn new(shield_vk: PathBuf, transfer_vk: PathBuf, unshield_vk: PathBuf) -> Self {
        Self {
            bb_bin: resolve_bb_binary(),
            shield_vk,
            transfer_vk,
            unshield_vk,
        }
    }

    fn vk_for(&self, kind: CircuitKind) -> &Path {
        match kind {
            CircuitKind::Shield => &self.shield_vk,
            CircuitKind::ShieldedTransfer => &self.transfer_vk,
            CircuitKind::Unshield => &self.unshield_vk,
        }
    }
}

impl ProofVerifier for BbVerifier {
    fn verify_proof(
        &self,
        kind: CircuitKind,
        proof: &[u8],
        public_inputs: &[FieldElement],
    ) -> Result<()> {
        let dir = TempDir::new().context("failed to create temp dir for bb verify")?;
        let proof_path = dir.path().join("proof");
        let pi_path = dir.path().join("public_inputs");
        fs::write(&proof_path, proof).context("failed to write temp proof")?;
        fs::write(&pi_path, encode_public_inputs(public_inputs))
            .context("failed to write temp public_inputs")?;

        let out = Command::new(&self.bb_bin)
            .arg("verify")
            .arg("-p")
            .arg(&proof_path)
            .arg("-k")
            .arg(self.vk_for(kind))
            .arg("-i")
            .arg(&pi_path)
            .output()
            .context("failed to execute bb verify")?;

        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("bb verify failed for {kind:?}: {}", stderr.trim());
        }
        Ok(())
    }
}

fn resolve_bb_binary() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        let candidate = Path::new(&home).join(".bb").join("bb");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("bb")
}

