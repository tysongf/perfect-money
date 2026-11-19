use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::FieldElement;
use acir::native_types::WitnessMap;
use anyhow::{Context, Result, bail};
use serde::Serialize;
use tempfile::TempDir;

use crate::artifact::write_witness_map;

/// Result of running the real Barretenberg prover + verifier on a candidate witness.
#[derive(Debug, Clone, Serialize)]
pub struct BbOracleResult {
    pub proved: bool,
    pub verified: bool,
    pub detail: String,
}

/// Wrapper around the installed `bb` binary for confirming surviving ACIR mutations.
pub struct BbOracle {
    bb_bin: PathBuf,
    artifact_path: PathBuf,
    vk_path: PathBuf,
    _vk_temp_dir: Option<TempDir>,
}

impl BbOracle {
    /// Initializes a `BbOracle`, reusing `--vk` if supplied or generating a VK via `bb write_vk`.
    pub fn new(artifact_path: PathBuf, vk_path: Option<PathBuf>) -> Result<Self> {
        let bb_bin = resolve_bb_binary()?;
        let (resolved_vk, temp_dir) = match vk_path {
            Some(p) => (p, None),
            None => {
                let dir = TempDir::new().context("failed to create temp dir for VK")?;
                let out = Command::new(&bb_bin)
                    .arg("write_vk")
                    .arg("-b")
                    .arg(&artifact_path)
                    .arg("-o")
                    .arg(dir.path())
                    .output()
                    .context("failed to execute bb write_vk")?;
                if !out.status.success() {
                    bail!(
                        "bb write_vk failed: {}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                }
                (dir.path().join("vk"), Some(dir))
            }
        };

        Ok(Self {
            bb_bin,
            artifact_path,
            vk_path: resolved_vk,
            _vk_temp_dir: temp_dir,
        })
    }

    /// Runs `bb prove` and `bb verify` against a candidate `WitnessMap`.
    pub fn confirm_witness(&self, witness: &WitnessMap<FieldElement>) -> Result<BbOracleResult> {
        let dir = TempDir::new().context("failed to create temp dir for bb prove")?;
        let witness_path = dir.path().join("witness.gz");
        write_witness_map(witness, &witness_path)?;

        let prove_out = Command::new(&self.bb_bin)
            .arg("prove")
            .arg("-b")
            .arg(&self.artifact_path)
            .arg("-w")
            .arg(&witness_path)
            .arg("-k")
            .arg(&self.vk_path)
            .arg("-o")
            .arg(dir.path())
            .output()
            .context("failed to invoke bb prove")?;

        if !prove_out.status.success() {
            return Ok(BbOracleResult {
                proved: false,
                verified: false,
                detail: truncate_err(&prove_out.stderr),
            });
        }

        let verify_out = Command::new(&self.bb_bin)
            .arg("verify")
            .arg("-p")
            .arg(dir.path().join("proof"))
            .arg("-k")
            .arg(&self.vk_path)
            .arg("-i")
            .arg(dir.path().join("public_inputs"))
            .output()
            .context("failed to invoke bb verify")?;

        let verified = verify_out.status.success();
        let detail = if verified {
            "bb verify exited 0".to_string()
        } else {
            truncate_err(&verify_out.stderr)
        };

        Ok(BbOracleResult {
            proved: true,
            verified,
            detail,
        })
    }
}

fn resolve_bb_binary() -> Result<PathBuf> {
    if let Ok(home) = env::var("HOME") {
        let candidate = Path::new(&home).join(".bb").join("bb");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Ok(PathBuf::from("bb"))
}

fn truncate_err(stderr: &[u8]) -> String {
    let s = String::from_utf8_lossy(stderr).trim().to_string();
    if s.len() > 240 {
        format!("{}...", &s[..240])
    } else {
        s
    }
}

