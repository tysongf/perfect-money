use std::env;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use serde::Serialize;

/// Verdict returned by `cvc5`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtStatus {
    Sat,
    Unsat,
    Unknown,
}

pub fn resolve_cvc5() -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        let candidate = Path::new(&home).join(".local/bin/cvc5");
        if candidate.is_file() {
            return candidate;
        }
    }
    PathBuf::from("cvc5")
}

/// Executes `cvc5 --lang smt2 --tlimit=<tlimit_ms> -` and parses `sat` / `unsat` / `unknown`.
pub fn run_cvc5(cvc5_bin: &Path, smt_script: &str, tlimit_ms: u64) -> Result<(SmtStatus, u128)> {
    let start = std::time::Instant::now();
    let mut child = Command::new(cvc5_bin)
        .args(["--lang", "smt2", &format!("--tlimit={tlimit_ms}"), "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn cvc5 at {}", cvc5_bin.display()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(smt_script.as_bytes())?;
    }

    let output = child.wait_with_output()?;
    let elapsed_ms = start.elapsed().as_millis();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if stdout.contains("unsat") {
        Ok((SmtStatus::Unsat, elapsed_ms))
    } else if stdout.contains("sat") {
        Ok((SmtStatus::Sat, elapsed_ms))
    } else if stdout.contains("unknown") || stderr.contains("timeout") {
        Ok((SmtStatus::Unknown, elapsed_ms))
    } else {
        bail!("cvc5 failed (status={}): stdout='{stdout}' stderr='{stderr}'", output.status);
    }
}

