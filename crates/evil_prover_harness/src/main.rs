mod attacks;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;

use crate::attacks::{AttackResult, load_circuit_bundle, resolve_tool, run_all_attacks};

#[derive(Debug, Parser)]
#[command(
    name = "evil_prover_harness",
    about = "Stage 2 Evil Prover adversarial red-team harness against Barretenberg and LedgerState"
)]
struct Cli {
    #[arg(long, default_value = "target/evil_prover_report.json")]
    report: PathBuf,
}

#[derive(Debug, Serialize)]
struct EvilProverReport {
    total_attacks: usize,
    rejected: usize,
    confirmed_exploits: usize,
    elapsed_ms: u128,
    results: Vec<AttackResult>,
}

fn find_workspace_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    if cwd.join("circuits/shielded_transfer/Nargo.toml").is_file() {
        return Ok(cwd);
    }
    let manifest_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .context("failed to locate workspace root")?;
    Ok(manifest_root)
}

fn run(cli: Cli) -> Result<bool> {
    let start = std::time::Instant::now();
    let root = find_workspace_root()?;
    let bb_bin = resolve_tool(".bb/bb", "bb");
    let nargo_bin = resolve_tool(".nargo/bin/nargo", "nargo");

    let shield = load_circuit_bundle(&root, "shield")?;
    let transfer = load_circuit_bundle(&root, "shielded_transfer")?;
    let unshield = load_circuit_bundle(&root, "unshield")?;

    let results = run_all_attacks(&root, &bb_bin, &nargo_bin, &shield, &transfer, &unshield)?;
    let total_attacks = results.len();
    let rejected = results.iter().filter(|r| r.rejected).count();
    let confirmed_exploits = total_attacks - rejected;
    let elapsed_ms = start.elapsed().as_millis();

    let report_path = if cli.report.is_relative() {
        root.join(&cli.report)
    } else {
        cli.report
    };
    if let Some(parent) = report_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }

    let report = EvilProverReport {
        total_attacks,
        rejected,
        confirmed_exploits,
        elapsed_ms,
        results,
    };
    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;

    println!(
        "evil_prover_harness summary: total_attacks={total_attacks}, rejected={rejected}, confirmed_exploits={confirmed_exploits}, elapsed_ms={elapsed_ms}"
    );
    for r in report.results.iter().filter(|r| !r.rejected) {
        eprintln!(
            "CONFIRMED EXPLOIT #{} [{} / {}] {}: {}",
            r.id, r.category, r.circuit, r.name, r.detail
        );
    }

    Ok(confirmed_exploits == 0 && total_attacks >= 50)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("evil_prover_harness error: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::attacks::{attempt_bb_exploit, load_circuit_bundle, resolve_tool};

    #[test]
    fn test_oracle_accepts_honest_baseline_witness_non_vacuously() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let bb_bin = resolve_tool(".bb/bb", "bb");
        let shield = load_circuit_bundle(root, "shield").unwrap();
        let verdict = attempt_bb_exploit(&bb_bin, &shield, &shield.baseline_witness).unwrap();
        assert!(
            verdict.verified,
            "oracle must report verified=true on valid baseline shield witness: {}",
            verdict.detail
        );
    }
}

