mod acir_to_smt;
mod cvc5;
mod proofs;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;
use serde::Serialize;

use crate::cvc5::resolve_cvc5;
use crate::proofs::{ProofObligationResult, ensure_all_passed, run_all_formal_proofs};

#[derive(Debug, Parser)]
#[command(
    name = "smt_checker",
    about = "Stage 3 formal verification over compiled Noir 1.0.0 ACIR artifacts using cvc5"
)]
struct Cli {
    #[arg(long, default_value = "target/smt_checker_report.json")]
    report: PathBuf,
}

#[derive(Debug, Serialize)]
struct SmtReport {
    total_obligations: usize,
    passed: usize,
    failed: usize,
    elapsed_ms: u128,
    results: Vec<ProofObligationResult>,
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
    let cvc5_bin = resolve_cvc5();

    let results = run_all_formal_proofs(&root, &cvc5_bin)?;
    let total = results.len();
    let passed = results.iter().filter(|r| r.passed).count();
    let failed = total - passed;
    let elapsed_ms = start.elapsed().as_millis();

    for r in &results {
        let tag = if r.passed { "PASS" } else { "FAIL" };
        println!(
            "[{tag}] {:<36} ({:<17}) expected={:<11} actual={:<11} {} ms",
            r.name, r.circuit, r.expected, r.actual, r.elapsed_ms
        );
    }

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
    let report = SmtReport {
        total_obligations: total,
        passed,
        failed,
        elapsed_ms,
        results: results.clone(),
    };
    fs::write(&report_path, serde_json::to_string_pretty(&report)?)?;

    println!(
        "smt_checker summary: total={total}, passed={passed}, failed={failed}, elapsed_ms={elapsed_ms}"
    );
    Ok(ensure_all_passed(&results).is_ok())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(err) => {
            eprintln!("smt_checker error: {err:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::acir_to_smt::{
        SmtProgramBuilder, ff_literal, load_smt_circuit, load_witness_map,
    };
    use crate::cvc5::{SmtStatus, resolve_cvc5, run_cvc5};
    use crate::proofs::{
        check_missing_curve_canary, check_missing_range_lia_canary, ensure_all_passed,
        run_all_formal_proofs,
    };

    #[test]
    fn test_canary_missing_range_is_sat() {
        let cvc5 = resolve_cvc5();
        assert_eq!(
            check_missing_range_lia_canary(&cvc5, false).unwrap(),
            SmtStatus::Sat
        );
        assert_eq!(
            check_missing_range_lia_canary(&cvc5, true).unwrap(),
            SmtStatus::Unsat
        );
    }

    #[test]
    fn test_canary_missing_curve_check_is_sat() {
        let cvc5 = resolve_cvc5();
        assert_eq!(
            check_missing_curve_canary(&cvc5, false).unwrap(),
            SmtStatus::Sat
        );
        assert_eq!(
            check_missing_curve_canary(&cvc5, true).unwrap(),
            SmtStatus::Unsat
        );
    }

    #[test]
    fn test_solved_and_canonical_agree_on_shield_consistency() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let cvc5 = resolve_cvc5();
        let shield =
            load_smt_circuit(&root.join("circuits/shield/target/shield.json"), "shield").unwrap();
        let wmap: Vec<_> = load_witness_map(&root.join("circuits/shield/target/witness.gz"))
            .unwrap()
            .into_iter()
            .collect();

        for solve_linear in [false, true] {
            let mut builder = SmtProgramBuilder::new();
            builder
                .emit_acir_copy(&shield.circuit, "", solve_linear)
                .unwrap();
            for &(w, val) in &wmap {
                let wname = format!("w{}", w.0);
                if builder.has_wire(&wname) {
                    builder.assert_raw(format!("(assert (= {wname} {}))", ff_literal(val)));
                }
            }
            let (status, _) = run_cvc5(&cvc5, &builder.build(), 15_000).unwrap();
            assert_eq!(
                status,
                SmtStatus::Sat,
                "witness_consistency_sat disagreed for solve_linear={solve_linear}"
            );

            let txb = shield.labels.get("tx_binding_hash").unwrap();
            let mut inv_builder = SmtProgramBuilder::new();
            inv_builder
                .emit_acir_copy(&shield.circuit, "", solve_linear)
                .unwrap();
            inv_builder.assert_raw(format!("(assert (= w{} (as ff0 F)))", txb.0));
            let (inv_status, _) = run_cvc5(&cvc5, &inv_builder.build(), 15_000).unwrap();
            assert_eq!(
                inv_status,
                SmtStatus::Unsat,
                "tx_binding_hash!=0 disagreed for solve_linear={solve_linear}"
            );
        }
    }

    #[test]
    fn test_all_real_circuit_formal_proofs_pass() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let cvc5 = resolve_cvc5();
        let results = run_all_formal_proofs(root, &cvc5).unwrap();
        assert_eq!(results.len(), 14);
        ensure_all_passed(&results).unwrap();
    }
}

