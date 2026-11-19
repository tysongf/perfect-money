use std::path::Path;

#[cfg(test)]
use acir::native_types::Witness;
use anyhow::{Result, bail};
use serde::Serialize;

use crate::acir_to_smt::{
    BN254_FR_PRIME, SmtCircuit, SmtProgramBuilder, ff_literal, load_smt_circuit, load_witness_map,
};
use crate::cvc5::{SmtStatus, run_cvc5};

/// Single formal verification obligation executed by `smt_checker`.
#[derive(Debug, Clone, Serialize)]
pub struct ProofObligationResult {
    pub name: String,
    pub circuit: String,
    pub expected: String,
    pub actual: String,
    pub passed: bool,
    pub elapsed_ms: u128,
    pub detail: String,
}

fn wref(c: &SmtCircuit, prefix: &str, abi_name: &str) -> Result<String> {
    let w = c
        .labels
        .get(abi_name)
        .ok_or_else(|| anyhow::anyhow!("missing ABI parameter '{abi_name}' in {}", c.name))?;
    Ok(format!("{prefix}w{}", w.0))
}

/// Runs all Stage 3 formal proof obligations across `shield`, `unshield`, and `shielded_transfer`.
pub fn run_all_formal_proofs(root: &Path, cvc5_bin: &Path) -> Result<Vec<ProofObligationResult>> {
    let shield = load_smt_circuit(&root.join("circuits/shield/target/shield.json"), "shield")?;
    let unshield = load_smt_circuit(
        &root.join("circuits/unshield/target/unshield.json"),
        "unshield",
    )?;
    let transfer = load_smt_circuit(
        &root.join("circuits/shielded_transfer/target/shielded_transfer.json"),
        "shielded_transfer",
    )?;

    let mut out = Vec::new();

    // 1. Witness-pinned consistency sanity checks (SAT => SMT encoding is non-vacuous)
    for c in [&shield, &unshield, &transfer] {
        let w_path = root.join("circuits").join(&c.name).join("target/witness.gz");
        let wmap = load_witness_map(&w_path)?;
        let mut builder = SmtProgramBuilder::new();
        builder.emit_acir_copy(&c.circuit, "", false)?;
        for (w, val) in wmap.into_iter() {
            let wname = format!("w{}", w.0);
            if builder.has_wire(&wname) {
                builder.assert_raw(format!("(assert (= {wname} {}))", ff_literal(val)));
            }
        }
        let (status, ms) = run_cvc5(cvc5_bin, &builder.build(), 15_000)?;
        out.push(ProofObligationResult {
            name: format!("{}_witness_consistency_sat", c.name),
            circuit: c.name.clone(),
            expected: "sat".to_string(),
            actual: fmt_status(status),
            passed: status == SmtStatus::Sat,
            elapsed_ms: ms,
            detail: "Non-vacuousness check pinning baseline WitnessMap in cvc5".to_string(),
        });
    }

    // 2. Range-Bound ACIR Audit (Lemma 1: u64 / u32 RANGE constraints emitted by Noir)
    out.push(audit_ranges(
        &shield,
        &[("mint_amount", 64), ("out_note.value", 64)],
    ));
    out.push(audit_ranges(
        &unshield,
        &[
            ("in_note.value", 64),
            ("burn_amount", 64),
            ("change_note.value", 64),
            ("fee", 64),
            ("in_leaf_index", 32),
        ],
    ));
    out.push(audit_ranges(
        &transfer,
        &[
            ("in_notes[0].value", 64),
            ("in_notes[1].value", 64),
            ("out_notes[0].value", 64),
            ("out_notes[1].value", 64),
            ("fee", 64),
            ("in_leaf_indices[0]", 32),
            ("in_leaf_indices[1]", 32),
        ],
    ));

    // 3. BN254 ValueConservation non-wrap formal proofs (QF_LIA, Lemma 3)
    out.push(run_lia_nonwrap_proof(
        "value_conservation_nonwrap_2in2out",
        "shielded_transfer",
        &["in0", "in1"],
        &["out0", "out1", "fee"],
        cvc5_bin,
    )?);
    out.push(run_lia_nonwrap_proof(
        "value_conservation_nonwrap_unshield",
        "unshield",
        &["in0"],
        &["burn", "change", "fee"],
        cvc5_bin,
    )?);

    // 4. Full-ACIR finite-field + UF constitutional invariant proofs (UNSAT)
    out.push(prove_shield_invariants(&shield, cvc5_bin)?);
    out.push(prove_unshield_invariants(&unshield, cvc5_bin)?);
    out.push(prove_transfer_invariants(&transfer, cvc5_bin)?);

    // 5. Two-copy ACIR determinism / uniqueness proofs (UNSAT)
    out.push(prove_two_copy_uniqueness(
        "shield_2copy_uniqueness",
        &shield,
        &[
            "out_note.value",
            "out_note.owner_pk_x",
            "out_note.owner_pk_y",
            "out_note.blinding",
        ],
        &["mint_amount", "out_commitment"],
        cvc5_bin,
    )?);
    out.push(prove_two_copy_uniqueness(
        "unshield_2copy_uniqueness",
        &unshield,
        &[
            "ask",
            "in_note.value",
            "in_note.owner_pk_x",
            "in_note.owner_pk_y",
            "in_note.blinding",
            "in_leaf_index",
            "change_note.value",
            "change_note.owner_pk_x",
            "change_note.owner_pk_y",
            "change_note.blinding",
        ],
        &["nullifier", "change_commitment"],
        cvc5_bin,
    )?);
    out.push(prove_two_copy_uniqueness(
        "shielded_transfer_2copy_uniqueness",
        &transfer,
        &[
            "ask",
            "in_notes[0].value",
            "in_notes[0].owner_pk_x",
            "in_notes[0].owner_pk_y",
            "in_notes[0].blinding",
            "in_notes[1].value",
            "in_notes[1].owner_pk_x",
            "in_notes[1].owner_pk_y",
            "in_notes[1].blinding",
            "in_leaf_indices[0]",
            "in_leaf_indices[1]",
            "out_notes[0].value",
            "out_notes[0].owner_pk_x",
            "out_notes[0].owner_pk_y",
            "out_notes[0].blinding",
            "out_notes[1].value",
            "out_notes[1].owner_pk_x",
            "out_notes[1].owner_pk_y",
            "out_notes[1].blinding",
        ],
        &[
            "nullifiers[0]",
            "nullifiers[1]",
            "out_commitments[0]",
            "out_commitments[1]",
        ],
        cvc5_bin,
    )?);

    Ok(out)
}

fn audit_ranges(c: &SmtCircuit, required: &[(&str, u32)]) -> ProofObligationResult {
    let start = std::time::Instant::now();
    let mut missing = Vec::new();
    for &(label, bits) in required {
        match c.labels.get(label) {
            None => missing.push(format!("{label} (missing ABI)")),
            Some(w) => {
                let ok = c
                    .range_bounds
                    .get(w)
                    .is_some_and(|set| set.contains(&bits));
                if !ok {
                    missing.push(format!("{label} ({w}, expected RANGE({bits}))"));
                }
            }
        }
    }
    let passed = missing.is_empty();
    ProofObligationResult {
        name: format!("{}_acir_range_audit", c.name),
        circuit: c.name.clone(),
        expected: "all_present".to_string(),
        actual: if passed {
            "all_present".to_string()
        } else {
            format!("missing: {}", missing.join(", "))
        },
        passed,
        elapsed_ms: start.elapsed().as_millis(),
        detail: format!("Verified {} RANGE opcodes in compiled ACIR", required.len()),
    }
}

fn run_lia_nonwrap_proof(
    name: &str,
    circuit_name: &str,
    ins: &[&str],
    outs: &[&str],
    cvc5_bin: &Path,
) -> Result<ProofObligationResult> {
    let mut lines = vec![
        "(set-logic QF_LIA)".to_string(),
        format!("(define-fun P () Int {BN254_FR_PRIME})"),
        "(define-fun U64_MAX () Int 18446744073709551615)".to_string(),
        "(declare-const k Int)".to_string(),
    ];
    for v in ins.iter().chain(outs.iter()) {
        lines.push(format!("(declare-const {v} Int)"));
        lines.push(format!("(assert (and (<= 0 {v}) (<= {v} U64_MAX)))"));
    }
    let sum_in = if ins.len() == 1 {
        ins[0].to_string()
    } else {
        format!("(+ {})", ins.join(" "))
    };
    let sum_out = if outs.len() == 1 {
        outs[0].to_string()
    } else {
        format!("(+ {})", outs.join(" "))
    };
    lines.push(format!("(assert (= (- {sum_in} {sum_out}) (* k P)))"));
    lines.push(format!("(assert (not (= {sum_in} {sum_out})))"));
    lines.push("(check-sat)".to_string());

    let (status, ms) = run_cvc5(cvc5_bin, &lines.join("\n"), 15_000)?;
    Ok(ProofObligationResult {
        name: name.to_string(),
        circuit: circuit_name.to_string(),
        expected: "unsat".to_string(),
        actual: fmt_status(status),
        passed: status == SmtStatus::Unsat,
        elapsed_ms: ms,
        detail: "Exact integer QF_LIA proof that u64 bounds preclude BN254 wrap-around".to_string(),
    })
}

fn prove_shield_invariants(c: &SmtCircuit, cvc5_bin: &Path) -> Result<ProofObligationResult> {
    let mut b = SmtProgramBuilder::new();
    b.emit_acir_copy(&c.circuit, "", true)?;
    let txb = wref(c, "", "tx_binding_hash")?;
    let mint = wref(c, "", "mint_amount")?;
    let out_v = wref(c, "", "out_note.value")?;
    let pk_x = wref(c, "", "out_note.owner_pk_x")?;
    let pk_y = wref(c, "", "out_note.owner_pk_y")?;

    b.assert_raw(format!(
        "(assert (or
  (= {txb} (as ff0 F))
  (= {mint} (as ff0 F))
  (not (= {out_v} {mint}))
  (= {pk_y} (as ff0 F))
  (not (= (ff.mul {pk_y} {pk_y}) (ff.add (ff.mul {pk_x} (ff.mul {pk_x} {pk_x})) (as ff-17 F))))
))"
    ));
    let (status, ms) = run_cvc5(cvc5_bin, &b.build(), 15_000)?;
    Ok(ProofObligationResult {
        name: "shield_full_acir_invariants".to_string(),
        circuit: c.name.clone(),
        expected: "unsat".to_string(),
        actual: fmt_status(status),
        passed: status == SmtStatus::Unsat,
        elapsed_ms: ms,
        detail: "Proves tx_binding!=0, mint>0, value equality, on-curve Grumpkin pk".to_string(),
    })
}

fn prove_unshield_invariants(c: &SmtCircuit, cvc5_bin: &Path) -> Result<ProofObligationResult> {
    let mut b = SmtProgramBuilder::new();
    b.emit_acir_copy(&c.circuit, "", true)?;
    let txb = wref(c, "", "tx_binding_hash")?;
    let ask = wref(c, "", "ask")?;
    let burn = wref(c, "", "burn_amount")?;
    let fee = wref(c, "", "fee")?;
    let in_v = wref(c, "", "in_note.value")?;
    let g_d_y = wref(c, "", "in_g_d_y")?;
    let chg_v = wref(c, "", "change_note.value")?;
    let chg_x = wref(c, "", "change_note.owner_pk_x")?;
    let chg_y = wref(c, "", "change_note.owner_pk_y")?;

    b.assert_raw(format!(
        "(assert (or
  (= {txb} (as ff0 F))
  (= {ask} (as ff0 F))
  (= {burn} (as ff0 F))
  (= {g_d_y} (as ff0 F))
  (not (= {in_v} (ff.add {burn} {chg_v} {fee})))
  (and
    (not (= {chg_v} (as ff0 F)))
    (or
      (= {chg_y} (as ff0 F))
      (not (= (ff.mul {chg_y} {chg_y}) (ff.add (ff.mul {chg_x} (ff.mul {chg_x} {chg_x})) (as ff-17 F))))
    )
  )
))"
    ));
    let (status, ms) = run_cvc5(cvc5_bin, &b.build(), 15_000)?;
    Ok(ProofObligationResult {
        name: "unshield_full_acir_invariants".to_string(),
        circuit: c.name.clone(),
        expected: "unsat".to_string(),
        actual: fmt_status(status),
        passed: status == SmtStatus::Unsat,
        elapsed_ms: ms,
        detail: "Proves tx_binding!=0, ask!=0, burn!=0, g_d_y!=0, change Grumpkin check, mod-p balance".to_string(),
    })
}

fn prove_transfer_invariants(c: &SmtCircuit, cvc5_bin: &Path) -> Result<ProofObligationResult> {
    let mut b = SmtProgramBuilder::new();
    b.emit_acir_copy(&c.circuit, "", true)?;
    let txb = wref(c, "", "tx_binding_hash")?;
    let ask = wref(c, "", "ask")?;
    let nf0 = wref(c, "", "nullifiers[0]")?;
    let nf1 = wref(c, "", "nullifiers[1]")?;
    let fee = wref(c, "", "fee")?;
    let in0 = wref(c, "", "in_notes[0].value")?;
    let in1 = wref(c, "", "in_notes[1].value")?;
    let out0 = wref(c, "", "out_notes[0].value")?;
    let o0x = wref(c, "", "out_notes[0].owner_pk_x")?;
    let o0y = wref(c, "", "out_notes[0].owner_pk_y")?;
    let out1 = wref(c, "", "out_notes[1].value")?;
    let o1x = wref(c, "", "out_notes[1].owner_pk_x")?;
    let o1y = wref(c, "", "out_notes[1].owner_pk_y")?;

    b.assert_raw(format!(
        "(assert (or
  (= {txb} (as ff0 F))
  (= {ask} (as ff0 F))
  (= {nf0} {nf1})
  (not (= (ff.add {in0} {in1}) (ff.add {out0} {out1} {fee})))
  (and
    (not (= {out0} (as ff0 F)))
    (or
      (= {o0y} (as ff0 F))
      (not (= (ff.mul {o0y} {o0y}) (ff.add (ff.mul {o0x} (ff.mul {o0x} {o0x})) (as ff-17 F))))
    )
  )
  (and
    (not (= {out1} (as ff0 F)))
    (or
      (= {o1y} (as ff0 F))
      (not (= (ff.mul {o1y} {o1y}) (ff.add (ff.mul {o1x} (ff.mul {o1x} {o1x})) (as ff-17 F))))
    )
  )
))"
    ));
    let (status, ms) = run_cvc5(cvc5_bin, &b.build(), 15_000)?;
    Ok(ProofObligationResult {
        name: "shielded_transfer_full_acir_invariants".to_string(),
        circuit: c.name.clone(),
        expected: "unsat".to_string(),
        actual: fmt_status(status),
        passed: status == SmtStatus::Unsat,
        elapsed_ms: ms,
        detail: "Proves tx_binding!=0, ask!=0, nf0!=nf1, mod-p balance, non-zero outputs on Grumpkin".to_string(),
    })
}

fn prove_two_copy_uniqueness(
    name: &str,
    c: &SmtCircuit,
    same_labels: &[&str],
    diff_labels: &[&str],
    cvc5_bin: &Path,
) -> Result<ProofObligationResult> {
    let mut b = SmtProgramBuilder::new();
    b.emit_acir_copy(&c.circuit, "a_", true)?;
    b.emit_acir_copy(&c.circuit, "b_", true)?;

    for lbl in same_labels {
        let wa = wref(c, "a_", lbl)?;
        let wb = wref(c, "b_", lbl)?;
        b.assert_raw(format!("(assert (= {wa} {wb}))"));
    }

    let mut diff_clauses = Vec::with_capacity(diff_labels.len());
    for lbl in diff_labels {
        let wa = wref(c, "a_", lbl)?;
        let wb = wref(c, "b_", lbl)?;
        diff_clauses.push(format!("(not (= {wa} {wb}))"));
    }
    b.assert_raw(format!("(assert (or {}))", diff_clauses.join(" ")));

    let (status, ms) = run_cvc5(cvc5_bin, &b.build(), 15_000)?;
    Ok(ProofObligationResult {
        name: name.to_string(),
        circuit: c.name.clone(),
        expected: "unsat".to_string(),
        actual: fmt_status(status),
        passed: status == SmtStatus::Unsat,
        elapsed_ms: ms,
        detail: format!("2-copy uniqueness over full ACIR for outputs {diff_labels:?}"),
    })
}

/// Helper used by canary unit test to confirm a circuit missing an invariant returns `sat`.
#[cfg(test)]
pub fn check_missing_curve_canary(cvc5_bin: &Path, with_curve_check: bool) -> Result<SmtStatus> {
    let x = Witness(0);
    let y = Witness(1);
    let mut smt = vec![
        "(set-logic ALL)".to_string(),
        format!("(define-sort F () (_ FiniteField {BN254_FR_PRIME}))"),
        format!("(declare-const w{} F)", x.0),
        format!("(declare-const w{} F)", y.0),
    ];
    if with_curve_check {
        smt.push(format!(
            "(assert (= (ff.mul w{} w{}) (ff.add (ff.mul w{} (ff.mul w{} w{})) (as ff-17 F))))",
            y.0, y.0, x.0, x.0, x.0
        ));
    }
    smt.push(format!(
        "(assert (not (= (ff.mul w{} w{}) (ff.add (ff.mul w{} (ff.mul w{} w{})) (as ff-17 F)))))",
        y.0, y.0, x.0, x.0, x.0
    ));
    smt.push("(check-sat)".to_string());
    let (status, _) = run_cvc5(cvc5_bin, &smt.join("\n"), 10_000)?;
    Ok(status)
}

#[cfg(test)]
pub fn check_missing_range_lia_canary(cvc5_bin: &Path, enforce_u64_bounds: bool) -> Result<SmtStatus> {
    let mut lines = vec![
        "(set-logic QF_LIA)".to_string(),
        format!("(define-fun P () Int {BN254_FR_PRIME})"),
        "(define-fun U64_MAX () Int 18446744073709551615)".to_string(),
        "(declare-const k Int)".to_string(),
        "(declare-const in0 Int)".to_string(),
        "(declare-const out0 Int)".to_string(),
        "(declare-const out1 Int)".to_string(),
    ];
    if enforce_u64_bounds {
        for v in ["in0", "out0", "out1"] {
            lines.push(format!("(assert (and (<= 0 {v}) (<= {v} U64_MAX)))"));
        }
    } else {
        lines.push("(assert (and (<= 0 in0) (<= 0 out0) (<= 0 out1)))".to_string());
    }
    lines.push("(assert (= (- in0 (+ out0 out1)) (* k P)))".to_string());
    lines.push("(assert (not (= in0 (+ out0 out1))))".to_string());
    lines.push("(check-sat)".to_string());
    let (status, _) = run_cvc5(cvc5_bin, &lines.join("\n"), 10_000)?;
    Ok(status)
}

fn fmt_status(s: SmtStatus) -> String {
    match s {
        SmtStatus::Sat => "sat".to_string(),
        SmtStatus::Unsat => "unsat".to_string(),
        SmtStatus::Unknown => "unknown".to_string(),
    }
}

pub fn ensure_all_passed(results: &[ProofObligationResult]) -> Result<()> {
    let failed: Vec<&ProofObligationResult> = results.iter().filter(|r| !r.passed).collect();
    if !failed.is_empty() {
        bail!("{} formal proof obligation(s) failed", failed.len());
    }
    Ok(())
}

