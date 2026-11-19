use std::collections::{BTreeMap, BTreeSet, VecDeque};

use acir::circuit::opcodes::BlackBoxFuncCall;
use acir::circuit::{Circuit, Opcode};
use acir::native_types::{Witness, WitnessMap};
use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use bn254_blackbox_solver::Bn254BlackBoxSolver;
use serde::Serialize;

use crate::artifact::LoadedArtifact;
use crate::bb_oracle::{BbOracle, BbOracleResult};
use crate::evaluator::verify_constraints;

/// Configuration for running Stage 1 ACIR single-wire and relational fuzzing.
#[derive(Debug, Clone)]
pub struct FuzzerConfig {
    pub allow_dummy_unused: bool,
    pub seed: u64,
    pub random_pairs: usize,
}

/// One surviving mutation detected by the in-memory ACIR evaluator.
#[derive(Debug, Clone, Serialize)]
pub struct SurvivingFinding {
    pub stage: String,
    pub probe: String,
    pub wires: Vec<String>,
    pub bb_confirmation: Option<BbOracleResult>,
}

/// Summary report emitted by `acir_fuzzer`.
#[derive(Debug, Clone, Serialize)]
pub struct FuzzReport {
    pub total_wires: usize,
    pub single_wire_mutations_checked: usize,
    pub relational_probes_checked: usize,
    pub whitelisted_dummy_wires: Vec<String>,
    pub whitelisted_survivors: usize,
    pub benign_is_zero_inverses: Vec<String>,
    pub benign_is_zero_survivors: usize,
    pub unexpected_survivors: Vec<SurvivingFinding>,
    pub confirmed_bb_exploits: usize,
    pub elapsed_ms: u128,
}

/// Runs Stage A (single-wire) and Stage B (relational) ACIR fuzzing on `circuit`.
pub fn run_fuzz_suite(
    artifact: &LoadedArtifact,
    baseline: &WitnessMap<FieldElement>,
    oracle: Option<&BbOracle>,
    cfg: &FuzzerConfig,
) -> Result<FuzzReport> {
    let start = std::time::Instant::now();
    let circuit = &artifact.program.functions[0];
    let solver = Bn254BlackBoxSolver;

    if let Err(fail) = verify_constraints(circuit, baseline, &solver) {
        bail!(
            "baseline witness failed ACIR constraint check at opcode {}: {}",
            fail.opcode_index,
            fail.reason
        );
    }

    let whitelist = if cfg.allow_dummy_unused {
        compute_dummy_unused_whitelist(artifact, circuit, baseline)
    } else {
        BTreeSet::new()
    };
    let benign_inverses = detect_benign_is_zero_inverses(artifact, circuit, baseline);

    let all_wires: Vec<(Witness, FieldElement)> = baseline.clone().into_iter().collect();
    let mut single_wire_checked = 0usize;
    let mut whitelisted_survivors = 0usize;
    let mut benign_is_zero_survivors = 0usize;
    let mut unexpected = Vec::new();
    let mut confirmed_exploits = 0usize;

    // Stage A: Exhaustive single-wire mutation sweep
    for &(w, orig) in &all_wires {
        let is_whitelisted = whitelist.contains(&w);
        let is_benign_inv = benign_inverses.contains(&w);
        for (mut_name, candidate) in single_wire_candidates(orig) {
            single_wire_checked += 1;
            let mut mutated = baseline.clone();
            mutated.insert(w, candidate);

            if verify_constraints(circuit, &mutated, &solver).is_ok() {
                if is_whitelisted {
                    whitelisted_survivors += 1;
                    continue;
                }
                if is_benign_inv {
                    benign_is_zero_survivors += 1;
                    continue;
                }
                let bb_confirmation = match oracle {
                    Some(bb) => Some(bb.confirm_witness(&mutated)?),
                    None => None,
                };
                if bb_confirmation.as_ref().is_some_and(|r| r.verified) {
                    confirmed_exploits += 1;
                }
                unexpected.push(SurvivingFinding {
                    stage: "single_wire".to_string(),
                    probe: mut_name.to_string(),
                    wires: vec![format_wire(w, &artifact.witness_to_label)],
                    bb_confirmation,
                });
            }
        }
    }

    // Stage B: Targeted relational attacks + seeded multi-wire random fuzzing
    let mut relational_checked = 0usize;
    let probes = build_targeted_relational_probes(artifact, circuit, baseline);
    for (probe_name, mutated, touched) in probes {
        relational_checked += 1;
        if verify_constraints(circuit, &mutated, &solver).is_ok() {
            let bb_confirmation = match oracle {
                Some(bb) => Some(bb.confirm_witness(&mutated)?),
                None => None,
            };
            if bb_confirmation.as_ref().is_some_and(|r| r.verified) {
                confirmed_exploits += 1;
            }
            unexpected.push(SurvivingFinding {
                stage: "relational_targeted".to_string(),
                probe: probe_name,
                wires: touched
                    .into_iter()
                    .map(|w| format_wire(w, &artifact.witness_to_label))
                    .collect(),
                bb_confirmation,
            });
        }
    }

    // Hold public parameters and return values fixed during random multi-wire fuzzing so
    // relational_random strictly checks private-witness soundness for fixed public statements.
    let active_wires: Vec<(Witness, FieldElement)> = all_wires
        .iter()
        .copied()
        .filter(|(w, _)| {
            !whitelist.contains(w)
                && !benign_inverses.contains(w)
                && !circuit.public_parameters.0.contains(w)
                && !circuit.return_values.0.contains(w)
        })
        .collect();

    if active_wires.len() >= 2 && cfg.random_pairs > 0 {
        let mut rng = SplitMix64(cfg.seed);
        let two_64 = FieldElement::from(1u128 << 64);
        let two_32 = FieldElement::from(1u128 << 32);

        for iter in 0..cfg.random_pairs {
            relational_checked += 1;
            let count = if iter % 3 == 0 && active_wires.len() >= 3 {
                3
            } else {
                2
            };
            let mut mutated = baseline.clone();
            let mut picked_indices = BTreeSet::new();
            let mut touched = Vec::with_capacity(count);

            while picked_indices.len() < count {
                let idx = (rng.next_u64() as usize) % active_wires.len();
                if picked_indices.insert(idx) {
                    let (w, orig) = active_wires[idx];
                    let mutated_val = match rng.next_u64() % 7 {
                        0 => orig + FieldElement::one(),
                        1 => orig - FieldElement::one(),
                        2 => FieldElement::zero(),
                        3 => -FieldElement::one(),
                        4 => orig + two_64,
                        5 => orig + two_32,
                        _ => -orig,
                    };
                    if mutated_val != orig {
                        mutated.insert(w, mutated_val);
                        touched.push(w);
                    }
                }
            }
            if touched.is_empty() {
                continue;
            }
            if verify_constraints(circuit, &mutated, &solver).is_ok() {
                let bb_confirmation = match oracle {
                    Some(bb) => Some(bb.confirm_witness(&mutated)?),
                    None => None,
                };
                if bb_confirmation.as_ref().is_some_and(|r| r.verified) {
                    confirmed_exploits += 1;
                }
                unexpected.push(SurvivingFinding {
                    stage: "relational_random".to_string(),
                    probe: format!("random_multi_{iter}"),
                    wires: touched
                        .into_iter()
                        .map(|w| format_wire(w, &artifact.witness_to_label))
                        .collect(),
                    bb_confirmation,
                });
            }
        }
    }

    let whitelisted_dummy_wires = whitelist
        .iter()
        .map(|w| format_wire(*w, &artifact.witness_to_label))
        .collect();
    let benign_is_zero_inverses = benign_inverses
        .iter()
        .map(|w| format_wire(*w, &artifact.witness_to_label))
        .collect();

    Ok(FuzzReport {
        total_wires: all_wires.len(),
        single_wire_mutations_checked: single_wire_checked,
        relational_probes_checked: relational_checked,
        whitelisted_dummy_wires,
        whitelisted_survivors,
        benign_is_zero_inverses,
        benign_is_zero_survivors,
        unexpected_survivors: unexpected,
        confirmed_bb_exploits: confirmed_exploits,
        elapsed_ms: start.elapsed().as_millis(),
    })
}

fn single_wire_candidates(orig: FieldElement) -> Vec<(&'static str, FieldElement)> {
    let two_64 = FieldElement::from(1u128 << 64);
    let two_32 = FieldElement::from(1u128 << 32);
    let p_minus_1 = -FieldElement::one();

    let mut out = vec![
        ("plus_1", orig + FieldElement::one()),
        ("minus_1", orig - FieldElement::one()),
        ("plus_2_pow_64", orig + two_64),
        ("plus_2_pow_32", orig + two_32),
    ];
    if !orig.is_zero() {
        out.push(("set_zero", FieldElement::zero()));
    }
    if orig != p_minus_1 {
        out.push(("set_p_minus_1", p_minus_1));
    }
    out
}

fn build_targeted_relational_probes(
    artifact: &LoadedArtifact,
    circuit: &Circuit<FieldElement>,
    baseline: &WitnessMap<FieldElement>,
) -> Vec<(String, WitnessMap<FieldElement>, Vec<Witness>)> {
    let mut probes = Vec::new();
    let map = &artifact.label_to_witness;
    let two_64 = FieldElement::from(1u128 << 64);
    let two_32 = FieldElement::from(1u128 << 32);

    // 1. Field wrap-around conservation: out0 = p - 1, out1 += 1
    if let (Some(&out0_v), Some(&out1_v)) = (
        map.get("out_notes[0].value"),
        map.get("out_notes[1].value"),
    ) {
        let mut m = baseline.clone();
        let b1 = m[&out1_v];
        m.insert(out0_v, -FieldElement::one());
        m.insert(out1_v, b1 + FieldElement::one());
        probes.push(("field_wrap_out_notes".to_string(), m, vec![out0_v, out1_v]));
    }

    // 2. 2^64 conservation wrap: in0 += 2^64, out0 += 2^64
    if let (Some(&in0_v), Some(&out0_v)) = (
        map.get("in_notes[0].value"),
        map.get("out_notes[0].value"),
    ) {
        let mut m = baseline.clone();
        m.insert(in0_v, m[&in0_v] + two_64);
        m.insert(out0_v, m[&out0_v] + two_64);
        probes.push(("wrap_2_pow_64_in_out".to_string(), m, vec![in0_v, out0_v]));
    }

    // 3. Paired value inflation: in0 += 1, out0 += 1 (preserves conservation)
    if let (Some(&in0_v), Some(&out0_v)) = (
        map.get("in_notes[0].value"),
        map.get("out_notes[0].value"),
    ) {
        let mut m = baseline.clone();
        m.insert(in0_v, m[&in0_v] + FieldElement::one());
        m.insert(out0_v, m[&out0_v] + FieldElement::one());
        probes.push((
            "paired_value_inflation".to_string(),
            m,
            vec![in0_v, out0_v],
        ));
    }

    // 4. 32-bit leaf_index aliasing (+2^32 single and paired)
    if let Some(&li0) = map.get("in_leaf_indices[0]") {
        let mut m = baseline.clone();
        m.insert(li0, m[&li0] + two_32);
        probes.push(("leaf_index0_plus_2_pow_32".to_string(), m, vec![li0]));

        if let Some(&li1) = map.get("in_leaf_indices[1]") {
            let mut m2 = baseline.clone();
            m2.insert(li0, m2[&li0] + two_32);
            m2.insert(li1, m2[&li1] + two_32);
            probes.push(("both_leaf_indices_plus_2_pow_32".to_string(), m2, vec![li0, li1]));
        }
    }

    // 5. Duplicate input / nullifier collision: copy slot 0 -> slot 1
    let slot_pairs = [
        ("in_notes[0].value", "in_notes[1].value"),
        ("in_notes[0].owner_pk_x", "in_notes[1].owner_pk_x"),
        ("in_notes[0].owner_pk_y", "in_notes[1].owner_pk_y"),
        ("in_notes[0].blinding", "in_notes[1].blinding"),
        ("in_diversifiers[0]", "in_diversifiers[1]"),
        ("in_g_d_nonces[0]", "in_g_d_nonces[1]"),
        ("in_g_d_ys[0]", "in_g_d_ys[1]"),
        ("in_leaf_indices[0]", "in_leaf_indices[1]"),
        ("nullifiers[0]", "nullifiers[1]"),
    ];
    if map.contains_key("in_notes[0].value") && map.contains_key("in_notes[1].value") {
        let mut m = baseline.clone();
        let mut touched = Vec::new();
        for (src, dst) in slot_pairs {
            if let (Some(&ws), Some(&wd)) = (map.get(src), map.get(dst)) {
                m.insert(wd, m[&ws]);
                touched.push(wd);
            }
        }
        for i in 0..32 {
            let src = format!("in_merkle_paths[0][{i}]");
            let dst = format!("in_merkle_paths[1][{i}]");
            if let (Some(&ws), Some(&wd)) = (map.get(&src), map.get(&dst)) {
                m.insert(wd, m[&ws]);
                touched.push(wd);
            }
        }
        probes.push(("duplicate_slot0_into_slot1".to_string(), m, touched));
    }

    // 6. Dummy-to-real escalation if any input note has value == 0
    for k in 0..2 {
        let key = format!("in_notes[{k}].value");
        if let (Some(&in_v), Some(&out0_v)) = (map.get(&key), map.get("out_notes[0].value")) {
            if baseline[&in_v].is_zero() {
                let mut m = baseline.clone();
                m.insert(in_v, FieldElement::one());
                m.insert(out0_v, m[&out0_v] + FieldElement::one());
                probes.push((
                    format!("dummy_to_real_escalation_slot_{k}"),
                    m,
                    vec![in_v, out0_v],
                ));
            }
        }
    }

    // 7. Off-curve output pubkey injection (y = 0 and y = y + 1 while value > 0)
    push_off_curve_output_probes(
        &mut probes,
        map,
        baseline,
        "out_notes[0].value",
        "out_notes[0].owner_pk_y",
        "off_curve_output",
    );
    push_off_curve_output_probes(
        &mut probes,
        map,
        baseline,
        "out_note.value",
        "out_note.owner_pk_y",
        "off_curve_shield_output",
    );
    push_off_curve_output_probes(
        &mut probes,
        map,
        baseline,
        "change_note.value",
        "change_note.owner_pk_y",
        "off_curve_change_output",
    );

    // 7b. Shield-specific relational probes
    if let (Some(&mint_w), Some(&out_v)) = (map.get("mint_amount"), map.get("out_note.value")) {
        let mut m1 = baseline.clone();
        m1.insert(mint_w, m1[&mint_w] + FieldElement::one());
        m1.insert(out_v, m1[&out_v] + FieldElement::one());
        probes.push(("shield_paired_mint_plus_1".to_string(), m1, vec![mint_w, out_v]));

        let mut m64 = baseline.clone();
        m64.insert(mint_w, m64[&mint_w] + two_64);
        m64.insert(out_v, m64[&out_v] + two_64);
        probes.push(("shield_wrap_2_pow_64".to_string(), m64, vec![mint_w, out_v]));

        let mut m0 = baseline.clone();
        m0.insert(mint_w, FieldElement::zero());
        m0.insert(out_v, FieldElement::zero());
        probes.push(("shield_zero_mint_paired".to_string(), m0, vec![mint_w, out_v]));
    }

    // 7c. Unshield-specific relational probes
    if let (Some(&in_v), Some(&burn_w), Some(&chg_v)) = (
        map.get("in_note.value"),
        map.get("burn_amount"),
        map.get("change_note.value"),
    ) {
        let mut m_inf = baseline.clone();
        m_inf.insert(in_v, m_inf[&in_v] + FieldElement::one());
        m_inf.insert(burn_w, m_inf[&burn_w] + FieldElement::one());
        probes.push((
            "unshield_paired_value_inflation".to_string(),
            m_inf,
            vec![in_v, burn_w],
        ));

        let mut m_wrap = baseline.clone();
        m_wrap.insert(burn_w, -FieldElement::one());
        m_wrap.insert(chg_v, m_wrap[&chg_v] + FieldElement::one());
        probes.push((
            "unshield_field_wrap_burn_change".to_string(),
            m_wrap,
            vec![burn_w, chg_v],
        ));

        let mut m_64 = baseline.clone();
        m_64.insert(in_v, m_64[&in_v] + two_64);
        m_64.insert(burn_w, m_64[&burn_w] + two_64);
        probes.push((
            "unshield_wrap_2_pow_64_in_burn".to_string(),
            m_64,
            vec![in_v, burn_w],
        ));
    }
    if let Some(&li) = map.get("in_leaf_index") {
        let mut m = baseline.clone();
        m.insert(li, m[&li] + two_32);
        probes.push(("unshield_leaf_index_plus_2_pow_32".to_string(), m, vec![li]));
    }

    // 8. Zero tx_binding_hash paired with co-occurring AssertZero witness mutations (inverse check)
    if let Some(&tx_w) = map.get("tx_binding_hash") {
        let mut co_wires = BTreeSet::new();
        for op in &circuit.opcodes {
            if let Opcode::AssertZero(expr) = op {
                let mut found = false;
                let mut local = Vec::new();
                for &(_, wl, wr) in &expr.mul_terms {
                    if wl == tx_w || wr == tx_w {
                        found = true;
                    }
                    local.push(wl);
                    local.push(wr);
                }
                for &(_, w) in &expr.linear_combinations {
                    if w == tx_w {
                        found = true;
                    }
                    local.push(w);
                }
                if found {
                    for w in local {
                        if w != tx_w {
                            co_wires.insert(w);
                        }
                    }
                }
            }
        }
        for cw in co_wires {
            for (label, val) in [
                ("0", FieldElement::zero()),
                ("1", FieldElement::one()),
                ("p-1", -FieldElement::one()),
            ] {
                let mut m = baseline.clone();
                m.insert(tx_w, FieldElement::zero());
                m.insert(cw, val);
                probes.push((
                    format!("zero_tx_binding_with_{cw}={label}"),
                    m,
                    vec![tx_w, cw],
                ));
            }
        }
    }

    // 9. Generic paired conservation test for synthetic/general circuits (first 3 witnesses)
    if map.is_empty() && baseline.clone().into_iter().count() >= 3 {
        let ws: Vec<Witness> = baseline.clone().into_iter().map(|(w, _)| w).collect();
        let mut m = baseline.clone();
        m.insert(ws[0], -FieldElement::one());
        m.insert(ws[1], m[&ws[1]] + FieldElement::one());
        probes.push(("generic_wrap_w0_w1".to_string(), m, vec![ws[0], ws[1]]));

        let mut m2 = baseline.clone();
        m2.insert(ws[0], m2[&ws[0]] + FieldElement::one());
        m2.insert(ws[2], m2[&ws[2]] + FieldElement::one());
        probes.push(("generic_shift_w0_w2".to_string(), m2, vec![ws[0], ws[2]]));
    }

    probes
}

/// Strictly identifies ABI wires and downstream dead intermediates for zero-value dummy slots.
/// Never whitelists value, blinding, owner_pk, leaf_index, nullifiers, out_commitments, fee, ask, or tx_binding_hash.
fn compute_dummy_unused_whitelist(
    artifact: &LoadedArtifact,
    circuit: &Circuit<FieldElement>,
    baseline: &WitnessMap<FieldElement>,
) -> BTreeSet<Witness> {
    let map = &artifact.label_to_witness;
    let mut seeds = BTreeSet::new();

    for k in 0..2 {
        let Some(&val_w) = map.get(&format!("in_notes[{k}].value")) else {
            continue;
        };
        if !baseline.get(&val_w).is_some_and(|v| v.is_zero()) {
            continue;
        }
        for name in [
            format!("in_diversifiers[{k}]"),
            format!("in_g_d_nonces[{k}]"),
            format!("in_g_d_ys[{k}]"),
        ] {
            if let Some(&w) = map.get(&name) {
                seeds.insert(w);
            }
        }
        for lvl in 0..32 {
            if let Some(&w) = map.get(&format!("in_merkle_paths[{k}][{lvl}]")) {
                seeds.insert(w);
            }
        }
    }

    if seeds.is_empty() {
        return BTreeSet::new();
    }

    // All non-dummy-seed ABI wires are permanently protected and must never be whitelisted.
    let mut protected_abi = BTreeSet::new();
    for &w in &artifact.abi_witnesses {
        if !seeds.contains(&w) {
            protected_abi.insert(w);
        }
    }

    // Build directed dataflow from BlackBox inputs->outputs and single-output AssertZero definitions
    // so only pure downstream dead intermediates of dummy seeds (that never touch protected wires) qualify.
    let mut forward_deps: BTreeMap<Witness, Vec<Witness>> = BTreeMap::new();
    let mut all_edges_for: BTreeMap<Witness, Vec<Witness>> = BTreeMap::new();

    for op in &circuit.opcodes {
        match op {
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::Poseidon2Permutation { inputs, outputs }) => {
                for inp in inputs {
                    if !inp.is_constant() {
                        let iw = inp.to_witness();
                        for &ow in outputs {
                            forward_deps.entry(iw).or_default().push(ow);
                            all_edges_for.entry(iw).or_default().push(ow);
                            all_edges_for.entry(ow).or_default().push(iw);
                        }
                    }
                }
            }
            Opcode::BlackBoxFuncCall(BlackBoxFuncCall::MultiScalarMul {
                points,
                scalars,
                outputs,
                ..
            }) => {
                for inp in points.iter().chain(scalars.iter()) {
                    if !inp.is_constant() {
                        let iw = inp.to_witness();
                        forward_deps.entry(iw).or_default().push(outputs.0);
                        forward_deps.entry(iw).or_default().push(outputs.1);
                        all_edges_for.entry(iw).or_default().push(outputs.0);
                        all_edges_for.entry(iw).or_default().push(outputs.1);
                        all_edges_for.entry(outputs.0).or_default().push(iw);
                        all_edges_for.entry(outputs.1).or_default().push(iw);
                    }
                }
            }
            Opcode::AssertZero(expr) => {
                let mut ws = BTreeSet::new();
                for &(_, wl, wr) in &expr.mul_terms {
                    ws.insert(wl);
                    ws.insert(wr);
                }
                for &(_, w) in &expr.linear_combinations {
                    ws.insert(w);
                }
                for &w1 in &ws {
                    for &w2 in &ws {
                        if w1 != w2 {
                            all_edges_for.entry(w1).or_default().push(w2);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // BFS forward from dummy seeds along Poseidon2/MSM forward outputs, excluding any protected ABI
    // wire and stopping at wires appearing in protected AssertZero constraints unless already dead.
    let mut whitelist = seeds.clone();
    let mut queue: VecDeque<Witness> = seeds.into_iter().collect();
    while let Some(cur) = queue.pop_front() {
        if let Some(nexts) = forward_deps.get(&cur) {
            for &nw in nexts {
                if protected_abi.contains(&nw) {
                    continue;
                }
                // Do not whitelist any intermediate wire shared with protected ABI wires except
                // via the gated dummy check (`is_real == 0`), where other ABI neighbors stay untouched.
                let touches_protected_directly = all_edges_for
                    .get(&nw)
                    .is_some_and(|nbrs| nbrs.iter().any(|n| protected_abi.contains(n)));
                if !touches_protected_directly && whitelist.insert(nw) {
                    queue.push_back(nw);
                }
            }
        }
    }

    whitelist
}

/// Identifies internal inverse-hint witnesses belonging strictly to canonical `IsZero(0)` gadgets:
/// `c_m * (x * inv + z - 1) == 0` paired with `k * x * z == 0`, where `baseline[x] == 0` and
/// `baseline[z] == 1`, and `inv` appears in no other non-Brillig opcode and is not an ABI input.
fn detect_benign_is_zero_inverses(
    artifact: &LoadedArtifact,
    circuit: &Circuit<FieldElement>,
    baseline: &WitnessMap<FieldElement>,
) -> BTreeSet<Witness> {
    let abi_set: BTreeSet<Witness> = artifact.abi_witnesses.iter().copied().collect();
    let mut opcode_refs: BTreeMap<Witness, Vec<usize>> = BTreeMap::new();

    for (idx, op) in circuit.opcodes.iter().enumerate() {
        for w in non_brillig_opcode_witnesses(op) {
            opcode_refs.entry(w).or_default().push(idx);
        }
    }

    let mut benign = BTreeSet::new();
    for (&inv, ref_ops) in &opcode_refs {
        if ref_ops.len() != 1
            || abi_set.contains(&inv)
            || circuit.public_parameters.0.contains(&inv)
            || circuit.private_parameters.contains(&inv)
            || circuit.return_values.0.contains(&inv)
        {
            continue;
        }
        let Opcode::AssertZero(e1) = &circuit.opcodes[ref_ops[0]] else {
            continue;
        };
        if e1.mul_terms.len() != 1 || e1.linear_combinations.len() != 1 {
            continue;
        }
        let (c_m, a, b) = e1.mul_terms[0];
        let (c_l, z) = e1.linear_combinations[0];
        if c_m.is_zero() || c_l != c_m || e1.q_c != -c_m {
            continue;
        }
        let x = if a == inv && b != inv {
            b
        } else if b == inv && a != inv {
            a
        } else {
            continue;
        };
        if z == inv || z == x {
            continue;
        }

        let has_companion = circuit.opcodes.iter().any(|op| {
            let Opcode::AssertZero(e2) = op else {
                return false;
            };
            if e2.mul_terms.len() != 1 || !e2.linear_combinations.is_empty() || !e2.q_c.is_zero()
            {
                return false;
            }
            let (k, a2, b2) = e2.mul_terms[0];
            !k.is_zero() && ((a2 == x && b2 == z) || (a2 == z && b2 == x))
        });
        if !has_companion {
            continue;
        }

        if baseline.get(&x) == Some(&FieldElement::zero())
            && baseline.get(&z) == Some(&FieldElement::one())
        {
            benign.insert(inv);
        }
    }

    benign
}

fn non_brillig_opcode_witnesses(op: &Opcode<FieldElement>) -> BTreeSet<Witness> {
    let mut out = BTreeSet::new();
    match op {
        Opcode::AssertZero(expr) => {
            for &(_, wl, wr) in &expr.mul_terms {
                out.insert(wl);
                out.insert(wr);
            }
            for &(_, w) in &expr.linear_combinations {
                out.insert(w);
            }
        }
        Opcode::BlackBoxFuncCall(call) => {
            for inp in call.get_inputs_vec() {
                if !inp.is_constant() {
                    out.insert(inp.to_witness());
                }
            }
            for w in call.get_outputs_vec() {
                out.insert(w);
            }
        }
        Opcode::BrilligCall { .. } => {}
        Opcode::MemoryInit { init, .. } => {
            for &w in init {
                out.insert(w);
            }
        }
        Opcode::MemoryOp { op, .. } => {
            out.insert(op.index);
            out.insert(op.value);
        }
        Opcode::Call { inputs, outputs, .. } => {
            for &w in inputs.iter().chain(outputs.iter()) {
                out.insert(w);
            }
        }
    }
    out
}

fn push_off_curve_output_probes(
    probes: &mut Vec<(String, WitnessMap<FieldElement>, Vec<Witness>)>,
    map: &BTreeMap<String, Witness>,
    baseline: &WitnessMap<FieldElement>,
    value_key: &str,
    y_key: &str,
    prefix: &str,
) {
    if let (Some(&val_w), Some(&y_w)) = (map.get(value_key), map.get(y_key)) {
        if !baseline[&val_w].is_zero() {
            let mut m0 = baseline.clone();
            m0.insert(y_w, FieldElement::zero());
            probes.push((format!("{prefix}_y_zero"), m0, vec![y_w]));

            let mut m1 = baseline.clone();
            m1.insert(y_w, m1[&y_w] + FieldElement::one());
            probes.push((format!("{prefix}_y_plus_1"), m1, vec![y_w]));
        }
    }
}

fn format_wire(w: Witness, witness_to_label: &BTreeMap<Witness, String>) -> String {
    match witness_to_label.get(&w) {
        Some(lbl) => format!("{w} ({lbl})"),
        None => format!("{w}"),
    }
}

struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}

