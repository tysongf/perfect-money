use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::circuit::Program;
use acir::native_types::{Witness, WitnessMap, WitnessStack};
use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail};
use base64::Engine;
use ledger_core::{
    BbVerifier, LedgerError, LedgerState, MERKLE_DEPTH, Note, ShieldTx, UnshieldTx, WalletKeys,
    compute_note_commitment, compute_nullifier, derive_diversified_address,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
struct NargoArtifactJson {
    abi: AbiJson,
    bytecode: String,
}

#[derive(Debug, Deserialize)]
struct AbiJson {
    parameters: Vec<AbiParam>,
}

#[derive(Debug, Deserialize)]
struct AbiParam {
    name: String,
    visibility: String,
    #[serde(rename = "type")]
    param_type: AbiType,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum AbiType {
    Field,
    Boolean,
    Integer {
        #[allow(dead_code)]
        sign: String,
        #[allow(dead_code)]
        width: u32,
    },
    Array {
        length: usize,
        #[serde(rename = "type")]
        elem_type: Box<AbiType>,
    },
    #[serde(rename = "struct")]
    Struct {
        #[allow(dead_code)]
        path: String,
        fields: Vec<AbiStructField>,
    },
    Tuple {
        fields: Vec<AbiType>,
    },
}

#[derive(Debug, Deserialize)]
struct AbiStructField {
    name: String,
    #[serde(rename = "type")]
    field_type: AbiType,
}

/// Loaded baseline circuit artifact + witness + proof + VK for adversarial testing.
pub struct CircuitBundle {
    pub name: &'static str,
    pub artifact_path: PathBuf,
    pub vk_path: PathBuf,
    pub labels: BTreeMap<String, Witness>,
    pub baseline_witness: WitnessMap<FieldElement>,
    pub baseline_proof: Vec<u8>,
    pub baseline_public_inputs: Vec<u8>,
}

/// Result of a single Evil Prover adversarial run against Barretenberg / LedgerState.
#[derive(Debug, Clone, Serialize)]
pub struct AttackResult {
    pub id: usize,
    pub category: String,
    pub circuit: String,
    pub name: String,
    pub rejected: bool,
    pub detail: String,
}

/// Oracle verdict on whether an adversarial witness or proof passes `bb verify`.
#[derive(Debug, Clone)]
pub struct OracleVerdict {
    pub verified: bool,
    pub detail: String,
}

pub fn resolve_tool(home_rel: &str, fallback: &str) -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        let p = Path::new(&home).join(home_rel);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(fallback)
}

pub fn load_circuit_bundle(root: &Path, name: &'static str) -> Result<CircuitBundle> {
    let target_dir = root.join("circuits").join(name).join("target");
    let artifact_path = target_dir.join(format!("{name}.json"));
    let witness_path = target_dir.join("witness.gz");
    let vk_path = target_dir.join("vk");
    let proof_path = target_dir.join("proof");
    let pi_path = target_dir.join("public_inputs");

    for p in [&artifact_path, &witness_path, &vk_path, &proof_path, &pi_path] {
        if !p.is_file() {
            bail!(
                "missing baseline artifact {} — run scripts/prove_and_verify.sh first",
                p.display()
            );
        }
    }

    let raw = fs::read_to_string(&artifact_path)?;
    let parsed: NargoArtifactJson = serde_json::from_str(&raw)?;
    let bytecode = base64::engine::general_purpose::STANDARD.decode(parsed.bytecode.trim())?;
    let program = Program::<FieldElement>::deserialize_program(&bytecode)?;
    let circuit = program
        .functions
        .first()
        .context("program has no functions")?;

    let mut pub_names = Vec::new();
    let mut priv_names = Vec::new();
    for param in &parsed.abi.parameters {
        let out = if param.visibility == "public" {
            &mut pub_names
        } else {
            &mut priv_names
        };
        flatten_abi(&param.name, &param.param_type, out);
    }

    let pub_ws: Vec<Witness> = circuit.public_parameters.0.iter().copied().collect();
    let priv_ws: Vec<Witness> = circuit.private_parameters.iter().copied().collect();
    if pub_names.len() != pub_ws.len() || priv_names.len() != priv_ws.len() {
        bail!("ABI parameter mismatch in {name}");
    }

    let mut labels = BTreeMap::new();
    for (n, w) in pub_names
        .into_iter()
        .zip(pub_ws)
        .chain(priv_names.into_iter().zip(priv_ws))
    {
        labels.insert(n, w);
    }

    let w_bytes = fs::read(&witness_path)?;
    let mut stack = WitnessStack::<FieldElement>::deserialize(&w_bytes)?;
    let baseline_witness = stack.pop().context("empty witness stack")?.witness;

    Ok(CircuitBundle {
        name,
        artifact_path,
        vk_path,
        labels,
        baseline_witness,
        baseline_proof: fs::read(proof_path)?,
        baseline_public_inputs: fs::read(pi_path)?,
    })
}

fn flatten_abi(prefix: &str, ty: &AbiType, out: &mut Vec<String>) {
    match ty {
        AbiType::Field | AbiType::Boolean | AbiType::Integer { .. } => {
            out.push(prefix.to_string());
        }
        AbiType::Array { length, elem_type } => {
            for i in 0..*length {
                flatten_abi(&format!("{prefix}[{i}]"), elem_type, out);
            }
        }
        AbiType::Struct { fields, .. } => {
            for f in fields {
                flatten_abi(&format!("{prefix}.{}", f.name), &f.field_type, out);
            }
        }
        AbiType::Tuple { fields } => {
            for (i, f) in fields.iter().enumerate() {
                flatten_abi(&format!("{prefix}.{i}"), f, out);
            }
        }
    }
}

/// Attempts to forge a valid Barretenberg proof from a mutated `WitnessMap`.
pub fn attempt_bb_exploit(
    bb_bin: &Path,
    bundle: &CircuitBundle,
    mutated_witness: &WitnessMap<FieldElement>,
) -> Result<OracleVerdict> {
    let dir = TempDir::new()?;
    let mut stack = WitnessStack::<FieldElement>::default();
    stack.push(0, mutated_witness.clone());
    let witness_path = dir.path().join("witness.gz");
    fs::write(&witness_path, stack.serialize()?)?;

    let prove_out = Command::new(bb_bin)
        .arg("prove")
        .arg("-b")
        .arg(&bundle.artifact_path)
        .arg("-w")
        .arg(&witness_path)
        .arg("-k")
        .arg(&bundle.vk_path)
        .arg("-o")
        .arg(dir.path())
        .output()
        .context("failed to invoke bb prove")?;

    if !prove_out.status.success() {
        return Ok(OracleVerdict {
            verified: false,
            detail: format!("bb prove rejected ({})", first_line(&prove_out.stderr)),
        });
    }

    let proof_bytes = fs::read(dir.path().join("proof"))?;
    let pi_bytes = fs::read(dir.path().join("public_inputs"))?;
    attempt_bb_verify_tamper(bb_bin, &bundle.vk_path, &proof_bytes, &pi_bytes)
}

/// Runs `bb verify` directly on raw `(vk, proof, public_inputs)` bytes.
pub fn attempt_bb_verify_tamper(
    bb_bin: &Path,
    vk_path: &Path,
    proof_bytes: &[u8],
    public_inputs_bytes: &[u8],
) -> Result<OracleVerdict> {
    let dir = TempDir::new()?;
    let p_path = dir.path().join("proof");
    let pi_path = dir.path().join("public_inputs");
    fs::write(&p_path, proof_bytes)?;
    fs::write(&pi_path, public_inputs_bytes)?;

    let out = Command::new(bb_bin)
        .arg("verify")
        .arg("-p")
        .arg(&p_path)
        .arg("-k")
        .arg(vk_path)
        .arg("-i")
        .arg(&pi_path)
        .output()
        .context("failed to invoke bb verify")?;

    if out.status.success() {
        Ok(OracleVerdict {
            verified: true,
            detail: "bb verify exited 0".to_string(),
        })
    } else {
        Ok(OracleVerdict {
            verified: false,
            detail: format!("bb verify rejected ({})", first_line(&out.stderr)),
        })
    }
}

/// Runs all 70 independent adversarial attacks across `shield`, `shielded_transfer`, `unshield`, and `LedgerState`.
pub fn run_all_attacks(
    root: &Path,
    bb_bin: &Path,
    nargo_bin: &Path,
    shield: &CircuitBundle,
    transfer: &CircuitBundle,
    unshield: &CircuitBundle,
) -> Result<Vec<AttackResult>> {
    let mut results = Vec::with_capacity(70);
    let mut next_id = 1usize;

    let two_64 = FieldElement::from(1u128 << 64);
    let two_32 = FieldElement::from(1u128 << 32);
    let p_minus_1 = -FieldElement::one();

    let mut run_witness_attack = |category: &str,
                                  bundle: &CircuitBundle,
                                  name: &str,
                                  mutate: &dyn Fn(&mut WitnessMap<FieldElement>, &BTreeMap<String, Witness>)|
     -> Result<()> {
        let mut w = bundle.baseline_witness.clone();
        mutate(&mut w, &bundle.labels);
        let verdict = attempt_bb_exploit(bb_bin, bundle, &w)?;
        results.push(AttackResult {
            id: next_id,
            category: category.to_string(),
            circuit: bundle.name.to_string(),
            name: name.to_string(),
            rejected: !verdict.verified,
            detail: verdict.detail,
        });
        next_id += 1;
        Ok(())
    };

    // =========================================================================
    // Category 1: Value Inflation & Overflow (12 runs)
    // =========================================================================
    run_witness_attack("value_inflation_overflow", shield, "shield_mint_amount_plus_1", &|w, m| {
        add_field(w, m["mint_amount"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", shield, "shield_out_note_value_plus_1", &|w, m| {
        add_field(w, m["out_note.value"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", shield, "shield_paired_mint_and_note_plus_1", &|w, m| {
        add_field(w, m["mint_amount"], FieldElement::one());
        add_field(w, m["out_note.value"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", shield, "shield_out_note_plus_2_pow_64", &|w, m| {
        add_field(w, m["out_note.value"], two_64);
    })?;
    run_witness_attack("value_inflation_overflow", shield, "shield_out_note_p_minus_1", &|w, m| {
        w.insert(m["out_note.value"], p_minus_1);
    })?;
    run_witness_attack("value_inflation_overflow", shield, "shield_mint_amount_p_minus_1", &|w, m| {
        w.insert(m["mint_amount"], p_minus_1);
    })?;

    run_witness_attack("value_inflation_overflow", transfer, "transfer_out0_plus_1", &|w, m| {
        add_field(w, m["out_notes[0].value"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", transfer, "transfer_field_wrap_out0_out1", &|w, m| {
        w.insert(m["out_notes[0].value"], p_minus_1);
        add_field(w, m["out_notes[1].value"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", transfer, "transfer_wrap_2_pow_64_in_out", &|w, m| {
        add_field(w, m["in_notes[0].value"], two_64);
        add_field(w, m["out_notes[0].value"], two_64);
    })?;
    run_witness_attack("value_inflation_overflow", transfer, "transfer_fee_p_minus_1", &|w, m| {
        w.insert(m["fee"], p_minus_1);
    })?;

    run_witness_attack("value_inflation_overflow", unshield, "unshield_burn_amount_plus_1", &|w, m| {
        add_field(w, m["burn_amount"], FieldElement::one());
    })?;
    run_witness_attack("value_inflation_overflow", unshield, "unshield_field_wrap_burn_change", &|w, m| {
        w.insert(m["burn_amount"], p_minus_1);
        add_field(w, m["change_note.value"], FieldElement::one());
    })?;

    // =========================================================================
    // Category 2: Unauthorized Spend & Key Forgery (10 runs)
    // =========================================================================
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_ask_plus_1", &|w, m| {
        add_field(w, m["ask"], FieldElement::one());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_ask_zero", &|w, m| {
        w.insert(m["ask"], FieldElement::zero());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_ask_p_minus_1", &|w, m| {
        w.insert(m["ask"], p_minus_1);
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_diversifier0_plus_1", &|w, m| {
        add_field(w, m["in_diversifiers[0]"], FieldElement::one());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_g_d_nonce0_plus_1", &|w, m| {
        add_field(w, m["in_g_d_nonces[0]"], FieldElement::one());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_g_d_y0_plus_1", &|w, m| {
        add_field(w, m["in_g_d_ys[0]"], FieldElement::one());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_g_d_y0_zero", &|w, m| {
        w.insert(m["in_g_d_ys[0]"], FieldElement::zero());
    })?;
    run_witness_attack("unauthorized_spend_keys", transfer, "transfer_negate_in0_owner_pk_y", &|w, m| {
        let y = w[&m["in_notes[0].owner_pk_y"]];
        w.insert(m["in_notes[0].owner_pk_y"], -y);
    })?;
    run_witness_attack("unauthorized_spend_keys", unshield, "unshield_ask_plus_1", &|w, m| {
        add_field(w, m["ask"], FieldElement::one());
    })?;
    run_witness_attack("unauthorized_spend_keys", unshield, "unshield_ask_zero", &|w, m| {
        w.insert(m["ask"], FieldElement::zero());
    })?;

    // =========================================================================
    // Category 3: Merkle Inclusion & leaf_index Aliasing (10 runs)
    // =========================================================================
    run_witness_attack("merkle_leaf_aliasing", transfer, "transfer_leaf_idx0_plus_2_pow_32", &|w, m| {
        add_field(w, m["in_leaf_indices[0]"], two_32);
    })?;
    run_witness_attack("merkle_leaf_aliasing", transfer, "transfer_leaf_idx1_plus_2_pow_32", &|w, m| {
        add_field(w, m["in_leaf_indices[1]"], two_32);
    })?;
    run_witness_attack("merkle_leaf_aliasing", transfer, "transfer_leaf_idx0_flip_lsb", &|w, m| {
        let cur = w[&m["in_leaf_indices[0]"]].to_u128();
        w.insert(m["in_leaf_indices[0]"], FieldElement::from(cur ^ 1));
    })?;
    run_witness_attack("merkle_leaf_aliasing", transfer, "transfer_merkle_root_plus_1", &|w, m| {
        add_field(w, m["merkle_root"], FieldElement::one());
    })?;
    for lvl in [0usize, 1, 15, 31] {
        let key = format!("in_merkle_paths[0][{lvl}]");
        let attack_name = format!("transfer_tamper_merkle_path0_lvl_{lvl}");
        run_witness_attack("merkle_leaf_aliasing", transfer, &attack_name, &|w, m| {
            add_field(w, m[&key], FieldElement::one());
        })?;
    }
    run_witness_attack("merkle_leaf_aliasing", unshield, "unshield_leaf_idx_plus_2_pow_32", &|w, m| {
        add_field(w, m["in_leaf_index"], two_32);
    })?;
    run_witness_attack("merkle_leaf_aliasing", unshield, "unshield_tamper_merkle_path_lvl_0", &|w, m| {
        add_field(w, m["in_merkle_path[0]"], FieldElement::one());
    })?;

    // =========================================================================
    // Category 4: Zero-Value & Dummy Edge Cases (8 runs)
    // =========================================================================
    run_witness_attack("zero_dummy_edge_cases", shield, "shield_mint_amount_zero", &|w, m| {
        w.insert(m["mint_amount"], FieldElement::zero());
    })?;
    run_witness_attack("zero_dummy_edge_cases", shield, "shield_paired_zero_mint", &|w, m| {
        w.insert(m["mint_amount"], FieldElement::zero());
        w.insert(m["out_note.value"], FieldElement::zero());
    })?;
    run_witness_attack("zero_dummy_edge_cases", unshield, "unshield_burn_amount_zero", &|w, m| {
        w.insert(m["burn_amount"], FieldElement::zero());
    })?;
    run_witness_attack("zero_dummy_edge_cases", unshield, "unshield_zero_burn_to_change", &|w, m| {
        let cur_burn = w[&m["burn_amount"]];
        w.insert(m["burn_amount"], FieldElement::zero());
        add_field(w, m["change_note.value"], cur_burn);
    })?;
    run_witness_attack("zero_dummy_edge_cases", transfer, "transfer_zero_in0_without_update", &|w, m| {
        w.insert(m["in_notes[0].value"], FieldElement::zero());
    })?;
    run_witness_attack("zero_dummy_edge_cases", transfer, "transfer_zero_in1_rebalance_out0", &|w, m| {
        let v1 = w[&m["in_notes[1].value"]];
        w.insert(m["in_notes[1].value"], FieldElement::zero());
        let o0 = w[&m["out_notes[0].value"]];
        w.insert(m["out_notes[0].value"], o0 - v1);
    })?;
    run_witness_attack("zero_dummy_edge_cases", transfer, "transfer_both_inputs_zero", &|w, m| {
        w.insert(m["in_notes[0].value"], FieldElement::zero());
        w.insert(m["in_notes[1].value"], FieldElement::zero());
    })?;
    run_witness_attack("zero_dummy_edge_cases", transfer, "transfer_bump_in1_and_out0_by_1", &|w, m| {
        add_field(w, m["in_notes[1].value"], FieldElement::one());
        add_field(w, m["out_notes[0].value"], FieldElement::one());
    })?;

    // =========================================================================
    // Category 5: Nullifier Replay, Swapping & Collision (8 runs)
    // =========================================================================
    run_witness_attack("nullifier_attacks", transfer, "transfer_nullifier0_plus_1", &|w, m| {
        add_field(w, m["nullifiers[0]"], FieldElement::one());
    })?;
    run_witness_attack("nullifier_attacks", transfer, "transfer_duplicate_nullifier1_eq_0", &|w, m| {
        let nf0 = w[&m["nullifiers[0]"]];
        w.insert(m["nullifiers[1]"], nf0);
    })?;
    run_witness_attack("nullifier_attacks", transfer, "transfer_swap_nullifiers", &|w, m| {
        let nf0 = w[&m["nullifiers[0]"]];
        let nf1 = w[&m["nullifiers[1]"]];
        w.insert(m["nullifiers[0]"], nf1);
        w.insert(m["nullifiers[1]"], nf0);
    })?;
    run_witness_attack("nullifier_attacks", transfer, "transfer_clone_slot0_into_slot1", &|w, m| {
        for (src, dst) in [
            ("in_notes[0].value", "in_notes[1].value"),
            ("in_notes[0].owner_pk_x", "in_notes[1].owner_pk_x"),
            ("in_notes[0].owner_pk_y", "in_notes[1].owner_pk_y"),
            ("in_notes[0].blinding", "in_notes[1].blinding"),
            ("in_diversifiers[0]", "in_diversifiers[1]"),
            ("in_g_d_nonces[0]", "in_g_d_nonces[1]"),
            ("in_g_d_ys[0]", "in_g_d_ys[1]"),
            ("in_leaf_indices[0]", "in_leaf_indices[1]"),
            ("nullifiers[0]", "nullifiers[1]"),
        ] {
            let v = w[&m[src]];
            w.insert(m[dst], v);
        }
        for i in 0..MERKLE_DEPTH {
            let v = w[&m[&format!("in_merkle_paths[0][{i}]")]];
            w.insert(m[&format!("in_merkle_paths[1][{i}]")], v);
        }
    })?;
    run_witness_attack("nullifier_attacks", transfer, "transfer_nullifier0_zero", &|w, m| {
        w.insert(m["nullifiers[0]"], FieldElement::zero());
    })?;
    run_witness_attack("nullifier_attacks", unshield, "unshield_nullifier_plus_1", &|w, m| {
        add_field(w, m["nullifier"], FieldElement::one());
    })?;
    run_witness_attack("nullifier_attacks", unshield, "unshield_nullifier_zero", &|w, m| {
        w.insert(m["nullifier"], FieldElement::zero());
    })?;
    run_witness_attack("nullifier_attacks", unshield, "unshield_nullifier_p_minus_1", &|w, m| {
        w.insert(m["nullifier"], p_minus_1);
    })?;

    // =========================================================================
    // Category 6: Off-Curve Output & Commitment Forgery (8 runs)
    // =========================================================================
    run_witness_attack("off_curve_and_commitment", shield, "shield_off_curve_pk_y_plus_1", &|w, m| {
        add_field(w, m["out_note.owner_pk_y"], FieldElement::one());
    })?;
    run_witness_attack("off_curve_and_commitment", shield, "shield_zero_y_pk", &|w, m| {
        w.insert(m["out_note.owner_pk_y"], FieldElement::zero());
    })?;
    run_witness_attack("off_curve_and_commitment", shield, "shield_point_at_infinity_pk", &|w, m| {
        w.insert(m["out_note.owner_pk_x"], FieldElement::zero());
        w.insert(m["out_note.owner_pk_y"], FieldElement::zero());
    })?;
    run_witness_attack("off_curve_and_commitment", shield, "shield_out_commitment_plus_1", &|w, m| {
        add_field(w, m["out_commitment"], FieldElement::one());
    })?;
    run_witness_attack("off_curve_and_commitment", transfer, "transfer_out0_off_curve_pk_y_plus_1", &|w, m| {
        add_field(w, m["out_notes[0].owner_pk_y"], FieldElement::one());
    })?;
    run_witness_attack("off_curve_and_commitment", transfer, "transfer_out0_zero_y_pk", &|w, m| {
        w.insert(m["out_notes[0].owner_pk_y"], FieldElement::zero());
    })?;
    run_witness_attack("off_curve_and_commitment", transfer, "transfer_out_commitment0_plus_1", &|w, m| {
        add_field(w, m["out_commitments[0]"], FieldElement::one());
    })?;
    run_witness_attack("off_curve_and_commitment", unshield, "unshield_change_off_curve_pk_y_plus_1", &|w, m| {
        add_field(w, m["change_note.owner_pk_y"], FieldElement::one());
    })?;

    // =========================================================================
    // Category 7: Tx Binding & Relayer Proof / Public-Input Tampering (8 runs)
    // =========================================================================
    run_witness_attack("tx_binding_and_tampering", shield, "shield_zero_tx_binding_hash", &|w, m| {
        w.insert(m["tx_binding_hash"], FieldElement::zero());
    })?;
    run_witness_attack("tx_binding_and_tampering", transfer, "transfer_zero_tx_binding_hash", &|w, m| {
        w.insert(m["tx_binding_hash"], FieldElement::zero());
    })?;
    run_witness_attack("tx_binding_and_tampering", unshield, "unshield_zero_tx_binding_hash", &|w, m| {
        w.insert(m["tx_binding_hash"], FieldElement::zero());
    })?;

    let mut push_pi_tamper = |bundle: &CircuitBundle, name: &str, byte_offset: usize| -> Result<()> {
        let mut bad_pi = bundle.baseline_public_inputs.clone();
        bad_pi[byte_offset] ^= 0x01;
        let v = attempt_bb_verify_tamper(bb_bin, &bundle.vk_path, &bundle.baseline_proof, &bad_pi)?;
        results.push(AttackResult {
            id: next_id,
            category: "tx_binding_and_tampering".to_string(),
            circuit: bundle.name.to_string(),
            name: name.to_string(),
            rejected: !v.verified,
            detail: v.detail,
        });
        next_id += 1;
        Ok(())
    };
    push_pi_tamper(shield, "shield_relayer_swap_tx_binding_pi", 2 * 32 + 31)?;
    push_pi_tamper(transfer, "transfer_relayer_swap_tx_binding_pi", 6 * 32 + 31)?;
    push_pi_tamper(unshield, "unshield_relayer_swap_tx_binding_pi", 5 * 32 + 31)?;

    for (label, idx) in [
        ("transfer_proof_tamper_first_byte", 0usize),
        (
            "transfer_proof_tamper_last_byte",
            transfer.baseline_proof.len() - 1,
        ),
    ] {
        let mut bad_proof = transfer.baseline_proof.clone();
        bad_proof[idx] ^= 0x01;
        let v = attempt_bb_verify_tamper(
            bb_bin,
            &transfer.vk_path,
            &bad_proof,
            &transfer.baseline_public_inputs,
        )?;
        results.push(AttackResult {
            id: next_id,
            category: "tx_binding_and_tampering".to_string(),
            circuit: transfer.name.to_string(),
            name: label.to_string(),
            rejected: !v.verified,
            detail: v.detail,
        });
        next_id += 1;
    }

    // =========================================================================
    // Category 8: Cross-Circuit & Ledger State Desync Attacks (6 runs)
    // =========================================================================
    let v_cross1 = attempt_bb_verify_tamper(
        bb_bin,
        &unshield.vk_path,
        &shield.baseline_proof,
        &shield.baseline_public_inputs,
    )?;
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "shield->unshield".to_string(),
        name: "cross_vk_shield_proof_under_unshield_vk".to_string(),
        rejected: !v_cross1.verified,
        detail: v_cross1.detail,
    });
    next_id += 1;

    let v_cross2 = attempt_bb_verify_tamper(
        bb_bin,
        &transfer.vk_path,
        &unshield.baseline_proof,
        &unshield.baseline_public_inputs,
    )?;
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "unshield->shielded_transfer".to_string(),
        name: "cross_vk_unshield_proof_under_transfer_vk".to_string(),
        rejected: !v_cross2.verified,
        detail: v_cross2.detail,
    });
    next_id += 1;

    let mut bad_shield_pi = shield.baseline_public_inputs.clone();
    bad_shield_pi[31] ^= 0x01; // mint_amount
    let v_pi_s = attempt_bb_verify_tamper(
        bb_bin,
        &shield.vk_path,
        &shield.baseline_proof,
        &bad_shield_pi,
    )?;
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "shield".to_string(),
        name: "shield_mutate_mint_amount_public_input".to_string(),
        rejected: !v_pi_s.verified,
        detail: v_pi_s.detail,
    });
    next_id += 1;

    let mut bad_unshield_pi = unshield.baseline_public_inputs.clone();
    bad_unshield_pi[3 * 32 + 31] ^= 0x01; // burn_amount
    let v_pi_u = attempt_bb_verify_tamper(
        bb_bin,
        &unshield.vk_path,
        &unshield.baseline_proof,
        &bad_unshield_pi,
    )?;
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "unshield".to_string(),
        name: "unshield_mutate_burn_amount_public_input".to_string(),
        rejected: !v_pi_u.verified,
        detail: v_pi_u.detail,
    });
    next_id += 1;

    // Ledger desync attacks (69: real nullifier replay in LedgerState, 70: shield exceeding vault)
    let verifier = BbVerifier::new(
        shield.vk_path.clone(),
        transfer.vk_path.clone(),
        unshield.vk_path.clone(),
    );

    // 69. Nullifier replay in LedgerState using a real shield(600) -> unshield(leaf 0) sequence
    let replay_res = test_real_unshield_nullifier_replay(root, nargo_bin, bb_bin, &verifier, shield)?;
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "ledger_core".to_string(),
        name: "ledger_replay_spent_real_unshield_nullifier".to_string(),
        rejected: replay_res.0,
        detail: replay_res.1,
    });
    next_id += 1;

    // 70. Attempt apply_shield(600) with only 599 public_vault_balance
    let mut ledger = LedgerState::new();
    ledger.mint_vault_supply(599)?;
    let shield_cm = FieldElement::from_be_bytes_reduce(&shield.baseline_public_inputs[32..64]);
    let shield_txb = FieldElement::from_be_bytes_reduce(&shield.baseline_public_inputs[64..96]);
    let vault_attack = ledger.apply_shield(
        &ShieldTx {
            mint_amount: 600,
            out_commitment: shield_cm,
            tx_binding_hash: shield_txb,
            proof: shield.baseline_proof.clone(),
        },
        &verifier,
    );
    let (vault_rejected, vault_detail) = match vault_attack {
        Err(LedgerError::InsufficientVaultBalance { .. }) => (
            true,
            "LedgerState rejected InsufficientVaultBalance".to_string(),
        ),
        other => (false, format!("unexpected result: {other:?}")),
    };
    results.push(AttackResult {
        id: next_id,
        category: "cross_circuit_and_ledger".to_string(),
        circuit: "ledger_core".to_string(),
        name: "ledger_shield_exceeding_vault_balance".to_string(),
        rejected: vault_rejected,
        detail: vault_detail,
    });

    Ok(results)
}

fn test_real_unshield_nullifier_replay(
    root: &Path,
    nargo_bin: &Path,
    bb_bin: &Path,
    verifier: &BbVerifier,
    shield: &CircuitBundle,
) -> Result<(bool, String)> {
    let tmp = TempDir::new()?;
    let tmp_circuits = tmp.path().join("circuits");
    copy_dir_files(&root.join("circuits/common"), &tmp_circuits.join("common"))?;
    copy_dir_files(&root.join("circuits/unshield"), &tmp_circuits.join("unshield"))?;
    let unshield_dir = tmp_circuits.join("unshield");
    fs::create_dir_all(unshield_dir.join("target"))?;
    fs::copy(
        root.join("circuits/unshield/target/unshield.json"),
        unshield_dir.join("target/unshield.json"),
    )?;
    fs::copy(
        root.join("circuits/unshield/target/vk"),
        unshield_dir.join("target/vk"),
    )?;

    let mut ledger = LedgerState::new();
    ledger.mint_vault_supply(600)?;
    let shield_cm = FieldElement::from_be_bytes_reduce(&shield.baseline_public_inputs[32..64]);
    let shield_txb = FieldElement::from_be_bytes_reduce(&shield.baseline_public_inputs[64..96]);
    let leaf_idx = ledger.apply_shield(
        &ShieldTx {
            mint_amount: 600,
            out_commitment: shield_cm,
            tx_binding_hash: shield_txb,
            proof: shield.baseline_proof.clone(),
        },
        verifier,
    )?;

    let alice = WalletKeys::from_ask(FieldElement::from(123456789u64))?;
    let addr0 = derive_diversified_address(alice.ivk, FieldElement::from(1001u64))?;
    let merkle_root = ledger.current_root();
    let path = ledger.merkle_tree.proof(leaf_idx)?;
    let nf = compute_nullifier(alice.nk, shield_cm, leaf_idx);
    let change_note = Note {
        value: 190,
        owner_pk_x: addr0.pk_d.x,
        owner_pk_y: addr0.pk_d.y,
        blinding: FieldElement::from_hex("0x2222333344445555").unwrap(),
    };
    let change_cm = compute_note_commitment(&change_note);
    let txb = FieldElement::from_hex("0x8888777766665555").unwrap();

    let path_toml = format!(
        "[\n{}\n]",
        path.iter()
            .map(|p| format!("\"0x{}\"", p.to_hex()))
            .collect::<Vec<_>>()
            .join(",\n")
    );
    let toml = format!(
        "merkle_root = \"0x{}\"\nnullifier = \"0x{}\"\nchange_commitment = \"0x{}\"\nburn_amount = \"400\"\nfee = \"10\"\ntx_binding_hash = \"0x{}\"\nask = \"123456789\"\nin_diversifier = \"1001\"\nin_g_d_nonce = {}\nin_g_d_y = \"0x{}\"\nin_leaf_index = {}\nin_merkle_path = {}\n\n[in_note]\nvalue = \"600\"\nowner_pk_x = \"0x{}\"\nowner_pk_y = \"0x{}\"\nblinding = \"0x1111222233334444\"\n\n[change_note]\nvalue = \"190\"\nowner_pk_x = \"0x{}\"\nowner_pk_y = \"0x{}\"\nblinding = \"0x2222333344445555\"\n",
        merkle_root.to_hex(),
        nf.to_hex(),
        change_cm.to_hex(),
        txb.to_hex(),
        addr0.nonce,
        addr0.g_d.y.to_hex(),
        leaf_idx,
        path_toml,
        addr0.pk_d.x.to_hex(),
        addr0.pk_d.y.to_hex(),
        change_note.owner_pk_x.to_hex(),
        change_note.owner_pk_y.to_hex(),
    );
    fs::write(unshield_dir.join("Prover.toml"), toml)?;

    let exec = Command::new(nargo_bin)
        .args(["execute", "witness"])
        .current_dir(&unshield_dir)
        .output()?;
    if !exec.status.success() {
        bail!("nargo execute failed: {}", String::from_utf8_lossy(&exec.stderr));
    }
    let proof_out = Command::new(bb_bin)
        .args([
            "prove",
            "-b",
            "./target/unshield.json",
            "-w",
            "./target/witness.gz",
            "-k",
            "./target/vk",
            "-o",
            "./target",
        ])
        .current_dir(&unshield_dir)
        .output()?;
    if !proof_out.status.success() {
        bail!("bb prove failed: {}", String::from_utf8_lossy(&proof_out.stderr));
    }
    let proof_bytes = fs::read(unshield_dir.join("target/proof"))?;
    let tx = UnshieldTx {
        merkle_root,
        nullifier: nf,
        change_commitment: change_cm,
        burn_amount: 400,
        fee: 10,
        tx_binding_hash: txb,
        proof: proof_bytes,
    };

    ledger.apply_unshield(&tx, verifier)?;
    match ledger.apply_unshield(&tx, verifier) {
        Err(LedgerError::NullifierAlreadySpent) => Ok((
            true,
            "LedgerState rejected replayed real unshield nullifier".to_string(),
        )),
        other => Ok((false, format!("unexpected replay result: {other:?}"))),
    }
}

fn copy_dir_files(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst.join("src"))?;
    fs::copy(src.join("Nargo.toml"), dst.join("Nargo.toml"))?;
    for entry in fs::read_dir(src.join("src"))? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            fs::copy(&p, dst.join("src").join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn add_field(w: &mut WitnessMap<FieldElement>, key: Witness, delta: FieldElement) {
    let cur = w[&key];
    w.insert(key, cur + delta);
}

fn first_line(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("non-zero exit")
        .trim()
        .chars()
        .take(160)
        .collect()
}

