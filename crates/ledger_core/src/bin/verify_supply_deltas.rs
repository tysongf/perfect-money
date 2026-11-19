use std::collections::VecDeque;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail};
use ledger_core::{
    BbVerifier, LedgerState, MERKLE_DEPTH, Note, ShieldTx, UnshieldTx, WalletKeys,
    compute_note_commitment, compute_nullifier, derive_diversified_address,
};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[derive(Debug, Deserialize)]
struct SupplyDeltasInput {
    mints: Vec<u64>,
    burns: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct BridgeOutput {
    verified_shields: usize,
    verified_unshields: usize,
    total_issued_supply: u128,
    total_shielded_supply: u128,
    public_vault_balance: u128,
    collected_fees: u128,
    merkle_root: String,
}

fn workspace_root() -> Result<PathBuf> {
    if let Ok(cwd) = env::current_dir() {
        if cwd.join("circuits/shield/Nargo.toml").is_file() {
            return Ok(cwd);
        }
    }
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(Path::to_path_buf)
        .context("failed to locate workspace root")
}

fn resolve_tool(home_rel: &str, fallback: &str) -> PathBuf {
    if let Ok(home) = env::var("HOME") {
        let p = Path::new(&home).join(home_rel);
        if p.is_file() {
            return p;
        }
    }
    PathBuf::from(fallback)
}

fn copy_circuit_dir(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst.join("src"))?;
    fs::copy(src.join("Nargo.toml"), dst.join("Nargo.toml"))?;
    for entry in fs::read_dir(src.join("src"))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, dst.join("src").join(entry.file_name()))?;
        }
    }
    Ok(())
}

fn toml_hex(f: FieldElement) -> String {
    format!("\"0x{}\"", f.to_hex())
}

fn toml_path(siblings: &[FieldElement; MERKLE_DEPTH]) -> String {
    let items: Vec<String> = siblings.iter().map(|s| toml_hex(*s)).collect();
    format!("[\n{}\n]", items.join(",\n"))
}

fn compile_and_write_vk(nargo: &Path, bb: &Path, circuit_dir: &Path, name: &str) -> Result<PathBuf> {
    let compile_out = Command::new(nargo)
        .args(["compile", "--deny-warnings"])
        .current_dir(circuit_dir)
        .output()
        .context("run nargo compile")?;
    if !compile_out.status.success() {
        bail!(
            "nargo compile failed for {name}: {}",
            String::from_utf8_lossy(&compile_out.stderr)
        );
    }
    let vk_out = Command::new(bb)
        .args(["write_vk", "-b", &format!("./target/{name}.json"), "-o", "./target"])
        .current_dir(circuit_dir)
        .output()
        .context("run bb write_vk")?;
    if !vk_out.status.success() {
        bail!(
            "bb write_vk failed for {name}: {}",
            String::from_utf8_lossy(&vk_out.stderr)
        );
    }
    Ok(circuit_dir.join("target").join("vk"))
}

fn prove_circuit(
    nargo: &Path,
    bb: &Path,
    circuit_dir: &Path,
    name: &str,
    prover_toml: &str,
) -> Result<Vec<u8>> {
    fs::write(circuit_dir.join("Prover.toml"), prover_toml)?;
    let exec_out = Command::new(nargo)
        .args(["execute", "witness"])
        .current_dir(circuit_dir)
        .output()
        .context("run nargo execute")?;
    if !exec_out.status.success() {
        bail!(
            "nargo execute failed for {name}: {}",
            String::from_utf8_lossy(&exec_out.stderr)
        );
    }
    let proof_dir = TempDir::new()?;
    let prove_out = Command::new(bb)
        .args([
            "prove",
            "-b",
            &format!("./target/{name}.json"),
            "-w",
            "./target/witness.gz",
            "-k",
            "./target/vk",
            "-o",
        ])
        .arg(proof_dir.path())
        .current_dir(circuit_dir)
        .output()
        .context("run bb prove")?;
    if !prove_out.status.success() {
        bail!(
            "bb prove failed for {name}: {}",
            String::from_utf8_lossy(&prove_out.stderr)
        );
    }
    Ok(fs::read(proof_dir.path().join("proof"))?)
}

fn main() -> Result<()> {
    let arg_path = env::args()
        .nth(1)
        .context("usage: verify_supply_deltas <deltas.json>")?;
    let raw = fs::read_to_string(&arg_path)
        .with_context(|| format!("failed to read {}", arg_path))?;
    let input: SupplyDeltasInput = serde_json::from_str(&raw)?;

    if input.mints.is_empty() {
        bail!("mints array must be non-empty");
    }
    for &m in &input.mints {
        if m == 0 {
            bail!("all mints must be > 0");
        }
    }
    for &b in &input.burns {
        if b == 0 {
            bail!("all burns must be > 0");
        }
    }
    let total_mints: u128 = input.mints.iter().map(|&v| v as u128).sum();
    let total_burns: u128 = input.burns.iter().map(|&v| v as u128).sum();
    if total_burns > total_mints {
        bail!("total burns ({total_burns}) exceed total mints ({total_mints})");
    }

    let root = workspace_root()?;
    let nargo = resolve_tool(".nargo/bin/nargo", "nargo");
    let bb = resolve_tool(".bb/bb", "bb");

    let tmp = TempDir::new()?;
    let circuits_tmp = tmp.path().join("circuits");
    for name in ["common", "shield", "unshield"] {
        copy_circuit_dir(&root.join("circuits").join(name), &circuits_tmp.join(name))?;
    }
    let shield_dir = circuits_tmp.join("shield");
    let unshield_dir = circuits_tmp.join("unshield");
    let shield_vk = compile_and_write_vk(&nargo, &bb, &shield_dir, "shield")?;
    let unshield_vk = compile_and_write_vk(&nargo, &bb, &unshield_dir, "unshield")?;

    // BbVerifier expects all 3 VKs; provide shield_vk as unused placeholder for transfer slot.
    let verifier = BbVerifier::new(shield_vk.clone(), shield_vk, unshield_vk);
    let mut ledger = LedgerState::new();

    let wallet = WalletKeys::from_ask(FieldElement::from(42424242u64))?;
    let addr = derive_diversified_address(wallet.ivk, FieldElement::from(7001u64))?;

    let mut owned_notes: VecDeque<(Note, u32, FieldElement)> = VecDeque::new();
    let mut verified_shields = 0usize;
    let mut verified_unshields = 0usize;
    let mut nonce_ctr: u64 = 1;

    for mint_amt in input.mints {
        ledger.mint_vault_supply(mint_amt)?;
        let note = Note {
            value: mint_amt,
            owner_pk_x: addr.pk_d.x,
            owner_pk_y: addr.pk_d.y,
            blinding: FieldElement::from(0x1000_0000_0000u64 + nonce_ctr),
        };
        let cm = compute_note_commitment(&note);
        let tx_bind = FieldElement::from(0xaa00_0000u64 + nonce_ctr);
        nonce_ctr += 1;

        let shield_toml = format!(
            "mint_amount = \"{mint_amt}\"\nout_commitment = {}\ntx_binding_hash = {}\n\n[out_note]\nvalue = \"{mint_amt}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
            toml_hex(cm),
            toml_hex(tx_bind),
            toml_hex(note.owner_pk_x),
            toml_hex(note.owner_pk_y),
            toml_hex(note.blinding),
        );
        let proof = prove_circuit(&nargo, &bb, &shield_dir, "shield", &shield_toml)?;
        let idx = ledger.apply_shield(
            &ShieldTx {
                mint_amount: mint_amt,
                out_commitment: cm,
                tx_binding_hash: tx_bind,
                proof,
            },
            &verifier,
        )?;
        owned_notes.push_back((note, idx, cm));
        verified_shields += 1;
    }

    for burn_target in input.burns {
        let mut rem_burn = burn_target;
        while rem_burn > 0 {
            let (in_note, in_idx, in_cm) = owned_notes
                .pop_front()
                .context("ran out of shielded notes while burning")?;
            let slice_burn = rem_burn.min(in_note.value);
            let chg_val = in_note.value - slice_burn;
            let cur_root = ledger.current_root();
            let path = ledger.merkle_tree.proof(in_idx)?;
            let nf = compute_nullifier(wallet.nk, in_cm, in_idx);

            let chg_note = Note {
                value: chg_val,
                owner_pk_x: addr.pk_d.x,
                owner_pk_y: addr.pk_d.y,
                blinding: FieldElement::from(0x2000_0000_0000u64 + nonce_ctr),
            };
            let chg_cm = compute_note_commitment(&chg_note);
            let tx_bind = FieldElement::from(0xbb00_0000u64 + nonce_ctr);
            nonce_ctr += 1;

            let unshield_toml = format!(
                "merkle_root = {}\nnullifier = {}\nchange_commitment = {}\nburn_amount = \"{slice_burn}\"\nfee = \"0\"\ntx_binding_hash = {}\nask = {}\nin_diversifier = {}\nin_g_d_nonce = {}\nin_g_d_y = {}\nin_leaf_index = {}\nin_merkle_path = {}\n\n[in_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[change_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
                toml_hex(cur_root),
                toml_hex(nf),
                toml_hex(chg_cm),
                toml_hex(tx_bind),
                toml_hex(wallet.ask),
                toml_hex(addr.diversifier),
                addr.nonce,
                toml_hex(addr.g_d.y),
                in_idx,
                toml_path(&path),
                in_note.value,
                toml_hex(in_note.owner_pk_x),
                toml_hex(in_note.owner_pk_y),
                toml_hex(in_note.blinding),
                chg_val,
                toml_hex(chg_note.owner_pk_x),
                toml_hex(chg_note.owner_pk_y),
                toml_hex(chg_note.blinding),
            );
            let proof = prove_circuit(&nargo, &bb, &unshield_dir, "unshield", &unshield_toml)?;
            let chg_idx = ledger.apply_unshield(
                &UnshieldTx {
                    merkle_root: cur_root,
                    nullifier: nf,
                    change_commitment: chg_cm,
                    burn_amount: slice_burn,
                    fee: 0,
                    tx_binding_hash: tx_bind,
                    proof,
                },
                &verifier,
            )?;
            ledger.burn_vault_supply(slice_burn)?;
            if chg_val > 0 {
                owned_notes.push_front((chg_note, chg_idx, chg_cm));
            }
            verified_unshields += 1;
            rem_burn -= slice_burn;
        }
    }

    ledger.assert_conservation_invariant();
    let expected_issued = total_mints - total_burns;
    if ledger.total_issued_supply != expected_issued || ledger.total_shielded_supply != expected_issued
    {
        bail!(
            "unexpected final supply: issued={}, shielded={}, expected={}",
            ledger.total_issued_supply,
            ledger.total_shielded_supply,
            expected_issued
        );
    }

    let out = BridgeOutput {
        verified_shields,
        verified_unshields,
        total_issued_supply: ledger.total_issued_supply,
        total_shielded_supply: ledger.total_shielded_supply,
        public_vault_balance: ledger.public_vault_balance,
        collected_fees: ledger.collected_fees,
        merkle_root: format!("0x{}", ledger.current_root().to_hex()),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
