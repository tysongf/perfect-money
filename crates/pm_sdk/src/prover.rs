use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use acir::{AcirField, FieldElement};
use anyhow::{Context, Result, bail};
use ledger_core::{
    BbVerifier, MERKLE_DEPTH, Note, ShieldTx, TransferTx, UnshieldTx, compute_note_commitment,
};
use tempfile::TempDir;

#[derive(Debug, Clone)]
pub struct TransferWitnessRequest {
    pub merkle_root: FieldElement,
    pub nullifiers: [FieldElement; 2],
    pub out_commitments: [FieldElement; 2],
    pub fee: u64,
    pub tx_binding_hash: FieldElement,
    pub ask: FieldElement,
    pub in_notes: [Note; 2],
    pub in_diversifiers: [FieldElement; 2],
    pub in_g_d_nonces: [u8; 2],
    pub in_g_d_ys: [FieldElement; 2],
    pub in_leaf_indices: [u32; 2],
    pub in_merkle_paths: [[FieldElement; MERKLE_DEPTH]; 2],
    pub out_notes: [Note; 2],
}

#[derive(Debug, Clone)]
pub struct UnshieldWitnessRequest {
    pub merkle_root: FieldElement,
    pub nullifier: FieldElement,
    pub change_commitment: FieldElement,
    pub burn_amount: u64,
    pub fee: u64,
    pub tx_binding_hash: FieldElement,
    pub ask: FieldElement,
    pub in_note: Note,
    pub in_diversifier: FieldElement,
    pub in_g_d_nonce: u8,
    pub in_g_d_y: FieldElement,
    pub in_leaf_index: u32,
    pub in_merkle_path: [FieldElement; MERKLE_DEPTH],
    pub change_note: Note,
}

pub trait CircuitProver: Send + Sync {
    fn prove_shield(&self, note: &Note, tx_binding_hash: FieldElement) -> Result<ShieldTx>;
    fn prove_transfer(&self, req: &TransferWitnessRequest) -> Result<TransferTx>;
    fn prove_unshield(&self, req: &UnshieldWitnessRequest) -> Result<UnshieldTx>;
}

/// Zero-latency mock prover for unit and CLI smoke suites.
#[derive(Debug, Default, Clone, Copy)]
pub struct MockProver;

impl CircuitProver for MockProver {
    fn prove_shield(&self, note: &Note, tx_binding_hash: FieldElement) -> Result<ShieldTx> {
        Ok(ShieldTx {
            mint_amount: note.value,
            out_commitment: compute_note_commitment(note),
            tx_binding_hash,
            proof: vec![0xA5; 32],
        })
    }

    fn prove_transfer(&self, req: &TransferWitnessRequest) -> Result<TransferTx> {
        Ok(TransferTx {
            merkle_root: req.merkle_root,
            nullifiers: req.nullifiers,
            out_commitments: req.out_commitments,
            fee: req.fee,
            tx_binding_hash: req.tx_binding_hash,
            proof: vec![0xB6; 32],
        })
    }

    fn prove_unshield(&self, req: &UnshieldWitnessRequest) -> Result<UnshieldTx> {
        Ok(UnshieldTx {
            merkle_root: req.merkle_root,
            nullifier: req.nullifier,
            change_commitment: req.change_commitment,
            burn_amount: req.burn_amount,
            fee: req.fee,
            tx_binding_hash: req.tx_binding_hash,
            proof: vec![0xC7; 32],
        })
    }
}

/// Real Noir (`nargo execute`) + Barretenberg UltraHonk (`bb prove`) prover operating inside a cache dir.
pub struct NargoBbProver {
    nargo_bin: PathBuf,
    bb_bin: PathBuf,
    cache_circuits_dir: PathBuf,
    lock: Mutex<()>,
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

fn copy_circuit_sources(src: &Path, dst: &Path) -> Result<()> {
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

fn compile_and_vk_if_needed(
    nargo: &Path,
    bb: &Path,
    circuit_dir: &Path,
    name: &str,
) -> Result<()> {
    let vk_path = circuit_dir.join("target").join("vk");
    let json_path = circuit_dir.join("target").join(format!("{name}.json"));
    if vk_path.is_file() && json_path.is_file() {
        return Ok(());
    }
    let compile_out = Command::new(nargo)
        .args(["compile", "--deny-warnings"])
        .current_dir(circuit_dir)
        .output()
        .with_context(|| format!("failed running nargo compile for {name}"))?;
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
        .with_context(|| format!("failed running bb write_vk for {name}"))?;
    if !vk_out.status.success() {
        bail!(
            "bb write_vk failed for {name}: {}",
            String::from_utf8_lossy(&vk_out.stderr)
        );
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

impl NargoBbProver {
    pub fn new(workspace_circuits_dir: &Path, cache_dir: &Path) -> Result<Self> {
        let nargo_bin = resolve_tool(".nargo/bin/nargo", "nargo");
        let bb_bin = resolve_tool(".bb/bb", "bb");
        let cache_circuits_dir = cache_dir.to_path_buf();
        for name in ["common", "shield", "shielded_transfer", "unshield"] {
            let src = workspace_circuits_dir.join(name);
            let dst = cache_circuits_dir.join(name);
            if !dst.join("Nargo.toml").is_file() {
                copy_circuit_sources(&src, &dst)?;
            }
        }
        for name in ["shield", "shielded_transfer", "unshield"] {
            compile_and_vk_if_needed(&nargo_bin, &bb_bin, &cache_circuits_dir.join(name), name)?;
        }
        Ok(Self {
            nargo_bin,
            bb_bin,
            cache_circuits_dir,
            lock: Mutex::new(()),
        })
    }

    pub fn bb_verifier(&self) -> BbVerifier {
        BbVerifier::new(
            self.cache_circuits_dir.join("shield").join("target").join("vk"),
            self.cache_circuits_dir
                .join("shielded_transfer")
                .join("target")
                .join("vk"),
            self.cache_circuits_dir.join("unshield").join("target").join("vk"),
        )
    }

    fn run_prove(&self, name: &str, prover_toml: &str) -> Result<Vec<u8>> {
        let _guard = self.lock.lock().expect("prover mutex");
        let circuit_dir = self.cache_circuits_dir.join(name);
        fs::write(circuit_dir.join("Prover.toml"), prover_toml)?;
        let exec_out = Command::new(&self.nargo_bin)
            .args(["execute", "witness"])
            .current_dir(&circuit_dir)
            .output()
            .with_context(|| format!("failed nargo execute for {name}"))?;
        if !exec_out.status.success() {
            bail!(
                "nargo execute failed for {name}: {}",
                String::from_utf8_lossy(&exec_out.stderr)
            );
        }
        let proof_dir = TempDir::new()?;
        let prove_out = Command::new(&self.bb_bin)
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
            .current_dir(&circuit_dir)
            .output()
            .with_context(|| format!("failed bb prove for {name}"))?;
        if !prove_out.status.success() {
            bail!(
                "bb prove failed for {name}: {}",
                String::from_utf8_lossy(&prove_out.stderr)
            );
        }
        Ok(fs::read(proof_dir.path().join("proof"))?)
    }
}

impl CircuitProver for NargoBbProver {
    fn prove_shield(&self, note: &Note, tx_binding_hash: FieldElement) -> Result<ShieldTx> {
        let cm = compute_note_commitment(note);
        let toml = format!(
            "mint_amount = \"{}\"\nout_commitment = {}\ntx_binding_hash = {}\n\n[out_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
            note.value,
            toml_hex(cm),
            toml_hex(tx_binding_hash),
            note.value,
            toml_hex(note.owner_pk_x),
            toml_hex(note.owner_pk_y),
            toml_hex(note.blinding),
        );
        let proof = self.run_prove("shield", &toml)?;
        Ok(ShieldTx {
            mint_amount: note.value,
            out_commitment: cm,
            tx_binding_hash,
            proof,
        })
    }

    fn prove_transfer(&self, req: &TransferWitnessRequest) -> Result<TransferTx> {
        let toml = format!(
            "merkle_root = {}\nnullifiers = [{}, {}]\nout_commitments = [{}, {}]\nfee = \"{}\"\ntx_binding_hash = {}\nask = {}\nin_diversifiers = [{}, {}]\nin_g_d_nonces = [{}, {}]\nin_g_d_ys = [{}, {}]\nin_leaf_indices = [{}, {}]\nin_merkle_paths = [\n{},\n{}\n]\n\n[[in_notes]]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[in_notes]]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[out_notes]]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[out_notes]]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
            toml_hex(req.merkle_root),
            toml_hex(req.nullifiers[0]),
            toml_hex(req.nullifiers[1]),
            toml_hex(req.out_commitments[0]),
            toml_hex(req.out_commitments[1]),
            req.fee,
            toml_hex(req.tx_binding_hash),
            toml_hex(req.ask),
            toml_hex(req.in_diversifiers[0]),
            toml_hex(req.in_diversifiers[1]),
            req.in_g_d_nonces[0],
            req.in_g_d_nonces[1],
            toml_hex(req.in_g_d_ys[0]),
            toml_hex(req.in_g_d_ys[1]),
            req.in_leaf_indices[0],
            req.in_leaf_indices[1],
            toml_path(&req.in_merkle_paths[0]),
            toml_path(&req.in_merkle_paths[1]),
            req.in_notes[0].value,
            toml_hex(req.in_notes[0].owner_pk_x),
            toml_hex(req.in_notes[0].owner_pk_y),
            toml_hex(req.in_notes[0].blinding),
            req.in_notes[1].value,
            toml_hex(req.in_notes[1].owner_pk_x),
            toml_hex(req.in_notes[1].owner_pk_y),
            toml_hex(req.in_notes[1].blinding),
            req.out_notes[0].value,
            toml_hex(req.out_notes[0].owner_pk_x),
            toml_hex(req.out_notes[0].owner_pk_y),
            toml_hex(req.out_notes[0].blinding),
            req.out_notes[1].value,
            toml_hex(req.out_notes[1].owner_pk_x),
            toml_hex(req.out_notes[1].owner_pk_y),
            toml_hex(req.out_notes[1].blinding),
        );
        let proof = self.run_prove("shielded_transfer", &toml)?;
        Ok(TransferTx {
            merkle_root: req.merkle_root,
            nullifiers: req.nullifiers,
            out_commitments: req.out_commitments,
            fee: req.fee,
            tx_binding_hash: req.tx_binding_hash,
            proof,
        })
    }

    fn prove_unshield(&self, req: &UnshieldWitnessRequest) -> Result<UnshieldTx> {
        let toml = format!(
            "merkle_root = {}\nnullifier = {}\nchange_commitment = {}\nburn_amount = \"{}\"\nfee = \"{}\"\ntx_binding_hash = {}\nask = {}\nin_diversifier = {}\nin_g_d_nonce = {}\nin_g_d_y = {}\nin_leaf_index = {}\nin_merkle_path = {}\n\n[in_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[change_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
            toml_hex(req.merkle_root),
            toml_hex(req.nullifier),
            toml_hex(req.change_commitment),
            req.burn_amount,
            req.fee,
            toml_hex(req.tx_binding_hash),
            toml_hex(req.ask),
            toml_hex(req.in_diversifier),
            req.in_g_d_nonce,
            toml_hex(req.in_g_d_y),
            req.in_leaf_index,
            toml_path(&req.in_merkle_path),
            req.in_note.value,
            toml_hex(req.in_note.owner_pk_x),
            toml_hex(req.in_note.owner_pk_y),
            toml_hex(req.in_note.blinding),
            req.change_note.value,
            toml_hex(req.change_note.owner_pk_x),
            toml_hex(req.change_note.owner_pk_y),
            toml_hex(req.change_note.blinding),
        );
        let proof = self.run_prove("unshield", &toml)?;
        Ok(UnshieldTx {
            merkle_root: req.merkle_root,
            nullifier: req.nullifier,
            change_commitment: req.change_commitment,
            burn_amount: req.burn_amount,
            fee: req.fee,
            tx_binding_hash: req.tx_binding_hash,
            proof,
        })
    }
}

