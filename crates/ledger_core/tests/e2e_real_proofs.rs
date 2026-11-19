use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::{AcirField, FieldElement};
use ledger_core::{
    BbVerifier, LedgerError, LedgerState, MERKLE_DEPTH, Note, ShieldTx, TransferTx, UnshieldTx,
    WalletKeys, compute_note_commitment, compute_nullifier, derive_diversified_address,
};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
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

fn copy_circuit_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst.join("src")).unwrap();
    fs::copy(src.join("Nargo.toml"), dst.join("Nargo.toml")).unwrap();
    for entry in fs::read_dir(src.join("src")).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            fs::copy(&path, dst.join("src").join(entry.file_name())).unwrap();
        }
    }
}

fn toml_hex(f: FieldElement) -> String {
    format!("\"0x{}\"", f.to_hex())
}

fn toml_path(siblings: &[FieldElement; MERKLE_DEPTH]) -> String {
    let items: Vec<String> = siblings.iter().map(|s| toml_hex(*s)).collect();
    format!("[\n{}\n]", items.join(",\n"))
}

fn compile_and_write_vk(nargo: &Path, bb: &Path, circuit_dir: &Path, name: &str) -> PathBuf {
    let compile_out = Command::new(nargo)
        .args(["compile", "--deny-warnings"])
        .current_dir(circuit_dir)
        .output()
        .expect("run nargo compile");
    assert!(
        compile_out.status.success(),
        "nargo compile failed for {name}: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let vk_out = Command::new(bb)
        .args([
            "write_vk",
            "-b",
            &format!("./target/{name}.json"),
            "-o",
            "./target",
        ])
        .current_dir(circuit_dir)
        .output()
        .expect("run bb write_vk");
    assert!(
        vk_out.status.success(),
        "bb write_vk failed for {name}: {}",
        String::from_utf8_lossy(&vk_out.stderr)
    );
    circuit_dir.join("target").join("vk")
}

fn prove_circuit(
    nargo: &Path,
    bb: &Path,
    circuit_dir: &Path,
    name: &str,
    prover_toml: &str,
) -> Vec<u8> {
    fs::write(circuit_dir.join("Prover.toml"), prover_toml).unwrap();

    let exec_out = Command::new(nargo)
        .args(["execute", "witness"])
        .current_dir(circuit_dir)
        .output()
        .expect("run nargo execute");
    assert!(
        exec_out.status.success(),
        "nargo execute failed for {name}: {}",
        String::from_utf8_lossy(&exec_out.stderr)
    );

    let proof_dir = TempDir::new().unwrap();
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
        .expect("run bb prove");
    assert!(
        prove_out.status.success(),
        "bb prove failed for {name}: {}",
        String::from_utf8_lossy(&prove_out.stderr)
    );

    fs::read(proof_dir.path().join("proof")).unwrap()
}

#[test]
fn test_e2e_real_proof_lifecycle() {
    let root = workspace_root();
    let nargo = resolve_tool(".nargo/bin/nargo", "nargo");
    let bb = resolve_tool(".bb/bb", "bb");

    let tmp = TempDir::new().unwrap();
    let circuits_tmp = tmp.path().join("circuits");
    for name in ["common", "shield", "shielded_transfer", "unshield"] {
        copy_circuit_dir(&root.join("circuits").join(name), &circuits_tmp.join(name));
    }

    let shield_dir = circuits_tmp.join("shield");
    let transfer_dir = circuits_tmp.join("shielded_transfer");
    let unshield_dir = circuits_tmp.join("unshield");

    let shield_vk = compile_and_write_vk(&nargo, &bb, &shield_dir, "shield");
    let transfer_vk = compile_and_write_vk(&nargo, &bb, &transfer_dir, "shielded_transfer");
    let unshield_vk = compile_and_write_vk(&nargo, &bb, &unshield_dir, "unshield");

    let verifier = BbVerifier::new(shield_vk, transfer_vk, unshield_vk);
    let mut ledger = LedgerState::new();

    // Key hierarchies for Alice and Bob
    let alice = WalletKeys::from_ask(FieldElement::from(123456789u64)).unwrap();
    let alice_d1 = derive_diversified_address(alice.ivk, FieldElement::from(1001u64)).unwrap();
    let alice_d2 = derive_diversified_address(alice.ivk, FieldElement::from(1002u64)).unwrap();

    let bob = WalletKeys::from_ask(FieldElement::from(987654321u64)).unwrap();
    let bob_d1 = derive_diversified_address(bob.ivk, FieldElement::from(2001u64)).unwrap();

    // 1. Vault issues 1000 PM into public vault balance
    ledger.mint_vault_supply(1000).unwrap();

    // 2. Shield 600 and 400 to Alice's two distinct diversified addresses
    let note_a1 = Note {
        value: 600,
        owner_pk_x: alice_d1.pk_d.x,
        owner_pk_y: alice_d1.pk_d.y,
        blinding: FieldElement::from_hex("0x1111222233334444").unwrap(),
    };
    let cm_a1 = compute_note_commitment(&note_a1);
    let tx_bind_s1 = FieldElement::from_hex("0xaa01").unwrap();
    let shield1_toml = format!(
        "mint_amount = \"600\"\nout_commitment = {}\ntx_binding_hash = {}\n\n[out_note]\nvalue = \"600\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
        toml_hex(cm_a1),
        toml_hex(tx_bind_s1),
        toml_hex(note_a1.owner_pk_x),
        toml_hex(note_a1.owner_pk_y),
        toml_hex(note_a1.blinding),
    );
    let shield1_proof = prove_circuit(&nargo, &bb, &shield_dir, "shield", &shield1_toml);
    let idx_a1 = ledger
        .apply_shield(
            &ShieldTx {
                mint_amount: 600,
                out_commitment: cm_a1,
                tx_binding_hash: tx_bind_s1,
                proof: shield1_proof,
            },
            &verifier,
        )
        .unwrap();
    assert_eq!(idx_a1, 0);

    let note_a2 = Note {
        value: 400,
        owner_pk_x: alice_d2.pk_d.x,
        owner_pk_y: alice_d2.pk_d.y,
        blinding: FieldElement::from_hex("0x5555666677778888").unwrap(),
    };
    let cm_a2 = compute_note_commitment(&note_a2);
    let tx_bind_s2 = FieldElement::from_hex("0xaa02").unwrap();
    let shield2_toml = format!(
        "mint_amount = \"400\"\nout_commitment = {}\ntx_binding_hash = {}\n\n[out_note]\nvalue = \"400\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
        toml_hex(cm_a2),
        toml_hex(tx_bind_s2),
        toml_hex(note_a2.owner_pk_x),
        toml_hex(note_a2.owner_pk_y),
        toml_hex(note_a2.blinding),
    );
    let shield2_proof = prove_circuit(&nargo, &bb, &shield_dir, "shield", &shield2_toml);
    let idx_a2 = ledger
        .apply_shield(
            &ShieldTx {
                mint_amount: 400,
                out_commitment: cm_a2,
                tx_binding_hash: tx_bind_s2,
                proof: shield2_proof,
            },
            &verifier,
        )
        .unwrap();
    assert_eq!(idx_a2, 1);

    // 3. Alice transfers 600 + 400 -> 750 to Bob + 240 change to Alice + 10 fee
    let root_before_tx = ledger.current_root();
    let path_a1 = ledger.merkle_tree.proof(idx_a1).unwrap();
    let path_a2 = ledger.merkle_tree.proof(idx_a2).unwrap();
    let nf_a1 = compute_nullifier(alice.nk, cm_a1, idx_a1);
    let nf_a2 = compute_nullifier(alice.nk, cm_a2, idx_a2);

    let note_bob = Note {
        value: 750,
        owner_pk_x: bob_d1.pk_d.x,
        owner_pk_y: bob_d1.pk_d.y,
        blinding: FieldElement::from_hex("0xaaaa1111bbbb2222").unwrap(),
    };
    let note_alice_chg = Note {
        value: 240,
        owner_pk_x: alice_d2.pk_d.x,
        owner_pk_y: alice_d2.pk_d.y,
        blinding: FieldElement::from_hex("0xcccc3333dddd4444").unwrap(),
    };
    let cm_bob = compute_note_commitment(&note_bob);
    let cm_alice_chg = compute_note_commitment(&note_alice_chg);
    let tx_bind_xfer = FieldElement::from_hex("0xbb01").unwrap();

    let xfer_toml = format!(
        "merkle_root = {}\nnullifiers = [{}, {}]\nout_commitments = [{}, {}]\nfee = \"10\"\ntx_binding_hash = {}\nask = {}\nin_diversifiers = [{}, {}]\nin_g_d_nonces = [{}, {}]\nin_g_d_ys = [{}, {}]\nin_leaf_indices = [{}, {}]\nin_merkle_paths = [\n{},\n{}\n]\n\n[[in_notes]]\nvalue = \"600\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[in_notes]]\nvalue = \"400\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[out_notes]]\nvalue = \"750\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[[out_notes]]\nvalue = \"240\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
        toml_hex(root_before_tx),
        toml_hex(nf_a1),
        toml_hex(nf_a2),
        toml_hex(cm_bob),
        toml_hex(cm_alice_chg),
        toml_hex(tx_bind_xfer),
        toml_hex(alice.ask),
        toml_hex(alice_d1.diversifier),
        toml_hex(alice_d2.diversifier),
        alice_d1.nonce,
        alice_d2.nonce,
        toml_hex(alice_d1.g_d.y),
        toml_hex(alice_d2.g_d.y),
        idx_a1,
        idx_a2,
        toml_path(&path_a1),
        toml_path(&path_a2),
        toml_hex(note_a1.owner_pk_x),
        toml_hex(note_a1.owner_pk_y),
        toml_hex(note_a1.blinding),
        toml_hex(note_a2.owner_pk_x),
        toml_hex(note_a2.owner_pk_y),
        toml_hex(note_a2.blinding),
        toml_hex(note_bob.owner_pk_x),
        toml_hex(note_bob.owner_pk_y),
        toml_hex(note_bob.blinding),
        toml_hex(note_alice_chg.owner_pk_x),
        toml_hex(note_alice_chg.owner_pk_y),
        toml_hex(note_alice_chg.blinding),
    );
    let xfer_proof = prove_circuit(&nargo, &bb, &transfer_dir, "shielded_transfer", &xfer_toml);

    // 4a. Verify 1-byte tampered proof is rejected by real BbVerifier via apply_transfer
    let mut bad_xfer = TransferTx {
        merkle_root: root_before_tx,
        nullifiers: [nf_a1, nf_a2],
        out_commitments: [cm_bob, cm_alice_chg],
        fee: 10,
        tx_binding_hash: tx_bind_xfer,
        proof: xfer_proof.clone(),
    };
    bad_xfer.proof[0] ^= 0x01;
    assert!(matches!(
        ledger.apply_transfer(&bad_xfer, &verifier),
        Err(LedgerError::InvalidProof(_))
    ));

    // Apply genuine transfer
    let valid_xfer = TransferTx {
        merkle_root: root_before_tx,
        nullifiers: [nf_a1, nf_a2],
        out_commitments: [cm_bob, cm_alice_chg],
        fee: 10,
        tx_binding_hash: tx_bind_xfer,
        proof: xfer_proof,
    };
    let [idx_bob, idx_alice_chg] = ledger.apply_transfer(&valid_xfer, &verifier).unwrap();
    assert_eq!(idx_bob, 2);
    assert_eq!(idx_alice_chg, 3);

    // 4b. Verify double-spend replay is rejected
    assert_eq!(
        ledger.apply_transfer(&valid_xfer, &verifier),
        Err(LedgerError::NullifierAlreadySpent)
    );

    // 5. Bob unshields 500 PM (+ 5 fee, 245 change back to Bob)
    let root_before_unshield = ledger.current_root();
    let path_bob = ledger.merkle_tree.proof(idx_bob).unwrap();
    let nf_bob = compute_nullifier(bob.nk, cm_bob, idx_bob);
    let note_bob_chg = Note {
        value: 245,
        owner_pk_x: bob_d1.pk_d.x,
        owner_pk_y: bob_d1.pk_d.y,
        blinding: FieldElement::from_hex("0xeeee5555ffff6666").unwrap(),
    };
    let cm_bob_chg = compute_note_commitment(&note_bob_chg);
    let tx_bind_unshield = FieldElement::from_hex("0xcc01").unwrap();

    let unshield_toml = format!(
        "merkle_root = {}\nnullifier = {}\nchange_commitment = {}\nburn_amount = \"500\"\nfee = \"5\"\ntx_binding_hash = {}\nask = {}\nin_diversifier = {}\nin_g_d_nonce = {}\nin_g_d_y = {}\nin_leaf_index = {}\nin_merkle_path = {}\n\n[in_note]\nvalue = \"750\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[change_note]\nvalue = \"245\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n",
        toml_hex(root_before_unshield),
        toml_hex(nf_bob),
        toml_hex(cm_bob_chg),
        toml_hex(tx_bind_unshield),
        toml_hex(bob.ask),
        toml_hex(bob_d1.diversifier),
        bob_d1.nonce,
        toml_hex(bob_d1.g_d.y),
        idx_bob,
        toml_path(&path_bob),
        toml_hex(note_bob.owner_pk_x),
        toml_hex(note_bob.owner_pk_y),
        toml_hex(note_bob.blinding),
        toml_hex(note_bob_chg.owner_pk_x),
        toml_hex(note_bob_chg.owner_pk_y),
        toml_hex(note_bob_chg.blinding),
    );
    let unshield_proof = prove_circuit(&nargo, &bb, &unshield_dir, "unshield", &unshield_toml);

    let idx_bob_chg = ledger
        .apply_unshield(
            &UnshieldTx {
                merkle_root: root_before_unshield,
                nullifier: nf_bob,
                change_commitment: cm_bob_chg,
                burn_amount: 500,
                fee: 5,
                tx_binding_hash: tx_bind_unshield,
                proof: unshield_proof,
            },
            &verifier,
        )
        .unwrap();
    assert_eq!(idx_bob_chg, 4);

    // 6. Vault burns the 500 unshielded PM
    ledger.burn_vault_supply(500).unwrap();

    // 7. Assert final supply & conservation accounting
    assert_eq!(ledger.total_issued_supply, 500);
    assert_eq!(ledger.public_vault_balance, 0);
    assert_eq!(ledger.total_shielded_supply, 485);
    assert_eq!(ledger.collected_fees, 15);
    ledger.assert_conservation_invariant();
}

