use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use acir::{AcirField, FieldElement};
use ledger_core::{
    BbVerifier, LedgerState, MERKLE_DEPTH, Note, ShieldTx, UnshieldTx, WalletKeys,
    compute_note_commitment, compute_nullifier, derive_diversified_address,
};
use offline_vouchers::{
    AttestationTrustStore, BleGattChannel, NfcTapChannel, OfflineMerchantWallet,
    OfflineTransport, PocketPolicy, PocketRegistry, SecureEnclave, SecurityLevel,
    SoftwareMockEnclave, VendorCa, VoucherError, compressed_pk, compute_pocket_fund_binding_hash,
    compute_pocket_reclaim_binding_hash, compute_voucher_settle_binding_hash,
    signing_key_from_seed,
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
        .args(["write_vk", "-b", &format!("./target/{name}.json"), "-o", "./target"])
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

fn prove_real_shield_tx(
    nargo: &Path,
    bb: &Path,
    shield_dir: &Path,
    note: &Note,
    tx_binding_hash: FieldElement,
) -> ShieldTx {
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
    let proof = prove_circuit(nargo, bb, shield_dir, "shield", &toml);
    ShieldTx {
        mint_amount: note.value,
        out_commitment: cm,
        tx_binding_hash,
        proof,
    }
}

#[test]
fn test_e2e_phase1_phase3_real_ultrahonk_offline_lifecycle() {
    let root = workspace_root();
    let nargo = resolve_tool(".nargo/bin/nargo", "nargo");
    let bb = resolve_tool(".bb/bb", "bb");

    let tmp = TempDir::new().unwrap();
    let circuits_tmp = tmp.path().join("circuits");
    for name in ["common", "shield", "unshield"] {
        copy_circuit_dir(&root.join("circuits").join(name), &circuits_tmp.join(name));
    }

    let shield_dir = circuits_tmp.join("shield");
    let unshield_dir = circuits_tmp.join("unshield");
    let shield_vk = compile_and_write_vk(&nargo, &bb, &shield_dir, "shield");
    let unshield_vk = compile_and_write_vk(&nargo, &bb, &unshield_dir, "unshield");

    let verifier = BbVerifier::new(shield_vk.clone(), shield_vk, unshield_vk);
    let mut ledger = LedgerState::new();

    // Setup Phase 3 trust store, CA, pocket enclave, and merchant wallets
    let now = 1_700_000_000u64;
    let policy = PocketPolicy::default();
    let ca = VendorCa::new("Apple-SecureEnclave-CA", signing_key_from_seed(b"apple_se_ca"));
    let mut trust = AttestationTrustStore::new();
    trust.register_ca(&ca.vendor_id, ca.public_key()).unwrap();
    let mut registry = PocketRegistry::new(policy.clone(), trust.clone()).unwrap();

    let mut alice_enclave = SoftwareMockEnclave::new(
        signing_key_from_seed(b"alice_se_e2e"),
        &ca,
        SecurityLevel::SecureEnclave,
        policy.clone(),
        now - 1000,
        now + 31_536_000,
        [0xA1; 16],
    )
    .unwrap();
    let alice_recovery_pk = compressed_pk(&signing_key_from_seed(b"alice_recovery_e2e"));

    let merch_a_pk = compressed_pk(&signing_key_from_seed(b"merch_a_p256"));
    let merch_b_pk = compressed_pk(&signing_key_from_seed(b"merch_b_p256"));
    let mut wallet_a =
        OfflineMerchantWallet::new(merch_a_pk, trust.clone(), policy.clone(), None).unwrap();
    let mut wallet_b =
        OfflineMerchantWallet::new(merch_b_pk, trust, policy.clone(), None).unwrap();

    // Shielded wallet identities (Noir Grumpkin)
    let alice_zk = WalletKeys::from_ask(FieldElement::from(123456789u64)).unwrap();
    let alice_addr = derive_diversified_address(alice_zk.ivk, FieldElement::from(1001u64)).unwrap();
    let merch_a_zk = WalletKeys::from_ask(FieldElement::from(222222222u64)).unwrap();
    let merch_a_addr =
        derive_diversified_address(merch_a_zk.ivk, FieldElement::from(3001u64)).unwrap();
    let merch_b_zk = WalletKeys::from_ask(FieldElement::from(333333333u64)).unwrap();
    let merch_b_addr =
        derive_diversified_address(merch_b_zk.ivk, FieldElement::from(4001u64)).unwrap();

    // 1. Mint 500 PM (500_000_000 micro-PM) & shield into Alice's shielded note using real `shield` proof
    let cap_amt = 500_000_000u64;
    ledger.mint_vault_supply(cap_amt).unwrap();
    let note_alice = Note {
        value: cap_amt,
        owner_pk_x: alice_addr.pk_d.x,
        owner_pk_y: alice_addr.pk_d.y,
        blinding: FieldElement::from_hex("0x1111222233334444").unwrap(),
    };
    let tx_shield_init = prove_real_shield_tx(
        &nargo,
        &bb,
        &shield_dir,
        &note_alice,
        FieldElement::from_hex("0xaa01").unwrap(),
    );
    let idx_alice = ledger.apply_shield(&tx_shield_init, &verifier).unwrap();
    let cm_alice = tx_shield_init.out_commitment;

    // 2. Alice unshields 500 PM via real `unshield` proof bound to pocket_id -> funds offline P-256 enclave
    let root_unshield = ledger.current_root();
    let path_alice = ledger.merkle_tree.proof(idx_alice).unwrap();
    let nf_alice = compute_nullifier(alice_zk.nk, cm_alice, idx_alice);
    let zero_change = Note {
        value: 0,
        owner_pk_x: FieldElement::zero(),
        owner_pk_y: FieldElement::zero(),
        blinding: FieldElement::from_hex("0x9999").unwrap(),
    };
    let cm_zero_chg = compute_note_commitment(&zero_change);
    let pid = alice_enclave.pocket_id();
    let tx_bind_fund = compute_pocket_fund_binding_hash(
        policy.chain_id,
        &pid,
        &alice_enclave.device_pk(),
        cap_amt,
    );
    let unshield_toml = format!(
        "merkle_root = {}\nnullifier = {}\nchange_commitment = {}\nburn_amount = \"{}\"\nfee = \"0\"\ntx_binding_hash = {}\nask = {}\nin_diversifier = {}\nin_g_d_nonce = {}\nin_g_d_y = {}\nin_leaf_index = {}\nin_merkle_path = {}\n\n[in_note]\nvalue = \"{}\"\nowner_pk_x = {}\nowner_pk_y = {}\nblinding = {}\n\n[change_note]\nvalue = \"0\"\nowner_pk_x = \"0x0\"\nowner_pk_y = \"0x0\"\nblinding = {}\n",
        toml_hex(root_unshield),
        toml_hex(nf_alice),
        toml_hex(cm_zero_chg),
        cap_amt,
        toml_hex(tx_bind_fund),
        toml_hex(alice_zk.ask),
        toml_hex(alice_addr.diversifier),
        alice_addr.nonce,
        toml_hex(alice_addr.g_d.y),
        idx_alice,
        toml_path(&path_alice),
        note_alice.value,
        toml_hex(note_alice.owner_pk_x),
        toml_hex(note_alice.owner_pk_y),
        toml_hex(note_alice.blinding),
        toml_hex(zero_change.blinding),
    );
    let unshield_proof = prove_circuit(&nargo, &bb, &unshield_dir, "unshield", &unshield_toml);
    let unshield_tx = UnshieldTx {
        merkle_root: root_unshield,
        nullifier: nf_alice,
        change_commitment: cm_zero_chg,
        burn_amount: cap_amt,
        fee: 0,
        tx_binding_hash: tx_bind_fund,
        proof: unshield_proof,
    };
    registry
        .fund_pocket_from_shielded(
            &mut ledger,
            &verifier,
            &unshield_tx,
            alice_enclave.attestation(),
            alice_recovery_pk,
            now,
        )
        .unwrap();
    alice_enclave.credit_funding(cap_amt).unwrap();
    assert_eq!(ledger.total_pocket_escrow, cap_amt as u128);

    // 3. Offline spends: 120 PM (ctr=1) over NFC tap to Merchant A; 80 PM (ctr=2) over BLE MTU-20 to Merchant B
    let v_a_out = alice_enclave
        .issue_voucher(merch_a_pk, 120_000_000, now + 10, 7200, [0x01; 16])
        .unwrap();
    let v_b_out = alice_enclave
        .issue_voucher(merch_b_pk, 80_000_000, now + 20, 7200, [0x02; 16])
        .unwrap();

    let mut nfc = NfcTapChannel::new();
    nfc.send_bundle(&v_a_out).unwrap();
    let rx_a = nfc.receive_bundle().unwrap();
    wallet_a.verify_and_accept_offline(&rx_a, now + 15).unwrap();

    let mut ble = BleGattChannel::new(20, 42);
    ble.reorder_reverse = true;
    ble.simulate_drop_retransmit = true;
    ble.send_bundle(&v_b_out).unwrap();
    let rx_b = ble.receive_bundle().unwrap();
    wallet_b.verify_and_accept_offline(&rx_b, now + 25).unwrap();

    // 4. Out-of-order settlement with real `shield` UltraHonk proofs: B settles ctr=2 FIRST, A settles ctr=1 SECOND
    let note_b = Note {
        value: 80_000_000,
        owner_pk_x: merch_b_addr.pk_d.x,
        owner_pk_y: merch_b_addr.pk_d.y,
        blinding: FieldElement::from_hex("0xbb11").unwrap(),
    };
    let cm_b = compute_note_commitment(&note_b);
    let tx_b = prove_real_shield_tx(
        &nargo,
        &bb,
        &shield_dir,
        &note_b,
        compute_voucher_settle_binding_hash(policy.chain_id, &rx_b.voucher.hash(), &merch_b_pk, cm_b),
    );
    registry
        .settle_voucher_to_shielded(&mut ledger, &verifier, &rx_b, &tx_b, merch_b_pk, now + 100)
        .unwrap();

    let note_a = Note {
        value: 120_000_000,
        owner_pk_x: merch_a_addr.pk_d.x,
        owner_pk_y: merch_a_addr.pk_d.y,
        blinding: FieldElement::from_hex("0xaa22").unwrap(),
    };
    let cm_a = compute_note_commitment(&note_a);
    let tx_a = prove_real_shield_tx(
        &nargo,
        &bb,
        &shield_dir,
        &note_a,
        compute_voucher_settle_binding_hash(policy.chain_id, &rx_a.voucher.hash(), &merch_a_pk, cm_a),
    );
    registry
        .settle_voucher_to_shielded(&mut ledger, &verifier, &rx_a, &tx_a, merch_a_pk, now + 110)
        .unwrap();

    // Replay must fail even with a genuine proof
    assert_eq!(
        registry.settle_voucher_to_shielded(
            &mut ledger,
            &verifier,
            &rx_a,
            &tx_a,
            merch_a_pk,
            now + 120
        ),
        Err(VoucherError::VoucherAlreadySettled(1))
    );

    // 5. Alice cooperatively closes enclave and immediately sweeps 300 PM back into shielded pool via real `shield` proof
    let close_stmt = alice_enclave.cooperative_close(now + 200).unwrap();
    let note_reclaim = Note {
        value: 300_000_000,
        owner_pk_x: alice_addr.pk_d.x,
        owner_pk_y: alice_addr.pk_d.y,
        blinding: FieldElement::from_hex("0xcc33").unwrap(),
    };
    let cm_reclaim = compute_note_commitment(&note_reclaim);
    let tx_reclaim = prove_real_shield_tx(
        &nargo,
        &bb,
        &shield_dir,
        &note_reclaim,
        compute_pocket_reclaim_binding_hash(policy.chain_id, &pid, 300_000_000, cm_reclaim),
    );
    let swept = registry
        .cooperative_close_pocket(&mut ledger, &verifier, &close_stmt, Some(&tx_reclaim), now + 200)
        .unwrap();
    assert_eq!(swept, 300_000_000);

    // 6. Strict conservation invariants across Phase 1 & Phase 3
    registry.assert_escrow_conservation(&ledger);
    assert_eq!(ledger.total_pocket_escrow, 0);
    assert_eq!(ledger.public_vault_balance, 0);
    assert_eq!(ledger.total_shielded_supply, cap_amt as u128);
    assert_eq!(ledger.total_issued_supply, cap_amt as u128);
}

