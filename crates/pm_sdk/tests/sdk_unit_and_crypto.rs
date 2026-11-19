use std::collections::BTreeSet;

use acir::{AcirField, FieldElement};
use anyhow::bail;
use ledger_core::{
    CircuitKind, LedgerState, Note, ProofVerifier, compute_note_commitment,
    derive_diversified_address,
};
use pm_sdk::{
    ClientWallet, MockProver, PaymentAddress, PublishedOutput, encrypt_note, field_to_hex,
    load_encrypted_wallet, save_encrypted_wallet, try_decrypt_note,
};
use tempfile::TempDir;

struct AcceptAllVerifier;

impl ProofVerifier for AcceptAllVerifier {
    fn verify_proof(
        &self,
        _kind: CircuitKind,
        _proof: &[u8],
        _public_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[test]
fn test_pm1_address_encode_decode_and_rejects_tamper() {
    let w = ClientWallet::new_from_seed("addr_test", 1_700_000_000).unwrap();
    let div = derive_diversified_address(w.keys.ivk, FieldElement::from(7u64)).unwrap();
    let addr = PaymentAddress::from_diversified(div);
    let encoded = addr.encode();
    assert!(encoded.starts_with("pm1"));
    assert_eq!(PaymentAddress::decode(&encoded).unwrap(), addr);

    // Wrong prefix rejected
    let wrong_prefix = format!("pm2{}", &encoded[3..]);
    assert!(PaymentAddress::decode(&wrong_prefix).is_err());

    // Corrupted trailing character (checksum tamper) rejected
    let mut tampered = encoded.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
    let tampered_str = String::from_utf8(tampered).unwrap();
    assert!(PaymentAddress::decode(&tampered_str).is_err());

    // Off-curve point rejected by validate()
    let mut off_curve = addr;
    off_curve.pk_d.y += FieldElement::one();
    assert!(off_curve.validate().is_err());
}

#[test]
fn test_grumpkin_ecdh_encrypt_decrypt_and_watch_only() {
    let mut bob = ClientWallet::new_from_seed("bob_ecdh", 1_700_000_000).unwrap();
    let eve = ClientWallet::new_from_seed("eve_ecdh", 1_700_000_000).unwrap();
    let bob_addr = bob.next_address().unwrap();
    let mut watch = bob.watch_only_ivk().unwrap();

    let note = Note {
        value: 42_000_000,
        owner_pk_x: bob_addr.pk_d.x,
        owner_pk_y: bob_addr.pk_d.y,
        blinding: FieldElement::from_hex("0x123456").unwrap(),
    };
    let cm = compute_note_commitment(&note);
    let esk = FieldElement::from(98765u64);
    let enc = encrypt_note(&bob_addr, &note, esk, cm, "espresso").unwrap();

    let dec = try_decrypt_note(bob.keys.ivk, cm, &enc).expect("bob decrypts own note");
    assert_eq!(dec.note, note);
    assert_eq!(dec.memo, "espresso");

    // Wrong IVK fails trial decryption
    assert!(try_decrypt_note(eve.keys.ivk, cm, &enc).is_none());

    // Commitment swap / ciphertext tampering fails
    assert!(try_decrypt_note(bob.keys.ivk, cm + FieldElement::one(), &enc).is_none());
    let mut bad_tag = enc.clone();
    bad_tag.tag_hex = format!("ff{}", &bad_tag.tag_hex[2..]);
    assert!(try_decrypt_note(bob.keys.ivk, cm, &bad_tag).is_none());

    // Watch-only wallet scans published output cleanly with zero spend key
    let found = watch.scan_outputs(
        &[PublishedOutput {
            leaf_index: 0,
            commitment_hex: field_to_hex(cm),
            encrypted_note: enc,
        }],
        &BTreeSet::new(),
    );
    assert_eq!(found, 1);
    assert_eq!(watch.unspent_balance(), 42_000_000);
    assert_eq!(watch.notes[0].memo, "espresso");
}

#[test]
fn test_encrypted_keystore_roundtrip_and_auth_failures() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("alice.pmk");

    let mut alice = ClientWallet::new_from_seed("alice_ks", 1_700_000_000).unwrap();
    let verifier = AcceptAllVerifier;
    let prover = MockProver;
    let mut ledger = LedgerState::new();
    ledger.mint_vault_supply(100_000_000).unwrap();
    let (s_tx, s_enc) = alice.build_shield(&prover, 100_000_000, "init").unwrap();
    let idx = ledger.apply_shield(&s_tx, &verifier).unwrap();
    alice.scan_outputs(
        &[PublishedOutput {
            leaf_index: idx,
            commitment_hex: field_to_hex(s_tx.out_commitment),
            encrypted_note: s_enc,
        }],
        &BTreeSet::new(),
    );
    offline_vouchers::SecureEnclave::credit_funding(&mut alice.enclave, 50_000_000).unwrap();

    save_encrypted_wallet(&path, &alice.to_snapshot(), "correct-horse-battery").unwrap();

    // Wrong passphrase rejected
    assert!(load_encrypted_wallet(&path, "wrong-password").is_err());

    // Valid passphrase restores full state
    let loaded =
        ClientWallet::from_snapshot(load_encrypted_wallet(&path, "correct-horse-battery").unwrap())
            .unwrap();
    assert_eq!(loaded.keys.ask, alice.keys.ask);
    assert_eq!(loaded.shielded_balance(), 100_000_000);
    assert_eq!(loaded.pocket_balance(), 50_000_000);

    // Tampered MAC in keystore file rejected
    let raw = std::fs::read_to_string(&path).unwrap();
    let mut val: serde_json::Value = serde_json::from_str(&raw).unwrap();
    val["mac_hex"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(&path, serde_json::to_vec(&val).unwrap()).unwrap();
    assert!(load_encrypted_wallet(&path, "correct-horse-battery").is_err());
}

#[test]
fn test_single_and_two_note_coin_selection_and_dummy_padding() {
    let verifier = AcceptAllVerifier;
    let prover = MockProver;
    let mut ledger = LedgerState::new();
    let mut alice = ClientWallet::new_from_seed("alice_cs", 1_700_000_000).unwrap();
    let mut bob = ClientWallet::new_from_seed("bob_cs", 1_700_000_000).unwrap();
    let bob_addr1 = bob.next_address().unwrap();
    let bob_addr2 = bob.next_address().unwrap();

    // Fund two separate notes: 100M and 150M
    ledger.mint_vault_supply(250_000_000).unwrap();
    let mut outputs = Vec::new();
    for (amt, memo) in [(100_000_000, "n1"), (150_000_000, "n2")] {
        let (tx, enc) = alice.build_shield(&prover, amt, memo).unwrap();
        let idx = ledger.apply_shield(&tx, &verifier).unwrap();
        outputs.push(PublishedOutput {
            leaf_index: idx,
            commitment_hex: field_to_hex(tx.out_commitment),
            encrypted_note: enc,
        });
    }
    alice.scan_outputs(&outputs, &BTreeSet::new());
    assert_eq!(alice.shielded_balance(), 250_000_000);

    // 1) Two-note spend: 210M + 2M fee = 212M (> any single note), change = 38M
    let (tx2, [e0, e1]) = alice
        .build_transfer(
            &prover,
            &bob_addr1,
            210_000_000,
            2_000_000,
            "merge",
            ledger.current_root(),
            |idx| {
                let sibs = ledger.merkle_tree.proof(idx).map_err(|e| anyhow::anyhow!("{e}"))?;
                Ok(pm_sdk::MerkleProofResponse {
                    root_hex: field_to_hex(ledger.current_root()),
                    leaf_index: idx,
                    siblings_hex: sibs.into_iter().map(field_to_hex).collect(),
                })
            },
        )
        .unwrap();
    let [i0, i1] = ledger.apply_transfer(&tx2, &verifier).unwrap();
    outputs.push(PublishedOutput {
        leaf_index: i0,
        commitment_hex: field_to_hex(tx2.out_commitments[0]),
        encrypted_note: e0,
    });
    outputs.push(PublishedOutput {
        leaf_index: i1,
        commitment_hex: field_to_hex(tx2.out_commitments[1]),
        encrypted_note: e1,
    });

    let spent: BTreeSet<String> = ledger.nullifiers.iter().map(|n| field_to_hex(*n)).collect();
    alice.scan_outputs(&outputs, &spent);
    bob.scan_outputs(&outputs, &spent);
    assert_eq!(alice.shielded_balance(), 38_000_000);
    assert_eq!(bob.shielded_balance(), 210_000_000);

    // 2) Single-note spend with dummy padding: Bob sends 50M + 1M fee -> 159M change
    let (tx1, [b0, b1]) = bob
        .build_transfer(
            &prover,
            &bob_addr2,
            50_000_000,
            1_000_000,
            "self-split",
            ledger.current_root(),
            |idx| {
                let sibs = ledger.merkle_tree.proof(idx).map_err(|e| anyhow::anyhow!("{e}"))?;
                if idx > 10 {
                    bail!("unexpected idx");
                }
                Ok(pm_sdk::MerkleProofResponse {
                    root_hex: field_to_hex(ledger.current_root()),
                    leaf_index: idx,
                    siblings_hex: sibs.into_iter().map(field_to_hex).collect(),
                })
            },
        )
        .unwrap();
    let [j0, j1] = ledger.apply_transfer(&tx1, &verifier).unwrap();
    outputs.push(PublishedOutput {
        leaf_index: j0,
        commitment_hex: field_to_hex(tx1.out_commitments[0]),
        encrypted_note: b0,
    });
    outputs.push(PublishedOutput {
        leaf_index: j1,
        commitment_hex: field_to_hex(tx1.out_commitments[1]),
        encrypted_note: b1,
    });
    let spent2: BTreeSet<String> = ledger.nullifiers.iter().map(|n| field_to_hex(*n)).collect();
    bob.scan_outputs(&outputs, &spent2);
    assert_eq!(bob.shielded_balance(), 209_000_000);
    assert_eq!(ledger.collected_fees, 3_000_000);
}
