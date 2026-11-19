use std::collections::BTreeSet;

use acir::{AcirField, FieldElement};
use anyhow::bail;
use ledger_core::{
    CircuitKind, LedgerState, Note, ProofVerifier, compute_note_commitment,
    derive_diversified_address,
};
use offline_vouchers::SecureEnclave;
use pm_sdk::{
    ClientWallet, KEYSTORE_VERSION, MnemonicWords, MockProver, PaymentAddress, PublishedOutput,
    encrypt_note, field_to_hex, generate_mnemonic, load_encrypted_wallet, parse_mnemonic,
    save_encrypted_wallet, try_decrypt_note,
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
    let enc2 = encrypt_note(&bob_addr, &note, esk, cm, "espresso").unwrap();
    assert_ne!(enc.nonce_hex, enc2.nonce_hex);
    assert_ne!(enc.ciphertext_hex, enc2.ciphertext_hex);
    assert!(try_decrypt_note(bob.keys.ivk, cm, &enc2).is_some());

    let dec = try_decrypt_note(bob.keys.ivk, cm, &enc).expect("bob decrypts own note");
    assert_eq!(dec.note, note);
    assert_eq!(dec.memo, "espresso");

    // Wrong IVK fails trial decryption
    assert!(try_decrypt_note(eve.keys.ivk, cm, &enc).is_none());

    // Commitment swap, ciphertext tampering, and nonce tampering fail AEAD auth
    assert!(try_decrypt_note(bob.keys.ivk, cm + FieldElement::one(), &enc).is_none());
    let mut bad_ct = enc.clone();
    let ct_prefix = if bad_ct.ciphertext_hex.starts_with("ff") {
        "00"
    } else {
        "ff"
    };
    bad_ct.ciphertext_hex = format!("{ct_prefix}{}", &bad_ct.ciphertext_hex[2..]);
    assert!(try_decrypt_note(bob.keys.ivk, cm, &bad_ct).is_none());

    let mut bad_nonce = enc.clone();
    let nonce_prefix = if bad_nonce.nonce_hex.starts_with("ff") {
        "00"
    } else {
        "ff"
    };
    bad_nonce.nonce_hex = format!("{nonce_prefix}{}", &bad_nonce.nonce_hex[2..]);
    assert!(try_decrypt_note(bob.keys.ivk, cm, &bad_nonce).is_none());

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

    let raw = std::fs::read_to_string(&path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(val["version"].as_u64().unwrap(), u64::from(KEYSTORE_VERSION));
    assert_eq!(val["m_cost_kib"].as_u64().unwrap(), 19_456);
    assert_eq!(val["t_cost"].as_u64().unwrap(), 2);
    assert_eq!(val["p_cost"].as_u64().unwrap(), 1);
    assert_eq!(val["nonce_hex"].as_str().unwrap().len(), 48);

    // Wrong passphrase rejected
    assert!(load_encrypted_wallet(&path, "wrong-password").is_err());

    // Valid passphrase restores full state
    let loaded =
        ClientWallet::from_snapshot(load_encrypted_wallet(&path, "correct-horse-battery").unwrap())
            .unwrap();
    assert_eq!(loaded.keys.ask, alice.keys.ask);
    assert_eq!(loaded.shielded_balance(), 100_000_000);
    assert_eq!(loaded.pocket_balance(), 50_000_000);

    // Tampered ciphertext / Poly1305 tag in keystore file rejected
    let mut bad_ct = val.clone();
    bad_ct["ciphertext_hex"] = serde_json::Value::String("00".repeat(32));
    std::fs::write(&path, serde_json::to_vec(&bad_ct).unwrap()).unwrap();
    assert!(load_encrypted_wallet(&path, "correct-horse-battery").is_err());

    // Tampered Argon2 parameter (bound via XChaCha20-Poly1305 AAD) rejected
    let mut bad_param = val;
    bad_param["m_cost_kib"] = serde_json::Value::from(1_024);
    std::fs::write(&path, serde_json::to_vec(&bad_param).unwrap()).unwrap();
    assert!(load_encrypted_wallet(&path, "correct-horse-battery").is_err());
}

#[test]
fn test_bip39_12_and_24_word_hkdf_derivation_and_lost_phone_recovery() {
    let (mut alice_12, m12) =
        ClientWallet::new_random(MnemonicWords::Words12, 1_700_000_000).unwrap();
    assert_eq!(m12.word_count(), 12);

    let m24 = generate_mnemonic(MnemonicWords::Words24).unwrap();
    assert_eq!(m24.word_count(), 24);
    let parsed_24 = parse_mnemonic(&m24.to_string()).unwrap();
    let w24_a = ClientWallet::new_from_mnemonic(&parsed_24, "", 1_700_000_000).unwrap();
    let w24_b = ClientWallet::new_from_mnemonic(&m24, "", 1_700_000_500).unwrap();
    assert_eq!(w24_a.keys.ask, w24_b.keys.ask);
    assert_eq!(
        w24_a.enclave.attestation().device_pk,
        w24_b.enclave.attestation().device_pk
    );
    assert_eq!(w24_a.recovery_public_key(), w24_b.recovery_public_key());
    assert_eq!(w24_a.merchant_public_key(), w24_b.merchant_public_key());
    assert_eq!(w24_a.enclave.pocket_id(), w24_b.enclave.pocket_id());

    // Distinct BIP-39 passphrase derives completely distinct keys
    let w24_pass =
        ClientWallet::new_from_mnemonic(&m24, "bip39-extra-secret", 1_700_000_000).unwrap();
    assert_ne!(w24_pass.keys.ask, w24_a.keys.ask);
    assert_ne!(w24_pass.merchant_public_key(), w24_a.merchant_public_key());
    assert_ne!(w24_pass.recovery_public_key(), w24_a.recovery_public_key());

    // Invalid mnemonic fails parsing
    assert!(parse_mnemonic("abandon abandon invalidword notreal").is_err());

    // Lost-phone recovery restores shielded notes from published chain outputs
    let verifier = AcceptAllVerifier;
    let prover = MockProver;
    let mut ledger = LedgerState::new();
    ledger.mint_vault_supply(75_000_000).unwrap();
    let (s_tx, s_enc) = alice_12.build_shield(&prover, 75_000_000, "phone-backup").unwrap();
    let idx = ledger.apply_shield(&s_tx, &verifier).unwrap();
    let published = vec![PublishedOutput {
        leaf_index: idx,
        commitment_hex: field_to_hex(s_tx.out_commitment),
        encrypted_note: s_enc,
    }];

    let parsed_12 = parse_mnemonic(&m12.to_string()).unwrap();
    let mut recovered = ClientWallet::new_from_mnemonic(&parsed_12, "", 1_700_001_000).unwrap();
    assert_eq!(recovered.keys.ask, alice_12.keys.ask);
    assert_eq!(
        recovered.enclave.attestation().device_pk,
        alice_12.enclave.attestation().device_pk
    );
    assert_eq!(recovered.scan_outputs(&published, &BTreeSet::new()), 1);
    assert_eq!(recovered.shielded_balance(), 75_000_000);
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
