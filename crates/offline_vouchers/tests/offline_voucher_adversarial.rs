use acir::FieldElement;
use anyhow::bail;
use ledger_core::{CircuitKind, LedgerError, LedgerState, ProofVerifier, ShieldTx, UnshieldTx};
use offline_vouchers::{
    AttestationTrustStore, BleGattChannel, CompromisedTestEnclave, DEFAULT_MAX_VOUCHER_TTL_SECS,
    DEFAULT_MERCHANT_MAX_HOPS, EncryptedMeshRelay, HardwareAttestation, MAX_NDEF_PAYLOAD_BYTES,
    NfcNdefFrame, NfcTapChannel, OfflineMerchantWallet, OfflineTransport, OfflineVoucher,
    PocketPolicy, PocketRegistry, PocketStatus, SecureEnclave, SecurityLevel, SoftwareMockEnclave,
    VendorCa, VoucherError, compressed_pk, compute_pocket_fund_binding_hash,
    compute_pocket_reclaim_binding_hash, compute_voucher_settle_binding_hash, decode_bundle,
    decode_close_statement, decode_frame, encode_bundle, encode_close_statement, encode_frame,
    encode_voucher, malleate_to_high_s, open_bundle_from_mesh, seal_bundle_for_mesh,
    seal_bundle_for_mesh_random, sign_hop_endorsement, sign_uncooperative_drain_request,
    signing_key_from_seed,
};

struct MockVerifier {
    accept: bool,
}

impl ProofVerifier for MockVerifier {
    fn verify_proof(
        &self,
        _kind: CircuitKind,
        _proof: &[u8],
        _public_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        if self.accept {
            Ok(())
        } else {
            bail!("mock verifier rejected")
        }
    }
}

struct Harness {
    verifier: MockVerifier,
    ledger: LedgerState,
    registry: PocketRegistry,
    ca: VendorCa,
    policy: PocketPolicy,
    now: u64,
}

impl Harness {
    fn new(max_pocket_balance: u64) -> Self {
        let now = 1_700_000_000u64;
        let policy = PocketPolicy {
            max_pocket_balance,
            ..PocketPolicy::default()
        };
        let ca = VendorCa::new("StrongBox-Test-CA", signing_key_from_seed(b"vendor_ca_1"));
        let mut trust = AttestationTrustStore::new();
        trust.register_ca(&ca.vendor_id, ca.public_key()).unwrap();
        let registry = PocketRegistry::new(policy.clone(), trust).unwrap();
        Self {
            verifier: MockVerifier { accept: true },
            ledger: LedgerState::new(),
            registry,
            ca,
            policy,
            now,
        }
    }

    fn shield_seed_funds(&mut self, amount: u64, tag: u64) {
        self.ledger.mint_vault_supply(amount).unwrap();
        let tx = ShieldTx {
            mint_amount: amount,
            out_commitment: FieldElement::from(10_000 + tag),
            tx_binding_hash: FieldElement::from(20_000 + tag),
            proof: vec![],
        };
        self.ledger.apply_shield(&tx, &self.verifier).unwrap();
    }

    fn make_enclave(&self, seed: &[u8], serial: [u8; 16]) -> SoftwareMockEnclave {
        let sk = signing_key_from_seed(seed);
        SoftwareMockEnclave::new(
            sk,
            &self.ca,
            SecurityLevel::StrongBox,
            self.policy.clone(),
            self.now - 1000,
            self.now + 31_536_000,
            serial,
        )
        .unwrap()
    }

    fn build_fund_tx(&self, att: &HardwareAttestation, amount: u64, tag: u64) -> UnshieldTx {
        let pid = att.pocket_id(self.policy.chain_id);
        UnshieldTx {
            merkle_root: self.ledger.current_root(),
            nullifier: FieldElement::from(30_000 + tag),
            change_commitment: FieldElement::from(40_000 + tag),
            burn_amount: amount,
            fee: 0,
            tx_binding_hash: compute_pocket_fund_binding_hash(
                self.policy.chain_id,
                &pid,
                &att.device_pk,
                amount,
            ),
            proof: vec![],
        }
    }

    fn build_settle_tx(&self, v: &OfflineVoucher, recip_pk: &[u8; 33], tag: u64) -> ShieldTx {
        let cm = FieldElement::from(50_000 + tag);
        ShieldTx {
            mint_amount: v.amount,
            out_commitment: cm,
            tx_binding_hash: compute_voucher_settle_binding_hash(
                self.policy.chain_id,
                &v.hash(),
                recip_pk,
                cm,
            ),
            proof: vec![],
        }
    }

    fn build_reclaim_tx(&self, att: &HardwareAttestation, amount: u64, tag: u64) -> ShieldTx {
        let cm = FieldElement::from(70_000 + tag);
        let pid = att.pocket_id(self.policy.chain_id);
        ShieldTx {
            mint_amount: amount,
            out_commitment: cm,
            tx_binding_hash: compute_pocket_reclaim_binding_hash(
                self.policy.chain_id,
                &pid,
                amount,
                cm,
            ),
            proof: vec![],
        }
    }
}

#[test]
fn test_wire_sizes_and_frame_integrity() {
    let h = Harness::new(500_000_000);
    let mut enclave = h.make_enclave(b"alice_wire", [1u8; 16]);
    enclave.credit_funding(200_000_000).unwrap();
    let merchant_pk = compressed_pk(&signing_key_from_seed(b"merchant_wire"));

    let bundle = enclave
        .issue_voucher(merchant_pk, 50_000_000, h.now, 3600, [9u8; 16])
        .unwrap();

    let raw_v = encode_voucher(&bundle.voucher);
    assert_eq!(raw_v.len(), 227);
    let frame = encode_frame(&encode_bundle(&bundle));
    assert!(
        frame.len() < 450,
        "framed single-hop bundle was {} bytes, expected < 450",
        frame.len()
    );

    let decoded = decode_bundle(&decode_frame(&frame).unwrap()).unwrap();
    assert_eq!(decoded, bundle);

    // Corrupted checksum rejected
    let mut bad = frame.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    assert!(matches!(decode_frame(&bad), Err(VoucherError::WireError(_))));

    // Truncated frame rejected
    assert!(matches!(
        decode_frame(&frame[..10]),
        Err(VoucherError::WireError(_))
    ));
}

#[test]
fn test_ble_mtu20_and_mtu247_out_of_order_and_retransmit() {
    let h = Harness::new(500_000_000);
    let mut enclave = h.make_enclave(b"alice_ble", [2u8; 16]);
    enclave.credit_funding(200_000_000).unwrap();
    let merchant_pk = compressed_pk(&signing_key_from_seed(b"merchant_ble"));
    let bundle = enclave
        .issue_voucher(merchant_pk, 25_000_000, h.now, 3600, [3u8; 16])
        .unwrap();

    // Legacy BLE MTU=20 with reversed chunk delivery + duplicate retransmit
    let mut ble20 = BleGattChannel::new(20, 77);
    ble20.reorder_reverse = true;
    ble20.simulate_drop_retransmit = true;
    ble20.send_bundle(&bundle).unwrap();
    assert!(ble20.last_chunk_count() > 20);
    assert_eq!(ble20.receive_bundle().unwrap(), bundle);

    // BLE 5.x MTU=247
    let mut ble247 = BleGattChannel::new(247, 88);
    ble247.send_bundle(&bundle).unwrap();
    assert_eq!(ble247.last_chunk_count(), 2);
    assert_eq!(ble247.receive_bundle().unwrap(), bundle);

    // Bit-flip corruption rejected
    let mut bad_ble = BleGattChannel::new(20, 99);
    bad_ble.corrupt_chunk_byte = Some((1, 8));
    bad_ble.send_bundle(&bundle).unwrap();
    assert!(matches!(
        bad_ble.receive_bundle(),
        Err(VoucherError::WireError(_))
    ));
}

#[test]
fn test_nfc_ndef_single_tap_and_oversize_rejection() {
    let h = Harness::new(500_000_000);
    let mut enclave = h.make_enclave(b"alice_nfc", [3u8; 16]);
    enclave.credit_funding(200_000_000).unwrap();
    let merchant_pk = compressed_pk(&signing_key_from_seed(b"merchant_nfc"));
    let bundle = enclave
        .issue_voucher(merchant_pk, 10_000_000, h.now, 3600, [4u8; 16])
        .unwrap();

    let mut nfc = NfcTapChannel::new();
    let tap_bytes = nfc.send_bundle(&bundle).unwrap();
    assert!(tap_bytes < 512);
    assert_eq!(nfc.receive_bundle().unwrap(), bundle);

    let mut bad_nfc = NfcTapChannel::new();
    bad_nfc.corrupt_byte = Some(20);
    bad_nfc.send_bundle(&bundle).unwrap();
    assert!(matches!(
        bad_nfc.receive_bundle(),
        Err(VoucherError::WireError(_))
    ));

    let oversized = vec![0xAA; MAX_NDEF_PAYLOAD_BYTES + 1];
    assert!(matches!(
        NfcNdefFrame::encode_ndef_record(&oversized),
        Err(VoucherError::WireError(_))
    ));
}

#[test]
fn test_out_of_order_merchant_settlement_and_replay_rejection() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(500_000_000, 1);

    let mut enclave = h.make_enclave(b"alice_ooo", [4u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"alice_rec_ooo"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 400_000_000, 1);
    h.registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(400_000_000).unwrap();

    let m_a_pk = compressed_pk(&signing_key_from_seed(b"merchant_a_ooo"));
    let m_b_pk = compressed_pk(&signing_key_from_seed(b"merchant_b_ooo"));
    let mut wallet_a =
        OfflineMerchantWallet::new(m_a_pk, h.registry.trust_store.clone(), h.policy.clone(), None)
            .unwrap();
    let mut wallet_b =
        OfflineMerchantWallet::new(m_b_pk, h.registry.trust_store.clone(), h.policy.clone(), None)
            .unwrap();

    let b1 = enclave
        .issue_voucher(m_a_pk, 120_000_000, h.now + 10, 7200, [11u8; 16])
        .unwrap();
    let b2 = enclave
        .issue_voucher(m_b_pk, 80_000_000, h.now + 20, 7200, [12u8; 16])
        .unwrap();

    wallet_a.verify_and_accept_offline(&b1, h.now + 15).unwrap();
    wallet_b.verify_and_accept_offline(&b2, h.now + 25).unwrap();

    // Merchant B settles ctr=2 FIRST, Merchant A settles ctr=1 SECOND
    let settle_b = h.build_settle_tx(&b2.voucher, &m_b_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &b2, &settle_b, m_b_pk, h.now + 100)
        .unwrap();

    let settle_a = h.build_settle_tx(&b1.voucher, &m_a_pk, 2);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &b1, &settle_a, m_a_pk, h.now + 110)
        .unwrap();

    // Replay of ctr=1 rejected cleanly
    let replay_a = h.build_settle_tx(&b1.voucher, &m_a_pk, 3);
    assert_eq!(
        h.registry.settle_voucher_to_shielded(
            &mut h.ledger,
            &h.verifier,
            &b1,
            &replay_a,
            m_a_pk,
            h.now + 120
        ),
        Err(VoucherError::VoucherAlreadySettled(1))
    );
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_bounded_multihop_up_to_3_hops_and_4th_hop_rejected() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(300_000_000, 1);
    let mut enclave = h.make_enclave(b"alice_hop", [5u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"alice_rec_hop"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 200_000_000, 1);
    h.registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(200_000_000).unwrap();

    let bob_sk = signing_key_from_seed(b"bob_hop");
    let carol_sk = signing_key_from_seed(b"carol_hop");
    let dave_sk = signing_key_from_seed(b"dave_hop");
    let eve_pk = compressed_pk(&signing_key_from_seed(b"eve_hop"));

    // Hop 1: Alice -> Bob
    let hop1 = enclave
        .issue_voucher(compressed_pk(&bob_sk), 50_000_000, h.now, 7200, [21u8; 16])
        .unwrap();
    // Hop 2: Bob -> Carol
    let hop2 = sign_hop_endorsement(&bob_sk, &hop1, compressed_pk(&carol_sk), h.now + 7200, [22u8; 16])
        .unwrap();
    // Hop 3: Carol -> Dave
    let hop3 = sign_hop_endorsement(&carol_sk, &hop2, compressed_pk(&dave_sk), h.now + 7200, [23u8; 16])
        .unwrap();

    // Merchant with default single-hop policy rejects 3-hop bundle
    assert_eq!(DEFAULT_MERCHANT_MAX_HOPS, 1);
    let mut dave_strict = OfflineMerchantWallet::new(
        compressed_pk(&dave_sk),
        h.registry.trust_store.clone(),
        h.policy.clone(),
        None,
    )
    .unwrap();
    assert!(matches!(
        dave_strict.verify_and_accept_offline(&hop3, h.now + 10),
        Err(VoucherError::HopLimitExceeded { hops: 3, max_hops: 1 })
    ));

    // Merchant opted into 3 hops accepts and settles cleanly
    let mut dave_optin = OfflineMerchantWallet::new(
        compressed_pk(&dave_sk),
        h.registry.trust_store.clone(),
        h.policy.clone(),
        Some(3),
    )
    .unwrap();
    dave_optin.verify_and_accept_offline(&hop3, h.now + 10).unwrap();

    let settle = h.build_settle_tx(&hop3.voucher, &compressed_pk(&dave_sk), 1);
    h.registry
        .settle_voucher_to_shielded(
            &mut h.ledger,
            &h.verifier,
            &hop3,
            &settle,
            compressed_pk(&dave_sk),
            h.now + 20,
        )
        .unwrap();

    // Adding a 4th hop (Dave -> Eve) is blocked by constitutional/policy max_hops_allowed=3
    let hop4 = sign_hop_endorsement(&dave_sk, &hop3, eve_pk, h.now + 7200, [24u8; 16]).unwrap();
    assert!(matches!(
        hop4.verify_hop_chain(&h.policy, 3, h.now + 10),
        Err(VoucherError::HopLimitExceeded { hops: 4, max_hops: 3 })
    ));
}

#[test]
fn test_fib_hardware_rollback_equivocation_revokes_and_caps_damage() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(500_000_000, 1);

    let dev_sk = signing_key_from_seed(b"evil_chip_fib");
    let att = h.ca.issue_attestation(
        compressed_pk(&dev_sk),
        SecurityLevel::StrongBox,
        h.now - 100,
        h.now + 1_000_000,
        [6u8; 16],
    );
    let rec_pk = compressed_pk(&signing_key_from_seed(b"evil_rec"));
    let fund_tx = h.build_fund_tx(&att, 500_000_000, 1);
    let pid = h
        .registry
        .fund_pocket_from_shielded(&mut h.ledger, &h.verifier, &fund_tx, &att, rec_pk, h.now)
        .unwrap();

    // Attacker uses FIB decapsulation + NVRAM rollback at counter 0 -> spends same counter twice!
    let mut evil = CompromisedTestEnclave::from_signing_key(dev_sk, att.clone(), h.policy.chain_id);
    let snap = evil.snapshot();

    let m_a_pk = compressed_pk(&signing_key_from_seed(b"victim_a"));
    let m_c_pk = compressed_pk(&signing_key_from_seed(b"victim_c"));
    let m_d_pk = compressed_pk(&signing_key_from_seed(b"victim_d"));

    let double_a = evil.issue_voucher_unchecked(m_a_pk, 200_000_000, 200_000_000, 1, h.now, 7200, [1u8; 16]);
    evil.rollback(snap);
    let double_c = evil.issue_voucher_unchecked(m_c_pk, 180_000_000, 180_000_000, 1, h.now + 5, 7200, [2u8; 16]);

    // Merchant A settles first
    let settle_a = h.build_settle_tx(&double_a.voucher, &m_a_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &double_a, &settle_a, m_a_pk, h.now + 10)
        .unwrap();

    // Merchant C attempts settlement -> registry catches equivocation on ctr=1, revokes pocket & slashes remaining 300M!
    let settle_c = h.build_settle_tx(&double_c.voucher, &m_c_pk, 2);
    assert_eq!(
        h.registry.settle_voucher_to_shielded(
            &mut h.ledger,
            &h.verifier,
            &double_c,
            &settle_c,
            m_c_pk,
            h.now + 20,
        ),
        Err(VoucherError::EquivocationDetected { counter: 1 })
    );
    assert_eq!(h.registry.pockets[&pid].status, PocketStatus::RevokedCompromised);
    assert_eq!(h.registry.victim_compensation_pool_pm, 300_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);

    // Merchant C claims 180M from slashed victim compensation pool cleanly
    let comp_tx = ShieldTx {
        mint_amount: 180_000_000,
        out_commitment: FieldElement::from(99_001u64),
        tx_binding_hash: FieldElement::from(99_002u64),
        proof: vec![],
    };
    h.registry
        .claim_victim_compensation(&mut h.ledger, &h.verifier, &comp_tx)
        .unwrap();
    assert_eq!(h.registry.victim_compensation_pool_pm, 120_000_000);
    assert_eq!(h.ledger.total_issued_supply, 500_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);

    // Offline Merchant D synced with CRL immediately rejects another voucher from the revoked enclave
    let mut wallet_d =
        OfflineMerchantWallet::new(m_d_pk, AttestationTrustStore::new(), h.policy.clone(), None)
            .unwrap();
    wallet_d.sync_crl(&h.registry.trust_store);
    let rejected_v = evil.issue_voucher_unchecked(m_d_pk, 10_000_000, 190_000_000, 2, h.now + 30, 7200, [3u8; 16]);
    assert_eq!(
        wallet_d.verify_and_accept_offline(&rejected_v, h.now + 35),
        Err(VoucherError::PocketRevoked)
    );
}

#[test]
fn test_offline_equivocation_detection_and_explicit_fraud_proof_submission() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(300_000_000, 1);

    let dev_sk = signing_key_from_seed(b"offline_equiv_chip");
    let att = h.ca.issue_attestation(
        compressed_pk(&dev_sk),
        SecurityLevel::SecureEnclave,
        h.now - 100,
        h.now + 1_000_000,
        [14u8; 16],
    );
    let rec_pk = compressed_pk(&signing_key_from_seed(b"offline_equiv_rec"));
    let fund_tx = h.build_fund_tx(&att, 300_000_000, 1);
    let pid = h
        .registry
        .fund_pocket_from_shielded(&mut h.ledger, &h.verifier, &fund_tx, &att, rec_pk, h.now)
        .unwrap();

    let mut evil = CompromisedTestEnclave::from_signing_key(dev_sk, att, h.policy.chain_id);
    let snap = evil.snapshot();
    let m_pk = compressed_pk(&signing_key_from_seed(b"offline_equiv_merch"));
    let mut wallet =
        OfflineMerchantWallet::new(m_pk, h.registry.trust_store.clone(), h.policy.clone(), None)
            .unwrap();

    let v1 = evil.issue_voucher_unchecked(m_pk, 40_000_000, 40_000_000, 1, h.now, 3600, [1u8; 16]);
    evil.rollback(snap);
    let v2 = evil.issue_voucher_unchecked(m_pk, 40_000_000, 40_000_000, 1, h.now + 2, 3600, [2u8; 16]);

    wallet.verify_and_accept_offline(&v1, h.now + 5).unwrap();
    assert_eq!(
        wallet.verify_and_accept_offline(&v2, h.now + 6),
        Err(VoucherError::EquivocationDetected { counter: 1 })
    );
    assert_eq!(wallet.detected_equivocations.len(), 1);

    let slashed = h
        .registry
        .submit_equivocation_fraud_proof(&wallet.detected_equivocations[0])
        .unwrap();
    assert_eq!(slashed, 300_000_000);
    assert_eq!(h.registry.pockets[&pid].status, PocketStatus::RevokedCompromised);
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_pocket_cap_enforcement_and_compromised_overspend_blocked() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(600_000_000, 1);

    let dev_sk = signing_key_from_seed(b"cap_chip");
    let mut enclave = h.make_enclave(b"cap_chip", [7u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"cap_rec"));
    let m_pk = compressed_pk(&signing_key_from_seed(b"cap_merch"));

    // Funding > 500 PM cap rejected without mutating ledger
    let over_fund = h.build_fund_tx(enclave.attestation(), 500_000_001, 1);
    assert!(matches!(
        h.registry.fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &over_fund,
            enclave.attestation(),
            rec_pk,
            h.now,
        ),
        Err(VoucherError::CapExceeded { .. })
    ));
    assert_eq!(h.ledger.total_shielded_supply, 600_000_000);

    // Fund exact 500 PM cap
    let ok_fund = h.build_fund_tx(enclave.attestation(), 500_000_000, 2);
    h.registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &ok_fund,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(500_000_000).unwrap();

    // Honest enclave refuses spend exceeding funded balance
    assert!(matches!(
        enclave.issue_voucher(m_pk, 500_000_001, h.now, 3600, [1u8; 16]),
        Err(VoucherError::InsufficientPocketBalance { .. })
    ));

    // Compromised enclave emitting 300M (ctr=1) + 300M (ctr=2): ctr=2 cannot inflate past 500M escrow!
    let mut evil = CompromisedTestEnclave::from_signing_key(
        dev_sk,
        enclave.attestation().clone(),
        h.policy.chain_id,
    );
    let b1 = evil.issue_voucher_unchecked(m_pk, 300_000_000, 300_000_000, 1, h.now, 7200, [1u8; 16]);
    let b2_lying_cum =
        evil.issue_voucher_unchecked(m_pk, 300_000_000, 300_000_000, 2, h.now + 5, 7200, [2u8; 16]);

    let s1 = h.build_settle_tx(&b1.voucher, &m_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &b1, &s1, m_pk, h.now + 10)
        .unwrap();

    let s2 = h.build_settle_tx(&b2_lying_cum.voucher, &m_pk, 2);
    assert_eq!(
        h.registry.settle_voucher_to_shielded(
            &mut h.ledger,
            &h.verifier,
            &b2_lying_cum,
            &s2,
            m_pk,
            h.now + 20,
        ),
        Err(VoucherError::InsufficientPocketBalance {
            requested: 300_000_000,
            available: 200_000_000,
        })
    );
    assert_eq!(h.ledger.total_issued_supply, 600_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_high_s_malleability_and_forged_attestation_rejected() {
    let h = Harness::new(500_000_000);
    let mut enclave = h.make_enclave(b"alice_malleate", [8u8; 16]);
    enclave.credit_funding(200_000_000).unwrap();
    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_malleate"));
    let mut wallet =
        OfflineMerchantWallet::new(m_pk, h.registry.trust_store.clone(), h.policy.clone(), None)
            .unwrap();

    let mut bad_bundle = enclave
        .issue_voucher(m_pk, 50_000_000, h.now, 3600, [5u8; 16])
        .unwrap();
    bad_bundle.voucher.sig = malleate_to_high_s(&bad_bundle.voucher.sig).unwrap();
    assert_eq!(
        wallet.verify_and_accept_offline(&bad_bundle, h.now + 10),
        Err(VoucherError::NonCanonicalHighS)
    );

    // Untrusted CA rejected
    let rogue_ca = VendorCa::new("Rogue-CA", signing_key_from_seed(b"rogue_ca"));
    let mut rogue_enclave = SoftwareMockEnclave::new(
        signing_key_from_seed(b"rogue_dev"),
        &rogue_ca,
        SecurityLevel::Fido2Hardware,
        h.policy.clone(),
        h.now - 100,
        h.now + 100_000,
        [9u8; 16],
    )
    .unwrap();
    rogue_enclave.credit_funding(100_000_000).unwrap();
    let rogue_b = rogue_enclave
        .issue_voucher(m_pk, 10_000_000, h.now, 3600, [6u8; 16])
        .unwrap();
    assert!(matches!(
        wallet.verify_and_accept_offline(&rogue_b, h.now + 10),
        Err(VoucherError::UntrustedVendorCa(_))
    ));

    // Expired attestation rejected
    let expired_time = enclave.attestation().expires_at + 1;
    assert_eq!(
        h.registry
            .trust_store
            .verify_attestation(enclave.attestation(), h.policy.chain_id, expired_time),
        Err(VoucherError::AttestationExpired)
    );
}

#[test]
fn test_cooperative_close_instant_unspent_sweep_protects_in_flight_merchants() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(500_000_000, 1);
    let mut enclave = h.make_enclave(b"alice_coop", [10u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"alice_rec_coop"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 500_000_000, 1);
    let pid = h
        .registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(500_000_000).unwrap();

    // Spend 120 PM offline (merchant hasn't come online yet)
    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_coop"));
    let b1 = enclave
        .issue_voucher(m_pk, 120_000_000, h.now + 5, 7200, [7u8; 16])
        .unwrap();

    // Alice cooperatively closes -> immediately sweeps 380 PM unspent, reserving 120 PM for merchant!
    let close_stmt = enclave.cooperative_close(h.now + 10).unwrap();
    assert!(enclave.is_closed());
    let sweep_tx = h.build_reclaim_tx(enclave.attestation(), 380_000_000, 1);
    let swept = h
        .registry
        .cooperative_close_pocket(&mut h.ledger, &h.verifier, &close_stmt, Some(&sweep_tx), h.now + 10)
        .unwrap();
    assert_eq!(swept, 380_000_000);
    assert_eq!(h.registry.pockets[&pid].escrow_balance, 120_000_000);
    assert_eq!(h.ledger.total_shielded_supply, 380_000_000);

    // Merchant settles in-flight 120 PM voucher AFTER cooperative close -> succeeds cleanly!
    let settle_m = h.build_settle_tx(&b1.voucher, &m_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &b1, &settle_m, m_pk, h.now + 100)
        .unwrap();
    assert_eq!(h.registry.pockets[&pid].escrow_balance, 0);
    assert_eq!(h.ledger.total_shielded_supply, 500_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_uncooperative_drain_cooldown_prevents_owner_rug() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(500_000_000, 1);
    let mut enclave = h.make_enclave(b"alice_drain", [11u8; 16]);
    let rec_sk = signing_key_from_seed(b"alice_rec_drain");
    let rec_pk = compressed_pk(&rec_sk);
    let fund_tx = h.build_fund_tx(enclave.attestation(), 500_000_000, 1);
    let pid = h
        .registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(500_000_000).unwrap();

    // Spend 100 PM offline
    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_drain"));
    let b1 = enclave
        .issue_voucher(m_pk, 100_000_000, h.now + 5, DEFAULT_MAX_VOUCHER_TTL_SECS, [8u8; 16])
        .unwrap();

    // Phone lost/unresponsive -> initiate drain via recovery_sk
    let drain_req = sign_uncooperative_drain_request(&rec_sk, h.policy.chain_id, pid, h.now + 60);
    let unlock_at = h
        .registry
        .initiate_uncooperative_drain(&drain_req, h.now + 60)
        .unwrap();

    // Early drain before 7-day cooldown fails!
    let early_tx = h.build_reclaim_tx(enclave.attestation(), 500_000_000, 1);
    assert!(matches!(
        h.registry.finalize_drain(
            &mut h.ledger,
            &h.verifier,
            &pid,
            Some(&early_tx),
            h.now + 10_000
        ),
        Err(VoucherError::DrainCooldownActive { .. })
    ));

    // Offline merchant comes online on day 2 and settles 100 PM safely during cooldown
    let settle_m = h.build_settle_tx(&b1.voucher, &m_pk, 1);
    h.registry
        .settle_voucher_to_shielded(
            &mut h.ledger,
            &h.verifier,
            &b1,
            &settle_m,
            m_pk,
            h.now + 2 * 86_400,
        )
        .unwrap();

    // After 7-day cooldown completes, Alice reclaims only the remaining 400 PM
    let reclaim_tx = h.build_reclaim_tx(enclave.attestation(), 400_000_000, 2);
    let drained = h
        .registry
        .finalize_drain(&mut h.ledger, &h.verifier, &pid, Some(&reclaim_tx), unlock_at)
        .unwrap();
    assert_eq!(drained, 400_000_000);
    assert_eq!(h.ledger.total_pocket_escrow, 0);
    assert_eq!(h.ledger.total_shielded_supply, 500_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_encrypted_mesh_store_and_forward_relay() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(300_000_000, 1);
    let mut enclave = h.make_enclave(b"alice_mesh", [12u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"alice_rec_mesh"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 200_000_000, 1);
    h.registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(200_000_000).unwrap();

    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_mesh"));
    let bundle = enclave
        .issue_voucher(m_pk, 45_000_000, h.now, 7200, [9u8; 16])
        .unwrap();

    let shared_secret = [0x42u8; 32];
    let env = seal_bundle_for_mesh(&bundle, &shared_secret, [0x11u8; 24], h.now, h.now + 7200);
    assert_eq!(env.nonce.len(), 24);
    let raw_bundle = encode_bundle(&bundle);
    assert!(
        !env.ciphertext.windows(raw_bundle.len()).any(|w| w == raw_bundle.as_slice()),
        "mesh ciphertext must not leak plaintext bundle"
    );

    // Tampered ciphertext and tampered AAD metadata fail XChaCha20-Poly1305 authentication
    let mut bad_ct_env = env.clone();
    bad_ct_env.ciphertext[0] ^= 0x01;
    assert!(matches!(
        open_bundle_from_mesh(&bad_ct_env, &shared_secret, h.now + 10),
        Err(VoucherError::TransportError(_))
    ));
    let mut bad_aad_env = env.clone();
    bad_aad_env.expires_at += 1;
    assert!(matches!(
        open_bundle_from_mesh(&bad_aad_env, &shared_secret, h.now + 10),
        Err(VoucherError::TransportError(_))
    ));

    // OS CSPRNG random nonces generate unique ciphertexts/envelope IDs
    let rand_a = seal_bundle_for_mesh_random(&bundle, &shared_secret, h.now, h.now + 7200).unwrap();
    let rand_b = seal_bundle_for_mesh_random(&bundle, &shared_secret, h.now, h.now + 7200).unwrap();
    assert_ne!(rand_a.nonce, rand_b.nonce);
    assert_ne!(rand_a.envelope_id, rand_b.envelope_id);
    assert_eq!(
        open_bundle_from_mesh(&rand_a, &shared_secret, h.now + 10).unwrap(),
        bundle
    );
    assert_eq!(
        open_bundle_from_mesh(&rand_b, &shared_secret, h.now + 10).unwrap(),
        bundle
    );

    let mut relay = EncryptedMeshRelay::new(16);
    assert!(relay.ingest(env.clone(), h.now + 5));
    assert!(!relay.ingest(env.clone(), h.now + 6)); // duplicate suppressed

    let delivered = relay.drain_ready(h.now + 30);
    assert_eq!(delivered.len(), 1);
    let opened = open_bundle_from_mesh(&delivered[0], &shared_secret, h.now + 30).unwrap();
    assert_eq!(opened, bundle);

    let settle = h.build_settle_tx(&opened.voucher, &m_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &opened, &settle, m_pk, h.now + 40)
        .unwrap();
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_ledger_rollback_does_not_leak_escrow_on_failed_shield() {
    let mut h = Harness::new(500_000_000);
    h.shield_seed_funds(200_000_000, 1);
    let mut enclave = h.make_enclave(b"alice_rb", [13u8; 16]);
    let rec_pk = compressed_pk(&signing_key_from_seed(b"rec_rb"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 200_000_000, 1);
    let pid = h
        .registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(200_000_000).unwrap();

    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_rb"));
    let bundle = enclave
        .issue_voucher(m_pk, 50_000_000, h.now, 3600, [13u8; 16])
        .unwrap();
    let bad_verifier = MockVerifier { accept: false };
    let settle = h.build_settle_tx(&bundle.voucher, &m_pk, 1);
    assert!(matches!(
        h.registry.settle_voucher_to_shielded(
            &mut h.ledger,
            &bad_verifier,
            &bundle,
            &settle,
            m_pk,
            h.now + 10,
        ),
        Err(VoucherError::Ledger(LedgerError::InvalidProof(_)))
    ));
    assert_eq!(h.registry.pockets[&pid].escrow_balance, 200_000_000);
    assert_eq!(h.ledger.total_pocket_escrow, 200_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);
}

#[test]
fn test_webauthn_passkey_dual_mode_settlement_and_adversarial_rejections() {
    let mut h = Harness::new(500_000_000);
    h.policy.allowed_webauthn_rp_id = Some("wallet.perfectmoney.local".to_string());
    h.policy.require_webauthn_uv = true;
    h.registry = PocketRegistry::new(h.policy.clone(), h.registry.trust_store.clone()).unwrap();
    h.shield_seed_funds(300_000_000, 1);

    let dev_sk = signing_key_from_seed(b"alice_webauthn_dev");
    let mut enclave = SoftwareMockEnclave::new_webauthn(
        dev_sk,
        &h.ca,
        SecurityLevel::StrongBox,
        h.policy.clone(),
        h.now - 1000,
        h.now + 31_536_000,
        [42u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
    )
    .unwrap();
    let rec_pk = compressed_pk(&signing_key_from_seed(b"alice_webauthn_rec"));
    let fund_tx = h.build_fund_tx(enclave.attestation(), 200_000_000, 1);
    h.registry
        .fund_pocket_from_shielded(
            &mut h.ledger,
            &h.verifier,
            &fund_tx,
            enclave.attestation(),
            rec_pk,
            h.now,
        )
        .unwrap();
    enclave.credit_funding(200_000_000).unwrap();

    let m_pk = compressed_pk(&signing_key_from_seed(b"merch_webauthn"));
    let v1 = enclave
        .issue_voucher(m_pk, 40_000_000, h.now, 7200, [1u8; 16])
        .unwrap();
    let v2 = enclave
        .issue_voucher(m_pk, 60_000_000, h.now + 5, 7200, [2u8; 16])
        .unwrap();
    assert!(v1.webauthn_assertion.is_some());
    assert_eq!(encode_voucher(&v1.voucher).len(), 227);
    assert_eq!(decode_bundle(&encode_bundle(&v1)).unwrap(), v1);

    // Out-of-order offline acceptance & online settlement: ctr=2 (sc=2) first, ctr=1 (sc=1) second
    let mut merchant = OfflineMerchantWallet::new(
        m_pk,
        h.registry.trust_store.clone(),
        h.policy.clone(),
        None,
    )
    .unwrap();
    merchant.verify_and_accept_offline(&v2, h.now + 10).unwrap();
    merchant.verify_and_accept_offline(&v1, h.now + 12).unwrap();

    let settle_2 = h.build_settle_tx(&v2.voucher, &m_pk, 1);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &v2, &settle_2, m_pk, h.now + 15)
        .unwrap();
    let settle_1 = h.build_settle_tx(&v1.voucher, &m_pk, 2);
    h.registry
        .settle_voucher_to_shielded(&mut h.ledger, &h.verifier, &v1, &settle_1, m_pk, h.now + 16)
        .unwrap();

    // Cooperative close with WebAuthn CloseStatement wire roundtrip + settlement
    let close_stmt = enclave.cooperative_close(h.now + 20).unwrap();
    assert!(close_stmt.webauthn_assertion.is_some());
    let close_wire = encode_close_statement(&close_stmt);
    assert_eq!(decode_close_statement(&close_wire).unwrap(), close_stmt);
    let reclaim_tx = h.build_reclaim_tx(enclave.attestation(), 100_000_000, 3);
    let drained = h
        .registry
        .cooperative_close_pocket(
            &mut h.ledger,
            &h.verifier,
            &close_stmt,
            Some(&reclaim_tx),
            h.now + 21,
        )
        .unwrap();
    assert_eq!(drained, 100_000_000);
    h.registry.assert_escrow_conservation(&h.ledger);

    // Adversarial WebAuthn rejections on a second WebAuthn-protected pocket
    let mut h2 = Harness::new(500_000_000);
    h2.policy.allowed_webauthn_rp_id = Some("wallet.perfectmoney.local".to_string());
    h2.policy.require_webauthn_uv = true;
    h2.registry = PocketRegistry::new(h2.policy.clone(), h2.registry.trust_store.clone()).unwrap();
    h2.shield_seed_funds(300_000_000, 1);

    let adv_sk = signing_key_from_seed(b"alice_webauthn_adv");
    let att2 = h2.ca.issue_attestation(
        compressed_pk(&adv_sk),
        SecurityLevel::StrongBox,
        h2.now - 1000,
        h2.now + 31_536_000,
        [43u8; 16],
    );
    let fund2 = h2.build_fund_tx(&att2, 200_000_000, 1);
    let pid2 = h2
        .registry
        .fund_pocket_from_shielded(&mut h2.ledger, &h2.verifier, &fund2, &att2, rec_pk, h2.now)
        .unwrap();

    let mut evil = CompromisedTestEnclave::from_signing_key(adv_sk, att2, h2.policy.chain_id);
    let mut merchant2 = OfflineMerchantWallet::new(
        m_pk,
        h2.registry.trust_store.clone(),
        h2.policy.clone(),
        None,
    )
    .unwrap();

    // Wrong RP ID
    let bad_rp = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        20_000_000,
        20_000_000,
        1,
        h2.now,
        7200,
        [10u8; 16],
        "evil-phish.example",
        "https://evil-phish.example",
        1,
        true,
    );
    assert!(matches!(
        merchant2.verify_and_accept_offline(&bad_rp, h2.now + 5),
        Err(VoucherError::WebAuthnRpIdMismatch)
    ));
    let bad_rp_tx = h2.build_settle_tx(&bad_rp.voucher, &m_pk, 10);
    assert!(matches!(
        h2.registry.settle_voucher_to_shielded(
            &mut h2.ledger,
            &h2.verifier,
            &bad_rp,
            &bad_rp_tx,
            m_pk,
            h2.now + 5
        ),
        Err(VoucherError::WebAuthnRpIdMismatch)
    ));

    // Missing UV flag
    let no_uv = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        20_000_000,
        20_000_000,
        1,
        h2.now,
        7200,
        [11u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
        1,
        false,
    );
    assert!(matches!(
        merchant2.verify_and_accept_offline(&no_uv, h2.now + 5),
        Err(VoucherError::WebAuthnUserVerificationRequired)
    ));

    // Valid ctr=1, sc=5
    let legit_c1 = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        20_000_000,
        20_000_000,
        1,
        h2.now,
        7200,
        [12u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
        5,
        true,
    );

    // Tampered challenge in clientDataJSON
    let mut bad_chal = legit_c1.clone();
    bad_chal.webauthn_assertion.as_mut().unwrap().client_data_json =
        br#"{"type":"webauthn.get","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://wallet.perfectmoney.local","crossOrigin":false}"#.to_vec();
    assert!(matches!(
        merchant2.verify_and_accept_offline(&bad_chal, h2.now + 5),
        Err(VoucherError::WebAuthnChallengeMismatch)
    ));

    // High-S WebAuthn signature malleability
    let mut high_s = legit_c1.clone();
    high_s.voucher.sig = malleate_to_high_s(&high_s.voucher.sig).unwrap();
    assert!(matches!(
        merchant2.verify_and_accept_offline(&high_s, h2.now + 5),
        Err(VoucherError::NonCanonicalHighS)
    ));

    // Accept & settle ctr=1 (sc=5)
    merchant2
        .verify_and_accept_offline(&legit_c1, h2.now + 6)
        .unwrap();
    let s1 = h2.build_settle_tx(&legit_c1.voucher, &m_pk, 11);
    h2.registry
        .settle_voucher_to_shielded(&mut h2.ledger, &h2.verifier, &legit_c1, &s1, m_pk, h2.now + 6)
        .unwrap();

    // Accept & settle ctr=2 (sc=6)
    let legit_c2 = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        30_000_000,
        50_000_000,
        2,
        h2.now + 7,
        7200,
        [13u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
        6,
        true,
    );
    merchant2
        .verify_and_accept_offline(&legit_c2, h2.now + 8)
        .unwrap();
    let s2 = h2.build_settle_tx(&legit_c2.voucher, &m_pk, 12);
    h2.registry
        .settle_voucher_to_shielded(&mut h2.ledger, &h2.verifier, &legit_c2, &s2, m_pk, h2.now + 8)
        .unwrap();

    // signCount regression (repeated sc=6 on ctr=3, lower sc=4 on ctr=3, and sc=0 downgrade)
    for bad_sc in [6u32, 4u32, 0u32] {
        let reg_v = evil.issue_webauthn_voucher_unchecked(
            m_pk,
            10_000_000,
            60_000_000,
            3,
            h2.now + 10,
            7200,
            [14u8 + bad_sc as u8; 16],
            "wallet.perfectmoney.local",
            "https://wallet.perfectmoney.local",
            bad_sc,
            true,
        );
        assert!(matches!(
            merchant2.verify_and_accept_offline(&reg_v, h2.now + 11),
            Err(VoucherError::WebAuthnSignCountRegression { prev: _, got }) if got == bad_sc
        ));
        let reg_tx = h2.build_settle_tx(&reg_v.voucher, &m_pk, 20 + bad_sc as u64);
        assert!(matches!(
            h2.registry.settle_voucher_to_shielded(
                &mut h2.ledger,
                &h2.verifier,
                &reg_v,
                &reg_tx,
                m_pk,
                h2.now + 11
            ),
            Err(VoucherError::WebAuthnSignCountRegression { prev: _, got }) if got == bad_sc
        ));
    }

    // Same-counter WebAuthn equivocation -> offline detection captures both assertions & slashes
    let snap = evil.snapshot();
    let eq_a = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        25_000_000,
        85_000_000,
        4,
        h2.now + 15,
        7200,
        [41u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
        7,
        true,
    );
    evil.rollback(snap);
    let eq_b = evil.issue_webauthn_voucher_unchecked(
        m_pk,
        30_000_000,
        90_000_000,
        4,
        h2.now + 16,
        7200,
        [42u8; 16],
        "wallet.perfectmoney.local",
        "https://wallet.perfectmoney.local",
        8,
        true,
    );
    merchant2
        .verify_and_accept_offline(&eq_a, h2.now + 20)
        .unwrap();
    let eq_err = merchant2
        .verify_and_accept_offline(&eq_b, h2.now + 21)
        .unwrap_err();
    assert!(matches!(
        eq_err,
        VoucherError::EquivocationDetected { counter: 4 }
    ));
    assert_eq!(merchant2.detected_equivocations.len(), 1);
    assert!(merchant2.detected_equivocations[0].webauthn_a.is_some());
    assert!(merchant2.detected_equivocations[0].webauthn_b.is_some());

    let slashed = h2
        .registry
        .submit_equivocation_fraud_proof(&merchant2.detected_equivocations[0])
        .unwrap();
    assert!(slashed > 0);
    assert_eq!(
        h2.registry.pockets[&pid2].status,
        PocketStatus::RevokedCompromised
    );
}

