use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use offline_vouchers::{
    BleGattChannel, NfcTapChannel, OfflineTransport, SecureEnclave, open_bundle_from_mesh,
    seal_bundle_for_mesh,
};
use pm_node::{NodeEngine, PmNodeServer};
use pm_sdk::{
    ClientWallet, ClosePocketRequest, FundPocketRequest, NargoBbProver, NodeRpcClient,
    SettleVoucherRequest, ShieldSubmitRequest, ShieldTxDto, TransferSubmitRequest, TransferTxDto,
    UnshieldTxDto, field_from_hex,
};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .to_path_buf()
}

fn sync_all(wallet: &mut ClientWallet, client: &NodeRpcClient) {
    let status = client.status().unwrap();
    let spent: BTreeSet<String> = status.spent_nullifiers_hex.into_iter().collect();
    let outs = client.chain_outputs(0).unwrap();
    wallet.scan_outputs(&outs.outputs, &spent);
    let crl = client.crl().unwrap();
    wallet.sync_crl(&crl).unwrap();
}

#[test]
fn test_e2e_wedge_mvp_real_ultrahonk_online_watch_only_and_offline_mesh() {
    let root = workspace_root();
    let cache_dir = TempDir::new().unwrap();
    let prover = NargoBbProver::new(&root.join("circuits"), cache_dir.path()).unwrap();
    let engine = NodeEngine::new(Box::new(prover.bb_verifier())).unwrap();
    let mut server = PmNodeServer::start("127.0.0.1:0", engine).unwrap();
    let client = NodeRpcClient::new(&server.base_url());

    let now = 1_700_000_000u64;
    let mut alice = ClientWallet::new_from_seed("mvp_alice", now).unwrap();
    let mut bob = ClientWallet::new_from_seed("mvp_bob", now).unwrap();
    let mut merchant = ClientWallet::new_from_seed("mvp_merchant", now).unwrap();

    let mut bob_watch = bob.watch_only_ivk().unwrap();
    let bob_addr = bob.next_address().unwrap();
    let merch_pk = merchant.merchant_public_key();

    // 1. Mint 600 PM -> Alice shields via real circuits/shield proof
    client.faucet_mint(600_000_000).unwrap();
    let (s_tx, s_enc) = alice.build_shield(&prover, 600_000_000, "salary").unwrap();
    client
        .submit_shield(&ShieldSubmitRequest {
            tx: ShieldTxDto::from_tx(&s_tx),
            encrypted_note: s_enc,
        })
        .unwrap();
    sync_all(&mut alice, &client);
    assert_eq!(alice.shielded_balance(), 600_000_000);

    // 2. Alice transfers 100 PM (+ 1 PM fee, 499 PM change) to Bob via real circuits/shielded_transfer
    let status = client.status().unwrap();
    let root_before_xfer = field_from_hex(&status.merkle_root_hex).unwrap();
    let (x_tx, x_encs) = alice
        .build_transfer(
            &prover,
            &bob_addr,
            100_000_000,
            1_000_000,
            "coffee & bread",
            root_before_xfer,
            |leaf| client.merkle_proof(leaf),
        )
        .unwrap();
    client
        .submit_transfer(&TransferSubmitRequest {
            tx: TransferTxDto::from_tx(&x_tx),
            encrypted_notes: x_encs,
        })
        .unwrap();

    sync_all(&mut alice, &client);
    sync_all(&mut bob, &client);
    let outs = client.chain_outputs(0).unwrap();
    let spent_set: BTreeSet<String> = client
        .status()
        .unwrap()
        .spent_nullifiers_hex
        .into_iter()
        .collect();
    bob_watch.scan_outputs(&outs.outputs, &spent_set);

    assert_eq!(alice.shielded_balance(), 499_000_000);
    assert_eq!(bob.shielded_balance(), 100_000_000);
    assert_eq!(bob_watch.unspent_balance(), 100_000_000);
    assert_eq!(bob_watch.notes[0].memo, "coffee & bread");

    // 3. Alice unshields 499 PM via real circuits/unshield into her P-256 pocket enclave
    let status2 = client.status().unwrap();
    let root_before_unshield = field_from_hex(&status2.merkle_root_hex).unwrap();
    let (u_tx, u_chg) = alice
        .build_unshield_to_pocket(
            &prover,
            499_000_000,
            0,
            root_before_unshield,
            |leaf| client.merkle_proof(leaf),
        )
        .unwrap();
    client
        .fund_pocket(&FundPocketRequest {
            tx: UnshieldTxDto::from_tx(&u_tx),
            change_encrypted_note: u_chg,
            attestation: alice.enclave.export_state().attestation,
            recovery_pk_hex: hex::encode(alice.recovery_public_key()),
            now_secs: now,
        })
        .unwrap();
    alice.enclave.credit_funding(499_000_000).unwrap();
    sync_all(&mut alice, &client);
    assert_eq!(alice.shielded_balance(), 0);
    assert_eq!(alice.pocket_balance(), 499_000_000);

    // 4. Offline air-gapped payments: 120 PM over NFC tap, 80 PM over BLE MTU-20 (shuffled + retransmit)
    let v1 = alice
        .issue_offline_payment(merch_pk, 120_000_000, now + 10, 7200)
        .unwrap();
    let v2 = alice
        .issue_offline_payment(merch_pk, 80_000_000, now + 20, 7200)
        .unwrap();

    let mut nfc = NfcTapChannel::new();
    nfc.send_bundle(&v1).unwrap();
    let rx_v1 = nfc.receive_bundle().unwrap();
    merchant.receive_offline_payment(&rx_v1, now + 15).unwrap();

    let mut ble = BleGattChannel::new(20, 11);
    ble.reorder_reverse = true;
    ble.simulate_drop_retransmit = true;
    ble.send_bundle(&v2).unwrap();
    let rx_v2 = ble.receive_bundle().unwrap();
    merchant.receive_offline_payment(&rx_v2, now + 25).unwrap();
    assert_eq!(merchant.pending_merchant_balance(), 200_000_000);

    // 5. Encrypted store-and-forward mesh relay delivers rx_v2 to gateway; out-of-order settle ctr=2 FIRST, ctr=1 SECOND
    let mesh_secret = [0x77u8; 32];
    let env_v2 = seal_bundle_for_mesh(&rx_v2, &mesh_secret, [0x55u8; 16], now + 30, now + 7200);
    let relay_resp = client
        .post_json::<_, pm_sdk::MeshRelayResponse>(
            &format!("/v1/mesh/relay?now={}", now + 35),
            &pm_sdk::MeshEnvelopeDto::from_env(&env_v2),
        )
        .unwrap();
    assert!(relay_resp.accepted);

    let drained = client
        .get_json::<pm_sdk::MeshDrainResponse>(&format!("/v1/mesh/drain?now={}", now + 40))
        .unwrap();
    assert_eq!(drained.envelopes.len(), 1);
    let gw_v2 = open_bundle_from_mesh(
        &drained.envelopes[0].to_env().unwrap(),
        &mesh_secret,
        now + 40,
    )
    .unwrap();

    // Settle ctr=2 (from mesh) via real circuits/shield proof FIRST
    let (s_v2_tx, s_v2_enc) = merchant.build_settle_voucher(&prover, &gw_v2).unwrap();
    client
        .settle_voucher(&SettleVoucherRequest {
            bundle: gw_v2,
            tx: ShieldTxDto::from_tx(&s_v2_tx),
            encrypted_note: s_v2_enc,
            recipient_pk_hex: hex::encode(merch_pk),
            now_secs: now + 50,
        })
        .unwrap();

    // Settle ctr=1 via real circuits/shield proof SECOND
    let (s_v1_tx, s_v1_enc) = merchant.build_settle_voucher(&prover, &rx_v1).unwrap();
    client
        .settle_voucher(&SettleVoucherRequest {
            bundle: rx_v1,
            tx: ShieldTxDto::from_tx(&s_v1_tx),
            encrypted_note: s_v1_enc,
            recipient_pk_hex: hex::encode(merch_pk),
            now_secs: now + 60,
        })
        .unwrap();
    sync_all(&mut merchant, &client);
    assert_eq!(merchant.shielded_balance(), 200_000_000);

    // 6. Alice cooperatively closes her pocket and sweeps remaining 299 PM via real circuits/shield
    let (close_stmt, reclaim_opt) = alice.build_cooperative_close(&prover, now + 100).unwrap();
    let (rec_tx, rec_enc) = reclaim_opt.unwrap();
    let close_resp = client
        .close_pocket(&ClosePocketRequest {
            close_statement: close_stmt,
            reclaim_tx: Some(ShieldTxDto::from_tx(&rec_tx)),
            reclaim_encrypted_note: Some(rec_enc),
            now_secs: now + 100,
        })
        .unwrap();
    assert_eq!(close_resp.reclaimed_amount, 299_000_000);
    sync_all(&mut alice, &client);
    assert_eq!(alice.shielded_balance(), 299_000_000);

    // 7. Strict global conservation across node RPC status
    let final_st = client.status().unwrap();
    assert_eq!(final_st.total_issued_supply, 600_000_000);
    assert_eq!(final_st.total_shielded_supply, 599_000_000);
    assert_eq!(final_st.collected_fees, 1_000_000);
    assert_eq!(final_st.total_pocket_escrow, 0);
    assert_eq!(final_st.public_vault_balance, 0);
    assert_eq!(
        alice.shielded_balance() + bob.shielded_balance() + merchant.shielded_balance(),
        599_000_000
    );

    server.stop();
}

