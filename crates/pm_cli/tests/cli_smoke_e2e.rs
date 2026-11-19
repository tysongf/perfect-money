use std::process::Command;

use pm_node::{NodeEngine, NodeMockVerifier, PmNodeServer};
use pm_sdk::NodeRpcClient;
use tempfile::TempDir;

fn run_cli(args: &[&str]) -> serde_json::Value {
    let bin = env!("CARGO_BIN_EXE_pm-cli");
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("execute pm-cli binary");
    assert!(
        out.status.success(),
        "pm-cli {:?} failed: stderr={}",
        args,
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("valid JSON output from pm-cli")
}

#[test]
fn test_cli_full_wallet_and_airgapped_offline_flow() {
    let engine = NodeEngine::new(Box::new(NodeMockVerifier)).unwrap();
    let mut server = PmNodeServer::start("127.0.0.1:0", engine).unwrap();
    let node_url = server.base_url();

    let dir = TempDir::new().unwrap();
    let alice_w = dir.path().join("alice.pmk");
    let merch_w = dir.path().join("merchant.pmk");
    let nfc_file = dir.path().join("nfc_voucher.bin");
    let ble_file = dir.path().join("ble_voucher.bin");

    let alice_w_s = alice_w.to_str().unwrap();
    let merch_w_s = merch_w.to_str().unwrap();
    let nfc_s = nfc_file.to_str().unwrap();
    let ble_s = ble_file.to_str().unwrap();
    let now_s = "1700000000";

    // 1. Init encrypted wallets
    run_cli(&[
        "init",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--seed",
        "cli-alice",
        "--node",
        &node_url,
        "--now",
        now_s,
    ]);
    let merch_init = run_cli(&[
        "init",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
        "--seed",
        "cli-merch",
        "--node",
        &node_url,
        "--now",
        now_s,
    ]);
    let merch_addr = merch_init["address"].as_str().unwrap().to_string();
    let merch_pk = merch_init["merchant_pk_hex"].as_str().unwrap().to_string();

    // 2. Faucet 500 PM -> Shield -> Send 100 PM (+1 PM fee, 399 PM change) to Merchant
    run_cli(&["faucet", "--node", &node_url, "--amount", "500000000"]);
    run_cli(&[
        "shield",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--node",
        &node_url,
        "--amount",
        "500000000",
        "--memo",
        "payroll",
        "--prover",
        "mock",
    ]);
    run_cli(&[
        "send",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--node",
        &node_url,
        "--to",
        &merch_addr,
        "--amount",
        "100000000",
        "--fee",
        "1000000",
        "--memo",
        "invoice-42",
        "--prover",
        "mock",
    ]);

    // 3. Alice moves 399 PM change into her offline P-256 pocket
    run_cli(&[
        "pocket-fund",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--node",
        &node_url,
        "--amount",
        "399000000",
        "--prover",
        "mock",
        "--now",
        now_s,
    ]);

    // 4. Air-gapped offline payments over NFC & BLE (zero --node flag!)
    run_cli(&[
        "offline-pay",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--to-pk",
        &merch_pk,
        "--amount",
        "50000000",
        "--transport",
        "nfc",
        "--out",
        nfc_s,
        "--now",
        "1700000010",
    ]);
    run_cli(&[
        "offline-pay",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--to-pk",
        &merch_pk,
        "--amount",
        "40000000",
        "--transport",
        "ble",
        "--out",
        ble_s,
        "--now",
        "1700000020",
    ]);

    // 5. Merchant verifies both offline without network
    run_cli(&[
        "offline-receive",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
        "--in",
        nfc_s,
        "--transport",
        "nfc",
        "--now",
        "1700000030",
    ]);
    let rx2 = run_cli(&[
        "offline-receive",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
        "--in",
        ble_s,
        "--transport",
        "ble",
        "--now",
        "1700000040",
    ]);
    assert_eq!(rx2["pending_merchant_balance"].as_u64().unwrap(), 90_000_000);

    // 6. Merchant comes online & settles both offline vouchers; Alice closes & sweeps 309 PM
    run_cli(&[
        "offline-settle",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
        "--node",
        &node_url,
        "--prover",
        "mock",
        "--now",
        "1700000100",
    ]);
    run_cli(&[
        "pocket-close",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
        "--node",
        &node_url,
        "--prover",
        "mock",
        "--now",
        "1700000200",
    ]);

    run_cli(&[
        "sync",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
        "--node",
        &node_url,
    ]);
    let a_bal = run_cli(&[
        "balance",
        "--wallet",
        alice_w_s,
        "--passphrase",
        "alice-pass",
    ]);
    let m_bal = run_cli(&[
        "balance",
        "--wallet",
        merch_w_s,
        "--passphrase",
        "merch-pass",
    ]);
    assert_eq!(a_bal["shielded_balance"].as_u64().unwrap(), 309_000_000);
    assert_eq!(a_bal["pocket_balance"].as_u64().unwrap(), 0);
    assert_eq!(m_bal["shielded_balance"].as_u64().unwrap(), 190_000_000);
    assert_eq!(m_bal["pending_merchant_balance"].as_u64().unwrap(), 0);

    let status = NodeRpcClient::new(&node_url).status().unwrap();
    assert_eq!(status.total_issued_supply, 500_000_000);
    assert_eq!(status.total_shielded_supply, 499_000_000);
    assert_eq!(status.collected_fees, 1_000_000);
    assert_eq!(status.total_pocket_escrow, 0);

    server.stop();
}

