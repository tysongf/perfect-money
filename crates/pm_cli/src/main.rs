use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use ledger_core::crypto::derive_diversified_address;
use pm_sdk::{
    CircuitProver, ClientWallet, ClosePocketRequest, FundPocketRequest, MockProver, NargoBbProver,
    NodeRpcClient, PaymentAddress, SettleVoucherRequest, ShieldSubmitRequest, ShieldTxDto,
    TransferSubmitRequest, TransferTxDto, UnshieldTxDto, WatchOnlyWallet,
    decode_bundle_transport_bytes, encode_bundle_transport_bytes, field_from_hex, field_to_hex,
    load_encrypted_wallet, save_encrypted_wallet,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProverMode {
    Mock,
    Real,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OfflineChannel {
    Nfc,
    Ble,
}

impl OfflineChannel {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nfc => "nfc",
            Self::Ble => "ble",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "pm-cli", about = "Perfect Money Phase 4 shielded & offline wallet CLI")]
struct Cli {
    #[arg(long, default_value = "./circuits")]
    circuits_dir: PathBuf,
    #[arg(long, default_value = "./target/pm_cli_prover_cache")]
    cache_dir: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        seed: String,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        now: Option<u64>,
    },
    Address {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    Sync {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
    },
    Balance {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
    },
    Faucet {
        #[arg(long)]
        node: String,
        #[arg(long)]
        amount: u64,
    },
    Shield {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value = "shield")]
        memo: String,
        #[arg(long, value_enum, default_value = "real")]
        prover: ProverMode,
    },
    Send {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long, default_value = "payment")]
        memo: String,
        #[arg(long, value_enum, default_value = "real")]
        prover: ProverMode,
    },
    PocketFund {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 0)]
        fee: u64,
        #[arg(long, value_enum, default_value = "real")]
        prover: ProverMode,
        #[arg(long)]
        now: Option<u64>,
    },
    OfflinePay {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        to_pk: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, value_enum, default_value = "nfc")]
        transport: OfflineChannel,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 7200)]
        ttl_secs: u64,
        #[arg(long)]
        now: Option<u64>,
    },
    OfflineReceive {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long = "in")]
        input: PathBuf,
        #[arg(long, value_enum, default_value = "nfc")]
        transport: OfflineChannel,
        #[arg(long)]
        now: Option<u64>,
    },
    OfflineSettle {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
        #[arg(long, value_enum, default_value = "real")]
        prover: ProverMode,
        #[arg(long)]
        now: Option<u64>,
    },
    PocketClose {
        #[arg(long)]
        wallet: PathBuf,
        #[arg(long)]
        passphrase: String,
        #[arg(long)]
        node: String,
        #[arg(long, value_enum, default_value = "real")]
        prover: ProverMode,
        #[arg(long)]
        now: Option<u64>,
    },
}

fn current_now(opt: Option<u64>) -> u64 {
    opt.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(1_700_000_000)
    })
}

fn build_prover(
    mode: ProverMode,
    circuits_dir: &Path,
    cache_dir: &Path,
) -> Result<Box<dyn CircuitProver>> {
    match mode {
        ProverMode::Mock => Ok(Box::new(MockProver)),
        ProverMode::Real => Ok(Box::new(NargoBbProver::new(circuits_dir, cache_dir)?)),
    }
}

fn load_wallet(path: &Path, passphrase: &str) -> Result<ClientWallet> {
    let snap = load_encrypted_wallet(path, passphrase)?;
    ClientWallet::from_snapshot(snap)
}

fn save_wallet(path: &Path, wallet: &ClientWallet, passphrase: &str) -> Result<()> {
    save_encrypted_wallet(path, &wallet.to_snapshot(), passphrase)
}

fn sync_wallet_from_node(wallet: &mut ClientWallet, client: &NodeRpcClient) -> Result<usize> {
    let status = client.status()?;
    let spent: BTreeSet<String> = status.spent_nullifiers_hex.into_iter().collect();
    let outputs = client.chain_outputs(0)?;
    let found = wallet.scan_outputs(&outputs.outputs, &spent);
    let crl = client.crl()?;
    wallet.sync_crl(&crl)?;
    Ok(found)
}

fn parse_pk33(s: &str) -> Result<[u8; 33]> {
    let raw = hex::decode(s.trim())?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("expected 33-byte compressed P-256 public key hex"))
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init {
            wallet,
            passphrase,
            seed,
            node,
            now,
        } => {
            if wallet.exists() {
                bail!("wallet file {} already exists", wallet.display());
            }
            let now_secs = current_now(now);
            let mut w = ClientWallet::new_from_seed(&seed, now_secs)?;
            if let Some(url) = node {
                let client = NodeRpcClient::new(&url);
                sync_wallet_from_node(&mut w, &client)?;
            }
            let addr = w.next_address()?;
            let mpk_hex = hex::encode(w.merchant_public_key());
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "wallet": wallet,
                    "ivk": field_to_hex(w.keys.ivk),
                    "address": addr.encode(),
                    "merchant_pk_hex": mpk_hex,
                    "pocket_id_hex": hex::encode(w.enclave.export_state().attestation.pocket_id(w.policy.chain_id).0),
                }))?
            );
        }
        Commands::Address { wallet, passphrase } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let addr = w.next_address()?;
            let mpk_hex = hex::encode(w.merchant_public_key());
            let _watch_check: WatchOnlyWallet = w.watch_only_ivk()?;
            let _div_check = derive_diversified_address(w.keys.ivk, addr.diversifier)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "address": addr.encode(),
                    "merchant_pk_hex": mpk_hex,
                    "ivk": field_to_hex(w.keys.ivk),
                }))?
            );
        }
        Commands::Sync {
            wallet,
            passphrase,
            node,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            let new_notes = sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "newly_discovered_notes": new_notes,
                    "shielded_balance": w.shielded_balance(),
                    "pocket_balance": w.pocket_balance(),
                    "pending_merchant_balance": w.pending_merchant_balance(),
                }))?
            );
        }
        Commands::Balance { wallet, passphrase } => {
            let w = load_wallet(&wallet, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "shielded_balance": w.shielded_balance(),
                    "pocket_balance": w.pocket_balance(),
                    "pending_merchant_balance": w.pending_merchant_balance(),
                    "unspent_note_count": w.notes.iter().filter(|n| !n.spent).count(),
                }))?
            );
        }
        Commands::Faucet { node, amount } => {
            let client = NodeRpcClient::new(&node);
            let status = client.faucet_mint(amount)?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        Commands::Shield {
            wallet,
            passphrase,
            node,
            amount,
            memo,
            prover,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            let p = build_prover(prover, &cli.circuits_dir, &cli.cache_dir)?;
            let (tx, encrypted_note) = w.build_shield(p.as_ref(), amount, &memo)?;
            let resp = client.submit_shield(&ShieldSubmitRequest {
                tx: ShieldTxDto::from_tx(&tx),
                encrypted_note,
            })?;
            sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::Send {
            wallet,
            passphrase,
            node,
            to,
            amount,
            fee,
            memo,
            prover,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            sync_wallet_from_node(&mut w, &client)?;
            let status = client.status()?;
            let root = field_from_hex(&status.merkle_root_hex)?;
            let recipient = PaymentAddress::decode(&to)?;
            let p = build_prover(prover, &cli.circuits_dir, &cli.cache_dir)?;
            let (tx, encrypted_notes) = w.build_transfer(
                p.as_ref(),
                &recipient,
                amount,
                fee,
                &memo,
                root,
                |leaf_idx| client.merkle_proof(leaf_idx),
            )?;
            let resp = client.submit_transfer(&TransferSubmitRequest {
                tx: TransferTxDto::from_tx(&tx),
                encrypted_notes,
            })?;
            sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::PocketFund {
            wallet,
            passphrase,
            node,
            amount,
            fee,
            prover,
            now,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            sync_wallet_from_node(&mut w, &client)?;
            let status = client.status()?;
            let root = field_from_hex(&status.merkle_root_hex)?;
            let p = build_prover(prover, &cli.circuits_dir, &cli.cache_dir)?;
            let (tx, change_encrypted_note) = w.build_unshield_to_pocket(
                p.as_ref(),
                amount,
                fee,
                root,
                |leaf_idx| client.merkle_proof(leaf_idx),
            )?;
            let resp = client.fund_pocket(&FundPocketRequest {
                tx: UnshieldTxDto::from_tx(&tx),
                change_encrypted_note,
                attestation: w.enclave.export_state().attestation,
                recovery_pk_hex: hex::encode(w.recovery_public_key()),
                now_secs: current_now(now),
            })?;
            offline_vouchers::SecureEnclave::credit_funding(&mut w.enclave, amount)?;
            sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
        Commands::OfflinePay {
            wallet,
            passphrase,
            to_pk,
            amount,
            transport,
            out,
            ttl_secs,
            now,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let recip_pk = parse_pk33(&to_pk)?;
            let bundle = w.issue_offline_payment(recip_pk, amount, current_now(now), ttl_secs)?;
            let wire_bytes = encode_bundle_transport_bytes(&bundle, transport.as_str())?;
            if let Some(parent) = out.parent() {
                if !parent.as_os_str().is_empty() {
                    fs::create_dir_all(parent)?;
                }
            }
            fs::write(&out, &wire_bytes)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "transport": transport.as_str(),
                    "wire_bytes": wire_bytes.len(),
                    "counter": bundle.voucher.counter,
                    "amount": bundle.voucher.amount,
                    "remaining_pocket_balance": w.pocket_balance(),
                    "out_file": out,
                }))?
            );
        }
        Commands::OfflineReceive {
            wallet,
            passphrase,
            input,
            transport,
            now,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let wire_bytes = fs::read(&input)?;
            let bundle = decode_bundle_transport_bytes(&wire_bytes, transport.as_str())?;
            let vhash = w.receive_offline_payment(&bundle, current_now(now))?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "accepted_voucher_hash_hex": hex::encode(vhash),
                    "amount": bundle.voucher.amount,
                    "counter": bundle.voucher.counter,
                    "pending_merchant_balance": w.pending_merchant_balance(),
                }))?
            );
        }
        Commands::OfflineSettle {
            wallet,
            passphrase,
            node,
            prover,
            now,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            let p = build_prover(prover, &cli.circuits_dir, &cli.cache_dir)?;
            let bundles = std::mem::take(&mut w.merchant_wallet.accepted_bundles);
            let mpk_hex = hex::encode(w.merchant_public_key());
            let now_secs = current_now(now);
            let mut settled_leaves = Vec::new();
            let mut unsettled = Vec::new();
            for (idx, b) in bundles.iter().enumerate() {
                match w
                    .build_settle_voucher(p.as_ref(), b)
                    .and_then(|(tx, encrypted_note)| {
                        client.settle_voucher(&SettleVoucherRequest {
                            bundle: b.clone(),
                            tx: ShieldTxDto::from_tx(&tx),
                            encrypted_note,
                            recipient_pk_hex: mpk_hex.clone(),
                            now_secs,
                        })
                    }) {
                    Ok(resp) => settled_leaves.push(resp.leaf_index),
                    Err(e) => {
                        unsettled.extend_from_slice(&bundles[idx..]);
                        w.merchant_wallet.accepted_bundles = unsettled;
                        save_wallet(&wallet, &w, &passphrase)?;
                        return Err(e);
                    }
                }
            }
            sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "settled_count": settled_leaves.len(),
                    "leaf_indices": settled_leaves,
                    "shielded_balance": w.shielded_balance(),
                }))?
            );
        }
        Commands::PocketClose {
            wallet,
            passphrase,
            node,
            prover,
            now,
        } => {
            let mut w = load_wallet(&wallet, &passphrase)?;
            let client = NodeRpcClient::new(&node);
            let p = build_prover(prover, &cli.circuits_dir, &cli.cache_dir)?;
            let now_secs = current_now(now);
            let (close_statement, reclaim_opt) = w.build_cooperative_close(p.as_ref(), now_secs)?;
            let (reclaim_tx, reclaim_encrypted_note) = match reclaim_opt {
                Some((tx, enc)) => (Some(ShieldTxDto::from_tx(&tx)), Some(enc)),
                None => (None, None),
            };
            let resp = client.close_pocket(&ClosePocketRequest {
                close_statement,
                reclaim_tx,
                reclaim_encrypted_note,
                now_secs,
            })?;
            sync_wallet_from_node(&mut w, &client)?;
            save_wallet(&wallet, &w, &passphrase)?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }
    }
    Ok(())
}
