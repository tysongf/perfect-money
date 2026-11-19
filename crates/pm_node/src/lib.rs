use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use acir::FieldElement;
use anyhow::{Result, bail};
use ledger_core::{CircuitKind, LedgerState, ProofVerifier};
use offline_vouchers::{EncryptedMeshRelay, PocketRegistry};
use pm_sdk::{
    ClosePocketRequest, ClosePocketResponse, CrlResponse, FraudProofRequest, FraudProofResponse,
    FundPocketRequest, FundPocketResponse, MerkleProofResponse, MeshDrainResponse, MeshEnvelopeDto,
    MeshRelayResponse, MintRequest, OutputsResponse, PublishedOutput, SettleVoucherRequest,
    ShieldSubmitRequest, ShieldSubmitResponse, StatusResponse, TransferSubmitRequest,
    TransferSubmitResponse, UnshieldSubmitRequest, UnshieldSubmitResponse, default_dev_trust_store,
    dev_default_policy, field_to_hex,
};
use serde::Serialize;

/// Accept-all ProofVerifier strictly for fast non-ZK CLI/harness testing.
#[derive(Debug, Default, Clone, Copy)]
pub struct NodeMockVerifier;

impl ProofVerifier for NodeMockVerifier {
    fn verify_proof(
        &self,
        _kind: CircuitKind,
        _proof: &[u8],
        _public_inputs: &[FieldElement],
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct NodeEngine {
    pub ledger: LedgerState,
    pub registry: PocketRegistry,
    pub mesh_relay: EncryptedMeshRelay,
    pub published_outputs: Vec<PublishedOutput>,
    pub verifier: Box<dyn ProofVerifier + Send + Sync>,
}

impl NodeEngine {
    pub fn new(verifier: Box<dyn ProofVerifier + Send + Sync>) -> Result<Self> {
        let policy = dev_default_policy();
        let trust = default_dev_trust_store();
        let registry = PocketRegistry::new(policy, trust)?;
        Ok(Self {
            ledger: LedgerState::new(),
            registry,
            mesh_relay: EncryptedMeshRelay::new(1024),
            published_outputs: Vec::new(),
            verifier,
        })
    }

    pub fn status(&self) -> StatusResponse {
        let mut nullifiers: Vec<String> = self
            .ledger
            .nullifiers
            .iter()
            .map(|f| field_to_hex(*f))
            .collect();
        nullifiers.sort();
        StatusResponse {
            total_issued_supply: self.ledger.total_issued_supply,
            public_vault_balance: self.ledger.public_vault_balance,
            total_shielded_supply: self.ledger.total_shielded_supply,
            total_pocket_escrow: self.ledger.total_pocket_escrow,
            collected_fees: self.ledger.collected_fees,
            victim_compensation_pool_pm: self.registry.victim_compensation_pool_pm,
            merkle_root_hex: field_to_hex(self.ledger.current_root()),
            leaf_count: self.ledger.merkle_tree.leaf_count(),
            crl_version: self.registry.trust_store.crl_version,
            spent_nullifiers_hex: nullifiers,
        }
    }

    pub fn crl(&self) -> CrlResponse {
        let ts = &self.registry.trust_store;
        CrlResponse {
            vendor_cas: ts
                .vendor_cas
                .iter()
                .map(|(k, v)| (k.clone(), hex::encode(v)))
                .collect(),
            revoked_pockets: ts.revoked_pockets.iter().copied().collect(),
            revoked_certs: ts.revoked_cert_serials.iter().copied().collect(),
            crl_version: ts.crl_version,
        }
    }

    pub fn handle_json_rpc(&mut self, method: &str, raw_path: &str, body: &[u8]) -> (u16, String) {
        match self.dispatch(method, raw_path, body) {
            Ok(json) => (200, json),
            Err(err) => {
                let code = if err.to_string().starts_with("not found:") {
                    404
                } else {
                    400
                };
                let msg = serde_json::json!({ "error": err.to_string() }).to_string();
                (code, msg)
            }
        }
    }

    fn dispatch(&mut self, method: &str, raw_path: &str, body: &[u8]) -> Result<String> {
        let (path, query) = raw_path.split_once('?').unwrap_or((raw_path, ""));

        match (method, path) {
            ("GET", "/health") => to_json(&serde_json::json!({ "ok": true })),
            ("GET", "/v1/status") => to_json(&self.status()),
            ("GET", "/v1/trust/crl") => to_json(&self.crl()),
            ("GET", "/v1/chain/outputs") => {
                let from: u32 = query
                    .split('&')
                    .find_map(|p| p.strip_prefix("from="))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let outputs: Vec<PublishedOutput> = self
                    .published_outputs
                    .iter()
                    .filter(|o| o.leaf_index >= from)
                    .cloned()
                    .collect();
                to_json(&OutputsResponse { outputs })
            }
            ("GET", p) if p.starts_with("/v1/merkle/proof/") => {
                let idx_str = p.trim_start_matches("/v1/merkle/proof/");
                let leaf_index: u32 = idx_str
                    .parse()
                    .map_err(|_| anyhow::anyhow!("invalid leaf_index '{idx_str}'"))?;
                let siblings = self.ledger.merkle_tree.proof(leaf_index)?;
                to_json(&MerkleProofResponse {
                    root_hex: field_to_hex(self.ledger.current_root()),
                    leaf_index,
                    siblings_hex: siblings.into_iter().map(field_to_hex).collect(),
                })
            }
            ("POST", "/v1/faucet/mint") => {
                let req: MintRequest = serde_json::from_slice(body)?;
                self.ledger.mint_vault_supply(req.amount)?;
                to_json(&self.status())
            }
            ("POST", "/v1/tx/shield") => {
                let req: ShieldSubmitRequest = serde_json::from_slice(body)?;
                let tx = req.tx.to_tx()?;
                let leaf_index = self.ledger.apply_shield(&tx, self.verifier.as_ref())?;
                self.published_outputs.push(PublishedOutput {
                    leaf_index,
                    commitment_hex: req.tx.out_commitment_hex,
                    encrypted_note: req.encrypted_note,
                });
                to_json(&ShieldSubmitResponse {
                    leaf_index,
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/tx/transfer") => {
                let req: TransferSubmitRequest = serde_json::from_slice(body)?;
                let tx = req.tx.to_tx()?;
                let [i0, i1] = self.ledger.apply_transfer(&tx, self.verifier.as_ref())?;
                self.published_outputs.push(PublishedOutput {
                    leaf_index: i0,
                    commitment_hex: req.tx.out_commitments_hex[0].clone(),
                    encrypted_note: req.encrypted_notes[0].clone(),
                });
                self.published_outputs.push(PublishedOutput {
                    leaf_index: i1,
                    commitment_hex: req.tx.out_commitments_hex[1].clone(),
                    encrypted_note: req.encrypted_notes[1].clone(),
                });
                to_json(&TransferSubmitResponse {
                    leaf_indices: [i0, i1],
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/tx/unshield") => {
                let req: UnshieldSubmitRequest = serde_json::from_slice(body)?;
                let tx = req.tx.to_tx()?;
                let change_leaf_index = self.ledger.apply_unshield(&tx, self.verifier.as_ref())?;
                if let Some(enc) = req.change_encrypted_note {
                    self.published_outputs.push(PublishedOutput {
                        leaf_index: change_leaf_index,
                        commitment_hex: req.tx.change_commitment_hex,
                        encrypted_note: enc,
                    });
                }
                to_json(&UnshieldSubmitResponse {
                    change_leaf_index,
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/pocket/fund") => {
                let req: FundPocketRequest = serde_json::from_slice(body)?;
                let tx = req.tx.to_tx()?;
                let rec_pk = parse_pk33(&req.recovery_pk_hex)?;
                let next_leaf_idx = self.ledger.merkle_tree.leaf_count() as u32;
                let pocket_id = self.registry.fund_pocket_from_shielded(
                    &mut self.ledger,
                    self.verifier.as_ref(),
                    &tx,
                    &req.attestation,
                    rec_pk,
                    req.now_secs,
                )?;
                if let Some(enc) = req.change_encrypted_note {
                    self.published_outputs.push(PublishedOutput {
                        leaf_index: next_leaf_idx,
                        commitment_hex: req.tx.change_commitment_hex,
                        encrypted_note: enc,
                    });
                }
                to_json(&FundPocketResponse {
                    pocket_id,
                    change_leaf_index: next_leaf_idx,
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/pocket/settle") => {
                let req: SettleVoucherRequest = serde_json::from_slice(body)?;
                let tx = req.tx.to_tx()?;
                let recip_pk = parse_pk33(&req.recipient_pk_hex)?;
                let leaf_index = self.registry.settle_voucher_to_shielded(
                    &mut self.ledger,
                    self.verifier.as_ref(),
                    &req.bundle,
                    &tx,
                    recip_pk,
                    req.now_secs,
                )?;
                self.published_outputs.push(PublishedOutput {
                    leaf_index,
                    commitment_hex: req.tx.out_commitment_hex,
                    encrypted_note: req.encrypted_note,
                });
                to_json(&ShieldSubmitResponse {
                    leaf_index,
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/pocket/close") => {
                let req: ClosePocketRequest = serde_json::from_slice(body)?;
                let reclaim_tx = req.reclaim_tx.as_ref().map(|t| t.to_tx()).transpose()?;
                let expected_leaf = self.ledger.merkle_tree.leaf_count() as u32;
                let reclaimed_amount = self.registry.cooperative_close_pocket(
                    &mut self.ledger,
                    self.verifier.as_ref(),
                    &req.close_statement,
                    reclaim_tx.as_ref(),
                    req.now_secs,
                )?;
                let reclaim_leaf_index = if reclaimed_amount > 0 {
                    if let (Some(tx_dto), Some(enc)) = (req.reclaim_tx, req.reclaim_encrypted_note)
                    {
                        self.published_outputs.push(PublishedOutput {
                            leaf_index: expected_leaf,
                            commitment_hex: tx_dto.out_commitment_hex,
                            encrypted_note: enc,
                        });
                    }
                    Some(expected_leaf)
                } else {
                    None
                };
                to_json(&ClosePocketResponse {
                    reclaimed_amount,
                    reclaim_leaf_index,
                    root_hex: field_to_hex(self.ledger.current_root()),
                })
            }
            ("POST", "/v1/pocket/fraud-proof") => {
                let req: FraudProofRequest = serde_json::from_slice(body)?;
                let slashed_amount = self.registry.submit_equivocation_fraud_proof(&req.proof)?;
                to_json(&FraudProofResponse { slashed_amount })
            }
            ("POST", "/v1/mesh/relay") => {
                let dto: MeshEnvelopeDto = serde_json::from_slice(body)?;
                let env = dto.to_env()?;
                let now = parse_query_u64(query, "now").unwrap_or_else(now_unix_secs);
                let accepted = self.mesh_relay.ingest(env, now);
                to_json(&MeshRelayResponse { accepted })
            }
            ("GET", "/v1/mesh/drain") => {
                let now = parse_query_u64(query, "now").unwrap_or_else(now_unix_secs);
                let envs = self.mesh_relay.drain_ready(now);
                to_json(&MeshDrainResponse {
                    envelopes: envs.iter().map(MeshEnvelopeDto::from_env).collect(),
                })
            }
            _ => bail!("not found: {method} {raw_path}"),
        }
    }
}

fn parse_query_u64(query: &str, key: &str) -> Option<u64> {
    let prefix = format!("{key}=");
    query
        .split('&')
        .find_map(|p| p.strip_prefix(&prefix))
        .and_then(|v| v.parse().ok())
}

fn to_json<T: Serialize>(val: &T) -> Result<String> {
    Ok(serde_json::to_string(val)?)
}

fn parse_pk33(hex_str: &str) -> Result<[u8; 33]> {
    let raw = hex::decode(hex_str)?;
    raw.try_into()
        .map_err(|_| anyhow::anyhow!("expected 33-byte compressed SEC1 pubkey hex"))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(1_700_000_000)
}

pub struct PmNodeServer {
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl PmNodeServer {
    pub fn start(bind_addr: &str, engine: NodeEngine) -> Result<Self> {
        let listener = TcpListener::bind(bind_addr)?;
        listener.set_nonblocking(true)?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Mutex::new(engine));
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);

        let handle = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_http_connection(stream, &shared);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            shutdown,
            handle: Some(handle),
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for PmNodeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn handle_http_connection(mut stream: TcpStream, shared: &Mutex<NodeEngine>) -> Result<()> {
    stream.set_nonblocking(false)?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line)? == 0 {
        return Ok(());
    }
    let mut parts = req_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut content_len = 0usize;
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line)?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_len = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_len];
    if content_len > 0 {
        reader.read_exact(&mut body)?;
    }

    let (status_code, resp_json) = {
        let mut guard = shared.lock().expect("node engine lock");
        guard.handle_json_rpc(&method, &path, &body)
    };
    let status_text = match status_code {
        200 => "OK",
        404 => "Not Found",
        _ => "Bad Request",
    };
    let header = format!(
        "HTTP/1.1 {status_code} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp_json.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(resp_json.as_bytes())?;
    stream.flush()?;
    Ok(())
}
