use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;

use anyhow::{Result, bail};
use ledger_core::{ShieldTx, TransferTx, UnshieldTx};
use offline_vouchers::{
    CloseStatement, EquivocationFraudProof, HardwareAttestation, MeshEnvelope, PocketId,
    VoucherBundle,
};
use serde::{Deserialize, Serialize};

use crate::note_crypto::{EncryptedNote, field_from_hex, field_to_hex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedOutput {
    pub leaf_index: u32,
    pub commitment_hex: String,
    pub encrypted_note: EncryptedNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub total_issued_supply: u128,
    pub public_vault_balance: u128,
    pub total_shielded_supply: u128,
    pub total_pocket_escrow: u128,
    pub collected_fees: u128,
    pub victim_compensation_pool_pm: u128,
    pub merkle_root_hex: String,
    pub leaf_count: u64,
    pub crl_version: u64,
    pub spent_nullifiers_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputsResponse {
    pub outputs: Vec<PublishedOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofResponse {
    pub root_hex: String,
    pub leaf_index: u32,
    pub siblings_hex: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrlResponse {
    pub vendor_cas: Vec<(String, String)>,
    pub revoked_pockets: Vec<PocketId>,
    pub revoked_certs: Vec<[u8; 16]>,
    pub crl_version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintRequest {
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldTxDto {
    pub mint_amount: u64,
    pub out_commitment_hex: String,
    pub tx_binding_hash_hex: String,
    pub proof_hex: String,
}

impl ShieldTxDto {
    pub fn from_tx(tx: &ShieldTx) -> Self {
        Self {
            mint_amount: tx.mint_amount,
            out_commitment_hex: field_to_hex(tx.out_commitment),
            tx_binding_hash_hex: field_to_hex(tx.tx_binding_hash),
            proof_hex: hex::encode(&tx.proof),
        }
    }

    pub fn to_tx(&self) -> Result<ShieldTx> {
        Ok(ShieldTx {
            mint_amount: self.mint_amount,
            out_commitment: field_from_hex(&self.out_commitment_hex)?,
            tx_binding_hash: field_from_hex(&self.tx_binding_hash_hex)?,
            proof: hex::decode(&self.proof_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferTxDto {
    pub merkle_root_hex: String,
    pub nullifiers_hex: [String; 2],
    pub out_commitments_hex: [String; 2],
    pub fee: u64,
    pub tx_binding_hash_hex: String,
    pub proof_hex: String,
}

impl TransferTxDto {
    pub fn from_tx(tx: &TransferTx) -> Self {
        Self {
            merkle_root_hex: field_to_hex(tx.merkle_root),
            nullifiers_hex: [
                field_to_hex(tx.nullifiers[0]),
                field_to_hex(tx.nullifiers[1]),
            ],
            out_commitments_hex: [
                field_to_hex(tx.out_commitments[0]),
                field_to_hex(tx.out_commitments[1]),
            ],
            fee: tx.fee,
            tx_binding_hash_hex: field_to_hex(tx.tx_binding_hash),
            proof_hex: hex::encode(&tx.proof),
        }
    }

    pub fn to_tx(&self) -> Result<TransferTx> {
        Ok(TransferTx {
            merkle_root: field_from_hex(&self.merkle_root_hex)?,
            nullifiers: [
                field_from_hex(&self.nullifiers_hex[0])?,
                field_from_hex(&self.nullifiers_hex[1])?,
            ],
            out_commitments: [
                field_from_hex(&self.out_commitments_hex[0])?,
                field_from_hex(&self.out_commitments_hex[1])?,
            ],
            fee: self.fee,
            tx_binding_hash: field_from_hex(&self.tx_binding_hash_hex)?,
            proof: hex::decode(&self.proof_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshieldTxDto {
    pub merkle_root_hex: String,
    pub nullifier_hex: String,
    pub change_commitment_hex: String,
    pub burn_amount: u64,
    pub fee: u64,
    pub tx_binding_hash_hex: String,
    pub proof_hex: String,
}

impl UnshieldTxDto {
    pub fn from_tx(tx: &UnshieldTx) -> Self {
        Self {
            merkle_root_hex: field_to_hex(tx.merkle_root),
            nullifier_hex: field_to_hex(tx.nullifier),
            change_commitment_hex: field_to_hex(tx.change_commitment),
            burn_amount: tx.burn_amount,
            fee: tx.fee,
            tx_binding_hash_hex: field_to_hex(tx.tx_binding_hash),
            proof_hex: hex::encode(&tx.proof),
        }
    }

    pub fn to_tx(&self) -> Result<UnshieldTx> {
        Ok(UnshieldTx {
            merkle_root: field_from_hex(&self.merkle_root_hex)?,
            nullifier: field_from_hex(&self.nullifier_hex)?,
            change_commitment: field_from_hex(&self.change_commitment_hex)?,
            burn_amount: self.burn_amount,
            fee: self.fee,
            tx_binding_hash: field_from_hex(&self.tx_binding_hash_hex)?,
            proof: hex::decode(&self.proof_hex)?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldSubmitRequest {
    pub tx: ShieldTxDto,
    pub encrypted_note: EncryptedNote,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldSubmitResponse {
    pub leaf_index: u32,
    pub root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSubmitRequest {
    pub tx: TransferTxDto,
    pub encrypted_notes: [EncryptedNote; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferSubmitResponse {
    pub leaf_indices: [u32; 2],
    pub root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshieldSubmitRequest {
    pub tx: UnshieldTxDto,
    pub change_encrypted_note: Option<EncryptedNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshieldSubmitResponse {
    pub change_leaf_index: u32,
    pub root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundPocketRequest {
    pub tx: UnshieldTxDto,
    pub change_encrypted_note: Option<EncryptedNote>,
    pub attestation: HardwareAttestation,
    pub recovery_pk_hex: String,
    pub now_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FundPocketResponse {
    pub pocket_id: PocketId,
    pub change_leaf_index: u32,
    pub root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettleVoucherRequest {
    pub bundle: VoucherBundle,
    pub tx: ShieldTxDto,
    pub encrypted_note: EncryptedNote,
    pub recipient_pk_hex: String,
    pub now_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePocketRequest {
    pub close_statement: CloseStatement,
    pub reclaim_tx: Option<ShieldTxDto>,
    pub reclaim_encrypted_note: Option<EncryptedNote>,
    pub now_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClosePocketResponse {
    pub reclaimed_amount: u64,
    pub reclaim_leaf_index: Option<u32>,
    pub root_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofRequest {
    pub proof: EquivocationFraudProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProofResponse {
    pub slashed_amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshEnvelopeDto {
    pub envelope_id_hex: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub mac_hex: String,
}

impl MeshEnvelopeDto {
    pub fn from_env(env: &MeshEnvelope) -> Self {
        Self {
            envelope_id_hex: hex::encode(env.envelope_id),
            created_at: env.created_at,
            expires_at: env.expires_at,
            nonce_hex: hex::encode(env.nonce),
            ciphertext_hex: hex::encode(&env.ciphertext),
            mac_hex: hex::encode(env.mac),
        }
    }

    pub fn to_env(&self) -> Result<MeshEnvelope> {
        let envelope_id: [u8; 32] = hex::decode(&self.envelope_id_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid envelope_id"))?;
        let nonce: [u8; 16] = hex::decode(&self.nonce_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid nonce"))?;
        let mac: [u8; 32] = hex::decode(&self.mac_hex)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid mac"))?;
        Ok(MeshEnvelope {
            envelope_id,
            created_at: self.created_at,
            expires_at: self.expires_at,
            nonce,
            ciphertext: hex::decode(&self.ciphertext_hex)?,
            mac,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRelayResponse {
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDrainResponse {
    pub envelopes: Vec<MeshEnvelopeDto>,
}

/// Zero-dependency HTTP/1.1 JSON client backed by `std::net::TcpStream`.
#[derive(Debug, Clone)]
pub struct NodeRpcClient {
    host_port: String,
}

impl NodeRpcClient {
    pub fn new(base_url: &str) -> Self {
        let trimmed = base_url
            .trim()
            .trim_start_matches("http://")
            .trim_end_matches('/');
        Self {
            host_port: trimmed.to_string(),
        }
    }

    fn request(&self, method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(&self.host_port)?;
        let payload = body.unwrap_or(&[]);
        let req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            self.host_port,
            payload.len()
        );
        stream.write_all(req.as_bytes())?;
        if !payload.is_empty() {
            stream.write_all(payload)?;
        }
        stream.flush()?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line)?;
        let status_code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("malformed HTTP status line: {status_line}"))?;

        let mut content_len: Option<usize> = None;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line)?;
            if n == 0 || line == "\r\n" || line == "\n" {
                break;
            }
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_len = v.trim().parse().ok();
                }
            }
        }

        let mut resp_body = Vec::new();
        if let Some(len) = content_len {
            resp_body.resize(len, 0);
            reader.read_exact(&mut resp_body)?;
        } else {
            reader.read_to_end(&mut resp_body)?;
        }

        if !(200..300).contains(&status_code) {
            bail!(
                "RPC {method} {path} failed ({status_code}): {}",
                String::from_utf8_lossy(&resp_body)
            );
        }
        Ok(resp_body)
    }

    pub fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let bytes = self.request("GET", path, None)?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn post_json<Req: Serialize, Resp: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp> {
        let body = serde_json::to_vec(req)?;
        let bytes = self.request("POST", path, Some(&body))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn status(&self) -> Result<StatusResponse> {
        self.get_json("/v1/status")
    }

    pub fn chain_outputs(&self, from: u32) -> Result<OutputsResponse> {
        self.get_json(&format!("/v1/chain/outputs?from={from}"))
    }

    pub fn merkle_proof(&self, leaf_index: u32) -> Result<MerkleProofResponse> {
        self.get_json(&format!("/v1/merkle/proof/{leaf_index}"))
    }

    pub fn crl(&self) -> Result<CrlResponse> {
        self.get_json("/v1/trust/crl")
    }

    pub fn faucet_mint(&self, amount: u64) -> Result<StatusResponse> {
        self.post_json("/v1/faucet/mint", &MintRequest { amount })
    }

    pub fn submit_shield(&self, req: &ShieldSubmitRequest) -> Result<ShieldSubmitResponse> {
        self.post_json("/v1/tx/shield", req)
    }

    pub fn submit_transfer(&self, req: &TransferSubmitRequest) -> Result<TransferSubmitResponse> {
        self.post_json("/v1/tx/transfer", req)
    }

    pub fn submit_unshield(&self, req: &UnshieldSubmitRequest) -> Result<UnshieldSubmitResponse> {
        self.post_json("/v1/tx/unshield", req)
    }

    pub fn fund_pocket(&self, req: &FundPocketRequest) -> Result<FundPocketResponse> {
        self.post_json("/v1/pocket/fund", req)
    }

    pub fn settle_voucher(&self, req: &SettleVoucherRequest) -> Result<ShieldSubmitResponse> {
        self.post_json("/v1/pocket/settle", req)
    }

    pub fn close_pocket(&self, req: &ClosePocketRequest) -> Result<ClosePocketResponse> {
        self.post_json("/v1/pocket/close", req)
    }

    pub fn submit_fraud_proof(&self, proof: EquivocationFraudProof) -> Result<FraudProofResponse> {
        self.post_json("/v1/pocket/fraud-proof", &FraudProofRequest { proof })
    }

    pub fn mesh_relay(&self, env: &MeshEnvelope) -> Result<MeshRelayResponse> {
        self.post_json("/v1/mesh/relay", &MeshEnvelopeDto::from_env(env))
    }

    pub fn mesh_drain(&self) -> Result<MeshDrainResponse> {
        self.get_json("/v1/mesh/drain")
    }
}

