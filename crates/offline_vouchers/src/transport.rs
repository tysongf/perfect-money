use std::collections::{BTreeSet, VecDeque};

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroizing;

use crate::crypto::{fill_os_random, sha256_raw};
use crate::error::VoucherError;
use crate::types::VoucherBundle;
use crate::wire::{
    BleChunk, BleReassembler, NfcNdefFrame, ble_fragment, decode_bundle, decode_frame,
    encode_bundle, encode_frame,
};

/// Offline proximity transport delivering canonical VoucherBundles across air-gapped links.
pub trait OfflineTransport {
    fn send_bundle(&mut self, bundle: &VoucherBundle) -> Result<usize, VoucherError>;
    fn receive_bundle(&mut self) -> Result<VoucherBundle, VoucherError>;
}

#[derive(Debug, Default)]
pub struct NfcTapChannel {
    in_flight: Option<Vec<u8>>,
    pub corrupt_byte: Option<usize>,
    pub drop_tap: bool,
    last_wire_bytes: usize,
}

impl NfcTapChannel {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn last_wire_bytes(&self) -> usize {
        self.last_wire_bytes
    }
}

impl OfflineTransport for NfcTapChannel {
    fn send_bundle(&mut self, bundle: &VoucherBundle) -> Result<usize, VoucherError> {
        let framed = encode_frame(&encode_bundle(bundle));
        let mut ndef = NfcNdefFrame::encode_ndef_record(&framed)?;
        self.last_wire_bytes = ndef.len();
        if self.drop_tap {
            self.in_flight = None;
            return Err(VoucherError::TransportError(
                "NFC tap interrupted mid-APDU".to_string(),
            ));
        }
        if let Some(pos) = self.corrupt_byte {
            if pos < ndef.len() {
                ndef[pos] ^= 0xFF;
            }
        }
        let n = ndef.len();
        self.in_flight = Some(ndef);
        Ok(n)
    }

    fn receive_bundle(&mut self) -> Result<VoucherBundle, VoucherError> {
        let ndef = self
            .in_flight
            .take()
            .ok_or_else(|| VoucherError::TransportError("no NFC tap payload pending".to_string()))?;
        let frame = NfcNdefFrame::decode_ndef_record(&ndef)?;
        let payload = decode_frame(&frame)?;
        decode_bundle(&payload)
    }
}

#[derive(Debug)]
pub struct BleGattChannel {
    pub mtu: usize,
    pub session_id: u16,
    pub reorder_reverse: bool,
    pub simulate_drop_retransmit: bool,
    pub corrupt_chunk_byte: Option<(usize, usize)>,
    pending_chunks: Vec<Vec<u8>>,
    last_chunk_count: usize,
    last_wire_bytes: usize,
}

impl BleGattChannel {
    pub fn new(mtu: usize, session_id: u16) -> Self {
        Self {
            mtu,
            session_id,
            reorder_reverse: false,
            simulate_drop_retransmit: false,
            corrupt_chunk_byte: None,
            pending_chunks: Vec::new(),
            last_chunk_count: 0,
            last_wire_bytes: 0,
        }
    }

    pub fn last_chunk_count(&self) -> usize {
        self.last_chunk_count
    }

    pub fn last_wire_bytes(&self) -> usize {
        self.last_wire_bytes
    }
}

impl OfflineTransport for BleGattChannel {
    fn send_bundle(&mut self, bundle: &VoucherBundle) -> Result<usize, VoucherError> {
        let frame = encode_frame(&encode_bundle(bundle));
        self.last_wire_bytes = frame.len();
        let chunks = ble_fragment(self.session_id, &frame, self.mtu)?;
        self.last_chunk_count = chunks.len();
        let mut raw_packets: Vec<Vec<u8>> = chunks.into_iter().map(|c| c.to_bytes()).collect();
        if self.simulate_drop_retransmit && raw_packets.len() > 1 {
            // Simulate packet 0 lost initially and recovered via duplicate retransmission at tail
            let retransmitted = raw_packets[0].clone();
            raw_packets.push(retransmitted);
        }
        if self.reorder_reverse {
            raw_packets.reverse();
        }
        if let Some((cidx, bidx)) = self.corrupt_chunk_byte {
            if cidx < raw_packets.len() && bidx < raw_packets[cidx].len() {
                raw_packets[cidx][bidx] ^= 0x01;
            }
        }
        self.pending_chunks = raw_packets;
        Ok(self.last_wire_bytes)
    }

    fn receive_bundle(&mut self) -> Result<VoucherBundle, VoucherError> {
        let mut reassembler = BleReassembler::new();
        let mut assembled = None;
        for raw in std::mem::take(&mut self.pending_chunks) {
            let chunk = BleChunk::from_bytes(&raw)?;
            if let Some(frame) = reassembler.push(chunk)? {
                assembled = Some(frame);
            }
        }
        let frame = assembled.ok_or_else(|| {
            VoucherError::TransportError("incomplete BLE chunk stream".to_string())
        })?;
        let payload = decode_frame(&frame)?;
        decode_bundle(&payload)
    }
}

/// Opaque XChaCha20-Poly1305 AEAD envelope carried by opportunistically connected mesh couriers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshEnvelope {
    pub envelope_id: [u8; 32],
    pub created_at: u64,
    pub expires_at: u64,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn mesh_aead_key(shared_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(sha256_raw(&[b"PM_MESH_AEAD_KEY_V2|", shared_secret]))
}

fn mesh_aad(created_at: u64, expires_at: u64) -> [u8; 31] {
    let mut aad = [0u8; 31];
    aad[..15].copy_from_slice(b"PM_MESH_AAD_V2|");
    aad[15..23].copy_from_slice(&created_at.to_le_bytes());
    aad[23..31].copy_from_slice(&expires_at.to_le_bytes());
    aad
}

pub fn seal_bundle_for_mesh(
    bundle: &VoucherBundle,
    shared_secret: &[u8; 32],
    nonce: [u8; 24],
    created_at: u64,
    expires_at: u64,
) -> MeshEnvelope {
    let plaintext = Zeroizing::new(encode_frame(&encode_bundle(bundle)));
    let key = mesh_aead_key(shared_secret);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = mesh_aad(created_at, expires_at);
    let ciphertext = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: plaintext.as_ref(),
                aad: &aad,
            },
        )
        .expect("XChaCha20-Poly1305 encryption cannot fail");
    let envelope_id = sha256_raw(&[b"PM_MESH_ID_V2|", &nonce, &ciphertext]);
    MeshEnvelope {
        envelope_id,
        created_at,
        expires_at,
        nonce,
        ciphertext,
    }
}

pub fn seal_bundle_for_mesh_random(
    bundle: &VoucherBundle,
    shared_secret: &[u8; 32],
    created_at: u64,
    expires_at: u64,
) -> Result<MeshEnvelope, VoucherError> {
    let mut nonce = [0u8; 24];
    fill_os_random(&mut nonce)?;
    Ok(seal_bundle_for_mesh(
        bundle,
        shared_secret,
        nonce,
        created_at,
        expires_at,
    ))
}

pub fn open_bundle_from_mesh(
    env: &MeshEnvelope,
    shared_secret: &[u8; 32],
    now_secs: u64,
) -> Result<VoucherBundle, VoucherError> {
    if now_secs > env.expires_at {
        return Err(VoucherError::TransportError(
            "mesh envelope expired".to_string(),
        ));
    }
    let key = mesh_aead_key(shared_secret);
    let cipher = XChaCha20Poly1305::new((&*key).into());
    let aad = mesh_aad(env.created_at, env.expires_at);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                (&env.nonce).into(),
                Payload {
                    msg: env.ciphertext.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| {
                VoucherError::TransportError("mesh envelope authentication failed".to_string())
            })?,
    );
    let payload = decode_frame(&plaintext)?;
    decode_bundle(&payload)
}

/// Opportunistic store-and-forward courier queue that suppresses duplicates and expires stale traffic.
#[derive(Debug)]
pub struct EncryptedMeshRelay {
    max_capacity: usize,
    seen_ids: BTreeSet<[u8; 32]>,
    queue: VecDeque<MeshEnvelope>,
}

impl EncryptedMeshRelay {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            max_capacity: max_capacity.max(1),
            seen_ids: BTreeSet::new(),
            queue: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, env: MeshEnvelope, now_secs: u64) -> bool {
        self.prune_expired(now_secs);
        if env.expires_at < now_secs || !self.seen_ids.insert(env.envelope_id) {
            return false;
        }
        if self.queue.len() == self.max_capacity {
            self.queue.pop_front();
        }
        self.queue.push_back(env);
        true
    }

    pub fn prune_expired(&mut self, now_secs: u64) {
        self.queue.retain(|e| e.expires_at >= now_secs);
    }

    pub fn drain_ready(&mut self, now_secs: u64) -> Vec<MeshEnvelope> {
        self.prune_expired(now_secs);
        self.queue.drain(..).collect()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

