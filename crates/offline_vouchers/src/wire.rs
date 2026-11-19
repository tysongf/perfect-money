use crate::crypto::sha256_raw;
use crate::error::VoucherError;
use crate::types::{
    CloseStatement, HardwareAttestation, HopEndorsement, OfflineVoucher, PocketId, SecurityLevel,
    VOUCHER_FORMAT_VERSION, VoucherBundle, WebAuthnAssertion,
};

pub const FRAME_MAGIC: &[u8; 4] = b"PMV1";
pub const MAX_NDEF_PAYLOAD_BYTES: usize = 4096;
pub const BLE_MIN_MTU: usize = 12;

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], VoucherError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| VoucherError::WireError("length overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(VoucherError::WireError("unexpected EOF".to_string()));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_u8(&mut self) -> Result<u8, VoucherError> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, VoucherError> {
        let mut arr = [0u8; 2];
        arr.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64, VoucherError> {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(arr))
    }

    fn read_vec_u16(&mut self) -> Result<Vec<u8>, VoucherError> {
        let n = self.read_u16()? as usize;
        Ok(self.take(n)?.to_vec())
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], VoucherError> {
        let mut arr = [0u8; N];
        arr.copy_from_slice(self.take(N)?);
        Ok(arr)
    }

    fn finish(self) -> Result<(), VoucherError> {
        if self.pos != self.buf.len() {
            return Err(VoucherError::WireError("trailing bytes".to_string()));
        }
        Ok(())
    }
}

pub fn encode_voucher(v: &OfflineVoucher) -> Vec<u8> {
    let mut out = Vec::with_capacity(OfflineVoucher::WIRE_SIZE);
    out.extend_from_slice(&v.signing_bytes());
    out.extend_from_slice(&v.sig);
    debug_assert_eq!(out.len(), OfflineVoucher::WIRE_SIZE);
    out
}

pub fn decode_voucher(bytes: &[u8]) -> Result<OfflineVoucher, VoucherError> {
    let mut r = ByteReader::new(bytes);
    let v = decode_voucher_inner(&mut r)?;
    r.finish()?;
    Ok(v)
}

fn decode_voucher_inner(r: &mut ByteReader<'_>) -> Result<OfflineVoucher, VoucherError> {
    let version = r.read_u16()?;
    if version != VOUCHER_FORMAT_VERSION {
        return Err(VoucherError::InvalidVersion(version));
    }
    Ok(OfflineVoucher {
        version,
        chain_id: r.read_u64()?,
        pocket_id: PocketId(r.read_array::<32>()?),
        counter: r.read_u64()?,
        amount: r.read_u64()?,
        cumulative_spent: r.read_u64()?,
        recipient_pk: r.read_array::<33>()?,
        prev_voucher_hash: r.read_array::<32>()?,
        issued_at: r.read_u64()?,
        expires_at: r.read_u64()?,
        nonce: r.read_array::<16>()?,
        sig: r.read_array::<64>()?,
    })
}

pub fn encode_attestation(att: &HardwareAttestation) -> Vec<u8> {
    let mut out = att.signing_bytes();
    out.extend_from_slice(&att.ca_sig);
    out
}

pub fn decode_attestation(bytes: &[u8]) -> Result<HardwareAttestation, VoucherError> {
    let mut r = ByteReader::new(bytes);
    let att = decode_attestation_inner(&mut r)?;
    r.finish()?;
    Ok(att)
}

fn decode_attestation_inner(r: &mut ByteReader<'_>) -> Result<HardwareAttestation, VoucherError> {
    let vlen = r.read_u16()? as usize;
    let vendor_raw = r.take(vlen)?;
    let vendor_id = std::str::from_utf8(vendor_raw)
        .map_err(|_| VoucherError::WireError("invalid vendor_id utf-8".to_string()))?
        .to_string();
    Ok(HardwareAttestation {
        vendor_id,
        device_pk: r.read_array::<33>()?,
        security_level: SecurityLevel::from_u8(r.read_u8()?)?,
        issued_at: r.read_u64()?,
        expires_at: r.read_u64()?,
        cert_serial: r.read_array::<16>()?,
        ca_sig: r.read_array::<64>()?,
    })
}

pub fn encode_hop(hop: &HopEndorsement) -> Vec<u8> {
    let mut out = Vec::with_capacity(HopEndorsement::WIRE_SIZE);
    out.extend_from_slice(&hop.signing_bytes());
    out.extend_from_slice(&hop.sig);
    debug_assert_eq!(out.len(), HopEndorsement::WIRE_SIZE);
    out
}

pub fn decode_hop(bytes: &[u8]) -> Result<HopEndorsement, VoucherError> {
    let mut r = ByteReader::new(bytes);
    let h = decode_hop_inner(&mut r)?;
    r.finish()?;
    Ok(h)
}

fn decode_hop_inner(r: &mut ByteReader<'_>) -> Result<HopEndorsement, VoucherError> {
    Ok(HopEndorsement {
        voucher_hash: r.read_array::<32>()?,
        hop_index: r.read_u8()?,
        from_pk: r.read_array::<33>()?,
        to_pk: r.read_array::<33>()?,
        expires_at: r.read_u64()?,
        nonce: r.read_array::<16>()?,
        sig: r.read_array::<64>()?,
    })
}

fn encode_optional_webauthn(wa_opt: Option<&WebAuthnAssertion>, out: &mut Vec<u8>) {
    match wa_opt {
        None => out.push(0),
        Some(wa) => {
            out.push(1);
            out.extend_from_slice(&(wa.authenticator_data.len() as u16).to_le_bytes());
            out.extend_from_slice(&wa.authenticator_data);
            out.extend_from_slice(&(wa.client_data_json.len() as u16).to_le_bytes());
            out.extend_from_slice(&wa.client_data_json);
        }
    }
}

fn decode_optional_webauthn(r: &mut ByteReader<'_>) -> Result<Option<WebAuthnAssertion>, VoucherError> {
    match r.read_u8()? {
        0 => Ok(None),
        1 => {
            let authenticator_data = r.read_vec_u16()?;
            let client_data_json = r.read_vec_u16()?;
            Ok(Some(WebAuthnAssertion {
                authenticator_data,
                client_data_json,
            }))
        }
        other => Err(VoucherError::WireError(format!(
            "invalid webauthn flag {other}"
        ))),
    }
}

pub fn encode_bundle(bundle: &VoucherBundle) -> Vec<u8> {
    let v = encode_voucher(&bundle.voucher);
    let att = encode_attestation(&bundle.attestation);
    let extra = bundle
        .webauthn_assertion
        .as_ref()
        .map(|w| 4 + w.authenticator_data.len() + w.client_data_json.len())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(
        v.len() + att.len() + 2 + bundle.hops.len() * HopEndorsement::WIRE_SIZE + extra,
    );
    out.extend_from_slice(&v);
    out.extend_from_slice(&att);
    out.push(bundle.hops.len() as u8);
    for hop in &bundle.hops {
        out.extend_from_slice(&encode_hop(hop));
    }
    encode_optional_webauthn(bundle.webauthn_assertion.as_ref(), &mut out);
    out
}

pub fn decode_bundle(bytes: &[u8]) -> Result<VoucherBundle, VoucherError> {
    let mut r = ByteReader::new(bytes);
    let voucher = decode_voucher_inner(&mut r)?;
    let attestation = decode_attestation_inner(&mut r)?;
    let hop_count = r.read_u8()? as usize;
    let mut hops = Vec::with_capacity(hop_count);
    for _ in 0..hop_count {
        hops.push(decode_hop_inner(&mut r)?);
    }
    let webauthn_assertion = decode_optional_webauthn(&mut r)?;
    r.finish()?;
    Ok(VoucherBundle {
        voucher,
        attestation,
        hops,
        webauthn_assertion,
    })
}

pub fn encode_close_statement(stmt: &CloseStatement) -> Vec<u8> {
    let extra = stmt
        .webauthn_assertion
        .as_ref()
        .map(|w| 4 + w.authenticator_data.len() + w.client_data_json.len())
        .unwrap_or(0);
    let mut out = Vec::with_capacity(CloseStatement::WIRE_SIZE + 1 + extra);
    out.extend_from_slice(&stmt.signing_bytes());
    out.extend_from_slice(&stmt.sig);
    encode_optional_webauthn(stmt.webauthn_assertion.as_ref(), &mut out);
    out
}

pub fn decode_close_statement(bytes: &[u8]) -> Result<CloseStatement, VoucherError> {
    let mut r = ByteReader::new(bytes);
    let chain_id = r.read_u64()?;
    let pocket_id = PocketId(r.read_array::<32>()?);
    let final_counter = r.read_u64()?;
    let final_cumulative_spent = r.read_u64()?;
    let closed_at = r.read_u64()?;
    let sig = r.read_array::<64>()?;
    let webauthn_assertion = if r.pos == r.buf.len() {
        None
    } else {
        decode_optional_webauthn(&mut r)?
    };
    r.finish()?;
    Ok(CloseStatement {
        chain_id,
        pocket_id,
        final_counter,
        final_cumulative_spent,
        closed_at,
        sig,
        webauthn_assertion,
    })
}

/// Frames an arbitrary canonical payload as `PMV1 || len_u32_le || payload || sha256_tag[0..4]`.
pub fn encode_frame(payload: &[u8]) -> Vec<u8> {
    let len_bytes = (payload.len() as u32).to_le_bytes();
    let tag = sha256_raw(&[FRAME_MAGIC, &len_bytes, payload]);
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&len_bytes);
    out.extend_from_slice(payload);
    out.extend_from_slice(&tag[..4]);
    out
}

pub fn decode_frame(frame: &[u8]) -> Result<Vec<u8>, VoucherError> {
    if frame.len() < 12 {
        return Err(VoucherError::WireError("frame shorter than header".to_string()));
    }
    if &frame[..4] != FRAME_MAGIC {
        return Err(VoucherError::WireError("invalid PMV1 frame magic".to_string()));
    }
    let mut len_arr = [0u8; 4];
    len_arr.copy_from_slice(&frame[4..8]);
    let plen = u32::from_le_bytes(len_arr) as usize;
    if frame.len() != 12 + plen {
        return Err(VoucherError::WireError("frame length mismatch".to_string()));
    }
    let payload = &frame[8..8 + plen];
    let expected = sha256_raw(&[FRAME_MAGIC, &len_arr, payload]);
    if frame[8 + plen..] != expected[..4] {
        return Err(VoucherError::WireError("frame checksum mismatch".to_string()));
    }
    Ok(payload.to_vec())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleChunk {
    pub session_id: u16,
    pub seq: u16,
    pub total: u16,
    pub data: Vec<u8>,
}

impl BleChunk {
    pub const HEADER_SIZE: usize = 6;

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_SIZE + self.data.len());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, VoucherError> {
        if raw.len() <= Self::HEADER_SIZE {
            return Err(VoucherError::WireError("empty or truncated BLE chunk".to_string()));
        }
        let session_id = u16::from_le_bytes([raw[0], raw[1]]);
        let seq = u16::from_le_bytes([raw[2], raw[3]]);
        let total = u16::from_le_bytes([raw[4], raw[5]]);
        if total == 0 || seq >= total {
            return Err(VoucherError::WireError("invalid BLE chunk index".to_string()));
        }
        Ok(Self {
            session_id,
            seq,
            total,
            data: raw[Self::HEADER_SIZE..].to_vec(),
        })
    }
}

pub fn ble_fragment(session_id: u16, frame: &[u8], mtu: usize) -> Result<Vec<BleChunk>, VoucherError> {
    if mtu < BLE_MIN_MTU {
        return Err(VoucherError::WireError(format!(
            "BLE MTU {mtu} below minimum {BLE_MIN_MTU}"
        )));
    }
    if frame.is_empty() {
        return Err(VoucherError::WireError("cannot fragment empty frame".to_string()));
    }
    let chunk_cap = mtu - BleChunk::HEADER_SIZE;
    let slices: Vec<&[u8]> = frame.chunks(chunk_cap).collect();
    let total = u16::try_from(slices.len())
        .map_err(|_| VoucherError::WireError("BLE chunk count overflow".to_string()))?;
    Ok(slices
        .into_iter()
        .enumerate()
        .map(|(i, s)| BleChunk {
            session_id,
            seq: i as u16,
            total,
            data: s.to_vec(),
        })
        .collect())
}

#[derive(Debug, Default)]
pub struct BleReassembler {
    session_id: Option<u16>,
    total: Option<u16>,
    parts: std::collections::BTreeMap<u16, Vec<u8>>,
}

impl BleReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, chunk: BleChunk) -> Result<Option<Vec<u8>>, VoucherError> {
        if chunk.total == 0 || chunk.seq >= chunk.total || chunk.data.is_empty() {
            return Err(VoucherError::WireError("malformed BLE chunk".to_string()));
        }
        match (self.session_id, self.total) {
            (Some(sid), Some(tot)) if sid != chunk.session_id || tot != chunk.total => {
                return Err(VoucherError::WireError(
                    "BLE chunk session/total mismatch".to_string(),
                ));
            }
            (None, None) => {
                self.session_id = Some(chunk.session_id);
                self.total = Some(chunk.total);
            }
            _ => {}
        }
        self.parts.entry(chunk.seq).or_insert(chunk.data);
        let tot = self.total.unwrap();
        if self.parts.len() == tot as usize {
            let mut full = Vec::new();
            for idx in 0..tot {
                let slice = self
                    .parts
                    .get(&idx)
                    .ok_or_else(|| VoucherError::WireError("missing BLE chunk".to_string()))?;
                full.extend_from_slice(slice);
            }
            return Ok(Some(full));
        }
        Ok(None)
    }
}

/// Compact NFC NDEF external-type record (`TNF=0x04`, type `"pm:v1"`).
pub struct NfcNdefFrame;

impl NfcNdefFrame {
    const RECORD_HEADER: u8 = 0xD4; // MB=1, ME=1, SR=1 (or 0xC4 when long), TNF=0x04
    const SHORT_MASK: u8 = 0x10;
    const TYPE_BYTES: &'static [u8] = b"pm:v1";

    pub fn encode_ndef_record(frame: &[u8]) -> Result<Vec<u8>, VoucherError> {
        if frame.is_empty() || frame.len() > MAX_NDEF_PAYLOAD_BYTES {
            return Err(VoucherError::WireError(format!(
                "NFC NDEF payload size {} outside 1..={MAX_NDEF_PAYLOAD_BYTES}",
                frame.len()
            )));
        }
        let tlen = Self::TYPE_BYTES.len() as u8;
        if frame.len() <= u8::MAX as usize {
            let mut out = Vec::with_capacity(3 + Self::TYPE_BYTES.len() + frame.len());
            out.push(Self::RECORD_HEADER);
            out.push(tlen);
            out.push(frame.len() as u8);
            out.extend_from_slice(Self::TYPE_BYTES);
            out.extend_from_slice(frame);
            Ok(out)
        } else {
            let mut out = Vec::with_capacity(6 + Self::TYPE_BYTES.len() + frame.len());
            out.push(Self::RECORD_HEADER & !Self::SHORT_MASK);
            out.push(tlen);
            out.extend_from_slice(&(frame.len() as u32).to_be_bytes());
            out.extend_from_slice(Self::TYPE_BYTES);
            out.extend_from_slice(frame);
            Ok(out)
        }
    }

    pub fn decode_ndef_record(raw: &[u8]) -> Result<Vec<u8>, VoucherError> {
        if raw.len() < 4 {
            return Err(VoucherError::WireError("truncated NDEF record".to_string()));
        }
        let header = raw[0];
        if header & 0x07 != 0x04 {
            return Err(VoucherError::WireError("unexpected NDEF TNF".to_string()));
        }
        let is_short = (header & Self::SHORT_MASK) != 0;
        let tlen = raw[1] as usize;
        let (plen, idx) = if is_short {
            (raw[2] as usize, 3usize)
        } else {
            if raw.len() < 7 {
                return Err(VoucherError::WireError("truncated long NDEF header".to_string()));
            }
            let plen = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]) as usize;
            (plen, 6usize)
        };
        if plen > MAX_NDEF_PAYLOAD_BYTES || raw.len() != idx + tlen + plen {
            return Err(VoucherError::WireError("NDEF length mismatch".to_string()));
        }
        if &raw[idx..idx + tlen] != Self::TYPE_BYTES {
            return Err(VoucherError::WireError("unexpected NDEF type".to_string()));
        }
        Ok(raw[idx + tlen..].to_vec())
    }
}

