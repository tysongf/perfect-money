use std::collections::BTreeSet;

use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use ledger_core::{
    MERKLE_DEPTH, Note, ShieldTx, TransferTx, UnshieldTx, WalletKeys, compute_note_commitment,
    compute_nullifier, derive_diversified_address,
};
use offline_vouchers::{
    AttestationTrustStore, BleGattChannel, CloseStatement, DEFAULT_MAX_CLOCK_SKEW_SECS,
    DEFAULT_MAX_HOPS_ALLOWED, DEFAULT_MAX_POCKET_BALANCE, DEFAULT_MAX_VOUCHER_TTL_SECS,
    DEFAULT_MERCHANT_MAX_HOPS, NfcTapChannel, OfflineMerchantWallet, OfflineTransport,
    PocketPolicy, SecurityLevel, SoftwareMockEnclave, VendorCa, VoucherBundle,
    compressed_pk, compute_pocket_fund_binding_hash, compute_pocket_reclaim_binding_hash,
    compute_voucher_settle_binding_hash, decode_bundle, decode_frame, encode_bundle, encode_frame,
    sign_hop_endorsement, signing_key_from_seed, SecureEnclave,
};
use p256::ecdsa::SigningKey;
use sha2::{Digest, Sha256};

use crate::address::PaymentAddress;
use crate::keystore::{OwnedNoteRecord, WalletSnapshot};
use crate::note_crypto::{
    EncryptedNote, compute_shield_tx_binding_hash, compute_transfer_tx_binding_hash,
    encrypt_note, field_from_hex, field_to_hex, try_decrypt_note,
};
use crate::prover::{CircuitProver, TransferWitnessRequest, UnshieldWitnessRequest};
use crate::rpc_types::{CrlResponse, MerkleProofResponse, PublishedOutput};

pub const DEFAULT_DEV_VENDOR_ID: &str = "PerfectMoney-DevCA-V1";

pub fn dev_vendor_ca() -> VendorCa {
    VendorCa::new(
        DEFAULT_DEV_VENDOR_ID,
        signing_key_from_seed(b"pm_dev_vendor_ca_v1"),
    )
}

pub fn default_dev_trust_store() -> AttestationTrustStore {
    let ca = dev_vendor_ca();
    let mut store = AttestationTrustStore::new();
    store
        .register_ca(&ca.vendor_id, ca.public_key())
        .expect("dev CA pubkey is valid");
    store
}

pub fn dev_default_policy() -> PocketPolicy {
    PocketPolicy {
        chain_id: 1,
        max_pocket_balance: DEFAULT_MAX_POCKET_BALANCE,
        constitutional_hard_cap: offline_vouchers::CONSTITUTIONAL_HARD_CAP,
        max_voucher_ttl_secs: DEFAULT_MAX_VOUCHER_TTL_SECS,
        uncooperative_drain_delay_secs: DEFAULT_MAX_VOUCHER_TTL_SECS,
        max_clock_skew_secs: DEFAULT_MAX_CLOCK_SKEW_SECS,
        max_hops_allowed: DEFAULT_MAX_HOPS_ALLOWED,
        default_merchant_max_hops: DEFAULT_MERCHANT_MAX_HOPS,
    }
}

fn derive_nonzero_field(seed_parts: &[&[u8]]) -> FieldElement {
    let mut counter: u64 = 0;
    loop {
        let mut h = Sha256::new();
        for p in seed_parts {
            h.update(p);
        }
        h.update(counter.to_le_bytes());
        let digest: [u8; 32] = h.finalize().into();
        let f = FieldElement::from_be_bytes_reduce(&digest);
        if !f.is_zero() {
            return f;
        }
        counter += 1;
    }
}

fn scan_outputs_inner(
    ivk: FieldElement,
    nk: Option<FieldElement>,
    notes: &mut Vec<OwnedNoteRecord>,
    outputs: &[PublishedOutput],
    spent_nullifiers: &BTreeSet<String>,
) -> usize {
    let mut known_leaves: BTreeSet<u32> = notes.iter().map(|n| n.leaf_index).collect();
    let mut newly_found = 0usize;

    for out in outputs {
        if known_leaves.contains(&out.leaf_index) {
            continue;
        }
        let Ok(cm) = field_from_hex(&out.commitment_hex) else {
            continue;
        };
        let Some(dec) = try_decrypt_note(ivk, cm, &out.encrypted_note) else {
            continue;
        };
        if dec.note.value == 0 {
            continue;
        }
        let nf_hex = match nk {
            Some(k) => field_to_hex(compute_nullifier(k, cm, out.leaf_index)),
            None => "0x0".to_string(),
        };
        let spent = nk.is_some() && spent_nullifiers.contains(&nf_hex);
        notes.push(OwnedNoteRecord {
            leaf_index: out.leaf_index,
            value: dec.note.value,
            owner_pk_x_hex: field_to_hex(dec.note.owner_pk_x),
            owner_pk_y_hex: field_to_hex(dec.note.owner_pk_y),
            blinding_hex: field_to_hex(dec.note.blinding),
            diversifier_hex: field_to_hex(dec.diversifier),
            g_d_nonce: dec.nonce,
            g_d_y_hex: field_to_hex(dec.g_d_y),
            commitment_hex: out.commitment_hex.clone(),
            nullifier_hex: nf_hex,
            memo: dec.memo,
            spent,
        });
        known_leaves.insert(out.leaf_index);
        newly_found += 1;
    }

    if nk.is_some() {
        for rec in notes.iter_mut() {
            if spent_nullifiers.contains(&rec.nullifier_hex) {
                rec.spent = true;
            }
        }
    }

    newly_found
}

/// Incoming-view or full-view watch-only wallet (never holds `ask` spend key).
#[derive(Debug, Clone)]
pub struct WatchOnlyWallet {
    pub ivk: FieldElement,
    pub nk: Option<FieldElement>,
    pub next_diversifier: u64,
    pub notes: Vec<OwnedNoteRecord>,
}

impl WatchOnlyWallet {
    pub fn from_ivk(ivk: FieldElement) -> Result<Self> {
        if ivk.is_zero() {
            bail!("ivk cannot be zero");
        }
        Ok(Self {
            ivk,
            nk: None,
            next_diversifier: 1,
            notes: Vec::new(),
        })
    }

    pub fn from_fvk(ivk: FieldElement, nk: FieldElement) -> Result<Self> {
        if ivk.is_zero() || nk.is_zero() {
            bail!("ivk and nk must be non-zero");
        }
        Ok(Self {
            ivk,
            nk: Some(nk),
            next_diversifier: 1,
            notes: Vec::new(),
        })
    }

    pub fn next_address(&mut self) -> Result<PaymentAddress> {
        let div = FieldElement::from(self.next_diversifier);
        self.next_diversifier += 1;
        let addr = derive_diversified_address(self.ivk, div)?;
        Ok(PaymentAddress::from_diversified(addr))
    }

    pub fn scan_outputs(
        &mut self,
        outputs: &[PublishedOutput],
        spent_nullifiers: &BTreeSet<String>,
    ) -> usize {
        scan_outputs_inner(self.ivk, self.nk, &mut self.notes, outputs, spent_nullifiers)
    }

    pub fn unspent_balance(&self) -> u64 {
        self.notes.iter().filter(|n| !n.spent).map(|n| n.value).sum()
    }
}

/// Full Phase 1 + Phase 3 client wallet owning shielded spend authority and an offline P-256 enclave.
pub struct ClientWallet {
    pub keys: WalletKeys,
    pub next_diversifier: u64,
    pub notes: Vec<OwnedNoteRecord>,
    pub enclave: SoftwareMockEnclave,
    pub recovery_sk: SigningKey,
    pub merchant_sk: SigningKey,
    pub merchant_wallet: OfflineMerchantWallet,
    pub policy: PocketPolicy,
}

impl ClientWallet {
    pub fn new_from_seed(seed_tag: &str, cert_now_secs: u64) -> Result<Self> {
        let ask = derive_nonzero_field(&[b"PM_WALLET_ASK_V1|", seed_tag.as_bytes()]);
        let keys = WalletKeys::from_ask(ask)?;

        let mut dev_seed = Vec::new();
        dev_seed.extend_from_slice(b"dev:");
        dev_seed.extend_from_slice(seed_tag.as_bytes());
        let dev_sk = signing_key_from_seed(&dev_seed);

        let mut rec_seed = Vec::new();
        rec_seed.extend_from_slice(b"rec:");
        rec_seed.extend_from_slice(seed_tag.as_bytes());
        let recovery_sk = signing_key_from_seed(&rec_seed);

        let mut merch_seed = Vec::new();
        merch_seed.extend_from_slice(b"merch:");
        merch_seed.extend_from_slice(seed_tag.as_bytes());
        let merchant_sk = signing_key_from_seed(&merch_seed);

        let serial_digest: [u8; 32] = Sha256::digest([b"serial:", seed_tag.as_bytes()].concat()).into();
        let serial: [u8; 16] = serial_digest[..16].try_into().unwrap();

        let policy = dev_default_policy();
        let ca = dev_vendor_ca();
        let trust = default_dev_trust_store();
        let enclave = SoftwareMockEnclave::new(
            dev_sk,
            &ca,
            SecurityLevel::StrongBox,
            policy.clone(),
            cert_now_secs.saturating_sub(3600),
            cert_now_secs.saturating_add(10 * 365 * 86_400),
            serial,
        )?;
        let merchant_pk = compressed_pk(&merchant_sk);
        let merchant_wallet = OfflineMerchantWallet::new(
            merchant_pk,
            trust,
            policy.clone(),
            Some(policy.max_hops_allowed),
        )?;

        Ok(Self {
            keys,
            next_diversifier: 1,
            notes: Vec::new(),
            enclave,
            recovery_sk,
            merchant_sk,
            merchant_wallet,
            policy,
        })
    }

    pub fn to_snapshot(&self) -> WalletSnapshot {
        let ts = &self.merchant_wallet.trust_store;
        WalletSnapshot {
            chain_id: self.policy.chain_id,
            ask_hex: field_to_hex(self.keys.ask),
            next_diversifier: self.next_diversifier,
            notes: self.notes.clone(),
            enclave_state: self.enclave.export_state(),
            recovery_sk_hex: hex::encode(self.recovery_sk.to_bytes()),
            merchant_sk_hex: hex::encode(self.merchant_sk.to_bytes()),
            pending_merchant_bundles: self.merchant_wallet.accepted_bundles.clone(),
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

    pub fn from_snapshot(snap: WalletSnapshot) -> Result<Self> {
        let ask = field_from_hex(&snap.ask_hex)?;
        let keys = WalletKeys::from_ask(ask)?;
        let enclave = SoftwareMockEnclave::from_persisted_state(snap.enclave_state)?;
        let recovery_sk = sk_from_hex(&snap.recovery_sk_hex)?;
        let merchant_sk = sk_from_hex(&snap.merchant_sk_hex)?;
        let policy = dev_default_policy();

        let mut trust = AttestationTrustStore::new();
        for (vid, pk_hex) in snap.vendor_cas {
            let pk_bytes: [u8; 33] = hex::decode(&pk_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid CA pubkey len"))?;
            trust.register_ca(vid, pk_bytes)?;
        }
        for pid in snap.revoked_pockets {
            trust.revoked_pockets.insert(pid);
        }
        for c in snap.revoked_certs {
            trust.revoked_cert_serials.insert(c);
        }
        trust.crl_version = snap.crl_version;

        let mut merchant_wallet = OfflineMerchantWallet::new(
            compressed_pk(&merchant_sk),
            trust,
            policy.clone(),
            Some(policy.max_hops_allowed),
        )?;
        for b in &snap.pending_merchant_bundles {
            merchant_wallet
                .seen_vouchers
                .insert((b.voucher.pocket_id, b.voucher.counter), b.voucher.clone());
        }
        merchant_wallet.accepted_bundles = snap.pending_merchant_bundles;

        Ok(Self {
            keys,
            next_diversifier: snap.next_diversifier,
            notes: snap.notes,
            enclave,
            recovery_sk,
            merchant_sk,
            merchant_wallet,
            policy,
        })
    }

    pub fn watch_only_ivk(&self) -> Result<WatchOnlyWallet> {
        WatchOnlyWallet::from_ivk(self.keys.ivk)
    }

    pub fn merchant_public_key(&self) -> [u8; 33] {
        compressed_pk(&self.merchant_sk)
    }

    pub fn recovery_public_key(&self) -> [u8; 33] {
        compressed_pk(&self.recovery_sk)
    }

    pub fn next_address(&mut self) -> Result<PaymentAddress> {
        let div = FieldElement::from(self.next_diversifier);
        self.next_diversifier += 1;
        let addr = derive_diversified_address(self.keys.ivk, div)?;
        Ok(PaymentAddress::from_diversified(addr))
    }

    fn next_secret_field(&mut self, tag: &[u8]) -> FieldElement {
        let seq = self.next_diversifier;
        self.next_diversifier += 1;
        derive_nonzero_field(&[
            b"PM_SECRET_V1|",
            tag,
            &self.keys.ask.to_be_bytes(),
            &seq.to_le_bytes(),
        ])
    }

    pub fn shielded_balance(&self) -> u64 {
        self.notes.iter().filter(|n| !n.spent).map(|n| n.value).sum()
    }

    pub fn pocket_balance(&self) -> u64 {
        self.enclave.remaining_balance()
    }

    pub fn pending_merchant_balance(&self) -> u64 {
        self.merchant_wallet
            .accepted_bundles
            .iter()
            .map(|b| b.voucher.amount)
            .sum()
    }

    pub fn scan_outputs(
        &mut self,
        outputs: &[PublishedOutput],
        spent_nullifiers: &BTreeSet<String>,
    ) -> usize {
        scan_outputs_inner(
            self.keys.ivk,
            Some(self.keys.nk),
            &mut self.notes,
            outputs,
            spent_nullifiers,
        )
    }

    pub fn sync_crl(&mut self, crl: &CrlResponse) -> Result<()> {
        let mut store = AttestationTrustStore::new();
        for (vid, pk_hex) in &crl.vendor_cas {
            let pk_bytes: [u8; 33] = hex::decode(pk_hex)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid CA key length"))?;
            store.register_ca(vid, pk_bytes)?;
        }
        for pid in &crl.revoked_pockets {
            store.revoked_pockets.insert(*pid);
        }
        for cert in &crl.revoked_certs {
            store.revoked_cert_serials.insert(*cert);
        }
        store.crl_version = crl.crl_version;
        self.merchant_wallet.sync_crl(&store);
        Ok(())
    }

    fn select_notes(&self, needed: u64) -> Result<Vec<OwnedNoteRecord>> {
        let mut unspent: Vec<OwnedNoteRecord> =
            self.notes.iter().filter(|n| !n.spent).cloned().collect();
        unspent.sort_by_key(|n| n.value);

        if let Some(single) = unspent.iter().find(|n| n.value >= needed) {
            return Ok(vec![single.clone()]);
        }
        unspent.reverse();
        if unspent.len() >= 2 && unspent[0].value.saturating_add(unspent[1].value) >= needed {
            return Ok(vec![unspent[0].clone(), unspent[1].clone()]);
        }
        bail!(
            "insufficient unspent notes in up to 2 JoinSplit inputs for {needed} (available={})",
            self.shielded_balance()
        );
    }

    pub fn build_shield(
        &mut self,
        prover: &dyn CircuitProver,
        amount: u64,
        memo: &str,
    ) -> Result<(ShieldTx, EncryptedNote)> {
        if amount == 0 {
            bail!("shield amount must be > 0");
        }
        let addr = self.next_address()?;
        let blinding = self.next_secret_field(b"shield_blind");
        let esk = self.next_secret_field(b"shield_esk");
        let note = Note {
            value: amount,
            owner_pk_x: addr.pk_d.x,
            owner_pk_y: addr.pk_d.y,
            blinding,
        };
        let cm = compute_note_commitment(&note);
        let enc = encrypt_note(&addr, &note, esk, cm, memo)?;
        let tx_bind = compute_shield_tx_binding_hash(self.policy.chain_id, &enc);
        let tx = prover.prove_shield(&note, tx_bind)?;
        Ok((tx, enc))
    }

    pub fn build_transfer<F>(
        &mut self,
        prover: &dyn CircuitProver,
        recipient: &PaymentAddress,
        amount: u64,
        fee: u64,
        memo: &str,
        merkle_root: FieldElement,
        mut fetch_merkle: F,
    ) -> Result<(TransferTx, [EncryptedNote; 2])>
    where
        F: FnMut(u32) -> Result<MerkleProofResponse>,
    {
        recipient.validate()?;
        let total_needed = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("amount + fee overflow"))?;
        let selected = self.select_notes(total_needed)?;
        let total_in: u64 = selected.iter().map(|n| n.value).sum();
        let change = total_in - total_needed;

        let mut in_notes = Vec::with_capacity(2);
        let mut in_divs = Vec::with_capacity(2);
        let mut in_nonces = Vec::with_capacity(2);
        let mut in_gys = Vec::with_capacity(2);
        let mut in_indices = Vec::with_capacity(2);
        let mut in_paths = Vec::with_capacity(2);
        let mut nullifiers = Vec::with_capacity(2);

        for rec in &selected {
            let note = record_to_note(rec)?;
            let cm = field_from_hex(&rec.commitment_hex)?;
            let nf = field_from_hex(&rec.nullifier_hex)?;
            let proof = fetch_merkle(rec.leaf_index)?;
            in_notes.push(note);
            in_divs.push(field_from_hex(&rec.diversifier_hex)?);
            in_nonces.push(rec.g_d_nonce);
            in_gys.push(field_from_hex(&rec.g_d_y_hex)?);
            in_indices.push(rec.leaf_index);
            in_paths.push(parse_siblings(&proof)?);
            nullifiers.push(nf);
            debug_assert_eq!(compute_note_commitment(&note), cm);
        }

        if selected.len() == 1 {
            let dummy = Note {
                value: 0,
                owner_pk_x: FieldElement::zero(),
                owner_pk_y: FieldElement::zero(),
                blinding: self.next_secret_field(b"dummy_in"),
            };
            let dummy_cm = compute_note_commitment(&dummy);
            let dummy_nf = compute_nullifier(self.keys.nk, dummy_cm, 0);
            in_notes.push(dummy);
            in_divs.push(FieldElement::zero());
            in_nonces.push(0);
            in_gys.push(FieldElement::zero());
            in_indices.push(0);
            in_paths.push([FieldElement::zero(); MERKLE_DEPTH]);
            nullifiers.push(dummy_nf);
        }

        let recip_blind = self.next_secret_field(b"out_recip");
        let recip_esk = self.next_secret_field(b"esk_recip");
        let out_recip = Note {
            value: amount,
            owner_pk_x: recipient.pk_d.x,
            owner_pk_y: recipient.pk_d.y,
            blinding: recip_blind,
        };
        let cm_recip = compute_note_commitment(&out_recip);
        let enc_recip = encrypt_note(recipient, &out_recip, recip_esk, cm_recip, memo)?;

        let chg_addr = self.next_address()?;
        let chg_blind = self.next_secret_field(b"out_chg");
        let chg_esk = self.next_secret_field(b"esk_chg");
        let out_chg = Note {
            value: change,
            owner_pk_x: chg_addr.pk_d.x,
            owner_pk_y: chg_addr.pk_d.y,
            blinding: chg_blind,
        };
        let cm_chg = compute_note_commitment(&out_chg);
        let enc_chg = encrypt_note(&chg_addr, &out_chg, chg_esk, cm_chg, "change")?;

        let encs = [enc_recip, enc_chg];
        let tx_bind = compute_transfer_tx_binding_hash(self.policy.chain_id, &encs);
        let req = TransferWitnessRequest {
            merkle_root,
            nullifiers: [nullifiers[0], nullifiers[1]],
            out_commitments: [cm_recip, cm_chg],
            fee,
            tx_binding_hash: tx_bind,
            ask: self.keys.ask,
            in_notes: [in_notes[0], in_notes[1]],
            in_diversifiers: [in_divs[0], in_divs[1]],
            in_g_d_nonces: [in_nonces[0], in_nonces[1]],
            in_g_d_ys: [in_gys[0], in_gys[1]],
            in_leaf_indices: [in_indices[0], in_indices[1]],
            in_merkle_paths: [in_paths[0], in_paths[1]],
            out_notes: [out_recip, out_chg],
        };
        let tx = prover.prove_transfer(&req)?;
        Ok((tx, encs))
    }

    pub fn build_unshield_to_pocket<F>(
        &mut self,
        prover: &dyn CircuitProver,
        amount: u64,
        fee: u64,
        merkle_root: FieldElement,
        mut fetch_merkle: F,
    ) -> Result<(UnshieldTx, Option<EncryptedNote>)>
    where
        F: FnMut(u32) -> Result<MerkleProofResponse>,
    {
        if amount == 0 {
            bail!("pocket funding amount must be > 0");
        }
        let needed = amount
            .checked_add(fee)
            .ok_or_else(|| anyhow::anyhow!("amount + fee overflow"))?;
        let single = self
            .notes
            .iter()
            .filter(|n| !n.spent && n.value >= needed)
            .min_by_key(|n| n.value)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!("no single unspent note covers {needed} for pocket unshield")
            })?;

        let in_note = record_to_note(&single)?;
        let nf = field_from_hex(&single.nullifier_hex)?;
        let proof = fetch_merkle(single.leaf_index)?;
        let chg_val = in_note.value - needed;

        let (change_note, change_enc) = if chg_val > 0 {
            let addr = self.next_address()?;
            let blind = self.next_secret_field(b"unshield_chg");
            let esk = self.next_secret_field(b"unshield_chg_esk");
            let note = Note {
                value: chg_val,
                owner_pk_x: addr.pk_d.x,
                owner_pk_y: addr.pk_d.y,
                blinding: blind,
            };
            let cm = compute_note_commitment(&note);
            let enc = encrypt_note(&addr, &note, esk, cm, "unshield-change")?;
            (note, Some(enc))
        } else {
            (
                Note {
                    value: 0,
                    owner_pk_x: FieldElement::zero(),
                    owner_pk_y: FieldElement::zero(),
                    blinding: self.next_secret_field(b"unshield_zero_chg"),
                },
                None,
            )
        };

        let change_commitment = compute_note_commitment(&change_note);
        let pid = self.enclave.pocket_id();
        let tx_bind = compute_pocket_fund_binding_hash(
            self.policy.chain_id,
            &pid,
            &self.enclave.device_pk(),
            amount,
        );
        let req = UnshieldWitnessRequest {
            merkle_root,
            nullifier: nf,
            change_commitment,
            burn_amount: amount,
            fee,
            tx_binding_hash: tx_bind,
            ask: self.keys.ask,
            in_note,
            in_diversifier: field_from_hex(&single.diversifier_hex)?,
            in_g_d_nonce: single.g_d_nonce,
            in_g_d_y: field_from_hex(&single.g_d_y_hex)?,
            in_leaf_index: single.leaf_index,
            in_merkle_path: parse_siblings(&proof)?,
            change_note,
        };
        let tx = prover.prove_unshield(&req)?;
        Ok((tx, change_enc))
    }

    pub fn issue_offline_payment(
        &mut self,
        recipient_pk: [u8; 33],
        amount: u64,
        now_secs: u64,
        ttl_secs: u64,
    ) -> Result<VoucherBundle> {
        let ctr = self.enclave.counter() + 1;
        let nonce_digest: [u8; 32] = Sha256::digest(
            [
                b"PM_OFFLINE_NONCE_V1|".as_slice(),
                &self.enclave.pocket_id().0,
                &ctr.to_le_bytes(),
                &now_secs.to_le_bytes(),
            ]
            .concat(),
        )
        .into();
        let nonce: [u8; 16] = nonce_digest[..16].try_into().unwrap();
        Ok(self
            .enclave
            .issue_voucher(recipient_pk, amount, now_secs, ttl_secs, nonce)?)
    }

    pub fn re_endorse_received_voucher(
        &self,
        bundle: &VoucherBundle,
        to_pk: [u8; 33],
        expires_at: u64,
    ) -> Result<VoucherBundle> {
        let nonce_digest: [u8; 32] = Sha256::digest(
            [
                b"PM_HOP_NONCE_V1|".as_slice(),
                &bundle.voucher.hash(),
                &[bundle.hops.len() as u8],
            ]
            .concat(),
        )
        .into();
        let nonce: [u8; 16] = nonce_digest[..16].try_into().unwrap();
        Ok(sign_hop_endorsement(
            &self.merchant_sk,
            bundle,
            to_pk,
            expires_at,
            nonce,
        )?)
    }

    pub fn receive_offline_payment(
        &mut self,
        bundle: &VoucherBundle,
        now_secs: u64,
    ) -> Result<[u8; 32]> {
        Ok(self
            .merchant_wallet
            .verify_and_accept_offline(bundle, now_secs)?)
    }

    pub fn build_settle_voucher(
        &mut self,
        prover: &dyn CircuitProver,
        bundle: &VoucherBundle,
    ) -> Result<(ShieldTx, EncryptedNote)> {
        let addr = self.next_address()?;
        let blind = self.next_secret_field(b"settle_blind");
        let esk = self.next_secret_field(b"settle_esk");
        let note = Note {
            value: bundle.voucher.amount,
            owner_pk_x: addr.pk_d.x,
            owner_pk_y: addr.pk_d.y,
            blinding: blind,
        };
        let cm = compute_note_commitment(&note);
        let enc = encrypt_note(&addr, &note, esk, cm, "offline-settle")?;
        let m_pk = self.merchant_public_key();
        let tx_bind = compute_voucher_settle_binding_hash(
            self.policy.chain_id,
            &bundle.voucher.hash(),
            &m_pk,
            cm,
        );
        let tx = prover.prove_shield(&note, tx_bind)?;
        Ok((tx, enc))
    }

    pub fn build_cooperative_close(
        &mut self,
        prover: &dyn CircuitProver,
        now_secs: u64,
    ) -> Result<(CloseStatement, Option<(ShieldTx, EncryptedNote)>)> {
        if self.enclave.is_closed() {
            bail!("pocket is already closed");
        }
        let unspent = self.enclave.remaining_balance();
        let stmt = self.enclave.cooperative_close(now_secs)?;
        if unspent == 0 {
            return Ok((stmt, None));
        }
        let addr = self.next_address()?;
        let blind = self.next_secret_field(b"reclaim_blind");
        let esk = self.next_secret_field(b"reclaim_esk");
        let note = Note {
            value: unspent,
            owner_pk_x: addr.pk_d.x,
            owner_pk_y: addr.pk_d.y,
            blinding: blind,
        };
        let cm = compute_note_commitment(&note);
        let enc = encrypt_note(&addr, &note, esk, cm, "pocket-reclaim")?;
        let tx_bind = compute_pocket_reclaim_binding_hash(
            self.policy.chain_id,
            &self.enclave.pocket_id(),
            unspent,
            cm,
        );
        let tx = prover.prove_shield(&note, tx_bind)?;
        Ok((stmt, Some((tx, enc))))
    }
}

pub fn encode_bundle_transport_bytes(bundle: &VoucherBundle, transport: &str) -> Result<Vec<u8>> {
    let mut ble = BleGattChannel::new(247, 1);
    let mut nfc = NfcTapChannel::new();
    match transport {
        "nfc" => {
            nfc.send_bundle(bundle)?;
            let decoded = nfc.receive_bundle()?;
            debug_assert_eq!(&decoded, bundle);
            // Persist framed NDEF bytes cleanly
            let frame = encode_frame(&encode_bundle(bundle));
            Ok(offline_vouchers::NfcNdefFrame::encode_ndef_record(&frame)?)
        }
        "ble" => {
            ble.send_bundle(bundle)?;
            Ok(encode_frame(&encode_bundle(bundle)))
        }
        other => bail!("unsupported offline transport '{other}' (expected nfc|ble)"),
    }
}

pub fn decode_bundle_transport_bytes(raw: &[u8], transport: &str) -> Result<VoucherBundle> {
    match transport {
        "nfc" => {
            let frame = offline_vouchers::NfcNdefFrame::decode_ndef_record(raw)?;
            Ok(decode_bundle(&decode_frame(&frame)?)?)
        }
        "ble" => Ok(decode_bundle(&decode_frame(raw)?)?),
        other => bail!("unsupported offline transport '{other}' (expected nfc|ble)"),
    }
}

fn sk_from_hex(s: &str) -> Result<SigningKey> {
    let raw: [u8; 32] = hex::decode(s)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte signing key hex"))?;
    Ok(SigningKey::from_bytes(&raw.into())?)
}

fn record_to_note(rec: &OwnedNoteRecord) -> Result<Note> {
    Ok(Note {
        value: rec.value,
        owner_pk_x: field_from_hex(&rec.owner_pk_x_hex)?,
        owner_pk_y: field_from_hex(&rec.owner_pk_y_hex)?,
        blinding: field_from_hex(&rec.blinding_hex)?,
    })
}

fn parse_siblings(proof: &MerkleProofResponse) -> Result<[FieldElement; MERKLE_DEPTH]> {
    if proof.siblings_hex.len() != MERKLE_DEPTH {
        bail!(
            "expected {MERKLE_DEPTH} siblings, got {}",
            proof.siblings_hex.len()
        );
    }
    let mut out = [FieldElement::zero(); MERKLE_DEPTH];
    for (dst, hex_str) in out.iter_mut().zip(&proof.siblings_hex) {
        *dst = field_from_hex(hex_str)?;
    }
    Ok(out)
}
