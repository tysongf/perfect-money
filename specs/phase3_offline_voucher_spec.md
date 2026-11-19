# Phase 3 Technical Spec: Decoupled Offline BLE/NFC P-256 Pocket Vouchers

## 1. Architectural Rationale: Strict Decoupling from Phase 1 Noir Circuits

Offline peer-to-peer cash cannot rely on zero-knowledge proof generation inside air-gapped IoT/feature-phone hardware enclaves or verify non-native **NIST P-256 (`secp256r1`)** ECDSA signatures inside Phase 1's BN254 JoinSplit circuits (`circuits/shielded_transfer`) without violating the `< 2.0s` mobile proving budget.

Phase 3 keeps Phase 1 (`circuits/`) **100% untouched** and bridges offline payments cleanly at the shielded-pool boundary:

```text
Shielded Pool (Phase 1)         Phase 3 Escrow Bridge              Air-Gapped Pocket Mesh
-----------------------         ---------------------              ----------------------
[Unshield Note (UnshieldTx)] -> [lock_to_pocket_escrow]         -> [Secure Enclave / StrongBox]
  tx_binding_hash =               PocketAccount(escrow <= 500 PM)     P-256 Key + Monotonic Counter
  PM_POCKET_FUND_BIND_V1                                               |
                                                                       v (NFC NDEF / BLE GATT)
                                                                   [OfflineMerchantWallet]
                                                                     Offline Verification + CRL
                                                                       |
                                                                       v (Online or Encrypted Mesh)
[Shield Note (ShieldTx)]     <- [release_from_pocket_escrow]    <- [settle_voucher_to_shielded]
  tx_binding_hash =               Out-of-order counter tracking       Strict low-S + Cap Enforcement
  PM_VOUCHER_SETTLE_BIND_V1       Zero Unbacked Inflation             Equivocation Auto-Slash & CRL
```

### Key Properties

1. **Zero Supply Inflation Under Total Hardware Compromise:** Settlement draws strictly from `pocket.escrow_balance`. Even if an adversary physically decapsulates a Secure Enclave / StrongBox chip and rolls back its monotonic counter (`ctr`), maximum settleable outflow from that pocket cannot exceed `pocket.total_funded <= max_pocket_balance`.
2. **Confidential Offline Mesh:** Online shielding/unshielding uses Phase 1 Noir UltraHonk notes; offline payments authenticate via hardware-bound P-256 keys (`device_pk`) without exposing the owner's spend key (`ask`) or shielded transaction graph. An opportunistic **store-and-forward encrypted mesh relay** (`EncryptedMeshRelay`) hides voucher and sender metadata from intermediate couriers.
3. **Out-of-Order Offline Settlement:** Online settlement tracks per-counter receipts (`settled_counters: BTreeMap<u64, OfflineVoucher>`), allowing Merchant B (`ctr=2`) to settle before Merchant A (`ctr=1`) while rejecting duplicates and turning conflicting `(pocket_id, ctr)` pairs into slashable `EquivocationFraudProof`s.

---

## 2. Constitutional Caps, Policy Bounds & Supply Conservation

### 2.1 Micro-PM Units & Default Policy (`PocketPolicy`)

Amounts are represented in integer `u64` micro-PM (`1 PM = 1_000_000` units):

| Parameter | Default Value | Constitutional Ceiling | Purpose |
| :--- | :--- | :--- | :--- |
| `max_pocket_balance` | `500_000_000` (`500 PM`) | `constitutional_hard_cap = 1_000_000_000` (`1,000 PM`) | Bounds single-chip hardware extractability & double-spend blast radius. |
| `max_voucher_ttl_secs` | `604_800` (`7 days`) | `604_800` | Caps offline validity window and reserve duration for in-flight vouchers. |
| `uncooperative_drain_delay_secs` | `604_800` (`7 days`) | `>= max_voucher_ttl_secs` | Prevents pocket owners from draining escrow before offline merchants settle. |
| `max_clock_skew_secs` | `300` (`5 min`) | `300` | Bounds tolerated future `issued_at` timestamp drift. |
| `max_hops_allowed` | `3` | `3` | Maximum bounded offline re-endorsement hops (`HopEndorsement`). |
| `default_merchant_max_hops` | `1` | `max_hops_allowed` | Merchants default to strict single-hop (direct pocket spend) unless explicitly opted into multi-hop (`<= 3`). |

### 2.2 Global Supply Conservation Invariant

Every ledger transition preserves strict 1:1 accounting in `crates/ledger_core::LedgerState` and `crates/offline_vouchers::PocketRegistry`:

```text
public_vault_balance + total_shielded_supply + total_pocket_escrow + collected_fees == total_issued_supply

sum(pocket.escrow_balance) + victim_compensation_pool_pm == total_pocket_escrow
```

* `lock_to_pocket_escrow(amount)` moves `amount` atomically from `public_vault_balance` to `total_pocket_escrow` (immediately after verifying `circuits/unshield`).
* `release_from_pocket_escrow(amount)` moves `amount` atomically from `total_pocket_escrow` back into `public_vault_balance` for immediate shielding via `circuits/shield` (settlement, victim compensation, cooperative sweep, or post-cooldown drain).

---

## 3. Cryptographic Primitives & Domain Separation

All offline signatures use **NIST P-256 (`secp256r1`) ECDSA** over `SHA-256(domain || canonical_payload)` with **strict BIP-0062/low-S canonicalization** (`sig.normalize_s() == sig`). Non-canonical high-S signatures are rejected by both air-gapped receivers and the online `PocketRegistry`.

| Domain Constant | Format / Inputs | Purpose |
| :--- | :--- | :--- |
| `PM_POCKET_ID_V1` | `chain_id (u64 LE) \|\| device_pk (33B compressed SEC1)` | Deterministic `PocketId` (`[u8; 32]`). |
| `PM_HW_ATTEST_V1` | Canonical vendor cert fields | Vendor CA attestation binding `device_pk` to Secure Enclave / StrongBox / FIDO2 hardware. |
| `PM_OFFLINE_VOUCHER_V1` | Canonical `227B` voucher body (`version..nonce`) | Hardware enclave signature binding `(pocket_id, ctr, amount, cumulative_spent, recipient_pk, prev_hash, ttl, nonce)`. |
| `PM_VOUCHER_HOP_V1` | `voucher_hash \|\| hop_index \|\| from_pk \|\| to_pk \|\| expires_at \|\| nonce` | Optional bounded offline re-endorsement signature from current holder. |
| `PM_POCKET_CLOSE_V1` | `chain_id \|\| pocket_id \|\| final_counter \|\| final_cumulative_spent \|\| closed_at` | Cooperative enclave-attested close statement proving total cumulative offline spend. |
| `PM_POCKET_DRAIN_V1` | `chain_id \|\| pocket_id \|\| requested_at` | Owner recovery-key request starting the 7-day uncooperative drain cooldown. |
| `PM_POCKET_FUND_BIND_V1` | `chain_id \|\| pocket_id \|\| device_pk \|\| amount` | Reduced mod BN254 `Fr` (`tx_binding_hash` in Phase 1 `UnshieldTx`). |
| `PM_VOUCHER_SETTLE_BIND_V1` | `chain_id \|\| voucher_hash \|\| recipient_pk \|\| out_commitment` | Reduced mod BN254 `Fr` (`tx_binding_hash` in merchant `ShieldTx`). |
| `PM_POCKET_RECLAIM_BIND_V1` | `chain_id \|\| pocket_id \|\| amount \|\| out_commitment` | Reduced mod BN254 `Fr` (`tx_binding_hash` in close/drain reclaim `ShieldTx`). |

---

## 4. Lifecycle, Out-of-Order Settlement & Close Paths

1. **Funding (`fund_pocket_from_shielded`):**
   * User submits a valid Phase 1 `UnshieldTx` with `tx_binding_hash == compute_pocket_fund_binding_hash(...)`.
   * Registry verifies `HardwareAttestation` (trusted vendor CA, active validity window, not on global CRL), `pocket_id == derive_pocket_id(...)`, and `new_escrow <= policy.max_pocket_balance`.
   * Executes `ledger.apply_unshield` then `ledger.lock_to_pocket_escrow(unshield_tx.burn_amount)`.
2. **Air-Gapped Spend (`OfflineMerchantWallet::verify_and_accept_offline`):**
   * Pocket enclave (`SoftwareMockEnclave`) increments monotonic `counter`, ensures `amount > 0` and `cumulative_spent + amount <= total_funded`, links `prev_voucher_hash`, and signs with hardware P-256 key (`device_pk`).
   * Air-gapped merchant checks vendor attestation against cached `AttestationTrustStore` + CRL, validates TTL/clock skew, low-S signature, hop chain (`<= max_accepted_hops`), and checks its local `(pocket_id, ctr)` cache.
   * Any conflicting second voucher at `(pocket_id, ctr)` is rejected while storing an `EquivocationFraudProof`.
3. **Settlement (`settle_voucher_to_shielded`):**
   * Supports settlement **in any counter order** via `pocket.settled_counters`.
   * Re-verifies voucher, attestation, hop chain, `ShieldTx.mint_amount == voucher.amount`, `ShieldTx.tx_binding_hash`, and `pocket.escrow_balance >= voucher.amount`.
   * Rejects identical `(pocket_id, ctr)` replay (`VoucherAlreadySettled`).
   * If a conflicting voucher arrives for an already-settled `(pocket_id, ctr)`, automatically executes `submit_equivocation_fraud_proof`: revokes `pocket_id` on global CRL and slashes all remaining `pocket.escrow_balance` into `victim_compensation_pool_pm`.
4. **Cooperative Close (`cooperative_close_pocket`):**
   * Hardware enclave signs `CloseStatement { final_counter, final_cumulative_spent, closed_at }` and locks further signing.
   * Provably unspent escrow `unspent_safe = (total_funded - final_cumulative_spent).min(escrow_balance)` is released and re-shielded **immediately** (`ShieldTx` with `PM_POCKET_RECLAIM_BIND_V1`), while `final_cumulative_spent - total_settled` remains reserved until `closed_at + max_voucher_ttl_secs` for in-flight offline merchants.
5. **Uncooperative Drain (`initiate_uncooperative_drain` / `finalize_drain`):**
   * If the phone is lost or destroyed, the owner signs `UncooperativeDrainRequest` with backup `recovery_pk`.
   * Transitions pocket to `DrainingUncooperative { unlock_at: now + 7 days }` during which legitimate offline merchants can still settle. After `unlock_at`, remaining unclaimed escrow can be drained back to the owner's shielded pool.

---

## 5. Compact Wire Codecs & Transports (`crates/offline_vouchers/src/wire.rs`, `transport.rs`)

* **Canonical Core `OfflineVoucher` Wire Size:** Exactly **`227` bytes**:
  `version (2B) + chain_id (8B) + pocket_id (32B) + counter (8B) + amount (8B) + cumulative_spent (8B) + recipient_pk (33B) + prev_voucher_hash (32B) + issued_at (8B) + expires_at (8B) + nonce (16B) + sig (64B)`.
* **Authenticated Envelope (`PMV1` Frame):** Magic `b"PMV1"` (`4B`) + length (`4B LE`) + payload + truncated `SHA-256` checksum (`4B`) = `12B` framing overhead.
* **NFC NDEF Channel (`NfcTapChannel`):** Encodes framed `VoucherBundle` inside an NDEF external-type record (`TNF = 0x04`, type `b"pm:v1"`, `<= 4096 B`), well under a single Android HCE / Apple CoreNFC APDU exchange (`~420 B` single-hop bundle).
* **BLE GATT Channel (`BleGattChannel`):** Fragments frames into `BleChunk` packets (`session_id: u16, seq: u16, total: u16, data`) supporting legacy **MTU `20`** (`14B` payload chunks) and BLE 5.x **MTU `247`**, with out-of-order reassembly, duplicate chunk tolerance, and checksum verification.
* **Store-and-Forward Mesh (`EncryptedMeshRelay`):** Wraps settlement payloads into opaque `MeshEnvelope` ciphertexts (`SHA-256` stream cipher + MAC keyed to receiver secret) with duplicate `envelope_id` suppression and TTL expiration, allowing nearby couriers to carry offline payments to internet gateways without learning amounts, identities, or voucher hashes.

---

## 6. Repository Layout & Verification Commands

* [`specs/phase3_offline_voucher_spec.md`](specs/phase3_offline_voucher_spec.md) — Canonical Phase 3 specification
* [`crates/ledger_core/src/ledger.rs`](crates/ledger_core/src/ledger.rs) — Additive `total_pocket_escrow` lock/release hooks
* [`crates/offline_vouchers/src/`](crates/offline_vouchers/src/lib.rs) — P-256 vouchers, enclave simulator, canonical BLE/NFC codecs, encrypted mesh relay, offline receiver, and settlement registry
* [`crates/offline_vouchers/tests/offline_voucher_adversarial.rs`](crates/offline_vouchers/tests/offline_voucher_adversarial.rs) — 11 adversarial security, transport, close/drain, and fraud-proof tests
* [`crates/offline_vouchers/tests/e2e_phase1_phase3_real_proofs.rs`](crates/offline_vouchers/tests/e2e_phase1_phase3_real_proofs.rs) — End-to-end real Barretenberg UltraHonk (`unshield` -> NFC/BLE P-256 offline spends -> out-of-order `shield` settlement -> cooperative sweep) bridge test
* [`scripts/run_phase3_suite.sh`](scripts/run_phase3_suite.sh) — Phase 3 verification runner

```bash
./scripts/run_phase3_suite.sh
```

