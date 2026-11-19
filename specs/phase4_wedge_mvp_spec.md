# Phase 4 Technical Spec: Wedge MVP Client SDK, Local Settlement Node & CLI

## 1. End-to-End Architecture

Phase 4 connects the verified components from Phases 1–3 into an end-to-end runnable local Wedge MVP stack across three new Rust crates:

```text
  [pm-cli] (crates/pm_cli)                <-- Air-gapped NFC/BLE file I/O + Encrypted Keystore
     |
     +--> [pm_sdk] (crates/pm_sdk)        <-- pm1 Addresses, Grumpkin ECDH, Prover, Watch-Only Scanner
             |
             | HTTP/1.1 JSON RPC (std::net::TcpStream)
             v
  [pm-node] (crates/pm_node)              <-- Stateful HTTP Node: LedgerState + PocketRegistry + MeshRelay
     |
     +--> ledger_core      (Phase 1 Noir UltraHonk + Poseidon2 Merkle Tree + Pocket Escrow)
     +--> offline_vouchers (Phase 3 P-256 Vouchers, BLE/NFC Frames, Fraud Proofs, CRL, Mesh)
```

* **Zero Phase 1 Circuit Changes:** `circuits/` remains byte-identical; `NargoBbProver` compiles and proves inside caller-supplied cache/temp directories without touching `circuits/*/Prover.toml`.
* **Devnet Trust Root:** Both `pm_node` and `pm_cli` initialize a deterministic devnet attestation CA (`PerfectMoney-DevCA-V1`) for offline StrongBox / Secure Enclave testing, while supporting custom CA trust injection and CRL synchronization via `GET /v1/trust/crl`.

---

## 2. Diversified Payment Addresses (`pm1...`)

A shielded payment address binds a wallet's diversified generator and public point `(diversifier, nonce, g_d, pk_d)` cleanly into a copy-pastable checksummed token:

* **Canonical Binary Payload (`133` bytes):**
  `diversifier (32B BE) || g_d_nonce (1B) || g_d.y (32B BE) || pk_d.x (32B BE) || pk_d.y (32B BE) || checksum (4B)`
  where `checksum = SHA-256("PM_ADDR_V1|" || payload[0..129])[0..4]`.
* **String Representation:** `"pm1"` + URL-safe unpadded Base64 (`RFC 4648 §5`) of the `133`-byte payload (`180` characters total).
* **Decoding Validation:** Recomputes `g_d.x = Poseidon2(DOMAIN_DIVERSIFIER, diversifier, nonce)` and enforces both `is_on_grumpkin(g_d.x, g_d.y)` and `is_on_grumpkin(pk_d.x, pk_d.y)`.

---

## 3. Grumpkin ECDH Off-Chain Note Encryption & Watch-Only Scanning

When shielding, transferring, or unshielding with change, the sender publishes an `EncryptedNote` on-chain (`tx_binding_hash` commits to the ciphertexts so node relays cannot swap encrypted memos):

1. **Sender Encryption (`encrypt_note`):**
   * Sample OS-CSPRNG non-zero ephemeral scalar `esk` and compute `epk = esk * g_d` and `shared = esk * pk_d` on Grumpkin (`ledger_core::crypto::grumpkin_scalar_mul`).
   * Derive `Zeroizing<[u8; 32]>` AEAD key via **HKDF-SHA256** (`info = "xchacha20poly1305-key"`, `salt = "PM_NOTE_AEAD_V2"`).
   * Serialize canonical plaintext: `value (8B LE) || blinding (32B BE) || diversifier (32B BE) || nonce (1B) || memo_len (2B LE) || memo_utf8`.
   * Encrypt via **XChaCha20-Poly1305** (`24`-byte OS CSPRNG nonce) with AAD binding `(cm, epk.x, epk.y)`.
2. **Receiver / Watch-Only Scanning (`try_decrypt_note`):**
   * `WatchOnlyWallet` holds only Incoming Viewing Key `ivk` (optionally `nk` for spent detection), NEVER `ask`.
   * Checks `is_on_grumpkin(epk.x, epk.y)`, derives `shared = ivk * epk` (`== esk * pk_d`), verifies XChaCha20-Poly1305 tag + AAD before decrypting, reconstructs `pk_d = derive_diversified_address(ivk, diversifier)`, verifies `addr.nonce == nonce` and `compute_note_commitment(note) == cm`.
3. **Transaction Ciphertext Binding (`tx_binding_hash`):**
   * `PM_SHIELD_BIND_V2`: binds `(chain_id, encrypted_note)`.
   * `PM_TRANSFER_BIND_V2`: binds `(chain_id, out_enc[0], out_enc[1])`.
   * `PM_POCKET_FUND_BIND_V1` / `PM_VOUCHER_SETTLE_BIND_V1` / `PM_POCKET_RECLAIM_BIND_V1`: Phase 3 pocket escrow bindings verified on settlement.

---

## 4. BIP-39 Recovery & Encrypted Wallet Keystore (`mnemonic.rs`, `keystore.rs`)

Wallet state (`ask`, `next_diversifier`, UTXO notes, serialized `PersistedEnclaveState`, `recovery_sk`, `merchant_sk`, `pending_merchant_bundles`, and cached `AttestationTrustStore` / CRL) is backed by two hardened layers:

* **BIP-39 + HKDF-SHA256 Root Derivation (`mnemonic.rs`):** 12-word (`128`-bit OS entropy) or 24-word (`256`-bit OS entropy) English mnemonics derive independent spend (`ask`), pocket device (`device_p256`), backup drain (`recovery_p256`), merchant settlement (`settle_p256`), and serial secrets using `HKDF-SHA256` (`Zeroizing` scrubbed after use).
* **KDF:** **Argon2id v0x13** (`19 MiB` memory, `t = 2`, `p = 1` OWASP production default; opt-in `--fast-kdf` for rapid debug/CI CLI runs) with a `16`-byte OS CSPRNG salt.
* **AEAD + AAD Integrity:** **XChaCha20-Poly1305** (`24`-byte OS CSPRNG nonce) binding `(version || m_cost || t_cost || p_cost || salt || nonce)` in Poly1305 AAD so wrong passphrases or parameter/ciphertext edits fail authentication before deserialization.

---

## 5. HTTP/1.1 Settlement & Mesh Node (`pm-node` / `crates/pm_node`)

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/health` | Health check (`{"ok":true}`) |
| `GET` | `/v1/status` | Global supply metrics (`total_issued_supply`, `public_vault_balance`, `total_shielded_supply`, `total_pocket_escrow`, `collected_fees`, `victim_compensation_pool_pm`, `merkle_root`, `leaf_count`, `crl_version`) |
| `GET` | `/v1/chain/outputs?from=N` | Paginated published `EncryptedNote` leaves & commitments for wallet scanning |
| `GET` | `/v1/merkle/proof/{leaf_index}` | Depth-32 Poseidon2 Merkle siblings for spend proofs |
| `GET` | `/v1/trust/crl` | Current `AttestationTrustStore` vendor CAs & revoked pocket/cert CRL |
| `POST` | `/v1/faucet/mint` | Devnet vault mint (`mint_vault_supply`) |
| `POST` | `/v1/tx/shield` | Verify & apply `ShieldTx` + publish output `EncryptedNote` |
| `POST` | `/v1/tx/transfer` | Verify & apply 2-in/2-out `TransferTx` + publish 2 encrypted outputs |
| `POST` | `/v1/tx/unshield` | Verify & apply `UnshieldTx` (+ optional encrypted change leaf) |
| `POST` | `/v1/pocket/fund` | Fund Phase 3 P-256 pocket escrow from shielded unshield proof |
| `POST` | `/v1/pocket/settle` | Out-of-order voucher settlement into merchant shielded note (`ShieldTx`) |
| `POST` | `/v1/pocket/close` | Cooperative pocket close & immediate unspent reclaim `ShieldTx` |
| `POST` | `/v1/pocket/fraud-proof` | Submit `EquivocationFraudProof` to revoke compromised pocket & slash escrow |
| `POST` | `/v1/mesh/relay` | Ingest opaque `MeshEnvelope` into `EncryptedMeshRelay` |
| `GET` | `/v1/mesh/drain` | Drain ready encrypted `MeshEnvelope`s for gateway submission |

---

## 6. Wallet & Air-Gapped Merchant CLI (`pm-cli` / `crates/pm_cli`)

Key commands:
`init`, `address`, `sync`, `balance`, `faucet`, `shield`, `send`, `pocket-fund`, air-gapped `offline-pay --transport nfc|ble --out <file>`, air-gapped `offline-receive --in <file> --transport nfc|ble`, `offline-settle`, and `pocket-close`.

```bash
./scripts/run_phase4_mvp.sh
```

