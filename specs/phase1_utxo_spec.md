# Phase 1 Technical Spec & Scaffolding Guide: Shielded UTXO Currency (Noir)

## 1. Executive Overview & Architecture Summary

This document is the canonical specification and scaffolding blueprint for **Phase 1** of **Perfect Money** — a sovereign, privacy-preserving digital currency.

### Core System Pillars

* **Value Anchor (Phase 2):** Endogenous supply backed by 100% censorship-resistant crypto collateral in isolated branches, with Liquity-v2-style hard redemptions against a PID-smoothed energy-and-goods basket target, governed by a single-token Schelling-point oracle.
* **Privacy & Auditability (Phase 1 — This Document):** Cash-like privacy for individual transfers via zero-knowledge proofs (single-asset shielded UTXO pool in Noir + Barretenberg UltraHonk), paired with real-time cryptographic auditability of shielded supply deltas at the vault bridge.
* **Settlement Rails (Phase 3):** Instant, near-zero-fee online settlement plus decoupled **capped-value offline pocket vouchers** backed by hardware Secure Enclaves / StrongBox (P-256 + monotonic counters), funded from and settled back into the shielded pool without bloating the online JoinSplit circuit with non-native P-256 arithmetic.
* **Governance:** Constitutional ossification of core invariants and credible open-source fork exit.

### Why Noir 1.0 + Barretenberg UltraHonk

* **Stable Toolchain:** Noir 1.0 compiles Rust-like high-level arithmetic and control flow into ACIR, minimizing under-constrained syntax errors.
* **Native Poseidon2 & Grumpkin Cycle:** Barretenberg accelerates BN254-native `poseidon2_permutation` (`t = 4`) and Grumpkin embedded-curve MSMs (`std::embedded_curve_ops`), enabling Orchard-style diversified 3-key privacy within a mobile proving budget (`< 2.0s`).
* **Chain-Agnostic Core:** Phase 1 keeps consensus out of the proving layer by encapsulating Merkle state, nullifier tracking, proof verification, and vault supply accounting inside a standalone Rust `crates/ledger_core` state-transition engine.

---

## 2. Environment Setup & Toolchain Prerequisites

Install the toolchain on Linux (`x86_64`) or macOS:

```bash
# 1. Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Noir 1.0 (nargo) via noirup
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash
noirup

# 3. Barretenberg (bb) proving backend via bbup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/next/barretenberg/bbup/install | bash
bbup

# 4. Verification helpers
# - jq for ACIR JSON inspection
# - cvc5 GPL static build (required for CoCoALib finite-field QF_FF theory support)
nargo --version
bb --version
cvc5 --version
```

### Mandatory Compiler Safety Rules

* Always compile and test with `nargo compile --deny-warnings` and `nargo test --deny-warnings`.
* **Strictly forbid** `--skip-underconstrained-check` and `--skip-brillig-constraints-check` in all build scripts, tests, and agent workflows.
* **Zero `unconstrained fn` in production circuit modules** (`src/types.nr`, `src/crypto.nr`, `src/merkle.nr`, `src/main.nr`). Any `unconstrained` helper introduced later requires a sibling negative soundness test and formal/relational verification gate approval.

---

## 3. Target Monorepo Directory Layout

```text
perfect-money/
├── README.md
├── .gitignore
├── specs/
│   ├── phase1_utxo_spec.md          # This document
│   └── phase2_peg_oracle_spec.md    # Monetary policy, oracle & red-team simulator spec
├── circuits/
│   ├── common/                      # Shared Noir library (types.nr, crypto.nr, merkle.nr)
│   │   ├── Nargo.toml
│   │   └── src/
│   │       ├── lib.nr
│   │       ├── types.nr
│   │       ├── crypto.nr
│   │       └── merkle.nr
│   ├── shielded_transfer/           # 2-in, 2-out single-asset shielded JoinSplit circuit
│   │   ├── Nargo.toml
│   │   ├── Prover.toml
│   │   └── src/main.nr
│   ├── shield/                      # Money-in Vault Shield circuit (mints 1 shielded note from vault)
│   │   ├── Nargo.toml
│   │   └── src/main.nr
│   └── unshield/                    # Money-out Vault Unshield circuit (1-in / 1-change-out burn to vault)
│       ├── Nargo.toml
│       └── src/main.nr
├── crates/
│   ├── ledger_core/                 # Chain-agnostic Rust state machine (Merkle tree, nullifiers, bb verify)
│   ├── acir_fuzzer/                 # Stage 1: Single-wire + multi-wire relational ACIR witness fuzzer
│   ├── evil_prover_harness/         # Stage 2: Adversarial witness generator + bb verify oracle
│   └── smt_checker/                 # Stage 3: NAVe ACIR -> SMT-LIB -> cvc5 QF_FF runner
└── scripts/
    ├── prove_and_verify.sh          # End-to-end compile, test, gate check, prove, and verify
    └── ci_security_gate.sh          # Runs all verification gates on every PR
```

---

## 4. Core Cryptographic Data Structures & State Model

### Pool Scope & Primitives

* **Single-Asset Shielded Pool:** Phase 1 shields **Perfect Money (PM) only**. There is no `asset_id` field on `Note`; `fee` is unambiguously denominated in PM. (A future multi-asset pool would require homomorphic Pedersen value commitments across per-asset generators.)
* **Scalar Field:** BN254 scalar field with prime modulus `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.
* **Embedded Elliptic Curve:** Grumpkin (`y^2 = x^3 - 17` over BN254 `Fr`, prime order equal to BN254 `Fq`, cofactor `1`, canonical generator `G = (1, sqrt(-16))`). Every Noir `Field` element `< r_BN254 < r_Grumpkin`, so `EmbeddedCurveScalar::from_field(s)` is always strictly less than the Grumpkin group order.
* **Hash Function:** Barretenberg-native **Poseidon2** (`t = 4`, rate `= 3`, capacity `= 1`) via `std::hash::poseidon2_permutation`, using the Aztec standard sponge construction with initial capacity element `IV = (input_len as Field) * 2^64` (`18446744073709551616`), absorbing 3-element chunks into `state[0..3]`, permuting, and squeezing `state[0]`.

### Domain Separation Constants

| Constant | Value | Context |
| :--- | :--- | :--- |
| `DOMAIN_NK` | `1` | Nullifier key derivation from `ask` |
| `DOMAIN_IVK` | `2` | Incoming viewing key derivation from `(ak, nk)` |
| `DOMAIN_DIVERSIFIER` | `3` | Diversified base point x-coordinate derivation |
| `DOMAIN_NOTE_COMMITMENT` | `4` | Shielded note commitment `cm` |
| `DOMAIN_NULLIFIER` | `5` | Deterministic note nullifier `nf` |
| `DOMAIN_MERKLE_NODE` | `6` | Binary Merkle internal node hash |
| `DOMAIN_SHIELD_UNSHIELD` | `7` | Vault shield / unshield bridge commitments |

### Orchard-Style Diversified 3-Key Hierarchy

| Key / Value | Derivation / Rule | Capability & Visibility |
| :--- | :--- | :--- |
| **Spend Key (`ask`)** | Private non-zero `Field` (`ask != 0`) | Root spend authority (never leaves sender's prover). |
| **Authorizing Key (`ak`)** | `ak = fixed_base_scalar_mul(ask)` on Grumpkin | Public component of Full Viewing Key. |
| **Nullifier Key (`nk`)** | `nk = Poseidon2(DOMAIN_NK, ask)` | Combined with `ak` forms `fvk = (ak, nk)` (detects incoming notes and spends, cannot spend). |
| **Incoming Viewing Key (`ivk`)** | `ivk = Poseidon2(DOMAIN_IVK, ak.x, ak.y, nk)` (`ivk != 0`) | Decrypts incoming notes via off-chain Grumpkin ECDH (`shared = ivk * eph_pk`); cannot detect spends or spend. |
| **Diversified Generator (`g_d`)** | `g_d.x = Poseidon2(DOMAIN_DIVERSIFIER, d, g_d_nonce as Field)`; `g_d.y^2 == g_d.x^3 - 17`, `g_d.y != 0` | Publicly verifiable per-invoice base point via `try-and-increment` nonce `g_d_nonce: u8`. |
| **Diversified Address (`pk_d`)** | `pk_d = ivk * g_d` (`multi_scalar_mul`) | Unlimited unlinkable payment addresses `(d, g_d_nonce, pk_d)` under one wallet `ivk`. |

### Note, Commitment, Nullifier & Tree Primitives

| Primitive | Fields / Formula | Visibility | Purpose |
| :--- | :--- | :--- | :--- |
| **Note** | `{ value: u64, owner_pk_x: Field, owner_pk_y: Field, blinding: Field }` | Private | Unspent shielded PM note bound to a Grumpkin diversified public key. |
| **Note Commitment (`cm`)** | `Poseidon2(DOMAIN_NOTE_COMMITMENT, value as Field, owner_pk_x, owner_pk_y, blinding)` | Public (on creation) | Leaf inserted into the global append-only Merkle tree. |
| **Nullifier (`nf`)** | `Poseidon2(DOMAIN_NULLIFIER, nk, cm, leaf_index as Field)` | Public (on spend) | Published to the global nullifier set; prevents double-spends without linking to `cm`. |
| **Merkle Tree** | Depth `32` (`4,294,967,296` leaves), `leaf_index: u32` | Root is Public | Proves a real spent note exists in historical state (`u32` prevents `leaf_index + 2^32` aliasing). |
| **Tx Binding Hash** | `tx_binding_hash: pub Field` (`!= 0`) | Public | Commits to `chain_id`, `protocol_version`, and encrypted note ciphertexts to prevent ciphertext swapping and cross-chain replay. |

### 2-in, 2-out JoinSplit Interface (`circuits/shielded_transfer`)

* **Public Inputs:**
  * `merkle_root: pub Field`
  * `nullifiers: pub [Field; 2]`
  * `out_commitments: pub [Field; 2]`
  * `fee: pub u64`
  * `tx_binding_hash: pub Field`
* **Private Inputs (Witness):**
  * `ask: Field`
  * `in_notes: [Note; 2]` (use `value = 0` with fresh random `blinding` for dummy inputs)
  * `in_diversifiers: [Field; 2]`
  * `in_g_d_nonces: [u8; 2]`
  * `in_g_d_ys: [Field; 2]`
  * `in_leaf_indices: [u32; 2]`
  * `in_merkle_paths: [[Field; 32]; 2]`
  * `out_notes: [Note; 2]`

---

## 5. Constitutional Invariants (Non-Negotiable Circuit Rules)

1. **Non-Degenerate Keys & Transaction Binding:**
   * `tx_binding_hash != 0`.
   * `ask != 0` and derived `ivk != 0`.
2. **Spend Authorization (Diversified Grumpkin Ownership):**
   * For every input note with `value > 0`:
     * `g_d.x = Poseidon2(DOMAIN_DIVERSIFIER, in_diversifiers[i], in_g_d_nonces[i] as Field)`.
     * `(g_d.x, in_g_d_ys[i])` MUST lie on Grumpkin (`y != 0` and `y^2 == x^3 - 17`).
     * `pk_d = ivk * g_d` MUST equal `(in_notes[i].owner_pk_x, in_notes[i].owner_pk_y)`.
3. **Merkle Inclusion (with Safe Dummy Handling):**
   * `in_leaf_indices` MUST be typed `u32` (32-bit constrained before decomposition into Merkle bits).
   * For every input note with `value > 0`, recomputing the depth-32 Poseidon2 Merkle root from `cm(in_notes[i])`, `in_leaf_indices[i]`, and `in_merkle_paths[i]` MUST equal `merkle_root`.
   * For dummy inputs (`value == 0`), the Merkle check and `g_d` on-curve check are skipped, a safe non-zero point (`G`) is fed into `multi_scalar_mul`, **and** the nullifier is still deterministically enforced. Wallets MUST sample a fresh random `blinding` on dummy inputs so dummy nullifiers remain random and indistinguishable on-chain.
4. **Deterministic & Distinct Nullifiers:**
   * `nullifiers[i] == Poseidon2(DOMAIN_NULLIFIER, nk, cm(in_notes[i]), in_leaf_indices[i] as Field)` for both `i in 0..2`.
   * `nullifiers[0] != nullifiers[1]` (blocks spending the same note twice in one JoinSplit).
5. **Output Commitment & Curve Integrity:**
   * For every output `j in 0..2`, `out_commitments[j] == cm(out_notes[j])`.
   * For every non-zero output (`out_notes[j].value > 0`), `(out_notes[j].owner_pk_x, out_notes[j].owner_pk_y)` MUST lie on Grumpkin (`y != 0` and `y^2 == x^3 - 17`), preventing accidental burns to non-curve coordinates.
6. **Strict Value Conservation & Overflow Protection:**
   * All note values and `fee` are `u64`.
   * Summation executes in `u128` (`max = 3 * (2^64 - 1) << 2^128 << p_BN254`) so BN254 modular wrap-around is impossible:
     `(in_notes[0].value as u128) + (in_notes[1].value as u128) == (out_notes[0].value as u128) + (out_notes[1].value as u128) + (fee as u128)`.

---

## 6. Vault Bridge (`circuits/shield`, `circuits/unshield`) & `ledger_core`

### Shared Crypto Library (`circuits/common`) & Vault Bridge Circuits

Shared types, Poseidon2 helpers, Grumpkin diversified key checks, and depth-32 Merkle verification live in a single Noir library crate (`circuits/common`) imported by all circuits so cryptographic primitives are never duplicated.

Connecting transparent Phase 2 collateral vaults to the shielded UTXO pool uses two purpose-built circuits rather than a single conditional `if mint / else burn` circuit (since the transparent vault always sees whether PM is entering or exiting the pool):

* **Money-In (`circuits/shield`):** Authorized when a transparent vault creates `mint_amount: pub u64` of PM debt (or shields existing unshielded PM). Public inputs: `(mint_amount: pub u64, out_commitment: pub Field, tx_binding_hash: pub Field)`. Enforces `mint_amount > 0`, `tx_binding_hash != 0`, `(out_note.owner_pk_x, out_note.owner_pk_y)` on Grumpkin, `out_note.value == mint_amount`, and `out_commitment == cm(out_note)` (~500 gates; no Merkle proof).
* **Money-Out (`circuits/unshield`):** Authorized when repaying vault debt or redeeming collateral (or unshielding PM to transparent staking/AMM). Public inputs: `(merkle_root: pub Field, nullifier: pub Field, change_commitment: pub Field, burn_amount: pub u64, fee: pub u64, tx_binding_hash: pub Field)`. Enforces 1-in / 1-change-out spend authorization, Merkle inclusion, deterministic nullifier, on-curve change pubkey (if `change_note.value > 0`), and `in_note.value as u128 == (burn_amount as u128) + (change_note.value as u128) + (fee as u128)`.

### `crates/ledger_core` (Chain-Agnostic State Engine)

Pure Rust state-transition library (no consensus/network assumptions):
* Append-only depth-32 Poseidon2 commitment Merkle tree + historical root ring buffer.
* Nullifier set with double-spend rejection.
* Barretenberg (`bb`) / `noir_rs` proof & public-input verification wrapper across `shield`, `shielded_transfer`, and `unshield`.
* Public supply accumulator enforcing `sum(shield_mints) - sum(unshield_burns) == total_shielded_supply` against transparent vault balances.

---

## 7. Automated 4-Stage Verification & Fuzzing Pipeline

| Stage | Engine | Goal | Failure Condition |
| :--- | :--- | :--- | :--- |
| **Stage 1: Relational Witness Fuzzer** | Rust (`acvm` + `bb`) | Apply single-wire perturbations (`+1`, `-1`, `0`, `p-1`, `2^64`) AND **multi-wire relational mutations** (paired value shifts, `u64` boundary swaps, `leaf_index` aliases, dummy edge cases). | Any invariant-violating witness survives ACIR solving or passes `bb verify`. |
| **Stage 2: Evil Prover Swarm** | Adversarial scripts + `bb` | Fix compiled ACIR; synthesize malicious witnesses targeting overflow, dummy notes, off-curve pubkeys, and nullifier reuse against real `bb prove && bb verify`. | Confirmed exploit passing `bb verify`. |
| **Stage 3: Formal ACIR Proof (`smt_checker`)** | Rust (`crates/smt_checker`) + `cvc5` (`ALL`: `(_ FiniteField p)` + UF + `QF_LIA`) | Translate compiled Noir 1.0.0 ACIR directly into solved-form SMT-LIB finite-field + uninterpreted-function formulas (implementing NAVe's ACIR-to-cvc5 semantics natively for Noir 1.0.0), audit `RANGE` opcodes, prove BN254 `ValueConservation` non-wrap (`QF_LIA`), and verify 1-copy invariants + 2-copy uniqueness (`exists x, w1, w2: C(x, w1) /\ C(x, w2) /\ (y1 != y2)`). | `cvc5` returns `SAT` (on invariant/uniqueness) or `UNSAT` (on witness consistency), or any `RANGE` bound is missing. |
| **Stage 4: CI Security Gate** | Script / GitHub Actions | Enforce `--deny-warnings`, block unvetted `unconstrained fn`, and run Stages 1–3 on every PR. | Any check fails or regresses. |

---

## 8. Phase 1 Definition of Done & Handoff

Phase 1 completes when all five gates pass:

1. **Functional Gate:** `shielded_transfer`, `shield`, and `unshield` (backed by `circuits/common`) compile with `nargo compile --deny-warnings` and pass 100% of positive and negative unit tests (`nargo test --deny-warnings`).
2. **Performance Gate:** Client-side UltraHonk proof generation benchmarks `< 2.0s` on a mid-range smartphone (`noir_rs` / Swoir / NoirAndroid).
3. **Fuzzing Gate:** `acir_fuzzer` reports zero unexpected unconstrained or relationally exploitable witness wires across all three circuits.
4. **Adversarial Gate:** At least 50 independent Evil Prover runs yield zero verified exploits against `bb verify`.
5. **Formal Gate:** `crates/smt_checker` + `cvc5` (`(_ FiniteField p)` + UF + `QF_LIA`) formal proofs pass across all three compiled ACIR artifacts (`shield`, `unshield`, `shielded_transfer`), covering witness consistency, `RANGE` audit, `ValueConservation` non-wrap, full-ACIR invariants, and 2-copy uniqueness.

### Phase 3 Handoff Note (Offline Mesh Architecture)

Offline BLE/NFC payments in Phase 3 do **not** run P-256 verification inside `shielded_transfer` (which costs ~150k–250k+ non-native gates per signature). Instead, users lock a small PM balance into a **capped-value offline pocket voucher** bound to an Apple Secure Enclave / Android StrongBox P-256 key and hardware monotonic counter, and periodically settle spent vouchers back into the online shielded pool.

