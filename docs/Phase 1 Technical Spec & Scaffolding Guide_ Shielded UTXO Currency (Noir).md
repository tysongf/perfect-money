# **Phase 1 Technical Spec & Scaffolding Guide: Shielded UTXO Currency (Noir)**

# **1\. Executive Overview & Architecture Summary**

This document serves as the machine-readable specification and project scaffolding blueprint for Phase 1 of a sovereign, two-layer monetary system. It is designed for a solo developer operating as Chief Architect and Adversarial Director with access to high-volume LLM compute.

## **Core System Pillars**

* **Value Anchor (Phase 2):** Supply adjusts algorithmically to maintain purchasing power against a global basket of essential goods and energy, enforced by Schelling-point adversarial oracles and hard-coded annual rate limits.  
* **Privacy & Auditability (Phase 1 — This Document):** Cash-like privacy for individual transactions via zero-knowledge proofs (Shielded UTXO model), paired with real-time cryptographic auditability of total money supply.  
* **Settlement Rails (Phase 3):** Instant, near-zero-fee digital settlement plus offline BLE/NFC mesh payments backed by hardware Secure Enclaves.  
* **Governance:** Constitutional ossification of core invariants, bicameral veto power, and credible open-source exit.

## **Why Noir 1.0 \+ Barretenberg**

* **Stable Toolchain:** [Noir 1.0](https://aztec.network/blog/noir-1-0-is-live) provides a stable, Rust-like zkDSL with semantic versioning in `nargo`, minimizing LLM code-generation hallucinations compared to lower-level circuit frameworks like Halo2.  
* **Lower Under-Constrained Risk:** Control flow and arithmetic compile to constraints automatically in ACIR (Abstract Circuit Intermediate Representation), isolating most soundness risks to explicit `unconstrained` (Brillig) helper functions.  
* **Mobile-Ready Performance:** Compiling to ACIR with the [Barretenberg](https://barretenberg.aztec.network/docs/getting_started/) (`bb`) UltraHonk backend enables sub-second client-side proving on modern smartphones via [noir\_rs](https://github.com/zkpassport/noir_rs), Swoir (iOS), and NoirAndroid.

# **2\. Environment Setup & Toolchain Prerequisites**

Install the following toolchain on your development machine (Linux or macOS recommended):h

# **1\. Install Rust toolchain**

curl \--proto '=https' \--tlsv1.2 \-sSf https\://sh.rustup.rs \| sh

# **2\. Install Noir 1.0 (nargo) via noirup**

curl \-L https\://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install \| bash  
noirup

# **3\. Install Barretenberg (bb) proving backend via bbup**

curl \-L https\://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/master/barretenberg/bbup/install \| bash  
bbup

# **4\. Verify installations**

nargo \--version  
bb \--version

````

### Additional Verification Tools
* **jq:** JSON processing for inspecting compiled ACIR artifacts (`brew install jq` or `apt install jq`).
* **CVC5:** SMT solver with native finite-field (`--finite-field`) theory support for Stage 3 formal uniqueness proofs.

### Mandatory Compiler Safety Rules
Per the [Nargo Reference](https://noir-lang.org/docs/reference/nargo_commands), always compile with `--deny-warnings` in CI. **Strictly forbid** `--skip-underconstrained-check` and `--skip-brillig-constraints-check` in all build scripts and agent workflows.

## 3. Target Monorepo Directory Layout

```text
perfect-money/
├── README.md
├── specs/
│   ├── phase1_utxo_spec.md          # Canonical invariants & byte layouts
│   └── smt_invariants.smt2          # Generated CVC5 uniqueness templates
├── circuits/
│   ├── shielded_transfer/           # 2-in, 2-out private JoinSplit circuit
│   │   ├── Nargo.toml
│   │   ├── Prover.toml
│   │   └── src/
│   │       ├── main.nr
│   │       ├── types.nr
│   │       ├── crypto.nr
│   │       └── merkle.nr
│   └── supply_mint_burn/            # Publicly auditable supply delta circuit
│       ├── Nargo.toml
│       └── src/main.nr
├── crates/
│   ├── acir_fuzzer/                 # Stage 1: Deterministic ACIR witness-mutation fuzzer
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── evil_prover_harness/         # Stage 2: WitnessMap mutator + bb verify oracle
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   └── smt_checker/                 # Stage 3: ACIR JSON -> SMT-LIB -> CVC5 runner
│       ├── Cargo.toml
│       └── src/main.rs
└── scripts/
    ├── prove_and_verify.sh          # End-to-end nargo execute + bb prove + bb verify
    └── ci_security_gate.sh          # Runs all verification stages on every PR
````

# **4\. Core Cryptographic Data Structures & State Model**

## **Field & Hash Parameters**

* **Scalar Field:** BN254 scalar field with prime modulus `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`.  
* **Hash Function:** Poseidon / Poseidon2 over BN254 (ZK-friendly arithmetic hash).  
* **Domain Separation Constants:** Every distinct hash context MUST use a unique domain tag to prevent cross-protocol collision attacks:  
  * `DOMAIN_OWNER_PK = 1`  
  * `DOMAIN_NOTE_COMMITMENT = 2`  
  * `DOMAIN_NULLIFIER = 3`  
  * `DOMAIN_MERKLE_NODE = 4`

## **Data Primitives**

| Primitive | Fields / Formula | Visibility | Purpose |
| :---- | :---- | :---- | :---- |
| **Note** | `{ value: u64, asset_id: Field, owner_pk: Field, blinding: Field }` | Private | Represents an unspent shielded balance. |
| **Owner Public Key** | `owner_pk = H(DOMAIN_OWNER_PK, owner_sk)` | Private | Proves spend authority without revealing identity. |
| **Note Commitment** | `cm = H(DOMAIN_NOTE_COMMITMENT, value, asset_id, owner_pk, blinding)` | Public (on creation) | Leaf stored in the global append-only Merkle tree. |
| **Nullifier** | `nf = H(DOMAIN_NULLIFIER, owner_sk, cm, leaf_index)` | Public (on spend) | Published to the global nullifier set to prevent double-spending without linking to `cm`. |
| **Merkle Tree** | Depth `32` (supports 4,294,967,296 notes) | Root is Public | Proves a spent note exists in historical state. |

## **2-in, 2-out JoinSplit Interface**

* **Public Inputs:**  
  * `merkle_root: pub Field` — Historical root of the note commitment tree.  
  * `nullifiers: pub [Field; 2]` — Nullifiers of the two consumed input notes.  
  * `out_commitments: pub [Field; 2]` — Commitments of the two newly created output notes.  
  * `fee: pub u64` — Optional transaction fee (set to `0` for zero-fee transfers).  
* **Private Inputs (Witness):**  
  * `owner_sk: Field` — Spending secret key of the sender.  
  * `in_notes: [Note; 2]` — Two input notes being spent (use `value = 0` for dummy inputs).  
  * `in_leaf_indices: [Field; 2]` — Leaf positions in the commitment tree.  
  * `in_merkle_paths: [[Field; 32]; 2]` — Sibling hashes for Merkle inclusion proofs.  
  * `out_notes: [Note; 2]` — Two output notes (recipient \+ change).

# **5\. Constitutional Invariants (Non-Negotiable Circuit Rules)**

Every coding agent and verification harness must enforce these six invariants:

1. **Spend Authorization:** For every input note with `value > 0`, `in_notes[i].owner_pk` MUST equal `H(DOMAIN_OWNER_PK, owner_sk)`.  
2. **Merkle Inclusion (with Safe Dummy Handling):** For every input note with `value > 0`, recomputing the Merkle root from `cm(in_notes[i])`, `in_leaf_indices[i]`, and `in_merkle_paths[i]` MUST equal the public `merkle_root`. If `value == 0` (dummy note), the Merkle check may be skipped, **but** its nullifier must still be validly derived to prevent malleability.  
3. **Deterministic Nullifiers:** Every public `nullifiers[i]` MUST equal `H(DOMAIN_NULLIFIER, owner_sk, cm(in_notes[i]), in_leaf_indices[i])`, and `nullifiers[0] != nullifiers[1]` (prevents spending the same note twice in a single transaction).  
4. **Strict Value Conservation & Overflow Protection:**  
   * All note values and `fee` MUST be constrained to `u64` (64-bit unsigned range checks).  
   * Perform summation in `u128` (or checked `u64` / bounded `Field` arithmetic where `max_sum = 3 * (2^64 - 1) << p`) so modular wrap-around in BN254 is mathematically impossible.  
   * Enforce: `(in_notes[0].value as u128) + (in_notes[1].value as u128) == (out_notes[0].value as u128) + (out_notes[1].value as u128) + (fee as u128)`.  
5. **Asset Homogeneity:** All non-zero input notes and non-zero output notes MUST share the exact same `asset_id`.  
6. **Output Commitment Integrity:** Every public `out_commitments[j]` MUST equal `cm(out_notes[j])`.

# **6\. Starter Code Scaffolding**

## **6.1 `circuits/shielded_transfer/Nargo.toml`**

l  
\[package\]  
name \= "shielded\_transfer"  
type \= "bin"  
authors \= \["Your Name"\]  
compiler\_version \= "\>=1.0.0"

\[dependencies\]  
poseidon \= { tag \= "v0.1.1", git \= "https\://github.com/noir-lang/poseidon" }

````

### 6.2 `circuits/shielded_transfer/src/types.nr`
```rust
pub global MERKLE_DEPTH: u32 = 32;

pub global DOMAIN_OWNER_PK: Field = 1;
pub global DOMAIN_NOTE_COMMITMENT: Field = 2;
pub global DOMAIN_NULLIFIER: Field = 3;
pub global DOMAIN_MERKLE_NODE: Field = 4;

pub struct Note {
    pub value: u64,
    pub asset_id: Field,
    pub owner_pk: Field,
    pub blinding: Field,
}
````

## **6.3 `circuits/shielded_transfer/src/crypto.nr`**

```
use dep::poseidon::poseidon::bn254;
use crate::types::{
    Note, DOMAIN_OWNER_PK, DOMAIN_NOTE_COMMITMENT, DOMAIN_NULLIFIER, DOMAIN_MERKLE_NODE
};

pub fn derive_owner_pk(owner_sk: Field) -> Field {
    bn254::hash_2([DOMAIN_OWNER_PK, owner_sk])
}

pub fn compute_note_commitment(note: Note) -> Field {
    bn254::hash_5([
        DOMAIN_NOTE_COMMITMENT,
        note.value as Field,
        note.asset_id,
        note.owner_pk,
        note.blinding,
    ])
}

pub fn compute_nullifier(owner_sk: Field, commitment: Field, leaf_index: Field) -> Field {
    bn254::hash_4([DOMAIN_NULLIFIER, owner_sk, commitment, leaf_index])
}

pub fn hash_merkle_node(left: Field, right: Field) -> Field {
    bn254::hash_3([DOMAIN_MERKLE_NODE, left, right])
}
```

## **6.4 `circuits/shielded_transfer/src/merkle.nr`**

```
use crate::types::MERKLE_DEPTH;
use crate::crypto::hash_merkle_node;

pub fn compute_merkle_root(
    leaf: Field,
    leaf_index: Field,
    siblings: [Field; MERKLE_DEPTH]
) -> Field {
    let index_bits: [u1; MERKLE_DEPTH] = leaf_index.to_le_bits();
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
        let is_right = index_bits[i];
        let (left, right) = if is_right == 1 {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hash_merkle_node(left, right);
    }

    current
}
```

## **6.5 `circuits/shielded_transfer/src/main.nr`**

```
mod types;
mod crypto;
mod merkle;

use types::{Note, MERKLE_DEPTH};
use crypto::{derive_owner_pk, compute_note_commitment, compute_nullifier};
use merkle::compute_merkle_root;

fn main(
    // Public inputs
    merkle_root: pub Field,
    nullifiers: pub [Field; 2],
    out_commitments: pub [Field; 2],
    fee: pub u64,

    // Private inputs
    owner_sk: Field,
    in_notes: [Note; 2],
    in_leaf_indices: [Field; 2],
    in_merkle_paths: [[Field; MERKLE_DEPTH]; 2],
    out_notes: [Note; 2],
) {
    let derived_pk = derive_owner_pk(owner_sk);

    // 1. Validate inputs: ownership, Merkle membership, and nullifiers
    for i in 0..2 {
        let note = in_notes[i];
        let cm = compute_note_commitment(note);
        let expected_nf = compute_nullifier(owner_sk, cm, in_leaf_indices[i]);
        assert(nullifiers[i] == expected_nf, "Invalid nullifier");

        if note.value > 0 {
            assert(note.owner_pk == derived_pk, "Unauthorized spend");
            let computed_root = compute_merkle_root(cm, in_leaf_indices[i], in_merkle_paths[i]);
            assert(computed_root == merkle_root, "Invalid Merkle inclusion proof");
        }
    }

    // Prevent spending the exact same note twice in one JoinSplit
    assert(nullifiers[0] != nullifiers[1], "Duplicate nullifiers");

    // 2. Validate output commitments
    for j in 0..2 {
        let out_cm = compute_note_commitment(out_notes[j]);
        assert(out_commitments[j] == out_cm, "Invalid output commitment");
    }

    // 3. Enforce asset homogeneity across all non-zero notes
    let ref_asset = in_notes[0].asset_id;
    if in_notes[1].value > 0 {
        assert(in_notes[1].asset_id == ref_asset, "Mismatched input asset_id");
    }
    for j in 0..2 {
        if out_notes[j].value > 0 {
            assert(out_notes[j].asset_id == ref_asset, "Mismatched output asset_id");
        }
    }

    // 4. Value conservation in u128 to prevent BN254 field wrap-around
    let total_in: u128 = (in_notes[0].value as u128) + (in_notes[1].value as u128);
    let total_out: u128 = (out_notes[0].value as u128)
        + (out_notes[1].value as u128)
        + (fee as u128);
    assert(total_in == total_out, "Value conservation violated");
}
```

## **6.6 End-to-End Proving & Verification Script (`scripts/prove_and_verify.sh`)**

```
#!/usr/bin/env bash
set -euo pipefail

cd circuits/shielded_transfer

# Compile with strict warning checks (never skip underconstrained checks)
nargo compile --deny-warnings

# Execute circuit against Prover.toml to produce witness (.gz)
nargo execute witness

# Generate UltraHonk proof and verification key via Barretenberg
bb prove -b ./target/shielded_transfer.json -w ./target/witness.gz --write_vk -o ./target

# Verify proof
bb verify -p ./target/proof -k ./target/vk
echo "Proof verified successfully."
```

# **7\. Automated 4-Stage LLM Verification & Fuzzing Pipeline**

Standard unit tests only validate the honest prover. To catch **under-constrained bugs** (where a malicious prover can forge valid proofs for invalid state transitions), wire up this 4-stage pipeline:

| Stage | Engine | Goal | Failure Condition |
| :---- | :---- | :---- | :---- |
| **Stage 1: Witness-Mutation Fuzzer** | Rust (`acvm` crate \+ `bb`) | Perturb every non-dead wire `w_i` in the serialized `WitnessMap` (`w_i + 1`, `0`, `p - 1`) and re-verify. | Any wire mutation that violates an invariant yet passes `bb verify`. |
| **Stage 2: LLM Evil Prover Swarm** | Parallel LLM agents \+ `bb` | Agents keep ACIR constraints fixed, synthesize malicious witnesses/Brillig hints targeting edge cases (overflow, dummy notes, nullifier reuse), and run `bb prove && bb verify`. | Confirmed critical exploit (0% false positives because the real verifier is the oracle). |
| **Stage 3: Compositional SMT Check** | ACIR JSON \-\> SMT-LIB \-\> CVC5 (`--finite-field`) | Decompose circuit into sub-gadgets (`ValueConservation`, `MerkleStep`, `Nullifier`) and check uniqueness: `exists x, w1, w2 : C(x, w1) AND C(x, w2) AND (y1 != y2)`. | CVC5 returns `SAT` and counterexample replays against Stage 1 verifier. |
| **Stage 4: CI Security Gate** | GitHub Actions / Local Runner | Reject any PR that introduces an `unconstrained fn` without a sibling negative test, or fails Stages 1–3. | Merge blocked until patched and re-verified. |

## **Starter Rust Harness Outline (`crates/acir_fuzzer/src/main.rs`)**

Your coding agent should build `acir_fuzzer` around the following loop:

1. Load compiled ACIR JSON (`target/shielded_transfer.json`) and baseline witness (`target/witness.gz`) using the `acvm` / `acir` Rust crates (or [noir\_rs](https://github.com/zkpassport/noir_rs)).  
2. Iterate through every witness index `w_i` in the `WitnessMap`.  
3. Clone the `WitnessMap`, mutate `w_i` with adversarial deltas (`+1`, `-1`, `0`, `p - 1`, `2^64`), and serialize the mutated witness to a temp file.  
4. Invoke `bb prove` \+ `bb verify` (or evaluate ACIR opcodes directly in-memory via `acvm` first for 100x speed, then confirm hits with `bb`).  
5. Log any witness index that can be freely mutated without causing constraint failure, excluding explicitly whitelisted unused dummy witnesses.

# **8\. Ready-to-Paste Prompts for Your LLM Agent Swarm**

When you are back at a keyboard, paste these prompts sequentially into your coding agents:

## **Prompt A: Initialize Repo & Unit Test Suite**

"Using Section 3 through Section 6 of specs/phase1\_utxo\_spec.md, initialize the perfect-money monorepo. Create circuits/shielded\_transfer, verify it compiles cleanly under Noir 1.0 with nargo compile \--deny-warnings, and write a comprehensive Noir unit test suite in src/main.nr covering: (1) valid 2-in/2-out transfer, (2) valid 1-in/2-out transfer using a zero-value dummy note, (3) unauthorized spend (\#\[test(should\_fail)\]), (4) duplicate nullifier (\#\[test(should\_fail)\]), (5) mismatched asset\_id (\#\[test(should\_fail)\]), and (6) value conservation mismatch (\#\[test(should\_fail)\]). Also generate a valid `Prover.toml` and verify `scripts/prove_and_verify.sh` passes end-to-end."

## **Prompt B: Build the ACIR Witness-Mutation Fuzzer**

"Build the Rust crate crates/acir\_fuzzer. It must deserialize the compiled Noir 1.0 ACIR artifact (`target/shielded_transfer.json`) and valid witness (`target/witness.gz`), iterate over every witness index in the WitnessMap, apply mutations (+1, 0, p-1, 1 \<\< 64), and check whether all ACIR AssertZero, Range, and blackbox constraints remain satisfied. Any surviving mutation must be automatically confirmed by invoking bb prove and bb verify and dumped as a reproducible JSON report."

## **Prompt C: Launch the "Evil Prover" Red-Team Agent**

"You are an adversarial cryptographic auditor attacking `circuits/shielded_transfer`. The circuit operates over the BN254 scalar field (`p = 21888242871839275222246405745257275088548364400416034343698204186575808495617`). Your goal is to forge a valid Barretenberg proof (`bb verify` exits 0\) that violates at least one Constitutional Invariant in Section 5 (e.g., minting value out of thin air via field wrap-around, spending a note without owning owner\_sk, or exploiting dummy zero-value note edge cases). You may NOT modify the circuit constraints, only `Prover.toml` or the serialized WitnessMap. Write automated exploit scripts in crates/evil\_prover\_harness and run them against bb verify."

## **Prompt D: Add the Publicly Auditable Mint/Burn Circuit**

"Create circuits/supply\_mint\_burn following the same cryptographic primitives in shielded\_transfer. It must prove creation or destruction of shielded notes while exposing a public `signed_supply_delta` so any external observer can verify total shielded money supply in real time without learning recipient identities."

# **9\. Phase 1 Definition of Done & Handoff to Phase 2**

Phase 1 is complete when all five gates pass:

* **Functional Gate:** `shielded_transfer` and `supply_mint_burn` compile with `nargo compile --deny-warnings` and pass 100% of positive and negative unit tests.  
* **Performance Gate:** Client-side proof generation benchmarks under **2.0 seconds** on a mid-range smartphone (via `noir_rs` / Swoir / NoirAndroid).  
* **Fuzzing Gate:** `acir_fuzzer` reports zero unexpected unconstrained witness wires across both circuits.  
* **Adversarial Gate:** At least 50 independent Evil Prover red-team runs produce zero verified exploits against `bb verify`.  
* **Formal Gate:** CVC5 `--finite-field` uniqueness checks pass on `ValueConservation` and `Nullifier` sub-gadgets (with Poseidon stubbed as an uninterpreted function).

## **Next Milestones After Phase 1**

* **Phase 2 (Months 4–6):** Build the Python/Rust multi-agent economic simulator for the Energy-and-Goods Basket Peg, Schelling-point oracle staking, asymmetric slashing, and 2%/year constitutional rate limits.  
* **Phase 3 (Months 7–9):** Prototype offline BLE/NFC mesh transfers with Secure Enclave monotonic counters and optimistic online sync.  
* **Phase 4 (Months 10–12):** Ship the focused "Wedge MVP" (e.g., an open-source AI-agent micro-payment SDK or zero-fee local merchant checkout app).

