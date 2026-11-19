# Perfect Money

A sovereign, privacy-preserving digital currency engineered across four phases:

1. **Phase 1 — Shielded UTXO Layer (Active):** Single-asset Noir 1.0 + Barretenberg UltraHonk shielded JoinSplit pool using Poseidon2 (`t = 4`), Grumpkin diversified 3-key hierarchy (`ask` / `nk` / `ivk` / `pk_d`), and a chain-agnostic Rust `ledger_core`, formally checked via multi-stage fuzzing and `cvc5` (`NAVe`).
2. **Phase 2 — Monetary Engine & Adversarial Red-Teaming:** Energy-and-goods geometric basket peg with Liquity-v2-style hard redemptions against a PID-smoothed target, 100% censorship-resistant isolated crypto collateral branches, Hybrid Stability Pools + Insurance Reserve, and a single-token Schelling-point oracle stress-tested by an LLM red-team swarm.
3. **Phase 3 — Offline Mesh Settlement:** Decoupled capped-value offline BLE/NFC pocket vouchers backed by hardware Secure Enclaves / StrongBox (P-256 + monotonic counters).
4. **Phase 4 — Wedge MVP:** Production client/SDK integration.

## Specifications

* [Phase 1 Spec: Shielded UTXO Currency (Noir)](specs/phase1_utxo_spec.md)
* [Phase 2 Spec: Basket Peg, Adversarial Oracles & Economic Simulator](specs/phase2_peg_oracle_spec.md)

## Quickstart (Phase 1)

Prerequisites: `rustup`/`cargo`, `nargo` (Noir 1.0+), `bb` (Barretenberg), `cvc5` (GPL static build with finite-field `QF_FF` support), and `jq`.

```bash
./scripts/prove_and_verify.sh
```

