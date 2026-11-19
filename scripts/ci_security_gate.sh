#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "============================================================"
echo "==> Gate 0: Static compiler & circuit safety checks"
echo "============================================================"
if grep -rn "unconstrained" "$ROOT_DIR"/circuits/*/src; then
    echo "ERROR: unconstrained function found in circuit source!"
    exit 1
fi
if grep -rn --exclude=ci_security_gate.sh -E -- '--skip-underconstrained-check|--skip-brillig-constraints-check' "$ROOT_DIR/scripts"; then
    echo "ERROR: forbidden underconstrained skip flag found in scripts!"
    exit 1
fi
echo "Static safety checks passed."

echo ""
echo "============================================================"
echo "==> Gate 1: Functional Gate (prove_and_verify.sh)"
echo "============================================================"
bash "$ROOT_DIR/scripts/prove_and_verify.sh"

echo ""
echo "============================================================"
echo "==> Gate 2: Stage 1 ACIR Fuzzer (fuzz_all_circuits.sh)"
echo "============================================================"
bash "$ROOT_DIR/scripts/fuzz_all_circuits.sh"

echo ""
echo "============================================================"
echo "==> Gate 3: Stage 2 Evil Prover Harness (70 real attacks)"
echo "============================================================"
cargo run --release -p evil_prover_harness -- --report "$ROOT_DIR/target/evil_prover_report.json"

echo ""
echo "============================================================"
echo "==> Gate 4: Stage 3 Formal Proofs (smt_checker + cvc5)"
echo "============================================================"
cargo run --release -p smt_checker -- --report "$ROOT_DIR/target/smt_checker_report.json"

echo ""
echo "============================================================"
echo "==> Gate 5: Full Rust Workspace Tests (unit, canary, parity, e2e)"
echo "============================================================"
cargo test --workspace

echo ""
echo "ALL CI SECURITY GATES PASSED."

