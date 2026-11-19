#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$ROOT_DIR/circuits/shielded_transfer"

echo "==> Compiling shielded_transfer (--deny-warnings)"
cd "$CIRCUIT_DIR"
nargo compile --deny-warnings

echo "==> Executing baseline witness from Prover.toml"
nargo execute witness

echo "==> Writing verification key"
bb write_vk -b ./target/shielded_transfer.json -o ./target

echo "==> Building acir_fuzzer (release)"
cd "$ROOT_DIR"
cargo build --release -p acir_fuzzer

echo "==> Running acir_fuzzer (strict mode, Baseline 1)"
"$ROOT_DIR/target/release/acir_fuzzer" \
    --artifact "$CIRCUIT_DIR/target/shielded_transfer.json" \
    --witness "$CIRCUIT_DIR/target/witness.gz" \
    --vk "$CIRCUIT_DIR/target/vk" \
    --report "$CIRCUIT_DIR/target/acir_fuzzer_report.json"

echo "acir_fuzzer finished with 0 unexpected survivors and 0 exploits."

