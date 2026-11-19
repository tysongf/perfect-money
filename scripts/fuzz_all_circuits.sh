#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Building acir_fuzzer (release)"
cd "$ROOT_DIR"
cargo build --release -p acir_fuzzer

for CIRCUIT in shield shielded_transfer unshield; do
    CIRCUIT_DIR="$ROOT_DIR/circuits/$CIRCUIT"
    cd "$CIRCUIT_DIR"

    echo ""
    echo "==> [$CIRCUIT] Compiling, executing Prover.toml, writing VK"
    nargo compile --deny-warnings
    nargo execute witness
    bb write_vk -b "./target/${CIRCUIT}.json" -o ./target

    echo "==> [$CIRCUIT] Running acir_fuzzer (strict mode)"
    "$ROOT_DIR/target/release/acir_fuzzer" \
        --artifact "./target/${CIRCUIT}.json" \
        --witness "./target/witness.gz" \
        --vk "./target/vk" \
        --report "./target/acir_fuzzer_report.json"
done

echo ""
echo "All 3 circuits passed Stage 1 acir_fuzzer with 0 unexpected survivors and 0 exploits."

