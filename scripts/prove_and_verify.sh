#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Tool versions"
nargo --version
bb --version
cvc5 --version | head -n 2

for CIRCUIT in shield shielded_transfer unshield; do
    CIRCUIT_DIR="$ROOT_DIR/circuits/$CIRCUIT"
    cd "$CIRCUIT_DIR"

    echo ""
    echo "============================================================"
    echo "==> [$CIRCUIT] Compiling (--deny-warnings)"
    echo "============================================================"
    nargo compile --deny-warnings

    echo "==> [$CIRCUIT] Running Noir unit tests (--deny-warnings)"
    nargo test --deny-warnings

    echo "==> [$CIRCUIT] Inspecting UltraHonk gate count"
    bb gates -b "./target/${CIRCUIT}.json"

    echo "==> [$CIRCUIT] Executing witness from Prover.toml"
    nargo execute witness

    echo "==> [$CIRCUIT] Writing verification key"
    bb write_vk -b "./target/${CIRCUIT}.json" -o ./target

    echo "==> [$CIRCUIT] Generating UltraHonk proof (timed)"
    START_NS=$(date +%s%N)
    bb prove -b "./target/${CIRCUIT}.json" -w ./target/witness.gz -k ./target/vk -o ./target
    END_NS=$(date +%s%N)
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
    echo "[$CIRCUIT] Proof generated in ${ELAPSED_MS} ms"

    echo "==> [$CIRCUIT] Verifying UltraHonk proof"
    bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs
    echo "[$CIRCUIT] Proof verified successfully."
done
