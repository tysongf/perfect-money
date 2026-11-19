#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CIRCUIT_DIR="$ROOT_DIR/circuits/shielded_transfer"
cd "$CIRCUIT_DIR"

echo "==> Tool versions"
nargo --version
bb --version
cvc5 --version | head -n 2

echo "==> Compiling shielded_transfer (--deny-warnings)"
nargo compile --deny-warnings

echo "==> Running Noir unit tests (--deny-warnings)"
nargo test --deny-warnings

echo "==> Inspecting UltraHonk gate count"
bb gates -b ./target/shielded_transfer.json

echo "==> Executing witness from Prover.toml"
nargo execute witness

echo "==> Writing verification key"
bb write_vk -b ./target/shielded_transfer.json -o ./target

echo "==> Generating UltraHonk proof (timed)"
START_NS=$(date +%s%N)
bb prove -b ./target/shielded_transfer.json -w ./target/witness.gz -k ./target/vk -o ./target
END_NS=$(date +%s%N)
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
echo "Proof generated in ${ELAPSED_MS} ms"

echo "==> Verifying UltraHonk proof"
bb verify -p ./target/proof -k ./target/vk -i ./target/public_inputs

echo "Proof verified successfully."

