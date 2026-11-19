#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Running Phase 3 ledger_core + offline_vouchers test suite (including real UltraHonk bridge)..."
cargo test -p ledger_core -p offline_vouchers --all-targets

