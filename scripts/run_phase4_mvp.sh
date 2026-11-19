#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Running Phase 4 Wedge MVP suite (pm_sdk, pm_node + real UltraHonk E2E, pm_cli)..."
cargo test -p pm_sdk -p pm_node -p pm_cli --all-targets

