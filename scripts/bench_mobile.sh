#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="$ROOT_DIR/bench/mobile"

cd "$ROOT_DIR"

if [[ ! -d "$BENCH_DIR/node_modules" ]]; then
  echo "==> Installing mobile benchmark dependencies..."
  npm --prefix "$BENCH_DIR" install
fi

echo "==> Running mobile benchmark suite (native constrained + Node pure-WASM)..."
npm --prefix "$BENCH_DIR" run bench

echo "==> Building mobile browser benchmark web app (Vite)..."
npm --prefix "$BENCH_DIR" run build

echo ""
echo "Mobile benchmark reports:"
echo "  - $ROOT_DIR/target/mobile_bench_native.json"
echo "  - $ROOT_DIR/target/mobile_bench_wasm_node.json"
echo "To benchmark on a real phone over LAN, run: bash scripts/bench_mobile_phone_server.sh"

