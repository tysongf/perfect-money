#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BENCH_DIR="$ROOT_DIR/bench/mobile"
CERT_DIR="$BENCH_DIR/.certs"
PORT="${PORT:-4173}"
MODE="https"

if [[ "${1:-}" == "--http" ]]; then
  MODE="http"
fi

if [[ ! -d "$BENCH_DIR/node_modules" ]]; then
  echo "==> Installing mobile benchmark dependencies..."
  npm --prefix "$BENCH_DIR" install
fi

echo "==> Preparing circuit fixtures..."
npm --prefix "$BENCH_DIR" run fixtures

LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
if [[ -z "$LAN_IP" ]]; then
  LAN_IP="127.0.0.1"
fi

if [[ "$MODE" == "https" ]] && command -v openssl >/dev/null 2>&1; then
  mkdir -p "$CERT_DIR"
  if [[ ! -f "$CERT_DIR/cert.pem" || ! -f "$CERT_DIR/key.pem" ]]; then
    echo "==> Generating self-signed TLS certificate for $LAN_IP..."
    openssl req -x509 -newkey rsa:2048 -nodes \
      -keyout "$CERT_DIR/key.pem" \
      -out "$CERT_DIR/cert.pem" \
      -days 30 \
      -subj "/CN=perfect-money-mobile-bench" \
      -addext "subjectAltName=IP:${LAN_IP},IP:127.0.0.1,DNS:localhost" >/dev/null 2>&1
  fi
  export MOBILE_BENCH_HTTPS=1
  echo ""
  echo "==> Open on your phone (accept the self-signed certificate warning so SharedArrayBuffer / crossOriginIsolated=true works):"
  echo "    https://${LAN_IP}:${PORT}"
  echo "    https://localhost:${PORT}"
  echo ""
else
  if [[ "$MODE" == "https" ]]; then
    echo "WARN: openssl not found; falling back to plain HTTP (browsers on LAN may restrict crossOriginIsolated to single-thread WASM)."
  fi
  export MOBILE_BENCH_HTTPS=0
  echo ""
  echo "==> Open in browser:"
  echo "    http://localhost:${PORT}"
  echo "    http://${LAN_IP}:${PORT}  (NOTE: plain HTTP over LAN is not a secure context -> 1-thread WASM)"
  echo ""
fi

cd "$BENCH_DIR"
exec ./node_modules/.bin/vite --host 0.0.0.0 --port "$PORT"

