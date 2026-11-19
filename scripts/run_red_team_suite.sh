#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.nargo/bin:$HOME/.bb:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [[ ! -d "$ROOT_DIR/.venv" ]]; then
  echo "==> Creating Python virtualenv (.venv)..."
  python3 -m venv "$ROOT_DIR/.venv"
fi

if ! "$ROOT_DIR/.venv/bin/python" -c "import yaml, pytest" >/dev/null 2>&1; then
  echo "==> Installing sim dependencies into .venv..."
  "$ROOT_DIR/.venv/bin/pip" install -q -r "$ROOT_DIR/sim/requirements.txt"
fi

echo "==> Running full Phase 2 pytest suite (Step 1 + Step 2 Swarm + Phase 1 Noir bridge)..."
"$ROOT_DIR/.venv/bin/pytest" -v "$ROOT_DIR/sim/tests"

echo ""
echo "==> Running 120-episode Adversarial Red-Team Swarm Audit..."
"$ROOT_DIR/.venv/bin/python" -m sim.red_team_agents.runner \
  --episodes-per-regime 30 \
  --report "$ROOT_DIR/target/phase2_red_team_report.json" \
  "$@"

