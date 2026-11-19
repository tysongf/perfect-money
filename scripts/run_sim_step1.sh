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

echo "==> Running Phase 2 Step 1 pytest suite (units, ablation, scenarios, Phase 1 bridge)..."
"$ROOT_DIR/.venv/bin/pytest" -v "$ROOT_DIR/sim/tests"

echo ""
echo "==> Scenario Summary (seed=42)"
"$ROOT_DIR/.venv/bin/python" - <<'PY'
from pathlib import Path
from sim.engine.environment import run_episode

scenarios = sorted((Path("sim/scenarios")).glob("*.yaml"))
hdr = (
    f"{'Scenario':<28} | {'BadDebt':>8} | {'MinCoC/PfC':>10} | "
    f"{'CartelROI':>9} | {'WbROI':>8} | {'D14Err%':>8} | {'Rec(h)':>6} | {'<14d':<5}"
)
print(hdr)
print("-" * len(hdr))
for sc in scenarios:
    s = run_episode(sc, seed=42).summary
    rec = str(s.recovery_hours_after_shock) if s.recovery_hours_after_shock is not None else "FAIL"
    print(
        f"{s.scenario_name:<28} | "
        f"{s.unbacked_bad_debt_pm:>8.1f} | "
        f"{s.min_coc_pfc_ratio:>9.2f}x | "
        f"{s.cartel_net_roi * 100:>8.1f}% | "
        f"{s.whistleblower_net_roi * 100:>7.1f}% | "
        f"{s.peg_error_at_day14_after_shock * 100:>7.3f}% | "
        f"{rec:>6} | "
        f"{'PASS' if s.restored_within_14_days else 'FAIL':<5}"
    )
PY

