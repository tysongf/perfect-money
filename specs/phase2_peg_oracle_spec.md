# Phase 2 Technical Spec & Simulator Guide: Energy-and-Goods Basket Peg, Adversarial Oracles & Economic Red-Teaming

## 1. Executive Overview & Handoff from Phase 1

This document is the canonical monetary policy and adversarial oracle specification for **Phase 2** of **Perfect Money (PM)**. While Phase 1 builds private shielded UTXO transfers and verifiable vault accounting (`circuits/shield` and `circuits/unshield`), Phase 2 engineers the censorship-resistant, collateralized peg engine that holds 1 PM stable in real purchasing power across decades without fiat pegs, RWA custodians, or a separate governance token.

### Core Design Principle

Never ship monetary mechanisms from static spreadsheets. Phase 2 builds a deterministic simulation engine (`sim/engine/`) and attacks it with an LLM-driven adversarial swarm (`sim/red_team_agents/`) to verify empirically that oracle manipulation and de-pegging attacks are net-negative.

### Bridge to Phase 1

* Supply expands and contracts **endogenously** through over-collateralized vaults (minting against collateral, repaying debt, and hard redemptions) rather than involuntary protocol-level wallet burns.
* Phase 1's `circuits/shield` and `circuits/unshield` circuits act as the cryptographic **Vault Shield/Unshield bridge**, exposing public mint/burn amounts so public ledger auditors verify that total shielded + unshielded PM always matches transparent vault debt invariants.

---

## 2. Energy-and-Goods Basket Peg Mathematics

### 2.1 Target Basket Composition

The reference purchasing-power basket spans **Energy (40%)**, **Essential Staples (45%)**, and **Compute Infrastructure Power (15%)**. Compute is anchored to **standardized datacenter grid capacity / electricity (MWh)** rather than raw GPU-seconds so Moore's Law hardware cost collapses do not induce structural deflation against food, energy, and shelter.

| Category | Component | Unit of Measurement | Initial Weight (`w_i`) | Rationale |
| :--- | :--- | :--- | :--- | :--- |
| **Energy (40%)** | Wholesale Electricity | 1 MWh (weighted global grid median) | `0.25` | Universal physical input to modern production. |
| **Energy (40%)** | Crude Oil / Natural Gas | 1 MMBtu energy equivalent | `0.15` | Transport and thermal energy costs. |
| **Staples (45%)** | Global Grain Index (Wheat / Rice / Corn) | 1 Metric Ton composite | `0.20` | Basic human caloric purchasing power. |
| **Staples (45%)** | Industrial Metals (Copper / Steel) | 1 Metric Ton composite | `0.15` | Physical infrastructure and manufacturing costs. |
| **Staples (45%)** | Global Housing / Rent Proxy | Standardized urban sq. meter index | `0.10` | Shelter costs without single-country bias. |
| **Compute Infra (15%)** | Datacenter Power / Industrial Grid Capacity | 1 MWh wholesale datacenter power | `0.15` | Captures AI/compute physical bottleneck without hardware-depreciation deflation. |

Weights MUST sum to `1.00` at all times.

### 2.2 Geometric Weighted Index & Dimensional Consistency

Both component prices `P_i(t)` and PM's observable spot market price `M(t)` are expressed in a shared external reference numeraire (e.g., USD or grams of gold — the numeraire cancels out of real purchasing power because `I(t)` only evaluates dimensionless ratios `P_i(t) / P_i(0)`):

```text
Target Basket Index at epoch t (in shared numeraire):
  I(t) = I_0 * PRODUCT_{i=1..N} [ (P_i(t) / P_i(0)) ^ w_i(t) ]

Where:
  I_0     = Initial basket value at genesis (normalized to 1.000000 numeraire units)
  P_i(t)  = Oracle-finalized price of component i at epoch t (in shared numeraire)
  P_i(0)  = Genesis baseline price of component i (in shared numeraire)
  w_i(t)  = Weight of component i at epoch t, SUM(w_i(t)) == 1.0
  M(t)    = Market spot price of 1 PM at epoch t (in the same shared numeraire)
```

### 2.3 Constitutional Ossification & Hard-Coded Speed Limits

* **Max Weight Shift:** `|w_i(t) - w_i(t - 1 year)| <= 0.02` (`<= 2%` per year per component).
* **Baseline Epoch Basket Delta:** Routine finalized oracle update clamped to `+/- 5%` (`max_epoch_delta = 0.05`) unless confirmed by a full 48-hour dispute escalation round — and further clamped tighter by **Low-Stake Auto-Throttling** (Section 4.3).
* **PID Rate Adjustment Clamp:** Per-epoch target rate adjustment `u(t)` capped at `+/- 1.5%` (`u_max = 0.015`).

### 2.4 Endogenous Vault Engine: Hard Redemptions + PID-Smoothed Target

Rather than relying on a purely floating RAI-style peg (which suffers weak secondary-market price floors) or freezeable tokenized T-bills, PM uses:

1. **100% Censorship-Resistant Isolated Collateral Branches:** Only permissionless, non-freezeable crypto collateral (e.g., ETH, trust-minimized BTC). No custodial RWAs or fiat-backed stablecoins. Each collateral type lives in an isolated branch with its own minimum collateral ratio (e.g., `150%`+), debt tracking, and Stability Pool so a crash in one asset cannot poison other branches.
2. **Borrower-Set Interest Rates & Liquity-v2 Hard Redemptions:**
   * Vault borrowers select their annual PM borrow rate `r_vault`.
   * Redemption target `R(t)` tracks the basket index `I(t)` smoothed through a discrete PID controller so flash market noise or bounded oracle ticks do not cause instant liquidation cascades.
   * **Arbitrage Floor:** Anyone can buy PM on the open market whenever `M(t) < R(t)` and **hard-redeem** 1 PM for `R(t)` numeraire-equivalent worth of collateral, starting with vaults paying the **lowest** interest rates (ordered across branches by branch risk / unbackedness).
   * **Arbitrage Ceiling:** Whenever `M(t) > R(t)`, borrowers mint fresh PM against collateral at `R(t)` and sell into the spot market for risk-free profit.
3. **PID Dampening Controller:**

```text
Peg Error at epoch t:
  e(t) = (I(t) - M(t)) / I(t)

Discrete PID Controller Output (Redemption Target Drift Adjustment):
  If |e(t)| < deadband (0.0025):
      u(t) = 0.0
  Else:
      P(t)      = K_p * e(t)
      I_term(t) = clamp( I_term(t-1) + K_i * e(t) * dt, -I_max, +I_max )
      D(t)      = K_d * (e(t) - e(t-1)) / dt
      u(t)      = clamp( P(t) + I_term(t) + D(t), -u_max, +u_max )

Target Redemption Price Update:
  R(t+1) = R(t) * (1 + u(t) * dt)
```

### 2.5 Hybrid A3 Bad-Debt Absorption (Single-Token, Zero MKR Equity)

Because PM is 100% single-token with no equity token to mint during insolvencies, extreme collateral crashes are absorbed in strict order:

1. **Per-Branch Stability Pools (Primary — Instant 1-Block Liquidations):** PM holders deposit unshielded PM into a collateral branch's Stability Pool, earning the majority share of borrower interest (`~65%` baseline) plus collateral liquidation discounts (`5%–10%`). Under-collateralized vaults are offset against the Stability Pool in a single block — avoiding Maker-style auction delays under congestion.
2. **Protocol Insurance Reserve (Secondary Buffer):** Funded continuously by a share of borrower interest (`~10%` baseline) plus `10%` of all oracle slashing proceeds. Absorbs tail bad debt if a Stability Pool temporarily empties.
3. **Pro-Rata Debt Redistribution (Final Fallback):** Any remaining bad debt and residual collateral in an exhausted branch are redistributed pro-rata to surviving vaults *within that isolated branch only*.

---

## 3. One-Token Schelling-Point Oracle & Escalation Court

All oracle reporters and 48-hour dispute escalation voters lock **unshielded Perfect Money (PM)** — eliminating dual-token death-spiral dynamics.

### 3.1 Epoch Lifecycle (`Commit -> Reveal -> Challenge -> Finalize`)

1. **Commit Phase (`T_commit = 1 hour`):**
   * Active oracle nodes `k` with locked stake `S_k >= S_min` submit `commit_k = Poseidon2(DOMAIN_ORACLE, epoch, asset_i, price_k, salt_k, node_id_k)`.
2. **Reveal Phase (`T_reveal = 1 hour`):**
   * Nodes publish `(price_k, salt_k)`. Unrevealed commits are slashed (`slash_no_reveal = 10%` of stake).
   * Protocol computes stake-weighted median `P_med`.
3. **Optimistic Challenge Window (`T_challenge`):**
   * Routine shifts (`|P_med(t) - P_med(t-1)| / P_med(t-1) <= 0.02`): `2 hours` (or extended under low-stake throttling).
   * Drastic shifts (`> 2%`): minimum `48 hours`.
   * **Anyone** can post a dispute bond `B_dispute` in PM to escalate to the time-locked (2+ year lockup) PM holder court using blind commit-reveal.
4. **Finalization:**
   * Upheld `P*` updates `I(t)` (subject to epoch delta clamping), rewards coherent reporters, and slashes outliers.

### 3.2 Patched Asymmetric Slashing Mathematics

To prevent a `>25%` cartel from inflating its own grace band within the same round by submitting wide outlier quotes, the tolerance band `epsilon` uses **lagged historical volatility** (`sigma_hist_ewma`, frozen before the current round begins) rather than same-round IQR:

```text
Relative Deviation of Reporter k from Finalized Consensus P*:
  d_k = |price_k - P*| / P*

Lagged Tolerance Band (immune to same-round IQR widening):
  epsilon = max(0.005, 1.5 * sigma_hist_ewma)

Slashing & Reward Function:
  If d_k <= epsilon:
      slash_k  = 0
      reward_k = Epoch_Fee_Pool * (S_k / S_coherent_total)
  If epsilon < d_k <= 3 * epsilon:
      slash_rate = 0.25 * ((d_k - epsilon) / (2 * epsilon))^2
      slash_k    = S_k * slash_rate
  If d_k > 3 * epsilon:
      slash_k    = 1.00 * S_k   # 100% nuclear slash
```

### 3.3 Slashed Stake Distribution (Anti-Griefing)

* **70% Burned Permanently** (neutral value accrual to all PM holders; removes incentive for majority collusion to falsely slash honest minorities).
* **20% Whistleblower / Challenger Bounty** (paid to successful challengers).
* **10% Protocol Insurance Reserve** (backstops collateral branches).

### 3.4 Stacked Security Defenses (`CoC >= 3.0 * PfC`)

To guarantee `Cost of Corruption >= 3.0 * Profit from Corruption` in a single-token lockup system:

1. **Dynamic Yield Routing:** Baseline `~25%` of vault borrow interest flows to active oracle reporters and 2+ year locked court stakers. Whenever `Total_Locked_PM < 3.0 * PfC`, borrow fee share routed to stakers scales upward dynamically (e.g., up to `40%`) to pull fresh PM lockups in.
2. **Low-Stake Auto-Throttling:** Whenever locked stake falls below `3.0 * PfC`, `max_epoch_delta` automatically tightens (from `5.0%` down toward `0.5%`) and the challenge window widens up to `7 days`, shrinking extractable `PfC` while stake recovers.
3. **Credible Fork Backstop:** Because court lockups span `2+ years` and drastic updates trigger a `48h+` delay, a 51% cartel pushing a blatantly fabricated price cannot withdraw stake before the community coordinates a social/client fork that burns `100%` of the cartel's locked PM on the canonical branch.

---

## 4. Target Monorepo Extension (`sim/`)

```text
perfect-money/
├── specs/
│   ├── phase1_utxo_spec.md
│   └── phase2_peg_oracle_spec.md
├── sim/
│   ├── engine/
│   │   ├── peg_controller.py           # Geometric basket + PID + auto-throttle clamps
│   │   ├── oracle_market.py            # Commit-reveal, lagged-EWMA slashing & dispute court
│   │   ├── amm_and_vaults.py           # Isolated collateral vaults, Stability Pools, Insurance Reserve, spot AMM
│   │   └── environment.py              # Deterministic epoch clock, CoC/PfC monitor & telemetry
│   ├── red_team_agents/
│   │   ├── base_agent.py               # Strict JSON action schema
│   │   ├── personas.py                 # Greedy Whale, Oracle Cartel, Whistleblower, Retail Herd, Hostile State, Arb
│   │   ├── covert_channel.py           # Private collusion channel for cartel coordination
│   │   └── runner.py                   # Multi-episode adversarial runner & invariant auditor
│   └── scenarios/
│       ├── 01_oracle_cartel_bribe.yaml
│       ├── 02_commodity_supply_shock.yaml
│       ├── 03_whale_bank_run.yaml
│       └── 04_hostile_state_short.yaml
└── scripts/
    └── run_red_team_suite.sh
```

---

## 5. Phase 2 Definition of Done

1. **Cartel Unprofitability Gate:** Across `100+` LLM red-team runs (up to `49%` colluding oracle stake), Oracle Cartel net ROI is `< 0` in `100%` of episodes with `>= 1` active Honest Whistleblower.
2. **Peg Stability Gate:** Under a simulated `+40%` energy shock or `30%` bank run, hard redemptions + PID restore `|e(t)| < 2%` within `14` simulated days without oscillatory instability.
3. **Solvency Gate:** System-wide collateralization and Stability Pool + Insurance Reserve coverage avoid unbacked bad debt under `-50%` single-branch collateral shocks.
4. **CoC > PfC Gate:** Telemetry confirms `CoC >= 3.0 * PfC` across all simulated liquidity tiers (via yield routing + auto-throttling).
5. **Phase 1 Bridge Gate:** Simulated vault mint/burn supply deltas compile and verify end-to-end through Phase 1's `circuits/shield` and `circuits/unshield` Noir circuits.

