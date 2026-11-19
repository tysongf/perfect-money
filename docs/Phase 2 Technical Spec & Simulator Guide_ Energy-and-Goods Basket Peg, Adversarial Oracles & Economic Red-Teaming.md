# **Phase 2 Technical Spec & Simulator Guide: Energy-and-Goods Basket Peg, Adversarial Oracles & Economic Red-Teaming**

# **1\. Executive Overview & Handoff from Phase 1**

This document is the companion specification to the Phase 1 Noir Shielded UTXO Guide. While Phase 1 solves private transfers and publicly verifiable supply accounting (circuits/supply\_mint\_burn), Phase 2 engineers the monetary policy engine that keeps 1 unit of the currency stable in real purchasing power across decades without a central bank.

## **Core Design Principle**

Never deploy economic mechanisms directly to mainnet based on static spreadsheet models. In Phase 2, you will first build a deterministic economic engine and attack it with an LLM-driven adversarial agent swarm to prove mathematically and empirically that manipulating the peg or capturing the oracle is always net-negative financially.

## **Bridge to Phase 1**

* Phase 1's `supply_mint_burn` circuit exposes a public `signed_supply_delta` for every epoch.  
* Phase 2's Peg Engine computes the authorized supply expansion/contraction and redemption rate, ensuring total shielded supply always matches the protocol's collateral and peg invariants.

---

# **2\. Energy-and-Goods Basket Peg Mathematics**

## **2.1 The Target Basket Composition**

To resist both fiat inflation and single-commodity shocks (such as an oil embargo or a harvest failure), the reference index tracks a diversified global basket of **Energy**, **Industrial & Agricultural Staples**, and **Basic Compute**.

| Category | Component | Unit of Measurement | Initial Weight (w\_i) | Rationale |
| :---- | :---- | :---- | :---- | :---- |
| **Energy (40%)** | Wholesale Electricity | 1 MWh (weighted global grid median) | 0.25 | Universal physical input to all modern production. |
| **Energy (40%)** | Brent / WTI Crude or Natural Gas | 1 MMBtu energy equivalent | 0.15 | Captures transport and thermal energy costs. |
| **Staples (45%)** | Global Grain Index (Wheat / Rice / Corn) | 1 Metric Ton composite | 0.20 | Anchors basic human caloric purchasing power. |
| **Staples (45%)** | Industrial Metals (Copper / Steel) | 1 Metric Ton composite | 0.15 | Anchors infrastructure and manufacturing costs. |
| **Staples (45%)** | Global Housing / Rent Proxy | Standardized urban sq. meter index | 0.10 | Captures shelter costs without single-country bias. |
| **Compute (15%)** | Standardized Compute | 1,000 H100-equivalent GPU-seconds (or FLOP unit) | 0.15 | Anchors digital-age productivity and AI micro-payments. |

## **2.2 Geometric Weighted Index Formula**

Use a **weighted geometric mean** rather than an arithmetic mean. A geometric index is invariant to unit scaling and prevents a single hyper-spiking commodity from dominating the entire basket.

```
Target Basket Index at epoch t:
  I(t) = I_0 * PRODUCT_{i=1..N} [ (P_i(t) / P_i(0)) ^ w_i(t) ]

Where:
  I_0     = Initial target purchasing power (normalized to 1.000000 at genesis)
  P_i(t)  = Oracle-finalized median price of component i at epoch t (denominated in currency units)
  P_i(0)  = Genesis baseline price of component i
  w_i(t)  = Weight of component i at epoch t, subject to SUM(w_i(t)) == 1.0
```

## **2.3 Constitutional Ossification & Hard-Coded Rate Limits**

To make governance capture mathematically slow and unprofitable, the protocol enforces immutable code-level speed limits:

* **Max Weight Shift:** `|w_i(t) - w_i(t - 1 year)| <= 0.02` (no single component's weight can change by more than 2% per year).  
* **Max Epoch Price Delta:** Any single epoch oracle update is clamped to a maximum change of `+/- 5%` (`max_epoch_delta = 0.05`) unless confirmed by a full 48-hour dispute escalation round.  
* **Max Supply Expansion/Contraction:** Per-epoch net algorithmic supply adjustment is capped at `+/- 1.5%` of total circulating supply (`max_supply_delta_bps = 150`).

## **2.4 Bootstrap Phase vs. Algorithmic Phase**

1. **Phase 2A (Bootstrap — 100% Hard-Backed):** Users mint currency by locking over-collateralized liquid assets (e.g., 150% collateral ratio in tokenized T-bills, gold, or major crypto assets) into non-custodial vaults. Arbitrageurs keep the market price `M(t)` pegged to `I(t)` by minting when `M(t) > I(t)` and redeeming collateral when `M(t) < I(t)`.  
2. **Phase 2B (Algorithmic PID Dampening):** Once liquidity exceeds a constitutional threshold, a discrete **Proportional-Integral-Derivative (PID) controller** (modeled on [classical feedback control theory](https://tlk-energy.de/blog-en/practical-pid-tuning-guide)) continuously adjusts the protocol's **redemption rate** `r(t)` (the interest/drift rate applied to vault debt and savings) to push market price `M(t)` back toward the basket index `I(t)`.

```
Peg Error at epoch t:
  e(t) = (I(t) - M(t)) / I(t)

Discrete PID Controller Output (Redemption Rate Adjustment):
  P(t) = K_p * e(t)
  I_term(t) = clamp( I_term(t-1) + K_i * e(t) * dt, -I_max, +I_max )   # Anti-windup clamp
  D(t) = K_d * (e(t) - e(t-1)) / dt

  u(t) = clamp( P(t) + I_term(t) + D(t), -u_max, +u_max )

Target Redemption Price Update:
  R(t+1) = R(t) * (1 + u(t) * dt)
```

* **Deadband (`|e(t)| < 0.0025`):** When market price is within 0.25% of the basket target, the controller outputs `0` to prevent micro-oscillations and noise trading.  
* **Anti-Windup:** Clamping `I_term(t)` prevents runaway rate spikes during prolonged liquidity crunches.

---

# **3\. Schelling-Point Adversarial Oracle & Slashing Rules**

The price feed `P_i(t)` is the highest-value attack surface in any indexed currency. The oracle uses a **two-tier architecture**: fast stake-weighted commit-reveal rounds for normal epochs, backed by an optimistic challenge window and escalation court (drawing on proven designs like [UMA's Optimistic Oracle & DVM](https://docs.uma.xyz/protocol-overview/how-does-umas-oracle-work) and [Schelling-point arbitration](https://arxiv.org/html/2610.20666v1)).

## **3.1 Epoch Lifecycle (Commit \-\> Reveal \-\> Challenge \-\> Finalize)**

1. **Commit Phase (Window: T\_commit \= 1 hour):**  
   * Each active oracle node `k` with staked collateral `S_k >= S_min` observes off-chain markets for basket component `i` and submits a blind hash:  
   * `commit_k = Poseidon(DOMAIN_ORACLE, epoch, asset_i, price_k, salt_k, node_id_k)`  
   * Blind commitments prevent lazy nodes from copying other reporters ("freeloader problem") and block front-running.  
2. **Reveal Phase (Window: T\_reveal \= 1 hour):**  
   * Nodes publish `(price_k, salt_k)`. Any committed node that fails to reveal is automatically penalized (`slash_no_reveal = 10%` of stake).  
   * The protocol computes the **stake-weighted median** `P_med` and the **stake-weighted interquartile range (IQR)** `sigma_iqr`.  
3. **Optimistic Challenge Window (Window: T\_challenge \= 48 hours for drastic shifts, 2 hours for routine shifts):**  
   * If `|P_med(t) - P_med(t-1)| / P_med(t-1) > 0.02`, the extended 48-hour challenge window activates automatically.  
   * **Anyone on Earth** can post a dispute bond `B_dispute` to challenge `P_med(t)`, triggering an escalation round voted on by time-locked token holders (2+ year lockup) using commit-reveal.  
4. **Finalization & Settlement:**  
   * If unchallenged (or upheld by escalation), `P_med(t)` becomes final, coherent reporters earn epoch fees, and outliers are slashed.

## **3.2 Asymmetric Slashing Mathematics**

Truthful reporting must be a strict Nash equilibrium. Rewards are small and steady; penalties for manipulation are severe and asymmetric.

```
Relative Deviation of Reporter k from Finalized Consensus P*:
  d_k = |price_k - P*| / P*

Tolerance Band:
  epsilon = max(0.005, 1.5 * sigma_iqr)   # Minimum 0.5% grace band for market spread

Slashing & Reward Function:
  If d_k <= epsilon:
      slash_k  = 0
      reward_k = Epoch_Fee_Pool * (S_k / S_coherent_total)

  If epsilon < d_k <= 3 * epsilon:
      # Quadratic penalty for moderate inaccuracy
      slash_rate = 0.25 * ((d_k - epsilon) / (2 * epsilon))^2
      slash_k    = S_k * slash_rate

  If d_k > 3 * epsilon (Severe Manipulation / Cartel Attack):
      # Asymmetric nuclear slash: 100% of stake forfeited
      slash_k = 1.00 * S_k
```

## **3.3 Slashed Stake Distribution (Preventing Griefing)**

Never send 100% of slashed funds to other oracle reporters (which incentivizes colluding to falsely slash honest minorities).

* **70% Burned Permanently:** Removed from circulating supply (benefits all holders neutrally).  
* **20% Whistleblower / Challenger Bounty:** Paid directly to the disputer who successfully challenged a manipulated round.  
* **10% Insurance Reserve:** Backstops the collateral pool during black-swan volatility.

## **3.4 The Economic Security Invariant (CoC \> PfC)**

The simulator must verify that at every simulated liquidity level:

* **Cost of Corruption (CoC):** `0.51 * Total_Oracle_Stake * Slash_Multiplier + Fork_Destruction_Loss`  
* **Profit from Corruption (PfC):** Maximum extractable arbitrage profit from skewing `I(t)` within the hard-coded `max_epoch_delta` (5%) cap across all open markets.  
* **Invariant:** `CoC >= 3.0 * PfC` at all times. If `Total_Oracle_Stake` drops below this safety margin, the protocol automatically raises oracle fees (via the PID/fee curve) to attract more stake or widens the challenge window.

---

# **4\. Target Monorepo Extension (Building on Phase 1\)**

Add the following directories to your existing `perfect-money/` monorepo:

```
perfect-money/
├── specs/
│   ├── phase1_utxo_spec.md
│   └── phase2_peg_oracle_spec.md       # This document
├── sim/
│   ├── engine/                         # Core deterministic market, vault, PID & oracle engine
│   │   ├── Cargo.toml                  # Optional Rust/PyO3 core for 1000x speed
│   │   ├── peg_controller.py           # Geometric basket + PID controller
│   │   ├── oracle_market.py            # Commit-reveal, median, slashing & dispute court
│   │   ├── amm_and_vaults.py           # Collateral vaults + simulated spot liquidity pool
│   │   └── environment.py              # Step-by-step simulation clock & telemetry logger
│   ├── red_team_agents/                # LLM-driven adversarial swarm
│   │   ├── base_agent.py               # Structured JSON tool-calling interface
│   │   ├── personas.py                 # Whale, Oracle Cartel, Retail Herd, Nation-State, Arb
│   │   ├── covert_channel.py           # Private message bus for cartel collusion testing
│   │   └── runner.py                   # Parallel scenario runner + invariant checker
│   └── scenarios/
│       ├── 01_oracle_cartel_bribe.yaml
│       ├── 02_commodity_supply_shock.yaml
│       ├── 03_whale_bank_run.yaml
│       └── 04_hostile_state_short.yaml
└── scripts/
    └── run_red_team_suite.sh           # Runs all scenarios and fails if any invariant breaks
```

---

# **5\. Multi-Agent Economic Red-Team Simulator Architecture**

Static Monte Carlo tests assume agents follow fixed math formulas. Real attackers adapt, collude, and exploit timing gaps. Your simulator pairs a strictly deterministic Python/Rust physics engine with an **LLM adversarial swarm**.

## **5.1 Agent Personas & Objectives**

| Agent Archetype | Count per Run | Capital / Stake | Objective Function (Prompt Goal) |
| :---- | :---- | :---- | :---- |
| **Greedy Whale** | 2–5 | 15% of market liquidity | Maximize net profit in external USD/Gold by front-running PID rate changes or triggering vault liquidations. |
| **Colluding Oracle Cartel** | 10–30 | 35%–55% of oracle stake | Coordinate via `covert_channel.py` to skew `P_med(t)` just enough to profit on leveraged trades without triggering a 48h challenge or getting slashed. |
| **Honest Whistleblower** | 3–5 | Moderate bond capital | Monitor off-chain ground-truth prices; post dispute bonds whenever `P_med(t)` deviates from truth by `> 1%`. |
| **Panicked Retail Herd** | 50–200 | Fragmented small balances | React to news shocks and peg deviations; simulate bank-run herd psychology and sudden velocity spikes. |
| **Hostile Nation-State** | 1 | Large external fiat budget | Non-profit-maximizing attacker: willing to lose capital to permanently de-peg the currency (\` |
| **Rational Arbitrageur** | 5–10 | High liquid capital | Close price gaps between spot market `M(t)` and vault redemption price `R(t)` for risk-free profit. |

## **5.2 Starter Code Scaffolding**

### **5.2.1 `sim/engine/peg_controller.py`**

```py
from dataclasses import dataclass, field
import math
from typing import Dict

@dataclass
class BasketConfig:
    weights: Dict[str, float]
    genesis_prices: Dict[str, float]
    max_annual_weight_shift: float = 0.02
    max_epoch_price_delta: float = 0.05

@dataclass
class PIDController:
    k_p: float = 0.50
    k_i: float = 0.05
    k_d: float = 0.10
    deadband: float = 0.0025
    i_max: float = 0.10
    u_max: float = 0.015  # 1.5% max adjustment per epoch
    integral: float = 0.0
    prev_error: float = 0.0

    def step(self, target_index: float, market_price: float, dt: float = 1.0) -> float:
        error = (target_index - market_price) / target_index
        if abs(error) < self.deadband:
            self.prev_error = error
            return 0.0

        p_term = self.k_p * error
        self.integral = max(-self.i_max, min(self.i_max, self.integral + error * dt))
        i_term = self.k_i * self.integral
        d_term = self.k_d * (error - self.prev_error) / dt
        self.prev_error = error

        raw_u = p_term + i_term + d_term
        return max(-self.u_max, min(self.u_max, raw_u))

def compute_geometric_basket(config: BasketConfig, current_prices: Dict[str, float]) -> float:
    log_sum = 0.0
    for asset, w in config.weights.items():
        ratio = current_prices[asset] / config.genesis_prices[asset]
        log_sum += w * math.log(ratio)
    return math.exp(log_sum)
```

### **5.2.2 `sim/engine/oracle_market.py`**

```py
from dataclasses import dataclass
from typing import List, Tuple

@dataclass
class OracleSubmission:
    node_id: str
    stake: float
    price: float
    revealed: bool = True

def weighted_median_and_iqr(subs: List[OracleSubmission]) -> Tuple[float, float]:
    valid = sorted([s for s in subs if s.revealed], key=lambda x: x.price)
    total_stake = sum(s.stake for s in valid)
    if total_stake == 0:
        raise ValueError("No revealed oracle submissions")

    def quantile(q: float) -> float:
        cum = 0.0
        target = q * total_stake
        for s in valid:
            cum += s.stake
            if cum >= target:
                return s.price
        return valid[-1].price

    med = quantile(0.50)
    iqr = (quantile(0.75) - quantile(0.25)) / max(med, 1e-9)
    return med, iqr

def settle_oracle_round(
    subs: List[OracleSubmission],
    final_price: float,
    iqr: float,
    epoch_fee_pool: float
) -> dict:
    epsilon = max(0.005, 1.5 * iqr)
    slashes = {}
    coherent_stake = 0.0

    for s in subs:
        if not s.revealed:
            slashes[s.node_id] = 0.10 * s.stake
            continue
        dev = abs(s.price - final_price) / final_price
        if dev <= epsilon:
            slashes[s.node_id] = 0.0
            coherent_stake += s.stake
        elif dev <= 3.0 * epsilon:
            rate = 0.25 * (((dev - epsilon) / (2.0 * epsilon)) ** 2)
            slashes[s.node_id] = s.stake * rate
        else:
            slashes[s.node_id] = s.stake  # 100% nuclear slash

    rewards = {}
    for s in subs:
        if s.revealed and slashes[s.node_id] == 0.0 and coherent_stake > 0:
            rewards[s.node_id] = epoch_fee_pool * (s.stake / coherent_stake)
        else:
            rewards[s.node_id] = 0.0

    total_slashed = sum(slashes.values())
    return {
        "final_price": final_price,
        "epsilon": epsilon,
        "slashes": slashes,
        "rewards": rewards,
        "burned": 0.70 * total_slashed,
        "whistleblower_pool": 0.20 * total_slashed,
        "insurance_reserve": 0.10 * total_slashed,
    }
```

### **5.2.3 `sim/red_team_agents/runner.py` (Agent Loop Blueprint)**

1. **Epoch Start:** Environment publishes ground-truth off-chain commodity shocks (e.g., electricity spikes \+18%) and current spot market state `M(t)`, vault collateral ratios, and oracle stake pool.  
2. **Covert Cartel Phase:** Cartel LLM agents exchange 1–2 rounds of messages on `covert_channel.py` to plan a coordinated false price report and matching spot/perp trade.  
3. **Action Phase:** All LLM agents output strict JSON actions (`SUBMIT_ORACLE_COMMIT`, `TRADE_AMM`, `MINT_VAULT`, `REDEEM_VAULT`, `POST_DISPUTE_BOND`).  
4. **Deterministic Settlement:** `oracle_market.py` and `peg_controller.py` resolve the round, execute slashing/rewards, update `R(t+1)`, and log metrics.  
5. **Invariant Audit:** Check at every tick whether:  
   * Any cartel achieved positive net ROI after slashing (`cartel_net_pnl > 0`).  
   * Market price stayed de-pegged (`|e(t)| > 0.05`) for more than `N` consecutive epochs.  
   * Vault solvency ratio dropped below `1.05`.

---

# **6\. Ready-to-Paste Prompts for Your LLM Agent Swarm**

## **Prompt A: Build the Deterministic Economic Engine**

"Using Section 2, Section 3, and Section 5.2 of `specs/phase2_peg_oracle_spec.md`, implement the full deterministic simulator in `sim/engine/`. Include peg\_controller.py (geometric basket \+ PID controller with deadband and anti-windup), oracle\_market.py (commit-reveal, stake-weighted median/IQR, asymmetric slashing, and 48-hour dispute escalation), and amm\_and\_vaults.py (over-collateralized mint/redeem vaults plus a constant-product spot AMM). Write pytest unit tests verifying every constitutional rate limit and slashing boundary."

## **Prompt B: Wire Up the LLM Adversarial Swarm**

"Implement sim/red\_team\_agents/ using async structured JSON calls to our LLM endpoint. Create the 6 personas in Section 5.1 (Greedy Whale, Colluding Oracle Cartel with covert\_channel.py, Honest Whistleblower, Panicked Retail Herd, Hostile Nation-State, and Rational Arbitrageur). Ensure every agent can only interact with `sim/engine/` via validated JSON actions and log full episode traces (PnL per agent, peg error e(t), slashed stake, and dispute outcomes) to Parquet/JSON."

## **Prompt C: Run the 4 Stress-Test Scenarios & Auto-Tune PID Gains**

"Create the 4 scenario configs in sim/scenarios/ (01\_oracle\_cartel\_bribe.yaml with 45% cartel stake, `02_commodity_supply_shock.yaml` with a sudden \+40% energy spike, 03\_whale\_bank\_run.yaml with coordinated 30% redemption panic, and 04\_hostile\_state\_short.yaml). Run 20 episodes per scenario. If any scenario breaks a safety invariant (e.g., cartel achieves positive ROI or peg oscillates), automatically analyze the failure trace, propose updated PID gains (`k_p`, `k_i`, `k_d`) or minimum oracle stake ratios, and re-run until all 4 scenarios pass."

## **Prompt D: Bridge Phase 2 Outputs to Phase 1 Noir Circuits**

"Write a Rust/Python integration script that takes the final signed\_supply\_delta emitted by sim/engine/ at the end of an epoch and generates valid Prover.toml inputs for Phase 1's circuits/supply\_mint\_burn Noir circuit, verifying end-to-end that monetary policy updates produce valid Barretenberg proofs."

---

# **7\. Phase 2 Definition of Done & Handoff to Phase 3**

Phase 2 is complete when all five gates pass:

* **Cartel Unprofitability Gate:** Across 100+ LLM red-team runs (up to 49% colluding oracle stake), the Oracle Cartel's net ROI is strictly negative (`< 0`) in 100% of episodes where at least 1 Honest Whistleblower is active.  
* **Peg Stability Gate:** Under a simulated \+40% energy shock or 30% bank run, the PID controller and arbitrage vaults restore `|e(t)| < 2%` within 14 simulated days without oscillatory instability.  
* **Solvency Gate:** System-wide collateralization never drops below `110%` during Bootstrap Phase 2A stress tests.  
* **CoC \> PfC Gate:** Telemetry confirms `Cost of Corruption >= 3.0 * Profit from Corruption` across all simulated liquidity tiers.  
* **Phase 1 Integration Gate:** Epoch supply deltas from the simulator cleanly prove and verify through Phase 1's `supply_mint_burn` Noir circuit.

## **Next Milestone: Phase 3 (Offline BLE/NFC Mesh Settlement)**

Once the private ledger (Phase 1\) and stable monetary engine (Phase 2\) are battle-tested, Phase 3 adds hardware-enforced monotonic counters (Apple Secure Enclave / Android StrongBox) and local Bluetooth/NFC state sync so two phones can settle transactions completely off-grid.