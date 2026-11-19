"""Isolated collateral vaults, Hybrid A3 Stability Pools + Insurance Reserve, redemptions, and spot AMM."""

from __future__ import annotations

from dataclasses import dataclass, field
import math

from .peg_controller import ThrottleState


@dataclass
class CollateralBranch:
    """Isolated crypto collateral branch with independent MCR, liquidation ratio, and Stability Pool."""

    name: str
    mint_mcr: float
    liq_cr: float
    liq_discount: float
    price: float
    stability_pool_pm: float = 0.0
    stability_pool_collateral: float = 0.0
    total_liquidated_debt_pm: float = 0.0
    total_redistributed_debt_pm: float = 0.0
    total_sp_offset_pm: float = 0.0
    total_insurance_offset_pm: float = 0.0
    unbacked_bad_debt_pm: float = 0.0


def default_collateral_branches() -> dict[str, CollateralBranch]:
    return {
        "ETH": CollateralBranch(name="ETH", mint_mcr=1.50, liq_cr=1.15, liq_discount=0.05, price=3000.0),
        "BTC": CollateralBranch(name="BTC", mint_mcr=1.50, liq_cr=1.15, liq_discount=0.05, price=90000.0),
        "SOL": CollateralBranch(name="SOL", mint_mcr=1.75, liq_cr=1.25, liq_discount=0.08, price=180.0),
    }


@dataclass
class Vault:
    vault_id: str
    owner: str
    branch: str
    collateral_qty: float
    debt_pm: float
    borrow_rate_apr: float

    def collateral_ratio(self, collateral_price: float, r_price: float) -> float:
        if self.debt_pm <= 1e-12:
            return float("inf")
        return (self.collateral_qty * collateral_price) / (self.debt_pm * r_price)


@dataclass
class SpotAMM:
    """Constant-product PM/numeraire spot AMM (M(t) = numeraire_reserve / pm_reserve)."""

    pm_reserve: float
    numeraire_reserve: float
    fee_rate: float = 0.003

    def __post_init__(self) -> None:
        if self.pm_reserve <= 0.0 or self.numeraire_reserve <= 0.0:
            raise ValueError("AMM reserves must be strictly positive")

    @property
    def spot_price(self) -> float:
        return self.numeraire_reserve / self.pm_reserve

    @property
    def liquidity_pm_equiv(self) -> float:
        return 2.0 * self.pm_reserve

    def quote_numeraire_to_pm(self, numeraire_in: float) -> float:
        if numeraire_in <= 0.0:
            return 0.0
        eff_in = numeraire_in * (1.0 - self.fee_rate)
        return (self.pm_reserve * eff_in) / (self.numeraire_reserve + eff_in)

    def quote_pm_to_numeraire(self, pm_in: float) -> float:
        if pm_in <= 0.0:
            return 0.0
        eff_in = pm_in * (1.0 - self.fee_rate)
        return (self.numeraire_reserve * eff_in) / (self.pm_reserve + eff_in)

    def swap_numeraire_for_pm(self, numeraire_in: float) -> float:
        if numeraire_in <= 0.0:
            raise ValueError("numeraire_in must be positive")
        pm_out = self.quote_numeraire_to_pm(numeraire_in)
        self.numeraire_reserve += numeraire_in
        self.pm_reserve -= pm_out
        return pm_out

    def swap_pm_for_numeraire(self, pm_in: float) -> float:
        if pm_in <= 0.0:
            raise ValueError("pm_in must be positive")
        num_out = self.quote_pm_to_numeraire(pm_in)
        self.pm_reserve += pm_in
        self.numeraire_reserve -= num_out
        return num_out

    def optimal_numeraire_in_for_target_price(self, effective_target_price: float) -> float:
        """Exact CP-AMM input size maximizing (effective_target_price * pm_out - num_in)."""
        gamma = 1.0 - self.fee_rate
        if self.spot_price >= effective_target_price * gamma:
            return 0.0
        num_after = math.sqrt(effective_target_price * gamma * self.pm_reserve * self.numeraire_reserve)
        return max(0.0, (num_after - self.numeraire_reserve) / gamma)

    def optimal_pm_in_for_target_price(self, r_price: float) -> float:
        """Exact CP-AMM PM sell size maximizing (num_out - r_price * pm_in)."""
        gamma = 1.0 - self.fee_rate
        if self.spot_price * gamma <= r_price:
            return 0.0
        pm_after = math.sqrt((self.numeraire_reserve * gamma * self.pm_reserve) / r_price)
        return max(0.0, (pm_after - self.pm_reserve) / gamma)


@dataclass(frozen=True)
class RedemptionReceipt:
    pm_redeemed: float
    collateral_numeraire_received: float
    fee_rate: float
    fee_total_numeraire: float
    fee_to_vaults_numeraire: float
    fee_to_insurance_numeraire: float
    collateral_received_by_branch: dict[str, float]


@dataclass(frozen=True)
class LiquidationReport:
    branch: str
    liquidated_vaults: int
    debt_cleared_pm: float
    sp_offset_pm: float
    insurance_offset_pm: float
    redistributed_debt_pm: float
    unbacked_bad_debt_pm: float


@dataclass
class VaultAndAmmSystem:
    """State machine managing agent balances, isolated vaults, Stability Pools, Insurance Reserve, and AMM."""

    branches: dict[str, CollateralBranch] = field(default_factory=default_collateral_branches)
    amm: SpotAMM = field(default_factory=lambda: SpotAMM(pm_reserve=250_000.0, numeraire_reserve=250_000.0))
    vaults: dict[str, Vault] = field(default_factory=dict)
    agent_pm: dict[str, float] = field(default_factory=dict)
    agent_numeraire: dict[str, float] = field(default_factory=dict)
    agent_collateral: dict[str, dict[str, float]] = field(default_factory=dict)

    insurance_reserve_pm: float = 0.0
    insurance_collateral_numeraire: float = 0.0
    oracle_fee_pool_pm: float = 0.0
    pending_dispute_bonds_pm: float = 0.0

    circulating_pm_supply: float = 0.0
    cumulative_slash_burned_pm: float = 0.0
    unbacked_bad_debt_pm: float = 0.0
    cumulative_vault_mints_pm: float = 0.0
    cumulative_vault_burns_pm: float = 0.0

    redemption_base_rate: float = 0.0
    last_redemption_hour: int = 0
    redemption_floor_fee: float = 0.005
    redemption_cap_fee: float = 0.05
    redemption_halflife_hours: float = 6.0

    _next_vault_num: int = 1

    def ensure_agent(self, agent_id: str) -> None:
        self.agent_pm.setdefault(agent_id, 0.0)
        self.agent_numeraire.setdefault(agent_id, 0.0)
        self.agent_collateral.setdefault(agent_id, {b: 0.0 for b in self.branches})
        for b in self.branches:
            self.agent_collateral[agent_id].setdefault(b, 0.0)

    def credit_pm(self, agent_id: str, amount: float) -> None:
        self.ensure_agent(agent_id)
        self.agent_pm[agent_id] += amount

    def active_vault_debt(self) -> float:
        return sum(v.debt_pm for v in self.vaults.values() if v.debt_pm > 0.0)

    def total_sp_pm(self) -> float:
        return sum(b.stability_pool_pm for b in self.branches.values())

    def current_redemption_fee(self, current_hour: int) -> float:
        dt_h = max(0, current_hour - self.last_redemption_hour)
        decayed = self.redemption_base_rate * (0.5 ** (dt_h / self.redemption_halflife_hours))
        return min(self.redemption_cap_fee, self.redemption_floor_fee + decayed)

    def open_or_mint_vault(
        self,
        owner: str,
        branch_name: str,
        add_collateral_qty: float,
        mint_pm: float,
        borrow_rate_apr: float,
        r_price: float,
        min_borrow_rate_apr: float = 0.005,
        *,
        vault_id: str | None = None,
        skip_owner_collateral_deduct: bool = False,
        initial_allocation_target: str | None = None,
    ) -> Vault:
        branch = self.branches[branch_name]
        if borrow_rate_apr < min_borrow_rate_apr:
            raise ValueError(
                f"borrow_rate_apr {borrow_rate_apr:.4f} below minimum floor {min_borrow_rate_apr:.4f}"
            )
        if add_collateral_qty < 0.0 or mint_pm < 0.0:
            raise ValueError("collateral and mint_pm must be non-negative")

        self.ensure_agent(owner)
        if not skip_owner_collateral_deduct and add_collateral_qty > 0.0:
            avail = self.agent_collateral[owner][branch_name]
            if avail + 1e-12 < add_collateral_qty:
                raise ValueError(
                    f"agent {owner} has {avail} {branch_name}, tried to deposit {add_collateral_qty}"
                )
            self.agent_collateral[owner][branch_name] = max(0.0, avail - add_collateral_qty)

        if vault_id is not None and vault_id in self.vaults:
            vault = self.vaults[vault_id]
            if vault.owner != owner or vault.branch != branch_name:
                raise ValueError("vault owner/branch mismatch")
            new_col = vault.collateral_qty + add_collateral_qty
            new_debt = vault.debt_pm + mint_pm
            new_rate = borrow_rate_apr
        else:
            vid = vault_id or f"V_{branch_name}_{self._next_vault_num}"
            self._next_vault_num += 1
            vault = Vault(
                vault_id=vid,
                owner=owner,
                branch=branch_name,
                collateral_qty=0.0,
                debt_pm=0.0,
                borrow_rate_apr=borrow_rate_apr,
            )
            new_col = add_collateral_qty
            new_debt = mint_pm
            new_rate = borrow_rate_apr

        if new_debt > 1e-12:
            cr = (new_col * branch.price) / (new_debt * r_price)
            if cr + 1e-12 < branch.mint_mcr:
                raise ValueError(
                    f"{branch_name} CR {cr:.4f} below mint MCR {branch.mint_mcr:.4f}"
                )

        vault.collateral_qty = new_col
        vault.debt_pm = new_debt
        vault.borrow_rate_apr = new_rate
        self.vaults[vault.vault_id] = vault

        if mint_pm > 0.0:
            recipient = initial_allocation_target or owner
            self.credit_pm(recipient, mint_pm)
            self.circulating_pm_supply += mint_pm
            self.cumulative_vault_mints_pm += mint_pm
        return vault

    def deposit_to_stability_pool(self, agent_id: str, branch_name: str, pm_amount: float) -> None:
        self.ensure_agent(agent_id)
        if pm_amount < 0.0 or self.agent_pm[agent_id] + 1e-12 < pm_amount:
            raise ValueError("insufficient PM for Stability Pool deposit")
        self.agent_pm[agent_id] -= min(pm_amount, self.agent_pm[agent_id])
        self.branches[branch_name].stability_pool_pm += pm_amount

    def repay_vault(self, vault_id: str, repay_pm: float) -> float:
        vault = self.vaults[vault_id]
        self.ensure_agent(vault.owner)
        actual = min(repay_pm, vault.debt_pm, self.agent_pm[vault.owner])
        if actual <= 0.0:
            return 0.0
        self.agent_pm[vault.owner] -= actual
        vault.debt_pm -= actual
        self.circulating_pm_supply -= actual
        self.cumulative_vault_burns_pm += actual
        return actual

    def swap_numeraire_for_pm(self, agent_id: str, numeraire_in: float) -> float:
        self.ensure_agent(agent_id)
        if numeraire_in <= 0.0 or self.agent_numeraire[agent_id] + 1e-9 < numeraire_in:
            raise ValueError(
                f"agent {agent_id} insufficient numeraire: has {self.agent_numeraire[agent_id]}, wants {numeraire_in}"
            )
        self.agent_numeraire[agent_id] = max(0.0, self.agent_numeraire[agent_id] - numeraire_in)
        pm_out = self.amm.swap_numeraire_for_pm(numeraire_in)
        self.agent_pm[agent_id] += pm_out
        return pm_out

    def swap_pm_for_numeraire(self, agent_id: str, pm_in: float) -> float:
        self.ensure_agent(agent_id)
        if pm_in <= 0.0 or self.agent_pm[agent_id] + 1e-9 < pm_in:
            raise ValueError(
                f"agent {agent_id} insufficient PM: has {self.agent_pm[agent_id]}, wants {pm_in}"
            )
        self.agent_pm[agent_id] = max(0.0, self.agent_pm[agent_id] - pm_in)
        num_out = self.amm.swap_pm_for_numeraire(pm_in)
        self.agent_numeraire[agent_id] += num_out
        return num_out

    def accrue_hourly_interest(
        self,
        throttle: ThrottleState,
        min_borrow_rate_apr: float,
        dt_years: float = 1.0 / 8760.0,
    ) -> float:
        total_interest = 0.0
        for vault in self.vaults.values():
            if vault.debt_pm <= 1e-12:
                continue
            effective_rate = max(vault.borrow_rate_apr, min_borrow_rate_apr)
            vault.borrow_rate_apr = effective_rate
            interest = vault.debt_pm * effective_rate * dt_years
            vault.debt_pm += interest
            total_interest += interest

            staker_part = interest * throttle.staker_fee_share
            ins_part = interest * throttle.insurance_fee_share
            sp_part = interest - staker_part - ins_part

            self.oracle_fee_pool_pm += staker_part
            self.insurance_reserve_pm += ins_part
            self.branches[vault.branch].stability_pool_pm += sp_part

        self.circulating_pm_supply += total_interest
        self.cumulative_vault_mints_pm += total_interest
        return total_interest

    def redeem_pm(
        self,
        redeemer: str,
        pm_amount: float,
        r_price: float,
        current_hour: int,
        *,
        convert_to_numeraire: bool = True,
    ) -> RedemptionReceipt:
        self.ensure_agent(redeemer)
        max_avail = min(pm_amount, self.agent_pm[redeemer], self.active_vault_debt())
        if max_avail <= 1e-12:
            return RedemptionReceipt(0.0, 0.0, self.current_redemption_fee(current_hour), 0.0, 0.0, 0.0, {})

        # Decay redemption base rate across elapsed hours
        dt_h = max(0, current_hour - self.last_redemption_hour)
        self.redemption_base_rate *= 0.5 ** (dt_h / self.redemption_halflife_hours)
        self.last_redemption_hour = current_hour

        f_redeem = min(self.redemption_cap_fee, self.redemption_floor_fee + self.redemption_base_rate)

        # Liquity-v2 ordering: lowest borrow_rate_apr first (tie-break: lowest CR, then vault_id).
        candidates = [v for v in self.vaults.values() if v.debt_pm > 1e-9]
        candidates.sort(
            key=lambda v: (
                v.borrow_rate_apr,
                v.collateral_ratio(self.branches[v.branch].price, r_price),
                v.vault_id,
            )
        )

        remaining = max_avail
        total_redeemed = 0.0
        total_col_received_val = 0.0
        total_fee_val = 0.0
        total_vault_fee_val = 0.0
        total_ins_fee_val = 0.0
        by_branch: dict[str, float] = {}

        for vault in candidates:
            if remaining <= 1e-12:
                break
            branch = self.branches[vault.branch]
            col_px = branch.price
            gross_needed_qty_per_pm = r_price / col_px
            # Ensure vault has enough collateral to honor redemption (minus 50% kept vault fee)
            net_deduct_qty_per_pm = ((1.0 - 0.5 * f_redeem) * r_price) / col_px
            max_pm_by_col = vault.collateral_qty / max(1e-12, net_deduct_qty_per_pm)
            d_pm = min(remaining, vault.debt_pm, max_pm_by_col)
            if d_pm <= 1e-12:
                continue

            gross_val = d_pm * r_price
            fee_val = gross_val * f_redeem
            vault_keep_val = 0.5 * fee_val
            ins_fee_val = 0.5 * fee_val
            redeemer_val = gross_val - fee_val

            redeemer_col_qty = redeemer_val / col_px
            ins_col_qty = ins_fee_val / col_px
            total_deduct_qty = min(vault.collateral_qty, redeemer_col_qty + ins_col_qty)

            vault.collateral_qty -= total_deduct_qty
            vault.debt_pm -= d_pm

            self.agent_pm[redeemer] -= d_pm
            self.circulating_pm_supply -= d_pm
            self.cumulative_vault_burns_pm += d_pm

            total_redeemed += d_pm
            total_col_received_val += redeemer_val
            total_fee_val += fee_val
            total_vault_fee_val += vault_keep_val
            total_ins_fee_val += ins_fee_val
            self.insurance_collateral_numeraire += ins_fee_val
            by_branch[branch.name] = by_branch.get(branch.name, 0.0) + redeemer_col_qty

            if convert_to_numeraire:
                self.agent_numeraire[redeemer] += redeemer_val
            else:
                self.agent_collateral[redeemer][branch.name] += redeemer_col_qty

            remaining -= d_pm

        if total_redeemed > 0.0:
            denom = max(1.0, self.circulating_pm_supply + total_redeemed)
            self.redemption_base_rate = min(
                self.redemption_cap_fee - self.redemption_floor_fee,
                self.redemption_base_rate + 0.5 * (total_redeemed / denom),
            )

        return RedemptionReceipt(
            pm_redeemed=total_redeemed,
            collateral_numeraire_received=total_col_received_val,
            fee_rate=f_redeem,
            fee_total_numeraire=total_fee_val,
            fee_to_vaults_numeraire=total_vault_fee_val,
            fee_to_insurance_numeraire=total_ins_fee_val,
            collateral_received_by_branch=by_branch,
        )

    def liquidate_branch(self, branch_name: str, r_price: float) -> LiquidationReport:
        """Hybrid A3 3-tier waterfall isolated to `branch_name` only."""
        branch = self.branches[branch_name]
        col_px = branch.price

        under_vaults = [
            v
            for v in self.vaults.values()
            if v.branch == branch_name
            and v.debt_pm > 1e-9
            and v.collateral_ratio(col_px, r_price) < branch.liq_cr
        ]
        if not under_vaults:
            return LiquidationReport(branch_name, 0, 0.0, 0.0, 0.0, 0.0, 0.0)

        under_ids = {v.vault_id for v in under_vaults}
        debt_cleared_total = 0.0
        sp_offset_total = 0.0
        ins_offset_total = 0.0
        redistributed_total = 0.0
        bad_debt_total = 0.0

        for vault in under_vaults:
            initial_debt = vault.debt_pm
            # Tier 1: Same-branch Stability Pool instant 1-block offset
            sp_offset = min(branch.stability_pool_pm, vault.debt_pm)
            if sp_offset > 0.0:
                branch.stability_pool_pm -= sp_offset
                vault.debt_pm -= sp_offset
                self.circulating_pm_supply -= sp_offset
                self.cumulative_vault_burns_pm += sp_offset
                sp_offset_total += sp_offset
                branch.total_sp_offset_pm += sp_offset

                target_col_val = sp_offset * r_price * (1.0 + branch.liq_discount)
                seize_qty = min(vault.collateral_qty, target_col_val / col_px)
                vault.collateral_qty -= seize_qty
                branch.stability_pool_collateral += seize_qty

            # Tier 2: Protocol Insurance Reserve (first use PM reserve; if needed, deploy insurance collateral)
            if vault.debt_pm > 1e-9:
                # If insurance holds collateral numeraire and PM reserve is low, swap up to needed via AMM
                if self.insurance_reserve_pm < vault.debt_pm and self.insurance_collateral_numeraire > 1e-9:
                    num_spend = min(self.insurance_collateral_numeraire, vault.debt_pm * r_price * 1.1)
                    if num_spend > 1e-9:
                        self.insurance_collateral_numeraire -= num_spend
                        bought_pm = self.amm.swap_numeraire_for_pm(num_spend)
                        self.insurance_reserve_pm += bought_pm

                ins_offset = min(self.insurance_reserve_pm, vault.debt_pm)
                if ins_offset > 0.0:
                    self.insurance_reserve_pm -= ins_offset
                    vault.debt_pm -= ins_offset
                    self.circulating_pm_supply -= ins_offset
                    self.cumulative_vault_burns_pm += ins_offset
                    ins_offset_total += ins_offset
                    branch.total_insurance_offset_pm += ins_offset

                    seize_val = ins_offset * r_price * (1.0 + branch.liq_discount)
                    seize_qty = min(vault.collateral_qty, seize_val / col_px)
                    vault.collateral_qty -= seize_qty
                    self.insurance_collateral_numeraire += seize_qty * col_px

            # If debt is fully settled and owner still has residual collateral, return surplus to owner
            if vault.debt_pm <= 1e-9:
                vault.debt_pm = 0.0
                if vault.collateral_qty > 0.0:
                    self.ensure_agent(vault.owner)
                    self.agent_collateral[vault.owner][branch_name] += vault.collateral_qty
                    vault.collateral_qty = 0.0
                debt_cleared_total += initial_debt
                branch.total_liquidated_debt_pm += initial_debt
                continue

            # Tier 3: Branch-isolated pro-rata debt redistribution ONLY among surviving healthy vaults in same branch
            rem_debt = vault.debt_pm
            rem_col = vault.collateral_qty
            survivors = [
                sv
                for sv in self.vaults.values()
                if sv.branch == branch_name and sv.vault_id not in under_ids and sv.debt_pm > 1e-9
            ]
            total_surv_debt = sum(sv.debt_pm for sv in survivors)
            if survivors and total_surv_debt > 1e-9:
                for sv in survivors:
                    weight = sv.debt_pm / total_surv_debt
                    sv.debt_pm += rem_debt * weight
                    sv.collateral_qty += rem_col * weight
                redistributed_total += rem_debt
                branch.total_redistributed_debt_pm += rem_debt
                vault.debt_pm = 0.0
                vault.collateral_qty = 0.0
            else:
                # No surviving vaults in isolated branch -> localized unbacked bad debt
                bad_debt_total += rem_debt
                branch.unbacked_bad_debt_pm += rem_debt
                self.unbacked_bad_debt_pm += rem_debt
                vault.debt_pm = 0.0
                # Residual collateral credited to insurance buffer
                if rem_col > 0.0:
                    self.insurance_collateral_numeraire += rem_col * col_px
                    vault.collateral_qty = 0.0

            debt_cleared_total += initial_debt
            branch.total_liquidated_debt_pm += initial_debt

        return LiquidationReport(
            branch=branch_name,
            liquidated_vaults=len(under_vaults),
            debt_cleared_pm=debt_cleared_total,
            sp_offset_pm=sp_offset_total,
            insurance_offset_pm=ins_offset_total,
            redistributed_debt_pm=redistributed_total,
            unbacked_bad_debt_pm=bad_debt_total,
        )

    def assert_conservation(self, oracle_locked_stake_pm: float) -> None:
        """Enforces exact dual PM conservation invariants across all buckets and vault liabilities."""
        all_buckets = (
            sum(self.agent_pm.values())
            + self.amm.pm_reserve
            + self.total_sp_pm()
            + self.insurance_reserve_pm
            + self.oracle_fee_pool_pm
            + self.pending_dispute_bonds_pm
            + oracle_locked_stake_pm
        )
        if abs(all_buckets - self.circulating_pm_supply) > 1e-4:
            raise AssertionError(
                f"PM bucket conservation violated: buckets={all_buckets:.6f} vs "
                f"circulating={self.circulating_pm_supply:.6f}"
            )
        liability = self.active_vault_debt() + self.unbacked_bad_debt_pm
        accounted = self.circulating_pm_supply + self.cumulative_slash_burned_pm
        if abs(liability - accounted) > 1e-4:
            raise AssertionError(
                f"PM backing conservation violated: debt+bad_debt={liability:.6f} vs "
                f"circulating+burned={accounted:.6f}"
            )

