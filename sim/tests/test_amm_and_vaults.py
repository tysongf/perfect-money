from sim.engine.amm_and_vaults import SpotAMM, VaultAndAmmSystem


def _make_backed_system(amm_reserve: float = 100_000.0) -> VaultAndAmmSystem:
    sys = VaultAndAmmSystem(amm=SpotAMM(pm_reserve=amm_reserve, numeraire_reserve=amm_reserve))
    col = (amm_reserve * 3.0) / sys.branches["ETH"].price
    sys.open_or_mint_vault(
        "lp_init",
        "ETH",
        col,
        amm_reserve,
        0.05,
        1.0,
        skip_owner_collateral_deduct=True,
        initial_allocation_target="_amm_",
        vault_id="V_AMM_BACK",
    )
    sys.agent_pm["_amm_"] = 0.0
    return sys


def test_lowest_borrow_rate_redemption_and_dynamic_fee_decay():
    sys = _make_backed_system(100_000.0)
    # Low-rate vault (4%) vs high-rate vault (9%)
    sys.open_or_mint_vault("alice", "ETH", 1.0, 1000.0, 0.04, 1.0, skip_owner_collateral_deduct=True, vault_id="V_LOW")
    sys.open_or_mint_vault("bob", "ETH", 1.0, 1000.0, 0.09, 1.0, skip_owner_collateral_deduct=True, vault_id="V_HIGH")
    # Mint redeemer's 600 PM cleanly from a separate higher-rate vault (12%) so all PM is vault-backed
    sys.open_or_mint_vault("funder", "ETH", 1.0, 600.0, 0.12, 1.0, skip_owner_collateral_deduct=True, initial_allocation_target="redeemer")

    receipt = sys.redeem_pm("redeemer", 500.0, r_price=1.0, current_hour=10)
    assert receipt.pm_redeemed == 500.0
    # Lowest rate vault V_LOW must absorb the entire redemption while V_HIGH stays untouched
    assert abs(sys.vaults["V_LOW"].debt_pm - 500.0) < 1e-9
    assert abs(sys.vaults["V_HIGH"].debt_pm - 1000.0) < 1e-9
    assert abs(receipt.fee_rate - 0.005) < 1e-9
    assert abs(receipt.fee_to_vaults_numeraire - receipt.fee_to_insurance_numeraire) < 1e-9

    # Dynamic fee rose after redemption, then halves every 6 hours back toward 0.5% floor
    elevated = sys.current_redemption_fee(10)
    after_6h = sys.current_redemption_fee(16)
    assert elevated > 0.005
    assert abs((after_6h - 0.005) - 0.5 * (elevated - 0.005)) < 1e-9
    sys.assert_conservation(0.0)


def test_hybrid_a3_single_branch_isolation_across_all_three_tiers():
    sys = _make_backed_system(100_000.0)
    # Healthy ETH and BTC vaults
    sys.open_or_mint_vault("eth_owner", "ETH", 10.0, 10_000.0, 0.05, 1.0, skip_owner_collateral_deduct=True, vault_id="V_ETH")
    sys.open_or_mint_vault("btc_owner", "BTC", 0.5, 15_000.0, 0.05, 1.0, skip_owner_collateral_deduct=True, vault_id="V_BTC")

    # SOL vaults: one risky (180% CR) + one very safe survivor (500% CR) so Tier 3 stays inside SOL ONLY
    sol_px = sys.branches["SOL"].price  # $180
    sys.open_or_mint_vault("sol_risky", "SOL", (10_000.0 * 1.80) / sol_px, 10_000.0, 0.06, 1.0, skip_owner_collateral_deduct=True, vault_id="V_SOL_RISKY")
    sys.open_or_mint_vault("sol_safe", "SOL", (10_000.0 * 5.00) / sol_px, 10_000.0, 0.06, 1.0, skip_owner_collateral_deduct=True, vault_id="V_SOL_SAFE")

    # Fund small SOL SP (2,000) and small Insurance Reserve (1,500) from backed ETH LP vaults
    sys.open_or_mint_vault("sp_lp", "ETH", 10.0, 2_000.0, 0.08, 1.0, skip_owner_collateral_deduct=True)
    sys.deposit_to_stability_pool("sp_lp", "SOL", 2_000.0)
    sys.open_or_mint_vault("ins_lp", "ETH", 10.0, 1_500.0, 0.08, 1.0, skip_owner_collateral_deduct=True, initial_allocation_target="_ins_")
    sys.agent_pm["_ins_"] -= 1_500.0
    sys.insurance_reserve_pm += 1_500.0

    # SOL crashes -55%: $180 -> $81 (V_SOL_RISKY drops to 81% CR < 125%; V_SOL_SAFE drops to 225% > 125%)
    sys.branches["SOL"].price *= 0.45
    rep = sys.liquidate_branch("SOL", r_price=1.0)

    assert rep.liquidated_vaults == 1
    assert rep.sp_offset_pm == 2_000.0
    assert rep.insurance_offset_pm == 1_500.0
    assert abs(rep.redistributed_debt_pm - 6_500.0) < 1e-6
    assert rep.unbacked_bad_debt_pm == 0.0

    # Surviving SOL vault absorbed Tier 3; healthy ETH and BTC branches suffered ZERO contagion
    assert abs(sys.vaults["V_SOL_SAFE"].debt_pm - 16_500.0) < 1e-6
    assert abs(sys.vaults["V_ETH"].debt_pm - 10_000.0) < 1e-6
    assert abs(sys.vaults["V_BTC"].debt_pm - 15_000.0) < 1e-6
    assert sys.branches["ETH"].total_redistributed_debt_pm == 0.0
    assert sys.branches["BTC"].total_redistributed_debt_pm == 0.0
    sys.assert_conservation(0.0)
