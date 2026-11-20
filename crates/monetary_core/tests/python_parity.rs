use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use monetary_core::{
    BasketSpec, OracleMarket, OracleNode, OracleRole, PegController, SCALE, SpotAmm,
    ThrottleConfig, VaultAndAmmSystem, compute_auto_throttle, default_collateral_branches,
    default_genesis_prices, pm_from_whole, scale_from_bps,
};
use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .to_path_buf()
}

fn find_python(root: &Path) -> PathBuf {
    let venv = root.join(".venv").join("bin").join("python3");
    if venv.is_file() {
        venv
    } else {
        PathBuf::from("python3")
    }
}

fn assert_close_f64(label: &str, rust_scaled: u128, denom: f64, py_val: f64, rel_tol: f64) {
    let rust_f = (rust_scaled as f64) / denom;
    let abs_tol = (rel_tol * py_val.abs()).max(1e-6);
    let diff = (rust_f - py_val).abs();
    assert!(
        diff <= abs_tol,
        "parity mismatch for {label}: rust={rust_f} vs python={py_val} (diff={diff}, tol={abs_tol})"
    );
}

#[test]
fn test_rust_monetary_core_parity_with_python_sim_engine() {
    let root = workspace_root();
    let py_bin = find_python(&root);

    let script = r#"
import json
from sim.engine.peg_controller import (
    BasketSpec, DEFAULT_GENESIS_PRICES, PegController, compute_auto_throttle
)
from sim.engine.oracle_market import OracleMarket, OracleNode
from sim.engine.amm_and_vaults import SpotAMM, VaultAndAmmSystem

# 1. Geometric index under multi-asset CPI shock
basket = BasketSpec()
shocked = dict(DEFAULT_GENESIS_PRICES)
shocked["electricity"] *= 1.40
shocked["oil_gas"] *= 1.25
shocked["grain"] *= 1.12
shocked["metals"] *= 0.92
shocked["housing"] *= 1.08
shocked["datacenter_power"] *= 1.35
geo_index = basket.index(shocked)

# 2. Auto-throttle low-stake & healthy-stake
low_thr = compute_auto_throttle(locked_pm=140_000.0, amm_liquidity_pm=400_000.0, total_pm_supply=1_000_000.0)
high_thr = compute_auto_throttle(locked_pm=35_000_000.0, amm_liquidity_pm=20_000_000.0, total_pm_supply=50_000_000.0)

# 3. 48-step decoupled PegController under -15% AMM spoof
pc = PegController(mode="patched_decoupled")
for _ in range(48):
    peg_res = pc.step(i_oracle=1.0, m_spot=0.85, dt_days=1.0 / 24.0)

# 4. Commit-reveal + 48h court overturn
om = OracleMarket(initial_prices=DEFAULT_GENESIS_PRICES)
om.add_node(OracleNode("h1", 51_000.0, is_court_voter=True, role="honest"))
om.add_node(OracleNode("c1", 49_000.0, is_court_voter=True, role="cartel"))
om.add_node(OracleNode("wb", 10_000.0, is_court_voter=True, role="whistleblower"))
thr_o = compute_auto_throttle(om.total_locked_stake(), 100_000.0, om.total_locked_stake())
om.start_round(0)
fake = {k: v * 1.10 for k, v in DEFAULT_GENESIS_PRICES.items()}
om.submit_commit("c1", fake, "sc")
om.advance(1, thr_o, 0.0)
om.submit_reveal("c1", fake, "sc")
om.advance(2, thr_o, 0.0)
om.challenge_round("wb", 5_000.0, 2)
om.submit_court_vote("h1", DEFAULT_GENESIS_PRICES, "vh1")
om.submit_court_vote("wb", DEFAULT_GENESIS_PRICES, "vwb")
om.submit_court_vote("c1", fake, "vc1")
ores, _, _ = om.advance(50, thr_o, 1_000.0)

# 5. Vault redemption + Hybrid A3 SOL -55% liquidation
sys = VaultAndAmmSystem(amm=SpotAMM(pm_reserve=100_000.0, numeraire_reserve=100_000.0))
sys.open_or_mint_vault("lp", "ETH", 100.0, 100_000.0, 0.05, 1.0, skip_owner_collateral_deduct=True, initial_allocation_target="_amm_")
sys.agent_pm["_amm_"] = 0.0
sys.open_or_mint_vault("alice", "ETH", 1.0, 1_000.0, 0.04, 1.0, skip_owner_collateral_deduct=True, vault_id="V_LOW")
sys.open_or_mint_vault("bob", "ETH", 1.0, 1_000.0, 0.09, 1.0, skip_owner_collateral_deduct=True, vault_id="V_HIGH")
sys.open_or_mint_vault("funder", "ETH", 1.0, 600.0, 0.12, 1.0, skip_owner_collateral_deduct=True, initial_allocation_target="redeemer")
receipt = sys.redeem_pm("redeemer", 500.0, r_price=1.0, current_hour=10)
fee_after_6h = sys.current_redemption_fee(16)

sys.open_or_mint_vault("eth_owner", "ETH", 10.0, 10_000.0, 0.05, 1.0, skip_owner_collateral_deduct=True, vault_id="V_ETH")
sys.open_or_mint_vault("sol_risky", "SOL", (10_000.0 * 1.80) / 180.0, 10_000.0, 0.06, 1.0, skip_owner_collateral_deduct=True, vault_id="V_SOL_RISKY")
sys.open_or_mint_vault("sol_safe", "SOL", (10_000.0 * 5.00) / 180.0, 10_000.0, 0.06, 1.0, skip_owner_collateral_deduct=True, vault_id="V_SOL_SAFE")
sys.open_or_mint_vault("sp_lp", "ETH", 10.0, 2_000.0, 0.08, 1.0, skip_owner_collateral_deduct=True)
sys.deposit_to_stability_pool("sp_lp", "SOL", 2_000.0)
sys.open_or_mint_vault("ins_lp", "ETH", 10.0, 1_500.0, 0.08, 1.0, skip_owner_collateral_deduct=True, initial_allocation_target="_ins_")
sys.agent_pm["_ins_"] -= 1_500.0
sys.insurance_reserve_pm += 1_500.0
sys.branches["SOL"].price *= 0.45
liq_rep = sys.liquidate_branch("SOL", r_price=1.0)

print(json.dumps({
    "geo_index": geo_index,
    "low_thr": {"max_delta": low_thr.max_epoch_delta, "challenge_h": low_thr.challenge_hours, "staker_share": low_thr.staker_fee_share, "coc_pfc": low_thr.coc_pfc_ratio},
    "high_thr": {"max_delta": high_thr.max_epoch_delta, "challenge_h": high_thr.challenge_hours, "staker_share": high_thr.staker_fee_share},
    "peg": {"r_price": peg_res.r_price, "min_borrow_rate_apr": peg_res.min_borrow_rate_apr},
    "oracle": {"electricity_star": ores.finalized_prices["electricity"], "wb_bounty": ores.bounty_payouts["wb"], "c1_stake": om.nodes["c1"].stake_pm, "h1_rewards": om.nodes["h1"].rewards_pm},
    "vaults": {"v_low_debt": sys.vaults["V_LOW"].debt_pm, "fee_after_6h": fee_after_6h, "sol_safe_debt": sys.vaults["V_SOL_SAFE"].debt_pm, "sol_redist": sys.branches["SOL"].total_redistributed_debt_pm, "eth_redist": sys.branches["ETH"].total_redistributed_debt_pm}
}))
"#;

    let out = Command::new(&py_bin)
        .args(["-c", script])
        .current_dir(&root)
        .output()
        .expect("execute python parity check");
    assert!(
        out.status.success(),
        "python parity script failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let py: Value = serde_json::from_slice(&out.stdout).expect("parse python parity JSON");

    // Run identical scenarios in Rust monetary_core
    let basket = BasketSpec::default();
    let mut shocked = default_genesis_prices();
    let mults = [
        ("electricity", 140u128),
        ("oil_gas", 125),
        ("grain", 112),
        ("metals", 92),
        ("housing", 108),
        ("datacenter_power", 135),
    ];
    for (k, m) in mults {
        *shocked.get_mut(k).unwrap() = (shocked[k] * m) / 100;
    }
    let rust_geo = basket.index(&shocked).unwrap();
    assert_close_f64(
        "geo_index",
        rust_geo,
        SCALE as f64,
        py["geo_index"].as_f64().unwrap(),
        1e-7,
    );

    let cfg = ThrottleConfig::default();
    let rust_low = compute_auto_throttle(
        pm_from_whole(140_000),
        pm_from_whole(400_000),
        pm_from_whole(1_000_000),
        &cfg,
    )
    .unwrap();
    assert_close_f64(
        "low_thr.max_delta",
        rust_low.max_epoch_delta,
        SCALE as f64,
        py["low_thr"]["max_delta"].as_f64().unwrap(),
        1e-7,
    );
    assert_eq!(
        rust_low.challenge_hours,
        py["low_thr"]["challenge_h"].as_u64().unwrap()
    );
    assert_close_f64(
        "low_thr.staker_share",
        rust_low.staker_fee_share,
        SCALE as f64,
        py["low_thr"]["staker_share"].as_f64().unwrap(),
        1e-7,
    );

    let rust_high = compute_auto_throttle(
        pm_from_whole(35_000_000),
        pm_from_whole(20_000_000),
        pm_from_whole(50_000_000),
        &cfg,
    )
    .unwrap();
    assert_close_f64(
        "high_thr.max_delta",
        rust_high.max_epoch_delta,
        SCALE as f64,
        py["high_thr"]["max_delta"].as_f64().unwrap(),
        1e-7,
    );
    assert_eq!(
        rust_high.challenge_hours,
        py["high_thr"]["challenge_h"].as_u64().unwrap()
    );

    let mut pc = PegController::default();
    let mut peg_res = None;
    for _ in 0..48 {
        peg_res = Some(pc.step(SCALE, 850_000_000, 1).unwrap());
    }
    let peg_res = peg_res.unwrap();
    assert_close_f64(
        "peg.r_price",
        peg_res.r_price,
        SCALE as f64,
        py["peg"]["r_price"].as_f64().unwrap(),
        1e-7,
    );
    assert_close_f64(
        "peg.min_borrow_rate_apr",
        peg_res.min_borrow_rate_apr,
        SCALE as f64,
        py["peg"]["min_borrow_rate_apr"].as_f64().unwrap(),
        1e-7,
    );

    let genesis = default_genesis_prices();
    let mut om = OracleMarket::new(genesis.clone()).unwrap();
    om.add_node(OracleNode::new(
        "h1",
        pm_from_whole(51_000),
        true,
        OracleRole::Honest,
    ));
    om.add_node(OracleNode::new(
        "c1",
        pm_from_whole(49_000),
        true,
        OracleRole::Cartel,
    ));
    om.add_node(OracleNode::new(
        "wb",
        pm_from_whole(10_000),
        true,
        OracleRole::Whistleblower,
    ));
    let thr_o = compute_auto_throttle(
        om.total_locked_stake(),
        pm_from_whole(100_000),
        om.total_locked_stake(),
        &cfg,
    )
    .unwrap();
    om.start_round(0).unwrap();
    let fake: BTreeMap<String, u128> = genesis
        .iter()
        .map(|(k, &v)| (k.clone(), (v * 110) / 100))
        .collect();
    om.submit_commit("c1", &fake, "sc").unwrap();
    om.advance(1, &thr_o, 0).unwrap();
    om.submit_reveal("c1", &fake, "sc").unwrap();
    om.advance(2, &thr_o, 0).unwrap();
    om.challenge_round("wb", pm_from_whole(5_000), 2).unwrap();
    om.submit_court_vote("h1", &genesis, "vh1").unwrap();
    om.submit_court_vote("wb", &genesis, "vwb").unwrap();
    om.submit_court_vote("c1", &fake, "vc1").unwrap();
    let (ores, _) = om.advance(50, &thr_o, pm_from_whole(1_000)).unwrap();
    let ores = ores.unwrap();
    assert_close_f64(
        "oracle.electricity_star",
        ores.finalized_prices["electricity"],
        SCALE as f64,
        py["oracle"]["electricity_star"].as_f64().unwrap(),
        1e-7,
    );
    assert_close_f64(
        "oracle.wb_bounty",
        ores.bounty_payouts["wb"],
        1_000_000.0,
        py["oracle"]["wb_bounty"].as_f64().unwrap(),
        1e-6,
    );
    assert_close_f64(
        "oracle.h1_rewards",
        om.nodes["h1"].rewards_pm,
        1_000_000.0,
        py["oracle"]["h1_rewards"].as_f64().unwrap(),
        1e-6,
    );

    let mut sys = VaultAndAmmSystem::new_backed(
        default_collateral_branches(),
        SpotAmm::new(
            pm_from_whole(100_000),
            pm_from_whole(100_000),
            scale_from_bps(30),
        )
        .unwrap(),
    )
    .unwrap();
    sys.open_or_mint_vault(
        "alice",
        "ETH",
        SCALE,
        pm_from_whole(1_000),
        scale_from_bps(400),
        SCALE,
        scale_from_bps(50),
        Some("V_LOW"),
        true,
        None,
    )
    .unwrap();
    sys.open_or_mint_vault(
        "bob",
        "ETH",
        SCALE,
        pm_from_whole(1_000),
        scale_from_bps(900),
        SCALE,
        scale_from_bps(50),
        Some("V_HIGH"),
        true,
        None,
    )
    .unwrap();
    sys.open_or_mint_vault(
        "funder",
        "ETH",
        SCALE,
        pm_from_whole(600),
        scale_from_bps(1200),
        SCALE,
        scale_from_bps(50),
        Some("V_FUNDER"),
        true,
        Some("redeemer"),
    )
    .unwrap();
    sys.redeem_pm("redeemer", pm_from_whole(500), SCALE, 10, true)
        .unwrap();
    let fee_6h = sys.current_redemption_fee(16).unwrap();

    sys.open_or_mint_vault(
        "eth_owner",
        "ETH",
        10 * SCALE,
        pm_from_whole(10_000),
        scale_from_bps(500),
        SCALE,
        scale_from_bps(50),
        Some("V_ETH"),
        true,
        None,
    )
    .unwrap();
    sys.open_or_mint_vault(
        "sol_risky",
        "SOL",
        100 * SCALE,
        pm_from_whole(10_000),
        scale_from_bps(600),
        SCALE,
        scale_from_bps(50),
        Some("V_SOL_RISKY"),
        true,
        None,
    )
    .unwrap();
    sys.open_or_mint_vault(
        "sol_safe",
        "SOL",
        (50_000 * SCALE) / 180,
        pm_from_whole(10_000),
        scale_from_bps(600),
        SCALE,
        scale_from_bps(50),
        Some("V_SOL_SAFE"),
        true,
        None,
    )
    .unwrap();
    sys.open_or_mint_vault(
        "sp_lp",
        "ETH",
        10 * SCALE,
        pm_from_whole(2_000),
        scale_from_bps(800),
        SCALE,
        scale_from_bps(50),
        Some("V_SP_LP"),
        true,
        None,
    )
    .unwrap();
    sys.deposit_to_stability_pool("sp_lp", "SOL", pm_from_whole(2_000))
        .unwrap();
    sys.open_or_mint_vault(
        "ins_lp",
        "ETH",
        10 * SCALE,
        pm_from_whole(1_500),
        scale_from_bps(800),
        SCALE,
        scale_from_bps(50),
        Some("V_INS_LP"),
        true,
        Some("_ins_"),
    )
    .unwrap();
    *sys.agent_pm.get_mut("_ins_").unwrap() -= pm_from_whole(1_500);
    sys.insurance_reserve_pm += pm_from_whole(1_500);
    sys.branches.get_mut("SOL").unwrap().price = 81 * SCALE;
    sys.liquidate_branch("SOL", SCALE).unwrap();

    assert_close_f64(
        "vaults.v_low_debt",
        sys.vaults["V_LOW"].debt_pm,
        1_000_000.0,
        py["vaults"]["v_low_debt"].as_f64().unwrap(),
        1e-7,
    );
    assert_close_f64(
        "vaults.fee_after_6h",
        fee_6h,
        SCALE as f64,
        py["vaults"]["fee_after_6h"].as_f64().unwrap(),
        1e-6,
    );
    assert_close_f64(
        "vaults.sol_safe_debt",
        sys.vaults["V_SOL_SAFE"].debt_pm,
        1_000_000.0,
        py["vaults"]["sol_safe_debt"].as_f64().unwrap(),
        1e-7,
    );
    assert_close_f64(
        "vaults.sol_redist",
        sys.branches["SOL"].total_redistributed_debt_pm,
        1_000_000.0,
        py["vaults"]["sol_redist"].as_f64().unwrap(),
        1e-7,
    );
    assert_eq!(sys.branches["ETH"].total_redistributed_debt_pm, 0);
}

