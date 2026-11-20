use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use ledger_core::LedgerState;
use monetary_core::{
    MonetaryEngine, MonetaryError, OracleMarket, OracleNode, OracleRole, SCALE, SCALE_TO_PM,
    SpotAmm, ThrottleConfig, VaultAndAmmSystem, compute_auto_throttle,
    default_collateral_branches, default_genesis_prices, pm_from_whole, scale_from_bps,
    weighted_median,
};
use pm_sdk::{ClientWallet, NargoBbProver, PublishedOutput, field_from_hex, field_to_hex};
use tempfile::TempDir;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates")
        .parent()
        .expect("root")
        .to_path_buf()
}

fn scaled_prices(mult_num: u128, mult_den: u128) -> std::collections::BTreeMap<String, u128> {
    default_genesis_prices()
        .into_iter()
        .map(|(k, v)| (k, (v * mult_num) / mult_den))
        .collect()
}

#[test]
fn test_weighted_median_ties_and_skew() {
    assert_eq!(weighted_median(&[(10, 1), (20, 1), (30, 1)]).unwrap(), 20);
    assert_eq!(weighted_median(&[(10, 49), (110, 51)]).unwrap(), 110);
    assert_eq!(weighted_median(&[(10, 51), (110, 49)]).unwrap(), 10);
    assert_eq!(
        weighted_median(&[]),
        Err(MonetaryError::EmptyWeightedMedian)
    );
}

#[test]
fn test_no_reveal_10pct_slash_and_conservation() {
    let mut engine = MonetaryEngine::new_default().unwrap();
    let eth_px = engine.vaults.branches["ETH"].price;
    let stake_col = (pm_from_whole(250_000) * SCALE_TO_PM * SCALE) / eth_px;
    engine
        .vaults
        .open_or_mint_vault(
            "h1",
            "ETH",
            stake_col,
            pm_from_whole(60_000),
            scale_from_bps(500),
            engine.peg.r_price,
            engine.peg.min_borrow_rate_apr,
            Some("V_H1"),
            true,
            None,
        )
        .unwrap();
    engine
        .vaults
        .open_or_mint_vault(
            "lazy",
            "ETH",
            stake_col,
            pm_from_whole(40_000),
            scale_from_bps(500),
            engine.peg.r_price,
            engine.peg.min_borrow_rate_apr,
            Some("V_LAZY"),
            true,
            None,
        )
        .unwrap();
    engine
        .stake_oracle_pm("h1", "h1", pm_from_whole(60_000), true, OracleRole::Honest)
        .unwrap();
    engine
        .stake_oracle_pm(
            "lazy",
            "lazy",
            pm_from_whole(40_000),
            true,
            OracleRole::Honest,
        )
        .unwrap();

    let genesis = default_genesis_prices();
    engine.oracle.start_round(0).unwrap();
    engine.oracle.submit_commit("h1", &genesis, "s1").unwrap();
    engine.oracle.submit_commit("lazy", &genesis, "s2").unwrap();
    engine.advance_hour(1).unwrap();
    engine.oracle.submit_reveal("h1", &genesis, "s1").unwrap();
    let ins_before = engine.vaults.insurance_reserve_pm;
    // lazy omits reveal -> 10% slash = 4,000 PM (90% burned, 10% insurance) plus 1h interest
    engine.advance_hour(2).unwrap();
    let ins_delta = engine.vaults.insurance_reserve_pm - ins_before;

    assert_eq!(engine.oracle.nodes["lazy"].stake_pm, pm_from_whole(36_000));
    assert!(ins_delta >= pm_from_whole(400));
    assert_eq!(engine.vaults.cumulative_slash_burned_pm, pm_from_whole(3_600));
    engine.assert_conservation().unwrap();
}

#[test]
fn test_same_round_outlier_cartel_blocked_by_frozen_ewma() {
    let genesis = default_genesis_prices();
    let mut om = OracleMarket::new(genesis.clone()).unwrap();
    om.add_node(OracleNode::new(
        "h1",
        pm_from_whole(260_000),
        true,
        OracleRole::Honest,
    ));
    om.add_node(OracleNode::new(
        "h2",
        pm_from_whole(260_000),
        true,
        OracleRole::Honest,
    ));
    for nid in ["c_low", "c_high", "c_extreme"] {
        om.add_node(OracleNode::new(
            nid,
            pm_from_whole(160_000),
            true,
            OracleRole::Cartel,
        ));
    }

    let thr = compute_auto_throttle(
        om.total_locked_stake(),
        pm_from_whole(100_000),
        om.total_locked_stake(),
        &ThrottleConfig::default(),
    )
    .unwrap();
    let frozen_eps = om.start_round(0).unwrap().frozen_epsilons.clone();

    let low = scaled_prices(70, 100);
    let high = scaled_prices(115, 100);
    let ext = scaled_prices(180, 100);

    om.submit_commit("h1", &genesis, "s1").unwrap();
    om.submit_commit("h2", &genesis, "s2").unwrap();
    om.submit_commit("c_low", &low, "s3").unwrap();
    om.submit_commit("c_high", &high, "s4").unwrap();
    om.submit_commit("c_extreme", &ext, "s5").unwrap();
    om.advance(1, &thr, 0).unwrap();

    om.submit_reveal("h1", &genesis, "s1").unwrap();
    om.submit_reveal("h2", &genesis, "s2").unwrap();
    om.submit_reveal("c_low", &low, "s3").unwrap();
    om.submit_reveal("c_high", &high, "s4").unwrap();
    om.submit_reveal("c_extreme", &ext, "s5").unwrap();
    om.advance(2, &thr, 0).unwrap();

    let mut res = None;
    for h in 3..60 {
        let (r, _) = om.advance(h, &thr, pm_from_whole(1_000)).unwrap();
        if r.is_some() {
            res = r;
            break;
        }
    }
    let res = res.unwrap();
    assert_eq!(res.epsilon_by_asset, frozen_eps);
    for cid in ["c_low", "c_high", "c_extreme"] {
        assert_eq!(om.nodes[cid].stake_pm, 0);
        assert!(om.nodes[cid].jailed);
    }
    assert_eq!(
        res.burned_pm + res.insurance_pm,
        pm_from_whole(480_000)
    );
}

#[test]
fn test_court_overturn_and_frivolous_challenger_bond_slash() {
    let mut engine = MonetaryEngine::new_default().unwrap();
    let eth_px = engine.vaults.branches["ETH"].price;
    let big_col = (pm_from_whole(400_000) * SCALE_TO_PM * SCALE) / eth_px;

    for (owner, mint) in [
        ("h1", 51_000u64),
        ("c1", 49_000),
        ("wb", 20_000),
        ("troll", 10_000),
    ] {
        engine
            .vaults
            .open_or_mint_vault(
                owner,
                "ETH",
                big_col,
                pm_from_whole(mint),
                scale_from_bps(500),
                engine.peg.r_price,
                engine.peg.min_borrow_rate_apr,
                None,
                true,
                None,
            )
            .unwrap();
    }
    engine
        .stake_oracle_pm("h1", "h1", pm_from_whole(51_000), true, OracleRole::Honest)
        .unwrap();
    engine
        .stake_oracle_pm("c1", "c1", pm_from_whole(49_000), true, OracleRole::Cartel)
        .unwrap();
    engine
        .stake_oracle_pm(
            "wb",
            "wb",
            pm_from_whole(10_000),
            true,
            OracleRole::Whistleblower,
        )
        .unwrap();

    // Round 1: h1 offline during commit, c1 pushes +10%, wb disputes & 48h court overturns
    let genesis = default_genesis_prices();
    let fake_110 = scaled_prices(110, 100);
    engine.oracle.start_round(0).unwrap();
    engine.oracle.submit_commit("c1", &fake_110, "sc").unwrap();
    engine.advance_hour(1).unwrap();
    engine.oracle.submit_reveal("c1", &fake_110, "sc").unwrap();
    engine.advance_hour(2).unwrap();

    engine
        .challenge_round_with_bond("wb", pm_from_whole(5_000), 2)
        .unwrap();
    engine.oracle.submit_court_vote("h1", &genesis, "vh1").unwrap();
    engine.oracle.submit_court_vote("wb", &genesis, "vwb").unwrap();
    engine.oracle.submit_court_vote("c1", &fake_110, "vc1").unwrap();

    let res1 = engine.advance_hour(50).unwrap().unwrap();
    assert!(res1.was_disputed);
    assert!(res1.dispute_upheld_challenger);
    assert_eq!(engine.oracle.nodes["c1"].stake_pm, 0);
    assert_eq!(res1.bond_refunds["wb"], pm_from_whole(5_000));
    assert_eq!(res1.bounty_payouts["wb"], pm_from_whole(9_800));
    assert!(engine.vaults.agent_pm["wb"] >= pm_from_whole(19_800));
    engine.assert_conservation().unwrap();

    // Round 2: honest median; troll launches frivolous challenge -> loses 5,000 PM bond (70/20/10)
    engine.oracle.start_round(54).unwrap();
    engine.oracle.submit_commit("h1", &genesis, "sh1").unwrap();
    engine.oracle.submit_commit("wb", &genesis, "swb").unwrap();
    engine.advance_hour(55).unwrap();
    engine.oracle.submit_reveal("h1", &genesis, "sh1").unwrap();
    engine.oracle.submit_reveal("wb", &genesis, "swb").unwrap();
    engine.advance_hour(56).unwrap();

    engine
        .challenge_round_with_bond("troll", pm_from_whole(5_000), 56)
        .unwrap();
    engine
        .oracle
        .submit_court_vote("h1", &genesis, "vh1b")
        .unwrap();
    engine
        .oracle
        .submit_court_vote("wb", &genesis, "vwbb")
        .unwrap();
    let res2 = engine.advance_hour(104).unwrap().unwrap();
    assert!(res2.was_disputed);
    assert!(!res2.dispute_upheld_challenger);
    assert_eq!(res2.forfeited_bond_pm, pm_from_whole(5_000));
    assert_eq!(res2.burned_pm, pm_from_whole(3_500));
    assert_eq!(res2.bond_fee_pool_pm, pm_from_whole(1_000));
    assert_eq!(res2.insurance_pm, pm_from_whole(500));
    assert_eq!(engine.vaults.pending_dispute_bonds_pm, 0);
    engine.assert_conservation().unwrap();
}

#[test]
fn test_lowest_borrow_rate_redemption_and_half_life_fee_decay() {
    let mut sys = VaultAndAmmSystem::new_backed(
        default_collateral_branches(),
        SpotAmm::new(pm_from_whole(100_000), pm_from_whole(100_000), scale_from_bps(30)).unwrap(),
    )
    .unwrap();

    sys.open_or_mint_vault(
        "alice",
        "ETH",
        SCALE,
        pm_from_whole(1_000),
        scale_from_bps(400), // 4%
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
        scale_from_bps(900), // 9%
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

    let receipt = sys
        .redeem_pm("redeemer", pm_from_whole(500), SCALE, 10, true)
        .unwrap();
    assert_eq!(receipt.pm_redeemed, pm_from_whole(500));
    assert_eq!(sys.vaults["V_LOW"].debt_pm, pm_from_whole(500));
    assert_eq!(sys.vaults["V_HIGH"].debt_pm, pm_from_whole(1_000));
    assert_eq!(receipt.fee_rate, 5_000_000);
    assert_eq!(
        receipt.fee_to_vaults_numeraire,
        receipt.fee_to_insurance_numeraire
    );

    let elevated = sys.current_redemption_fee(10).unwrap();
    let after_6h = sys.current_redemption_fee(16).unwrap();
    assert!(elevated > 5_000_000);
    let excess_elev = elevated - 5_000_000;
    let excess_6h = after_6h - 5_000_000;
    assert!(excess_6h.abs_diff(excess_elev / 2) <= 2);
    sys.assert_conservation(0).unwrap();
}

#[test]
fn test_hybrid_a3_single_branch_isolation_across_all_three_tiers() {
    let mut sys = VaultAndAmmSystem::new_backed(
        default_collateral_branches(),
        SpotAmm::new(pm_from_whole(100_000), pm_from_whole(100_000), scale_from_bps(30)).unwrap(),
    )
    .unwrap();

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
        "btc_owner",
        "BTC",
        SCALE / 2,
        pm_from_whole(15_000),
        scale_from_bps(500),
        SCALE,
        scale_from_bps(50),
        Some("V_BTC"),
        true,
        None,
    )
    .unwrap();

    // SOL = $180 -> 18,000 / 180 = 100 SOL (180% CR), 50,000 / 180 = 277.777777777 SOL (500% CR)
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

    // SOL crashes -55%: $180 -> $81 (risky CR = 81% < 125%; safe CR = 225% >= 125%)
    sys.branches.get_mut("SOL").unwrap().price = 81 * SCALE;
    let rep = sys.liquidate_branch("SOL", SCALE).unwrap();
    assert_eq!(rep.liquidated_vaults, 1);
    assert_eq!(rep.sp_offset_pm, pm_from_whole(2_000));
    assert_eq!(rep.insurance_offset_pm, pm_from_whole(1_500));
    assert_eq!(rep.redistributed_debt_pm, pm_from_whole(6_500));
    assert_eq!(rep.unbacked_bad_debt_pm, 0);

    // Zero contagion to ETH / BTC branches
    assert_eq!(sys.vaults["V_SOL_SAFE"].debt_pm, pm_from_whole(16_500));
    assert_eq!(sys.vaults["V_ETH"].debt_pm, pm_from_whole(10_000));
    assert_eq!(sys.vaults["V_BTC"].debt_pm, pm_from_whole(15_000));
    assert_eq!(sys.branches["ETH"].total_redistributed_debt_pm, 0);
    assert_eq!(sys.branches["BTC"].total_redistributed_debt_pm, 0);
    sys.assert_conservation(0).unwrap();
}

#[test]
fn test_real_noir_ultrahonk_vault_shield_unshield_repay_bridge() {
    let root = workspace_root();
    let cache = TempDir::new().unwrap();
    let prover = NargoBbProver::new(&root.join("circuits"), cache.path()).unwrap();
    let bb_verifier = prover.bb_verifier();

    let mut engine = MonetaryEngine::new_default().unwrap();
    let mut ledger = LedgerState::new();
    let mut alice = ClientWallet::new_from_seed("monetary_bridge_alice", 1_700_000_000).unwrap();

    // 1. Alice locks 1 ETH ($3,000) and mints 500 PM via MonetaryEngine -> LedgerState unshielded balance
    engine
        .mint_vault_to_ledger(
            &mut ledger,
            "alice",
            "ETH",
            SCALE,
            500_000_000,
            scale_from_bps(200),
            Some("V_BRIDGE_ALICE"),
            true,
        )
        .unwrap();
    assert_eq!(engine.vaults.ledger_bridge_pm, 500_000_000);
    assert_eq!(ledger.total_issued_supply, 500_000_000);
    assert_eq!(ledger.public_vault_balance, 500_000_000);

    // 2. Alice shields 500 PM into Phase 1 UTXO pool with a REAL circuits/shield UltraHonk proof
    let (s_tx, s_enc) = alice.build_shield(&prover, 500_000_000, "vault-mint").unwrap();
    let leaf_idx = ledger.apply_shield(&s_tx, &bb_verifier).unwrap();
    alice.scan_outputs(
        &[PublishedOutput {
            leaf_index: leaf_idx,
            commitment_hex: field_to_hex(s_tx.out_commitment),
            encrypted_note: s_enc,
        }],
        &BTreeSet::new(),
    );
    assert_eq!(alice.shielded_balance(), 500_000_000);
    engine.assert_ledger_bridge_conservation(&ledger).unwrap();

    // 3. Alice unshields 200 PM back to public vault balance with a REAL circuits/unshield proof
    let cur_root = ledger.current_root();
    let (u_tx, chg_opt) = alice
        .build_unshield_to_pocket(&prover, 200_000_000, 0, cur_root, |idx| {
            let siblings = ledger
                .merkle_tree
                .proof(idx)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(pm_sdk::MerkleProofResponse {
                root_hex: field_to_hex(cur_root),
                leaf_index: idx,
                siblings_hex: siblings.into_iter().map(field_to_hex).collect(),
            })
        })
        .unwrap();
    let chg_idx = ledger.apply_unshield(&u_tx, &bb_verifier).unwrap();
    assert_eq!(ledger.public_vault_balance, 200_000_000);
    let spent: BTreeSet<String> = ledger.nullifiers.iter().map(|n| field_to_hex(*n)).collect();
    if let Some(chg_enc) = chg_opt {
        let cm_hex = field_to_hex(u_tx.change_commitment);
        let _ = field_from_hex(&cm_hex).unwrap();
        alice.scan_outputs(
            &[PublishedOutput {
                leaf_index: chg_idx,
                commitment_hex: cm_hex,
                encrypted_note: chg_enc,
            }],
            &spent,
        );
    }

    // 4. Repay 150 PM vault debt + hard-redeem 50 PM against lowest-rate vault V_BRIDGE_ALICE
    let repaid = engine
        .repay_vault_from_ledger(&mut ledger, "V_BRIDGE_ALICE", 150_000_000)
        .unwrap();
    assert_eq!(repaid, 150_000_000);

    let receipt = engine
        .redeem_pm_from_ledger(&mut ledger, "alice", 50_000_000, true)
        .unwrap();
    assert_eq!(receipt.pm_redeemed, 50_000_000);

    assert_eq!(ledger.public_vault_balance, 0);
    assert_eq!(ledger.total_shielded_supply, 300_000_000);
    assert_eq!(ledger.total_issued_supply, 300_000_000);
    assert_eq!(engine.vaults.ledger_bridge_pm, 300_000_000);
    assert_eq!(engine.vaults.vaults["V_BRIDGE_ALICE"].debt_pm, 300_000_000);
    assert_eq!(alice.shielded_balance(), 300_000_000);
    engine.assert_ledger_bridge_conservation(&ledger).unwrap();
}
