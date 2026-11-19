from sim.engine.oracle_market import OracleMarket, OracleNode, weighted_median
from sim.engine.peg_controller import DEFAULT_GENESIS_PRICES, compute_auto_throttle


def _healthy_throttle(locked: float):
    return compute_auto_throttle(locked_pm=locked, amm_liquidity_pm=100_000.0, total_pm_supply=locked)


def test_weighted_median_ties_and_skew():
    assert weighted_median([(10.0, 1.0), (20.0, 1.0), (30.0, 1.0)]) == 20.0
    assert weighted_median([(10.0, 0.49), (110.0, 0.51)]) == 110.0
    assert weighted_median([(10.0, 0.51), (110.0, 0.49)]) == 10.0


def test_no_reveal_10pct_slash():
    om = OracleMarket(initial_prices=DEFAULT_GENESIS_PRICES)
    om.add_node(OracleNode("h1", 60_000.0, role="honest"))
    om.add_node(OracleNode("lazy", 40_000.0, role="honest"))

    thr = _healthy_throttle(om.total_locked_stake())
    om.start_round(0)
    om.submit_commit("h1", DEFAULT_GENESIS_PRICES, "s1")
    om.submit_commit("lazy", DEFAULT_GENESIS_PRICES, "s2")
    om.advance(1, thr, 0.0)
    om.submit_reveal("h1", DEFAULT_GENESIS_PRICES, "s1")
    # lazy intentionally withholds reveal
    _, no_rev, _ = om.advance(2, thr, 0.0)

    assert om.nodes["lazy"].stake_pm == 36_000.0
    assert no_rev["total_slashed_pm"] == 4_000.0
    assert abs((no_rev["burned_pm"] + no_rev["insurance_pm"]) - 4_000.0) < 1e-9


def test_same_round_outlier_cartel_blocked_by_frozen_ewma():
    om = OracleMarket(initial_prices=DEFAULT_GENESIS_PRICES)
    om.add_node(OracleNode("h1", 260_000.0, role="honest"))
    om.add_node(OracleNode("h2", 260_000.0, role="honest"))
    # 48% cartel submits wide outliers trying to poison epsilon within the same round
    om.add_node(OracleNode("c_low", 160_000.0, role="cartel"))
    om.add_node(OracleNode("c_high", 160_000.0, role="cartel"))
    om.add_node(OracleNode("c_extreme", 160_000.0, role="cartel"))

    thr = _healthy_throttle(om.total_locked_stake())
    rnd = om.start_round(0)
    frozen_eps = dict(rnd.frozen_epsilons)

    om.submit_commit("h1", DEFAULT_GENESIS_PRICES, "s1")
    om.submit_commit("h2", DEFAULT_GENESIS_PRICES, "s2")
    om.submit_commit("c_low", {k: v * 0.70 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s3")
    om.submit_commit("c_high", {k: v * 1.15 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s4")
    om.submit_commit("c_extreme", {k: v * 1.80 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s5")

    om.advance(1, thr, 0.0)
    om.submit_reveal("h1", DEFAULT_GENESIS_PRICES, "s1")
    om.submit_reveal("h2", DEFAULT_GENESIS_PRICES, "s2")
    om.submit_reveal("c_low", {k: v * 0.70 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s3")
    om.submit_reveal("c_high", {k: v * 1.15 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s4")
    om.submit_reveal("c_extreme", {k: v * 1.80 for k, v in DEFAULT_GENESIS_PRICES.items()}, "s5")

    om.advance(2, thr, 0.0)
    res = None
    for h in range(3, 60):
        res, _, _ = om.advance(h, thr, 1_000.0)
        if res is not None:
            break
    assert res is not None
    # Epsilon used in round stayed frozen at historical level, unaffected by outlier reveals
    assert res.epsilon_by_asset == frozen_eps
    for c_id in ("c_low", "c_high", "c_extreme"):
        assert om.nodes[c_id].stake_pm == 0.0
        assert om.nodes[c_id].jailed is True
    assert abs((res.burned_pm + res.insurance_pm) - 480_000.0) < 1e-6


def test_court_overturns_captured_median_and_frivolous_challenger_slashed():
    om = OracleMarket(initial_prices=DEFAULT_GENESIS_PRICES)
    om.add_node(OracleNode("h1", 51_000.0, role="honest", is_court_voter=True))
    om.add_node(OracleNode("c1", 49_000.0, role="cartel", is_court_voter=True))
    om.add_node(OracleNode("wb", 10_000.0, role="whistleblower", is_court_voter=True))

    # Simulate h1 offline in commit -> c1 captures P_med (+10%), wb disputes and court overturns
    thr = _healthy_throttle(om.total_locked_stake())
    om.start_round(0)
    om.submit_commit("c1", {k: v * 1.10 for k, v in DEFAULT_GENESIS_PRICES.items()}, "sc")
    om.advance(1, thr, 0.0)
    om.submit_reveal("c1", {k: v * 1.10 for k, v in DEFAULT_GENESIS_PRICES.items()}, "sc")
    om.advance(2, thr, 0.0)

    om.challenge_round("wb", 5_000.0, 2)
    om.submit_court_vote("h1", DEFAULT_GENESIS_PRICES, "vh1")
    om.submit_court_vote("wb", DEFAULT_GENESIS_PRICES, "vwb")
    om.submit_court_vote("c1", {k: v * 1.10 for k, v in DEFAULT_GENESIS_PRICES.items()}, "vc1")

    res, _, _ = om.advance(50, thr, 1_000.0)
    assert res is not None
    assert res.was_disputed is True
    assert res.dispute_upheld_challenger is True
    assert om.nodes["c1"].stake_pm == 0.0
    assert res.bond_refunds["wb"] == 5_000.0
    assert abs(res.bounty_payouts["wb"] - 0.20 * 49_000.0) < 1e-6

    # Now frivolous challenge against honest P_med -> challenger loses 5,000 bond (70/20/10)
    thr2 = _healthy_throttle(om.total_locked_stake())
    om.start_round(54)
    om.submit_commit("h1", DEFAULT_GENESIS_PRICES, "sh1")
    om.submit_commit("wb", DEFAULT_GENESIS_PRICES, "swb")
    om.advance(55, thr2, 0.0)
    om.submit_reveal("h1", DEFAULT_GENESIS_PRICES, "sh1")
    om.submit_reveal("wb", DEFAULT_GENESIS_PRICES, "swb")
    om.advance(56, thr2, 0.0)

    om.challenge_round("troll", 5_000.0, 56)
    om.submit_court_vote("h1", DEFAULT_GENESIS_PRICES, "vh1b")
    om.submit_court_vote("wb", DEFAULT_GENESIS_PRICES, "vwbb")
    res2, _, _ = om.advance(104, thr2, 0.0)
    assert res2 is not None
    assert res2.dispute_upheld_challenger is False
    assert abs(res2.burned_pm - 3_500.0) < 1e-6
    assert abs(res2.bond_fee_pool_pm - 1_000.0) < 1e-6
    assert abs(res2.insurance_pm - 500.0) < 1e-6

