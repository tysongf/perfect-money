use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::MonetaryError;
use crate::fixed::{PM_SCALE, SCALE, mul_div_ceil, mul_div_floor, mul_div_round};
use crate::peg::ThrottleState;

/// Computes exact integer stake-weighted median over `(price, weight)` pairs.
pub fn weighted_median(pairs: &[(u128, u128)]) -> Result<u128, MonetaryError> {
    let mut valid: Vec<(u128, u128)> = pairs.iter().copied().filter(|(_, w)| *w > 0).collect();
    if valid.is_empty() {
        return Err(MonetaryError::EmptyWeightedMedian);
    }
    valid.sort_by_key(|(v, _)| *v);
    let total_w: u128 = valid.iter().map(|(_, w)| *w).sum();
    let half_up = total_w.div_ceil(2);
    let mut acc: u128 = 0;
    for (val, w) in &valid {
        acc += *w;
        if acc >= half_up {
            return Ok(*val);
        }
    }
    Ok(valid.last().expect("valid is non-empty").0)
}

/// Computes canonical SHA-256 commit digest for an oracle price report or court vote.
pub fn make_oracle_commit(
    round_id: u64,
    asset: &str,
    price: u128,
    salt: &str,
    node_id: &str,
) -> [u8; 32] {
    let payload = format!("PM_ORACLE_V2|{round_id}|{asset}|{price}|{salt}|{node_id}");
    Sha256::digest(payload.as_bytes()).into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OraclePhase {
    Commit,
    Reveal,
    Challenge,
    Court,
    Finalized,
}

impl OraclePhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "COMMIT",
            Self::Reveal => "REVEAL",
            Self::Challenge => "CHALLENGE",
            Self::Court => "COURT",
            Self::Finalized => "FINALIZED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OracleRole {
    #[default]
    Honest,
    Cartel,
    Whistleblower,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleNode {
    pub node_id: String,
    pub stake_pm: u128,
    pub is_court_voter: bool,
    pub role: OracleRole,
    pub rewards_pm: u128,
    pub slashed_pm: u128,
    pub jailed: bool,
}

impl OracleNode {
    pub fn new(
        node_id: impl Into<String>,
        stake_pm: u128,
        is_court_voter: bool,
        role: OracleRole,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            stake_pm,
            is_court_voter,
            role,
            rewards_pm: 0,
            slashed_pm: 0,
            jailed: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleCommit {
    pub node_id: String,
    pub asset_hashes: BTreeMap<String, [u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleReveal {
    pub node_id: String,
    pub prices: BTreeMap<String, u128>,
    pub salt: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NoRevealReport {
    pub burned_pm: u128,
    pub insurance_pm: u128,
    pub total_slashed_pm: u128,
    pub slashed_nodes: BTreeMap<String, u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleFinalizeResult {
    pub round_id: u64,
    pub open_hour: u64,
    pub finalized_prices: BTreeMap<String, u128>,
    pub p_med: BTreeMap<String, u128>,
    pub was_disputed: bool,
    pub dispute_upheld_challenger: bool,
    pub is_drastic: bool,
    pub epsilon_by_asset: BTreeMap<String, u128>,
    pub burned_pm: u128,
    pub insurance_pm: u128,
    pub bond_fee_pool_pm: u128,
    pub forfeited_bond_pm: u128,
    pub total_rewards_paid_pm: u128,
    pub bounty_payouts: BTreeMap<String, u128>,
    pub bond_refunds: BTreeMap<String, u128>,
    pub reward_payouts: BTreeMap<String, u128>,
    pub node_slashes: BTreeMap<String, u128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleRound {
    pub round_id: u64,
    pub open_hour: u64,
    pub phase: OraclePhase,
    pub phase_end_hour: u64,
    pub frozen_epsilons: BTreeMap<String, u128>,
    pub commits: BTreeMap<String, OracleCommit>,
    pub reveals: BTreeMap<String, OracleReveal>,
    pub no_reveal_slashed_pm: u128,
    pub no_reveal_slashes: BTreeMap<String, u128>,
    pub p_med: BTreeMap<String, u128>,
    pub is_drastic: bool,
    pub challenge_hours_assigned: u64,
    pub disputed: bool,
    pub challenger_id: Option<String>,
    pub dispute_bond_pm: u128,
    pub court_commits: BTreeMap<String, BTreeMap<String, [u8; 32]>>,
    pub court_reveals: BTreeMap<String, OracleReveal>,
    pub final_result: Option<OracleFinalizeResult>,
}

/// Fixed-point Schelling-point commit -> reveal -> challenge -> 48h court -> finalize oracle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OracleMarket {
    pub initial_prices: BTreeMap<String, u128>,
    pub nodes: BTreeMap<String, OracleNode>,
    pub s_min_pm: u128,
    pub dispute_bond_min_pm: u128,
    pub slash_no_reveal_bps: u64,
    pub ewma_alpha: u128,
    pub ewma_min: u128,
    pub ewma_max: u128,
    pub epsilon_floor: u128,
    pub sigma_hist_ewma: BTreeMap<String, u128>,
    pub last_finalized_prices: BTreeMap<String, u128>,
    pub active_round: Option<OracleRound>,
    pub next_round_id: u64,
    pub history: Vec<OracleFinalizeResult>,
}

impl OracleMarket {
    pub fn new(initial_prices: BTreeMap<String, u128>) -> Result<Self, MonetaryError> {
        if initial_prices.is_empty() {
            return Err(MonetaryError::InvalidParameter(
                "initial_prices cannot be empty".to_string(),
            ));
        }
        for (asset, &px) in &initial_prices {
            if px == 0 {
                return Err(MonetaryError::NonPositivePrice(asset.clone()));
            }
        }
        let sigma_hist_ewma = initial_prices
            .keys()
            .map(|a| (a.clone(), 4_000_000)) // 0.004 initial volatility estimate
            .collect();
        Ok(Self {
            last_finalized_prices: initial_prices.clone(),
            initial_prices,
            nodes: BTreeMap::new(),
            s_min_pm: 1_000 * PM_SCALE,
            dispute_bond_min_pm: 5_000 * PM_SCALE,
            slash_no_reveal_bps: 1_000, // 10%
            ewma_alpha: 100_000_000,    // 0.10
            ewma_min: 2_000_000,        // 0.002
            ewma_max: 30_000_000,       // 0.03
            epsilon_floor: 5_000_000,   // 0.005
            sigma_hist_ewma,
            active_round: None,
            next_round_id: 1,
            history: Vec::new(),
        })
    }

    pub fn add_node(&mut self, node: OracleNode) {
        self.nodes.insert(node.node_id.clone(), node);
    }

    pub fn total_locked_stake(&self) -> u128 {
        self.nodes.values().map(|n| n.stake_pm).sum()
    }

    pub fn current_epsilons(&self) -> BTreeMap<String, u128> {
        self.initial_prices
            .keys()
            .map(|asset| {
                let sig = self.sigma_hist_ewma[asset];
                let band = (sig * 3) / 2;
                (asset.clone(), self.epsilon_floor.max(band))
            })
            .collect()
    }

    pub fn start_round(&mut self, hour: u64) -> Result<&OracleRound, MonetaryError> {
        if let Some(rnd) = &self.active_round {
            if rnd.phase != OraclePhase::Finalized {
                return Err(MonetaryError::RoundAlreadyActive(rnd.round_id));
            }
        }
        let rnd = OracleRound {
            round_id: self.next_round_id,
            open_hour: hour,
            phase: OraclePhase::Commit,
            phase_end_hour: hour + 1,
            frozen_epsilons: self.current_epsilons(),
            commits: BTreeMap::new(),
            reveals: BTreeMap::new(),
            no_reveal_slashed_pm: 0,
            no_reveal_slashes: BTreeMap::new(),
            p_med: BTreeMap::new(),
            is_drastic: false,
            challenge_hours_assigned: 2,
            disputed: false,
            challenger_id: None,
            dispute_bond_pm: 0,
            court_commits: BTreeMap::new(),
            court_reveals: BTreeMap::new(),
            final_result: None,
        };
        self.next_round_id += 1;
        self.active_round = Some(rnd);
        Ok(self.active_round.as_ref().expect("just inserted"))
    }

    pub fn submit_commit(
        &mut self,
        node_id: &str,
        prices: &BTreeMap<String, u128>,
        salt: &str,
    ) -> Result<bool, MonetaryError> {
        let eligible = self
            .nodes
            .get(node_id)
            .is_some_and(|n| !n.jailed && n.stake_pm >= self.s_min_pm);
        let round_id = self.require_phase(OraclePhase::Commit)?.round_id;
        if !eligible {
            return Ok(false);
        }
        let mut hashes = BTreeMap::new();
        for asset in self.initial_prices.keys() {
            let px = prices
                .get(asset)
                .copied()
                .ok_or_else(|| MonetaryError::NonPositivePrice(asset.clone()))?;
            hashes.insert(
                asset.clone(),
                make_oracle_commit(round_id, asset, px, salt, node_id),
            );
        }
        let rnd = self.active_round.as_mut().expect("checked");
        rnd.commits.insert(
            node_id.to_string(),
            OracleCommit {
                node_id: node_id.to_string(),
                asset_hashes: hashes,
            },
        );
        Ok(true)
    }

    pub fn submit_reveal(
        &mut self,
        node_id: &str,
        prices: &BTreeMap<String, u128>,
        salt: &str,
    ) -> Result<bool, MonetaryError> {
        let initial_keys: Vec<String> = self.initial_prices.keys().cloned().collect();
        let rnd = self.require_phase_mut(OraclePhase::Reveal)?;
        let Some(commit) = rnd.commits.get(node_id) else {
            return Ok(false);
        };
        let Some(verified) = verify_commit_against_prices(
            rnd.round_id,
            "",
            node_id,
            &initial_keys,
            &commit.asset_hashes,
            prices,
            salt,
        ) else {
            return Ok(false);
        };
        rnd.reveals.insert(
            node_id.to_string(),
            OracleReveal {
                node_id: node_id.to_string(),
                prices: verified,
                salt: salt.to_string(),
            },
        );
        Ok(true)
    }

    pub fn challenge_round(
        &mut self,
        challenger_id: &str,
        bond_pm: u128,
        hour: u64,
    ) -> Result<u128, MonetaryError> {
        let min_bond = self.dispute_bond_min_pm;
        let rnd = self.require_phase_mut(OraclePhase::Challenge)?;
        if rnd.disputed {
            return Err(MonetaryError::RoundAlreadyDisputed);
        }
        if bond_pm < min_bond {
            return Err(MonetaryError::DisputeBondTooLow {
                provided: bond_pm,
                minimum: min_bond,
            });
        }
        rnd.disputed = true;
        rnd.challenger_id = Some(challenger_id.to_string());
        rnd.dispute_bond_pm = bond_pm;
        rnd.phase = OraclePhase::Court;
        rnd.phase_end_hour = hour + 48;
        Ok(bond_pm)
    }

    pub fn submit_court_commit(
        &mut self,
        node_id: &str,
        prices: &BTreeMap<String, u128>,
        salt: &str,
    ) -> Result<bool, MonetaryError> {
        let eligible = self
            .nodes
            .get(node_id)
            .is_some_and(|n| n.is_court_voter && !n.jailed && n.stake_pm >= self.s_min_pm);
        let round_id = self.require_phase(OraclePhase::Court)?.round_id;
        if !eligible {
            return Ok(false);
        }
        let mut hashes = BTreeMap::new();
        for asset in self.initial_prices.keys() {
            let px = prices
                .get(asset)
                .copied()
                .ok_or_else(|| MonetaryError::NonPositivePrice(asset.clone()))?;
            let scoped_asset = format!("COURT_{asset}");
            hashes.insert(
                asset.clone(),
                make_oracle_commit(round_id, &scoped_asset, px, salt, node_id),
            );
        }
        let rnd = self.active_round.as_mut().expect("checked");
        rnd.court_commits.insert(node_id.to_string(), hashes);
        Ok(true)
    }

    pub fn submit_court_reveal(
        &mut self,
        node_id: &str,
        prices: &BTreeMap<String, u128>,
        salt: &str,
    ) -> Result<bool, MonetaryError> {
        let initial_keys: Vec<String> = self.initial_prices.keys().cloned().collect();
        let rnd = self.require_phase_mut(OraclePhase::Court)?;
        let Some(hashes) = rnd.court_commits.get(node_id) else {
            return Ok(false);
        };
        let Some(verified) = verify_commit_against_prices(
            rnd.round_id,
            "COURT_",
            node_id,
            &initial_keys,
            hashes,
            prices,
            salt,
        ) else {
            return Ok(false);
        };
        rnd.court_reveals.insert(
            node_id.to_string(),
            OracleReveal {
                node_id: node_id.to_string(),
                prices: verified,
                salt: salt.to_string(),
            },
        );
        Ok(true)
    }

    pub fn submit_court_vote(
        &mut self,
        node_id: &str,
        prices: &BTreeMap<String, u128>,
        salt: &str,
    ) -> Result<bool, MonetaryError> {
        if !self.submit_court_commit(node_id, prices, salt)? {
            return Ok(false);
        }
        self.submit_court_reveal(node_id, prices, salt)
    }

    /// Advances active oracle round if the current phase deadline `phase_end_hour <= hour` is met.
    pub fn advance(
        &mut self,
        hour: u64,
        throttle: &ThrottleState,
        oracle_fee_pool_pm: u128,
    ) -> Result<(Option<OracleFinalizeResult>, NoRevealReport), MonetaryError> {
        let no_rev = NoRevealReport::default();
        let Some(rnd) = self.active_round.as_ref() else {
            return Ok((None, no_rev));
        };
        if rnd.phase == OraclePhase::Finalized || hour < rnd.phase_end_hour {
            return Ok((None, no_rev));
        }

        match rnd.phase {
            OraclePhase::Commit => {
                let rnd_mut = self.active_round.as_mut().expect("present");
                rnd_mut.phase = OraclePhase::Reveal;
                rnd_mut.phase_end_hour = hour + 1;
                Ok((None, no_rev))
            }
            OraclePhase::Reveal => {
                let report = self.resolve_reveal_and_enter_challenge(hour, throttle)?;
                Ok((None, report))
            }
            OraclePhase::Challenge | OraclePhase::Court => {
                let res = self.finalize_round(throttle, oracle_fee_pool_pm)?;
                Ok((Some(res), no_rev))
            }
            OraclePhase::Finalized => Ok((None, no_rev)),
        }
    }

    fn resolve_reveal_and_enter_challenge(
        &mut self,
        hour: u64,
        throttle: &ThrottleState,
    ) -> Result<NoRevealReport, MonetaryError> {
        let mut report = NoRevealReport::default();
        let committers: Vec<String> = self
            .active_round
            .as_ref()
            .expect("active")
            .commits
            .keys()
            .cloned()
            .collect();

        for node_id in committers {
            let revealed = self
                .active_round
                .as_ref()
                .expect("active")
                .reveals
                .contains_key(&node_id);
            if !revealed {
                let node = self.nodes.get_mut(&node_id).expect("committer exists");
                let raw_slash = mul_div_floor(node.stake_pm, self.slash_no_reveal_bps as u128, 10_000)?;
                let slash = node.stake_pm.min(raw_slash);
                node.stake_pm -= slash;
                node.slashed_pm += slash;
                report.total_slashed_pm += slash;
                *report.slashed_nodes.entry(node_id.clone()).or_insert(0) += slash;

                let rnd_mut = self.active_round.as_mut().expect("active");
                rnd_mut.no_reveal_slashed_pm += slash;
                *rnd_mut.no_reveal_slashes.entry(node_id).or_insert(0) += slash;
            }
        }

        let rnd = self.active_round.as_ref().expect("active");
        let mut p_med = BTreeMap::new();
        for (asset, &prev_px) in &self.last_finalized_prices {
            let pairs: Vec<(u128, u128)> = rnd
                .reveals
                .iter()
                .filter_map(|(nid, rev)| {
                    let st = self.nodes.get(nid).map(|n| n.stake_pm).unwrap_or(0);
                    if st > 0 {
                        Some((rev.prices[asset], st))
                    } else {
                        None
                    }
                })
                .collect();
            let med = if pairs.is_empty() {
                prev_px
            } else {
                weighted_median(&pairs)?
            };
            p_med.insert(asset.clone(), med);
        }

        let mut max_rel_shift = 0u128;
        for (asset, &prev_px) in &self.last_finalized_prices {
            let shift = mul_div_floor(p_med[asset].abs_diff(prev_px), SCALE, prev_px)?;
            if shift > max_rel_shift {
                max_rel_shift = shift;
            }
        }
        let is_drastic = max_rel_shift > 20_000_000; // > 2%
        let base_window = if is_drastic { 48 } else { 2 };
        let assigned = base_window.max(throttle.challenge_hours);

        let rnd_mut = self.active_round.as_mut().expect("active");
        rnd_mut.p_med = p_med;
        rnd_mut.is_drastic = is_drastic;
        rnd_mut.challenge_hours_assigned = assigned;
        rnd_mut.phase = OraclePhase::Challenge;
        rnd_mut.phase_end_hour = hour + assigned;

        report.insurance_pm = report.total_slashed_pm / 10;
        report.burned_pm = report.total_slashed_pm - report.insurance_pm;
        Ok(report)
    }

    fn finalize_round(
        &mut self,
        throttle: &ThrottleState,
        oracle_fee_pool_pm: u128,
    ) -> Result<OracleFinalizeResult, MonetaryError> {
        let rnd = self.active_round.take().expect("active");
        let epsilons = rnd.frozen_epsilons.clone();
        let mut bounty_payouts = BTreeMap::new();
        let mut bond_refunds = BTreeMap::new();
        let mut reward_payouts = BTreeMap::new();
        let mut node_slashes = BTreeMap::new();

        let mut burned_pm = 0u128;
        let mut insurance_pm = 0u128;
        let mut bond_fee_pool_pm = 0u128;
        let mut forfeited_bond_pm = 0u128;
        let mut effective_fee_pool = oracle_fee_pool_pm;

        let court_confirmed = rnd.disputed;
        let mut dispute_upheld_challenger = false;

        let raw_p_star = if rnd.disputed {
            let mut p_court = BTreeMap::new();
            for (asset, &prev_px) in &self.last_finalized_prices {
                let pairs: Vec<(u128, u128)> = rnd
                    .court_reveals
                    .iter()
                    .filter_map(|(nid, rev)| {
                        let st = self.nodes.get(nid).map(|n| n.stake_pm).unwrap_or(0);
                        if st > 0 {
                            Some((rev.prices[asset], st))
                        } else {
                            None
                        }
                    })
                    .collect();
                let med = if pairs.is_empty() {
                    prev_px
                } else {
                    weighted_median(&pairs)?
                };
                p_court.insert(asset.clone(), med);
            }

            let mut overturned = false;
            for (asset, &pc) in &p_court {
                let rel_diff = mul_div_floor(pc.abs_diff(rnd.p_med[asset]), SCALE, pc.max(1))?;
                if rel_diff > epsilons[asset] {
                    overturned = true;
                    break;
                }
            }
            if overturned {
                dispute_upheld_challenger = true;
                if let Some(cid) = &rnd.challenger_id {
                    bond_refunds.insert(cid.clone(), rnd.dispute_bond_pm);
                }
                p_court
            } else {
                let bond = rnd.dispute_bond_pm;
                let bond_ins = bond / 10;
                let bond_fee = mul_div_floor(bond, 2, 10)?;
                let bond_burn = bond - bond_ins - bond_fee;
                burned_pm += bond_burn;
                insurance_pm += bond_ins;
                bond_fee_pool_pm = bond_fee;
                forfeited_bond_pm = bond;
                effective_fee_pool = effective_fee_pool
                    .checked_add(bond_fee)
                    .ok_or(MonetaryError::MathOverflow)?;
                rnd.p_med.clone()
            }
        } else {
            rnd.p_med.clone()
        };

        let allow_full_jump = court_confirmed || (rnd.is_drastic && throttle.deficit_frac == 0);
        let mut finalized_prices = BTreeMap::new();
        for (asset, &prev_px) in &self.last_finalized_prices {
            let target_px = raw_p_star[asset];
            if allow_full_jump {
                finalized_prices.insert(asset.clone(), target_px);
            } else {
                let lo = mul_div_floor(prev_px, SCALE.saturating_sub(throttle.max_epoch_delta), SCALE)?;
                let hi = mul_div_ceil(prev_px, SCALE + throttle.max_epoch_delta, SCALE)?;
                finalized_prices.insert(asset.clone(), target_px.clamp(lo, hi));
            }
        }

        let mut coherent_ids = Vec::new();
        let mut total_reporter_slashed = 0u128;

        for (node_id, rev) in &rnd.reveals {
            let node = self.nodes.get_mut(node_id).expect("revealer exists");
            if node.stake_pm == 0 {
                continue;
            }
            let mut max_ratio = 0u128;
            for (asset, &p_star) in &finalized_prices {
                let d_k = mul_div_floor(rev.prices[asset].abs_diff(p_star), SCALE, p_star)?;
                let ratio = mul_div_floor(d_k, SCALE, epsilons[asset])?;
                if ratio > max_ratio {
                    max_ratio = ratio;
                }
            }

            if max_ratio <= SCALE {
                coherent_ids.push(node_id.clone());
            } else if max_ratio <= 3 * SCALE {
                let x = (max_ratio - SCALE) / 2;
                let slash_rate = mul_div_floor(x, x, 4 * SCALE)?;
                let slash = mul_div_floor(node.stake_pm, slash_rate, SCALE)?;
                node.stake_pm -= slash;
                node.slashed_pm += slash;
                node_slashes.insert(node_id.clone(), slash);
                total_reporter_slashed += slash;
            } else {
                let slash = node.stake_pm;
                node.stake_pm = 0;
                node.slashed_pm += slash;
                node.jailed = true;
                node_slashes.insert(node_id.clone(), slash);
                total_reporter_slashed += slash;
            }
        }

        if total_reporter_slashed > 0 {
            let ins_cut = total_reporter_slashed / 10;
            let bounty = if dispute_upheld_challenger && rnd.challenger_id.is_some() {
                mul_div_floor(total_reporter_slashed, 2, 10)?
            } else {
                0
            };
            let burn_cut = total_reporter_slashed - ins_cut - bounty;
            burned_pm += burn_cut;
            insurance_pm += ins_cut;
            if let (true, Some(cid)) = (bounty > 0, &rnd.challenger_id) {
                *bounty_payouts.entry(cid.clone()).or_insert(0) += bounty;
            }
        }

        let mut coherent_voters: BTreeMap<String, u128> = BTreeMap::new();
        for nid in coherent_ids {
            let st = self.nodes[&nid].stake_pm;
            if st > 0 {
                coherent_voters.insert(nid, st);
            }
        }
        if rnd.disputed {
            for (nid, rev) in &rnd.court_reveals {
                let st = self.nodes.get(nid).map(|n| n.stake_pm).unwrap_or(0);
                if st == 0 {
                    continue;
                }
                let within = finalized_prices.iter().all(|(asset, &p_star)| {
                    mul_div_floor(rev.prices[asset].abs_diff(p_star), SCALE, p_star)
                        .map(|rel| rel <= epsilons[asset])
                        .unwrap_or(false)
                });
                if within {
                    coherent_voters.insert(nid.clone(), st);
                }
            }
        }

        let total_coherent_stake: u128 = coherent_voters.values().copied().sum();
        let mut total_rewards_paid_pm = 0u128;
        if total_coherent_stake > 0 && effective_fee_pool > 0 {
            for (nid, st) in &coherent_voters {
                let reward = mul_div_floor(effective_fee_pool, *st, total_coherent_stake)?;
                if reward > 0 {
                    self.nodes.get_mut(nid).expect("node exists").rewards_pm += reward;
                    reward_payouts.insert(nid.clone(), reward);
                    total_rewards_paid_pm += reward;
                }
            }
        }

        // Update lagged historical volatility EWMA AFTER round finalization for the NEXT round.
        for (asset, &prev_px) in &self.last_finalized_prices {
            let new_px = finalized_prices[asset];
            let rel_move = mul_div_floor(new_px.abs_diff(prev_px), SCALE, prev_px)?;
            let prev_ewma = self.sigma_hist_ewma[asset];
            let weighted_prev = mul_div_round(prev_ewma, SCALE - self.ewma_alpha, SCALE)?;
            let weighted_new = mul_div_round(rel_move, self.ewma_alpha, SCALE)?;
            let updated = (weighted_prev + weighted_new).clamp(self.ewma_min, self.ewma_max);
            self.sigma_hist_ewma.insert(asset.clone(), updated);
        }

        self.last_finalized_prices = finalized_prices.clone();
        let result = OracleFinalizeResult {
            round_id: rnd.round_id,
            open_hour: rnd.open_hour,
            finalized_prices,
            p_med: rnd.p_med.clone(),
            was_disputed: rnd.disputed,
            dispute_upheld_challenger,
            is_drastic: rnd.is_drastic,
            epsilon_by_asset: epsilons,
            burned_pm,
            insurance_pm,
            bond_fee_pool_pm,
            forfeited_bond_pm,
            total_rewards_paid_pm,
            bounty_payouts,
            bond_refunds,
            reward_payouts,
            node_slashes,
        };

        let mut finalized_rnd = rnd;
        finalized_rnd.phase = OraclePhase::Finalized;
        finalized_rnd.final_result = Some(result.clone());
        self.active_round = Some(finalized_rnd);
        self.history.push(result.clone());
        Ok(result)
    }

    fn require_phase(&self, expected: OraclePhase) -> Result<&OracleRound, MonetaryError> {
        let Some(rnd) = &self.active_round else {
            return Err(MonetaryError::UnexpectedOraclePhase {
                expected: expected.as_str(),
                actual: "NONE".to_string(),
            });
        };
        if rnd.phase != expected {
            return Err(MonetaryError::UnexpectedOraclePhase {
                expected: expected.as_str(),
                actual: rnd.phase.as_str().to_string(),
            });
        }
        Ok(rnd)
    }

    fn require_phase_mut(&mut self, expected: OraclePhase) -> Result<&mut OracleRound, MonetaryError> {
        let Some(rnd) = &mut self.active_round else {
            return Err(MonetaryError::UnexpectedOraclePhase {
                expected: expected.as_str(),
                actual: "NONE".to_string(),
            });
        };
        if rnd.phase != expected {
            return Err(MonetaryError::UnexpectedOraclePhase {
                expected: expected.as_str(),
                actual: rnd.phase.as_str().to_string(),
            });
        }
        Ok(rnd)
    }
}

fn verify_commit_against_prices(
    round_id: u64,
    asset_prefix: &str,
    node_id: &str,
    assets: &[String],
    expected_hashes: &BTreeMap<String, [u8; 32]>,
    prices: &BTreeMap<String, u128>,
    salt: &str,
) -> Option<BTreeMap<String, u128>> {
    let mut verified = BTreeMap::new();
    for asset in assets {
        let expected_hash = expected_hashes.get(asset)?;
        let &px = prices.get(asset)?;
        if px == 0 {
            return None;
        }
        let scoped_asset = format!("{asset_prefix}{asset}");
        let actual_hash = make_oracle_commit(round_id, &scoped_asset, px, salt, node_id);
        if &actual_hash != expected_hash {
            return None;
        }
        verified.insert(asset.clone(), px);
    }
    Some(verified)
}
