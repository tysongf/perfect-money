use std::collections::{BTreeSet, VecDeque};

use acir::{AcirField, FieldElement};
use thiserror::Error;

use crate::merkle::MerkleTree;
use crate::verifier::{CircuitKind, ProofVerifier};

const DEFAULT_MAX_RECENT_ROOTS: usize = 64;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LedgerError {
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("tx_binding_hash cannot be zero")]
    ZeroTxBindingHash,
    #[error("insufficient public vault balance: requested {requested}, available {available}")]
    InsufficientVaultBalance { requested: u64, available: u128 },
    #[error("insufficient pocket escrow balance: requested {requested}, available {available}")]
    InsufficientPocketEscrow { requested: u64, available: u128 },
    #[error("unknown or expired merkle root")]
    UnknownMerkleRoot,
    #[error("nullifier already spent")]
    NullifierAlreadySpent,
    #[error("duplicate nullifiers in same transaction")]
    DuplicateNullifierInTx,
    #[error("proof verification failed: {0}")]
    InvalidProof(String),
    #[error("merkle tree error: {0}")]
    MerkleTree(String),
}

#[derive(Debug, Clone)]
pub struct ShieldTx {
    pub mint_amount: u64,
    pub out_commitment: FieldElement,
    pub tx_binding_hash: FieldElement,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TransferTx {
    pub merkle_root: FieldElement,
    pub nullifiers: [FieldElement; 2],
    pub out_commitments: [FieldElement; 2],
    pub fee: u64,
    pub tx_binding_hash: FieldElement,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct UnshieldTx {
    pub merkle_root: FieldElement,
    pub nullifier: FieldElement,
    pub change_commitment: FieldElement,
    pub burn_amount: u64,
    pub fee: u64,
    pub tx_binding_hash: FieldElement,
    pub proof: Vec<u8>,
}

/// Chain-agnostic state machine enforcing Merkle inclusion, nullifier uniqueness,
/// ZK proof verification, and 1:1 vault-to-shielded supply conservation.
#[derive(Debug, Clone)]
pub struct LedgerState {
    pub merkle_tree: MerkleTree,
    recent_roots: VecDeque<FieldElement>,
    max_recent_roots: usize,
    pub nullifiers: BTreeSet<FieldElement>,
    pub total_issued_supply: u128,
    pub public_vault_balance: u128,
    pub total_shielded_supply: u128,
    pub total_pocket_escrow: u128,
    pub collected_fees: u128,
}

impl Default for LedgerState {
    fn default() -> Self {
        Self::new()
    }
}

impl LedgerState {
    pub fn new() -> Self {
        Self::with_recent_root_capacity(DEFAULT_MAX_RECENT_ROOTS)
    }

    pub fn with_recent_root_capacity(max_recent_roots: usize) -> Self {
        assert!(max_recent_roots >= 1, "max_recent_roots must be >= 1");
        let merkle_tree = MerkleTree::new();
        let mut recent_roots = VecDeque::with_capacity(max_recent_roots);
        recent_roots.push_back(merkle_tree.root());
        Self {
            merkle_tree,
            recent_roots,
            max_recent_roots,
            nullifiers: BTreeSet::new(),
            total_issued_supply: 0,
            public_vault_balance: 0,
            total_shielded_supply: 0,
            total_pocket_escrow: 0,
            collected_fees: 0,
        }
    }

    pub fn current_root(&self) -> FieldElement {
        self.merkle_tree.root()
    }

    pub fn is_known_root(&self, root: &FieldElement) -> bool {
        self.recent_roots.contains(root)
    }

    /// Phase 2 vault hook: creates unshielded PM against locked collateral before shielding.
    pub fn mint_vault_supply(&mut self, amount: u64) -> Result<(), LedgerError> {
        if amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        self.total_issued_supply += amount as u128;
        self.public_vault_balance += amount as u128;
        self.assert_conservation_invariant();
        Ok(())
    }

    /// Phase 2 vault hook: burns unshielded PM returned from unshielding (e.g. debt repayment / redemption).
    pub fn burn_vault_supply(&mut self, amount: u64) -> Result<(), LedgerError> {
        if amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if self.public_vault_balance < amount as u128 {
            return Err(LedgerError::InsufficientVaultBalance {
                requested: amount,
                available: self.public_vault_balance,
            });
        }
        self.public_vault_balance -= amount as u128;
        self.total_issued_supply -= amount as u128;
        self.assert_conservation_invariant();
        Ok(())
    }

    /// Phase 3 escrow hook: moves unshielded PM into capped offline pocket escrow.
    pub fn lock_to_pocket_escrow(&mut self, amount: u64) -> Result<(), LedgerError> {
        if amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if self.public_vault_balance < amount as u128 {
            return Err(LedgerError::InsufficientVaultBalance {
                requested: amount,
                available: self.public_vault_balance,
            });
        }
        self.public_vault_balance -= amount as u128;
        self.total_pocket_escrow += amount as u128;
        self.assert_conservation_invariant();
        Ok(())
    }

    /// Phase 3 escrow hook: releases settled or reclaimed pocket escrow back to `public_vault_balance`.
    pub fn release_from_pocket_escrow(&mut self, amount: u64) -> Result<(), LedgerError> {
        if amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if self.total_pocket_escrow < amount as u128 {
            return Err(LedgerError::InsufficientPocketEscrow {
                requested: amount,
                available: self.total_pocket_escrow,
            });
        }
        self.total_pocket_escrow -= amount as u128;
        self.public_vault_balance += amount as u128;
        self.assert_conservation_invariant();
        Ok(())
    }

    /// Verifies a `circuits/shield` proof and moves `mint_amount` from public vault balance to shielded pool.
    pub fn apply_shield(
        &mut self,
        tx: &ShieldTx,
        verifier: &dyn ProofVerifier,
    ) -> Result<u32, LedgerError> {
        if tx.mint_amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if tx.tx_binding_hash.is_zero() {
            return Err(LedgerError::ZeroTxBindingHash);
        }
        if self.public_vault_balance < tx.mint_amount as u128 {
            return Err(LedgerError::InsufficientVaultBalance {
                requested: tx.mint_amount,
                available: self.public_vault_balance,
            });
        }

        let public_inputs = [
            FieldElement::from(tx.mint_amount),
            tx.out_commitment,
            tx.tx_binding_hash,
        ];
        verifier
            .verify_proof(CircuitKind::Shield, &tx.proof, &public_inputs)
            .map_err(|e| LedgerError::InvalidProof(e.to_string()))?;

        let idx = self
            .merkle_tree
            .insert(tx.out_commitment)
            .map_err(|e| LedgerError::MerkleTree(e.to_string()))?;
        self.push_current_root();

        self.public_vault_balance -= tx.mint_amount as u128;
        self.total_shielded_supply += tx.mint_amount as u128;
        self.assert_conservation_invariant();
        Ok(idx)
    }

    /// Verifies a `circuits/shielded_transfer` JoinSplit proof and updates commitments, nullifiers, and fees.
    pub fn apply_transfer(
        &mut self,
        tx: &TransferTx,
        verifier: &dyn ProofVerifier,
    ) -> Result<[u32; 2], LedgerError> {
        if tx.tx_binding_hash.is_zero() {
            return Err(LedgerError::ZeroTxBindingHash);
        }
        if tx.nullifiers[0] == tx.nullifiers[1] {
            return Err(LedgerError::DuplicateNullifierInTx);
        }
        if !self.is_known_root(&tx.merkle_root) {
            return Err(LedgerError::UnknownMerkleRoot);
        }
        if self.nullifiers.contains(&tx.nullifiers[0]) || self.nullifiers.contains(&tx.nullifiers[1])
        {
            return Err(LedgerError::NullifierAlreadySpent);
        }

        let public_inputs = [
            tx.merkle_root,
            tx.nullifiers[0],
            tx.nullifiers[1],
            tx.out_commitments[0],
            tx.out_commitments[1],
            FieldElement::from(tx.fee),
            tx.tx_binding_hash,
        ];
        verifier
            .verify_proof(CircuitKind::ShieldedTransfer, &tx.proof, &public_inputs)
            .map_err(|e| LedgerError::InvalidProof(e.to_string()))?;

        let idx0 = self
            .merkle_tree
            .insert(tx.out_commitments[0])
            .map_err(|e| LedgerError::MerkleTree(e.to_string()))?;
        let idx1 = self
            .merkle_tree
            .insert(tx.out_commitments[1])
            .map_err(|e| LedgerError::MerkleTree(e.to_string()))?;
        self.push_current_root();

        self.nullifiers.insert(tx.nullifiers[0]);
        self.nullifiers.insert(tx.nullifiers[1]);
        self.total_shielded_supply -= tx.fee as u128;
        self.collected_fees += tx.fee as u128;
        self.assert_conservation_invariant();
        Ok([idx0, idx1])
    }

    /// Verifies a `circuits/unshield` proof and returns `burn_amount` to public vault balance.
    pub fn apply_unshield(
        &mut self,
        tx: &UnshieldTx,
        verifier: &dyn ProofVerifier,
    ) -> Result<u32, LedgerError> {
        if tx.burn_amount == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        if tx.tx_binding_hash.is_zero() {
            return Err(LedgerError::ZeroTxBindingHash);
        }
        if !self.is_known_root(&tx.merkle_root) {
            return Err(LedgerError::UnknownMerkleRoot);
        }
        if self.nullifiers.contains(&tx.nullifier) {
            return Err(LedgerError::NullifierAlreadySpent);
        }

        let public_inputs = [
            tx.merkle_root,
            tx.nullifier,
            tx.change_commitment,
            FieldElement::from(tx.burn_amount),
            FieldElement::from(tx.fee),
            tx.tx_binding_hash,
        ];
        verifier
            .verify_proof(CircuitKind::Unshield, &tx.proof, &public_inputs)
            .map_err(|e| LedgerError::InvalidProof(e.to_string()))?;

        let idx = self
            .merkle_tree
            .insert(tx.change_commitment)
            .map_err(|e| LedgerError::MerkleTree(e.to_string()))?;
        self.push_current_root();

        self.nullifiers.insert(tx.nullifier);
        self.total_shielded_supply -= (tx.burn_amount as u128) + (tx.fee as u128);
        self.public_vault_balance += tx.burn_amount as u128;
        self.collected_fees += tx.fee as u128;
        self.assert_conservation_invariant();
        Ok(idx)
    }

    pub fn assert_conservation_invariant(&self) {
        assert_eq!(
            self.public_vault_balance
                + self.total_shielded_supply
                + self.total_pocket_escrow
                + self.collected_fees,
            self.total_issued_supply,
            "supply conservation invariant violated"
        );
    }

    fn push_current_root(&mut self) {
        let root = self.merkle_tree.root();
        if self.recent_roots.back() == Some(&root) {
            return;
        }
        if self.recent_roots.len() >= self.max_recent_roots {
            self.recent_roots.pop_front();
        }
        self.recent_roots.push_back(root);
    }
}

#[cfg(test)]
mod tests {
    use anyhow::bail;

    use super::*;

    struct MockVerifier {
        accept: bool,
    }

    impl ProofVerifier for MockVerifier {
        fn verify_proof(
            &self,
            _kind: CircuitKind,
            _proof: &[u8],
            _public_inputs: &[FieldElement],
        ) -> anyhow::Result<()> {
            if self.accept {
                Ok(())
            } else {
                bail!("mock rejected proof")
            }
        }
    }

    #[test]
    fn test_ledger_state_transitions_and_guards() {
        let ok_verifier = MockVerifier { accept: true };
        let bad_verifier = MockVerifier { accept: false };
        let mut ledger = LedgerState::with_recent_root_capacity(2);
        let initial_root = ledger.current_root();

        assert_eq!(ledger.mint_vault_supply(0), Err(LedgerError::ZeroAmount));
        assert_eq!(ledger.burn_vault_supply(0), Err(LedgerError::ZeroAmount));
        assert_eq!(
            ledger.burn_vault_supply(1),
            Err(LedgerError::InsufficientVaultBalance {
                requested: 1,
                available: 0
            })
        );

        ledger.mint_vault_supply(1000).unwrap();

        // Insufficient vault balance check
        let too_big = ShieldTx {
            mint_amount: 1001,
            out_commitment: FieldElement::from(11u64),
            tx_binding_hash: FieldElement::from(99u64),
            proof: vec![],
        };
        assert_eq!(
            ledger.apply_shield(&too_big, &ok_verifier),
            Err(LedgerError::InsufficientVaultBalance {
                requested: 1001,
                available: 1000
            })
        );

        // Failed proof does not mutate state
        let s1 = ShieldTx {
            mint_amount: 600,
            out_commitment: FieldElement::from(101u64),
            tx_binding_hash: FieldElement::from(1u64),
            proof: vec![],
        };
        assert!(matches!(
            ledger.apply_shield(&s1, &bad_verifier),
            Err(LedgerError::InvalidProof(_))
        ));
        assert_eq!(ledger.public_vault_balance, 1000);
        assert_eq!(ledger.merkle_tree.leaf_count(), 0);

        ledger.apply_shield(&s1, &ok_verifier).unwrap();
        let root_after_s1 = ledger.current_root();
        assert!(ledger.is_known_root(&initial_root));
        assert!(ledger.is_known_root(&root_after_s1));

        // Second shield evicts initial_root from capacity-2 ring buffer
        let s2 = ShieldTx {
            mint_amount: 400,
            out_commitment: FieldElement::from(102u64),
            tx_binding_hash: FieldElement::from(2u64),
            proof: vec![],
        };
        ledger.apply_shield(&s2, &ok_verifier).unwrap();
        assert!(!ledger.is_known_root(&initial_root));
        assert!(ledger.is_known_root(&root_after_s1));

        // Duplicate nullifier in same transfer rejected
        let dup_tx = TransferTx {
            merkle_root: ledger.current_root(),
            nullifiers: [FieldElement::from(77u64), FieldElement::from(77u64)],
            out_commitments: [FieldElement::from(201u64), FieldElement::from(202u64)],
            fee: 10,
            tx_binding_hash: FieldElement::from(3u64),
            proof: vec![],
        };
        assert_eq!(
            ledger.apply_transfer(&dup_tx, &ok_verifier),
            Err(LedgerError::DuplicateNullifierInTx)
        );

        // Expired root rejected
        let stale_tx = TransferTx {
            merkle_root: initial_root,
            nullifiers: [FieldElement::from(77u64), FieldElement::from(78u64)],
            out_commitments: [FieldElement::from(201u64), FieldElement::from(202u64)],
            fee: 10,
            tx_binding_hash: FieldElement::from(3u64),
            proof: vec![],
        };
        assert_eq!(
            ledger.apply_transfer(&stale_tx, &ok_verifier),
            Err(LedgerError::UnknownMerkleRoot)
        );

        // Valid transfer
        let valid_tx = TransferTx {
            merkle_root: ledger.current_root(),
            nullifiers: [FieldElement::from(77u64), FieldElement::from(78u64)],
            out_commitments: [FieldElement::from(201u64), FieldElement::from(202u64)],
            fee: 10,
            tx_binding_hash: FieldElement::from(3u64),
            proof: vec![],
        };
        ledger.apply_transfer(&valid_tx, &ok_verifier).unwrap();
        assert_eq!(
            ledger.apply_transfer(&valid_tx, &ok_verifier),
            Err(LedgerError::NullifierAlreadySpent)
        );

        // Unshield and replay check
        let unshield_tx = UnshieldTx {
            merkle_root: ledger.current_root(),
            nullifier: FieldElement::from(88u64),
            change_commitment: FieldElement::from(301u64),
            burn_amount: 500,
            fee: 5,
            tx_binding_hash: FieldElement::from(4u64),
            proof: vec![],
        };
        ledger.apply_unshield(&unshield_tx, &ok_verifier).unwrap();
        assert_eq!(
            ledger.apply_unshield(&unshield_tx, &ok_verifier),
            Err(LedgerError::NullifierAlreadySpent)
        );

        ledger.burn_vault_supply(500).unwrap();
        assert_eq!(ledger.total_issued_supply, 500);
        assert_eq!(ledger.public_vault_balance, 0);
        assert_eq!(ledger.total_shielded_supply, 485);
        assert_eq!(ledger.collected_fees, 15);
    }

    #[test]
    fn test_pocket_escrow_lock_release_and_conservation() {
        let verifier = MockVerifier { accept: true };
        let mut ledger = LedgerState::new();
        ledger.mint_vault_supply(500).unwrap();

        let s1 = ShieldTx {
            mint_amount: 500,
            out_commitment: FieldElement::from(11u64),
            tx_binding_hash: FieldElement::from(21u64),
            proof: vec![],
        };
        ledger.apply_shield(&s1, &verifier).unwrap();

        let u1 = UnshieldTx {
            merkle_root: ledger.current_root(),
            nullifier: FieldElement::from(31u64),
            change_commitment: FieldElement::from(41u64),
            burn_amount: 300,
            fee: 0,
            tx_binding_hash: FieldElement::from(51u64),
            proof: vec![],
        };
        ledger.apply_unshield(&u1, &verifier).unwrap();
        assert_eq!(ledger.public_vault_balance, 300);

        assert_eq!(ledger.lock_to_pocket_escrow(0), Err(LedgerError::ZeroAmount));
        assert_eq!(
            ledger.lock_to_pocket_escrow(301),
            Err(LedgerError::InsufficientVaultBalance {
                requested: 301,
                available: 300,
            })
        );
        ledger.lock_to_pocket_escrow(300).unwrap();
        assert_eq!(ledger.public_vault_balance, 0);
        assert_eq!(ledger.total_pocket_escrow, 300);
        assert_eq!(ledger.total_shielded_supply, 200);

        assert_eq!(
            ledger.release_from_pocket_escrow(0),
            Err(LedgerError::ZeroAmount)
        );
        assert_eq!(
            ledger.release_from_pocket_escrow(301),
            Err(LedgerError::InsufficientPocketEscrow {
                requested: 301,
                available: 300,
            })
        );

        ledger.release_from_pocket_escrow(120).unwrap();
        assert_eq!(ledger.total_pocket_escrow, 180);
        assert_eq!(ledger.public_vault_balance, 120);

        let settle = ShieldTx {
            mint_amount: 120,
            out_commitment: FieldElement::from(61u64),
            tx_binding_hash: FieldElement::from(71u64),
            proof: vec![],
        };
        ledger.apply_shield(&settle, &verifier).unwrap();
        assert_eq!(ledger.total_shielded_supply, 320);
        assert_eq!(ledger.total_pocket_escrow, 180);
        assert_eq!(ledger.total_issued_supply, 500);
        ledger.assert_conservation_invariant();
    }
}

