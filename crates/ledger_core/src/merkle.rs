use std::collections::BTreeMap;

use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};

use crate::crypto::{MERKLE_DEPTH, hash_merkle_node};

/// Sparse append-only depth-32 Poseidon2 Merkle tree matching `common::merkle`.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    zeros: [FieldElement; MERKLE_DEPTH],
    empty_root: FieldElement,
    nodes: BTreeMap<(u32, u32), FieldElement>,
    next_index: u64,
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl MerkleTree {
    /// Creates an empty depth-32 tree with canonical zero-subtree hashes (`zeros[0] = 0`).
    pub fn new() -> Self {
        let mut zeros = [FieldElement::zero(); MERKLE_DEPTH];
        for i in 1..MERKLE_DEPTH {
            zeros[i] = hash_merkle_node(zeros[i - 1], zeros[i - 1]);
        }
        let empty_root = hash_merkle_node(zeros[MERKLE_DEPTH - 1], zeros[MERKLE_DEPTH - 1]);
        Self {
            zeros,
            empty_root,
            nodes: BTreeMap::new(),
            next_index: 0,
        }
    }

    pub fn leaf_count(&self) -> u64 {
        self.next_index
    }

    pub fn root(&self) -> FieldElement {
        if self.next_index == 0 {
            return self.empty_root;
        }
        *self
            .nodes
            .get(&(MERKLE_DEPTH as u32, 0))
            .unwrap_or(&self.empty_root)
    }

    /// Inserts a leaf commitment at the next available index and updates ancestors up to root.
    pub fn insert(&mut self, commitment: FieldElement) -> Result<u32> {
        let max_leaves = 1u64 << MERKLE_DEPTH;
        if self.next_index >= max_leaves {
            bail!("merkle tree capacity exhausted ({max_leaves} leaves)");
        }
        let leaf_idx = self.next_index as u32;
        self.next_index += 1;

        self.nodes.insert((0, leaf_idx), commitment);
        let mut cur_idx = leaf_idx;
        let mut cur_val = commitment;

        for level in 0..(MERKLE_DEPTH as u32) {
            let sibling_idx = cur_idx ^ 1;
            let sibling_val = self.node_or_zero(level, sibling_idx);
            let (left, right) = if (cur_idx & 1) == 1 {
                (sibling_val, cur_val)
            } else {
                (cur_val, sibling_val)
            };
            let parent_val = hash_merkle_node(left, right);
            let parent_idx = cur_idx >> 1;
            self.nodes.insert((level + 1, parent_idx), parent_val);
            cur_idx = parent_idx;
            cur_val = parent_val;
        }

        Ok(leaf_idx)
    }

    /// Returns the 32 sibling hashes needed to verify `leaf_index`.
    pub fn proof(&self, leaf_index: u32) -> Result<[FieldElement; MERKLE_DEPTH]> {
        if (leaf_index as u64) >= self.next_index {
            bail!(
                "leaf_index {leaf_index} out of bounds (leaf_count={})",
                self.next_index
            );
        }
        let mut siblings = [FieldElement::zero(); MERKLE_DEPTH];
        for (level, slot) in siblings.iter_mut().enumerate() {
            let sib_idx = (leaf_index >> level) ^ 1;
            *slot = self.node_or_zero(level as u32, sib_idx);
        }
        Ok(siblings)
    }

    fn node_or_zero(&self, level: u32, index: u32) -> FieldElement {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.zeros[level as usize])
    }
}

