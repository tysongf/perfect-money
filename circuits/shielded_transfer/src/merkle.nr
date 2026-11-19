use crate::crypto::hash_merkle_node;
use crate::types::MERKLE_DEPTH;

/// Recomputes a depth-32 Poseidon2 Merkle root from `leaf`, `leaf_index: u32`, and `siblings`.
pub fn compute_merkle_root(
    leaf: Field,
    leaf_index: u32,
    siblings: [Field; MERKLE_DEPTH],
) -> Field {
    let index_bits: [bool; MERKLE_DEPTH] = (leaf_index as Field).to_le_bits();
    let mut current = leaf;

    for i in 0..MERKLE_DEPTH {
        let is_right = index_bits[i];
        let (left, right) = if is_right {
            (siblings[i], current)
        } else {
            (current, siblings[i])
        };
        current = hash_merkle_node(left, right);
    }

    current
}
