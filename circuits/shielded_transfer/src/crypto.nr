use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};
use std::hash::poseidon2_permutation;
use crate::types::{
    DOMAIN_DIVERSIFIER, DOMAIN_IVK, DOMAIN_MERKLE_NODE, DOMAIN_NK, DOMAIN_NOTE_COMMITMENT,
    DOMAIN_NULLIFIER, GRUMPKIN_NEG_B, Note,
};

global POSEIDON2_RATE: u32 = 3;
global TWO_POW_64: Field = 18446744073709551616;

/// Aztec-standard Poseidon2 sponge (t = 4, rate = 3, capacity = 1) over fixed-length inputs.
pub fn poseidon2_hash<let N: u32>(input: [Field; N]) -> Field {
    let iv: Field = (N as Field) * TWO_POW_64;
    let mut state: [Field; 4] = [0, 0, 0, iv];

    for chunk_idx in 0..(N / POSEIDON2_RATE) {
        for i in 0..POSEIDON2_RATE {
            state[i] += input[chunk_idx * POSEIDON2_RATE + i];
        }
        state = poseidon2_permutation(state);
    }

    let rem = N % POSEIDON2_RATE;
    if (N == 0) | (rem != 0) {
        let remainder_start = (N / POSEIDON2_RATE) * POSEIDON2_RATE;
        for j in 0..POSEIDON2_RATE {
            if j < rem {
                state[j] += input[remainder_start + j];
            }
        }
        state = poseidon2_permutation(state);
    }

    state[0]
}

pub fn hash_2(input: [Field; 2]) -> Field {
    poseidon2_hash(input)
}

pub fn hash_3(input: [Field; 3]) -> Field {
    poseidon2_hash(input)
}

pub fn hash_4(input: [Field; 4]) -> Field {
    poseidon2_hash(input)
}

pub fn hash_5(input: [Field; 5]) -> Field {
    poseidon2_hash(input)
}

/// Derives authorizing public key `ak = ask * G` on Grumpkin.
pub fn derive_ak(ask: Field) -> EmbeddedCurvePoint {
    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(ask))
}

/// Derives nullifier key `nk = Poseidon2(DOMAIN_NK, ask)`.
pub fn derive_nk(ask: Field) -> Field {
    hash_2([DOMAIN_NK, ask])
}

/// Derives incoming viewing key `ivk = Poseidon2(DOMAIN_IVK, ak.x, ak.y, nk)`.
pub fn derive_ivk(ak: EmbeddedCurvePoint, nk: Field) -> Field {
    hash_4([DOMAIN_IVK, ak.x, ak.y, nk])
}

/// Derives the x-coordinate of a diversified Grumpkin base point `g_d`.
pub fn derive_diversifier_x(diversifier: Field, nonce: u8) -> Field {
    hash_3([DOMAIN_DIVERSIFIER, diversifier, nonce as Field])
}

/// Constrains `(x, y)` to be a non-infinite point on Grumpkin (`y^2 == x^3 - 17`, `y != 0`).
pub fn assert_on_grumpkin(x: Field, y: Field) {
    assert(y != 0, "Point cannot have y == 0 (invalid or order-2)");
    let x2 = x * x;
    assert(y * y == x2 * x - GRUMPKIN_NEG_B, "Point not on Grumpkin curve");
}

/// Derives diversified address public key `pk_d = ivk * g_d`.
pub fn derive_diversified_pk(ivk: Field, g_d: EmbeddedCurvePoint) -> EmbeddedCurvePoint {
    multi_scalar_mul([g_d], [EmbeddedCurveScalar::from_field(ivk)])
}

pub fn compute_note_commitment(note: Note) -> Field {
    hash_5([
        DOMAIN_NOTE_COMMITMENT,
        note.value as Field,
        note.owner_pk_x,
        note.owner_pk_y,
        note.blinding,
    ])
}

pub fn compute_nullifier(nk: Field, commitment: Field, leaf_index: u32) -> Field {
    hash_4([DOMAIN_NULLIFIER, nk, commitment, leaf_index as Field])
}

pub fn hash_merkle_node(left: Field, right: Field) -> Field {
    hash_3([DOMAIN_MERKLE_NODE, left, right])
}

