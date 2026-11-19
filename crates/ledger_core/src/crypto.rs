use acir::{AcirField, FieldElement};
use anyhow::{Result, bail};
use bn254_blackbox_solver::{multi_scalar_mul, poseidon2_permutation};
use serde::{Deserialize, Serialize};

pub const MERKLE_DEPTH: usize = 32;

pub const DOMAIN_NK: u64 = 1;
pub const DOMAIN_IVK: u64 = 2;
pub const DOMAIN_DIVERSIFIER: u64 = 3;
pub const DOMAIN_NOTE_COMMITMENT: u64 = 4;
pub const DOMAIN_NULLIFIER: u64 = 5;
pub const DOMAIN_MERKLE_NODE: u64 = 6;
pub const DOMAIN_SHIELD_UNSHIELD: u64 = 7;

const POSEIDON2_RATE: usize = 3;
const TWO_POW_64: u128 = 1u128 << 64;
const GRUMPKIN_NEG_B: u64 = 17;

/// Canonical Grumpkin generator G = (1, sqrt(-16)) matching Noir stdlib.
const GRUMPKIN_GEN_X: u64 = 1;
const GRUMPKIN_GEN_Y_DEC: &str = "17631683881184975370165255887551781615748388533673675138860";

/// Tonelli-Shanks constants for BN254 scalar field Fr (p - 1 = Q * 2^28, non-residue z = 5).
const TS_S: u32 = 28;
const TS_Q_HEX: &str = "0x000000030644e72e131a029b85045b68181585d2833e84879b9709143e1f593f";
const TS_Q_PLUS_1_DIV_2_HEX: &str =
    "0x0000000183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0faca0";
const TS_P_MINUS_1_DIV_2_HEX: &str =
    "0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000000";
const TS_C_INIT_HEX: &str = "0x2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0";

/// Affine point on Grumpkin (`y^2 = x^3 - 17`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrumpkinPoint {
    pub x: FieldElement,
    pub y: FieldElement,
}

/// Shielded Perfect Money note matching `common::types::Note`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Note {
    pub value: u64,
    pub owner_pk_x: FieldElement,
    pub owner_pk_y: FieldElement,
    pub blinding: FieldElement,
}

/// Orchard-style 3-key hierarchy derived from root spend key `ask`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletKeys {
    pub ask: FieldElement,
    pub ak: GrumpkinPoint,
    pub nk: FieldElement,
    pub ivk: FieldElement,
}

/// Diversified Grumpkin address derived from an `ivk` and diversifier `d`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiversifiedAddress {
    pub diversifier: FieldElement,
    pub nonce: u8,
    pub g_d: GrumpkinPoint,
    pub pk_d: GrumpkinPoint,
}

/// Aztec-standard Poseidon2 sponge (`t = 4`, `rate = 3`) over BN254 `Fr`.
pub fn poseidon2_hash(input: &[FieldElement]) -> FieldElement {
    let iv = FieldElement::from((input.len() as u128) * TWO_POW_64);
    let mut state = [
        FieldElement::zero(),
        FieldElement::zero(),
        FieldElement::zero(),
        iv,
    ];

    let full_chunks = input.len() / POSEIDON2_RATE;
    for chunk_idx in 0..full_chunks {
        for i in 0..POSEIDON2_RATE {
            state[i] += input[chunk_idx * POSEIDON2_RATE + i];
        }
        let next = poseidon2_permutation(&state).expect("poseidon2_permutation failed on t=4");
        state.copy_from_slice(&next);
    }

    let rem = input.len() % POSEIDON2_RATE;
    if input.is_empty() || rem != 0 {
        let start = full_chunks * POSEIDON2_RATE;
        for j in 0..rem {
            state[j] += input[start + j];
        }
        let next = poseidon2_permutation(&state).expect("poseidon2_permutation failed on t=4");
        state.copy_from_slice(&next);
    }

    state[0]
}

pub fn hash_2(a: FieldElement, b: FieldElement) -> FieldElement {
    poseidon2_hash(&[a, b])
}

pub fn hash_3(a: FieldElement, b: FieldElement, c: FieldElement) -> FieldElement {
    poseidon2_hash(&[a, b, c])
}

pub fn hash_4(a: FieldElement, b: FieldElement, c: FieldElement, d: FieldElement) -> FieldElement {
    poseidon2_hash(&[a, b, c, d])
}

pub fn hash_5(
    a: FieldElement,
    b: FieldElement,
    c: FieldElement,
    d: FieldElement,
    e: FieldElement,
) -> FieldElement {
    poseidon2_hash(&[a, b, c, d, e])
}

/// Splits a `FieldElement` into `(lo, hi)` 128-bit limbs matching `EmbeddedCurveScalar::from_field`.
pub fn split_field_to_u128_limbs(val: FieldElement) -> (FieldElement, FieldElement) {
    let be = val.to_be_bytes();
    let mut hi_bytes = [0u8; 16];
    let mut lo_bytes = [0u8; 16];
    hi_bytes.copy_from_slice(&be[0..16]);
    lo_bytes.copy_from_slice(&be[16..32]);
    (
        FieldElement::from(u128::from_be_bytes(lo_bytes)),
        FieldElement::from(u128::from_be_bytes(hi_bytes)),
    )
}

/// Computes `scalar * point` on Grumpkin via `bn254_blackbox_solver::multi_scalar_mul`.
pub fn grumpkin_scalar_mul(point: GrumpkinPoint, scalar: FieldElement) -> Result<GrumpkinPoint> {
    let (lo, hi) = split_field_to_u128_limbs(scalar);
    let (x, y) = multi_scalar_mul(&[point.x, point.y], &[lo], &[hi])?;
    Ok(GrumpkinPoint { x, y })
}

pub fn grumpkin_generator() -> GrumpkinPoint {
    GrumpkinPoint {
        x: FieldElement::from(GRUMPKIN_GEN_X),
        y: FieldElement::try_from_str(GRUMPKIN_GEN_Y_DEC)
            .expect("valid canonical Grumpkin generator y"),
    }
}

pub fn is_on_grumpkin(x: FieldElement, y: FieldElement) -> bool {
    if y.is_zero() {
        return false;
    }
    y * y == x * x * x - FieldElement::from(GRUMPKIN_NEG_B)
}

/// Tonelli-Shanks square root in BN254 scalar field `Fr`.
pub fn sqrt_bn254(a: FieldElement) -> Option<FieldElement> {
    if a.is_zero() {
        return Some(FieldElement::zero());
    }
    let p_m1_2 = FieldElement::from_hex(TS_P_MINUS_1_DIV_2_HEX).expect("valid hex");
    if a.pow(&p_m1_2) != FieldElement::one() {
        return None;
    }

    let q = FieldElement::from_hex(TS_Q_HEX).expect("valid hex");
    let q_p1_2 = FieldElement::from_hex(TS_Q_PLUS_1_DIV_2_HEX).expect("valid hex");
    let mut m = TS_S;
    let mut c = FieldElement::from_hex(TS_C_INIT_HEX).expect("valid hex");
    let mut t = a.pow(&q);
    let mut r = a.pow(&q_p1_2);

    while t != FieldElement::one() {
        let mut i = 1u32;
        let mut t2i = t * t;
        while t2i != FieldElement::one() {
            t2i = t2i * t2i;
            i += 1;
        }
        let mut b = c;
        for _ in 0..(m - i - 1) {
            b = b * b;
        }
        m = i;
        c = b * b;
        t = t * c;
        r = r * b;
    }

    Some(r)
}

impl WalletKeys {
    /// Derives `(ak, nk, ivk)` from a non-zero root spend key `ask`.
    pub fn from_ask(ask: FieldElement) -> Result<Self> {
        if ask.is_zero() {
            bail!("ask cannot be zero");
        }
        let ak = grumpkin_scalar_mul(grumpkin_generator(), ask)?;
        let nk = hash_2(FieldElement::from(DOMAIN_NK), ask);
        let ivk = hash_4(FieldElement::from(DOMAIN_IVK), ak.x, ak.y, nk);
        if ivk.is_zero() {
            bail!("derived ivk cannot be zero");
        }
        Ok(Self { ask, ak, nk, ivk })
    }
}

/// Derives a diversified Grumpkin payment address `(d, nonce, g_d, pk_d)` from `ivk`.
pub fn derive_diversified_address(
    ivk: FieldElement,
    diversifier: FieldElement,
) -> Result<DiversifiedAddress> {
    if ivk.is_zero() {
        bail!("ivk cannot be zero");
    }
    let neg_b = FieldElement::from(GRUMPKIN_NEG_B);
    for nonce in 0u8..=u8::MAX {
        let x = hash_3(
            FieldElement::from(DOMAIN_DIVERSIFIER),
            diversifier,
            FieldElement::from(nonce as u64),
        );
        let rhs = x * x * x - neg_b;
        if let Some(y) = sqrt_bn254(rhs) {
            if !y.is_zero() {
                let g_d = GrumpkinPoint { x, y };
                let pk_d = grumpkin_scalar_mul(g_d, ivk)?;
                return Ok(DiversifiedAddress {
                    diversifier,
                    nonce,
                    g_d,
                    pk_d,
                });
            }
        }
    }
    bail!("no valid diversified point found in 256 nonces")
}

pub fn compute_note_commitment(note: &Note) -> FieldElement {
    hash_5(
        FieldElement::from(DOMAIN_NOTE_COMMITMENT),
        FieldElement::from(note.value),
        note.owner_pk_x,
        note.owner_pk_y,
        note.blinding,
    )
}

pub fn compute_nullifier(
    nk: FieldElement,
    commitment: FieldElement,
    leaf_index: u32,
) -> FieldElement {
    hash_4(
        FieldElement::from(DOMAIN_NULLIFIER),
        nk,
        commitment,
        FieldElement::from(leaf_index as u64),
    )
}

pub fn hash_merkle_node(left: FieldElement, right: FieldElement) -> FieldElement {
    hash_3(FieldElement::from(DOMAIN_MERKLE_NODE), left, right)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    #[test]
    fn test_cross_language_parity_with_noir_prover_toml() {
        let sender = WalletKeys::from_ask(FieldElement::from(123456789u64)).unwrap();
        let recip = WalletKeys::from_ask(FieldElement::from(987654321u64)).unwrap();

        let addr0 = derive_diversified_address(sender.ivk, FieldElement::from(1001u64)).unwrap();
        let addr1 = derive_diversified_address(sender.ivk, FieldElement::from(1002u64)).unwrap();
        let addr_r = derive_diversified_address(recip.ivk, FieldElement::from(2001u64)).unwrap();

        assert_eq!(addr0.nonce, 1);
        assert_eq!(addr1.nonce, 5);
        assert_eq!(addr_r.nonce, 0);

        assert_eq!(
            addr0.g_d.y.to_hex(),
            "1388e9af76fcc13c00e320824551d6d044b32a25b4c4feaeddffdfd624caeae7"
        );
        assert_eq!(
            addr0.pk_d.x.to_hex(),
            "2abb2c2819b2d7f10405dac13bdd5eb9921e727e03d784a36cf4bff58dd29984"
        );
        assert_eq!(
            addr0.pk_d.y.to_hex(),
            "1da70e4fd29e92131aeae8b6801b0d5809c283a7fd7ce048f5af3b5470b0f037"
        );
        assert_eq!(
            addr1.pk_d.x.to_hex(),
            "0369f2ef9e9331d53d4f8f9f6bd9cdc1b07b5756a8a8e99aa175a894b5b0ddde"
        );
        assert_eq!(
            addr1.pk_d.y.to_hex(),
            "050a548dfa9b9b5de42d51df932e68049900fa8d0c3b3fbb96b5de42ceb321dd"
        );
        assert!(is_on_grumpkin(addr0.pk_d.x, addr0.pk_d.y));
        assert!(is_on_grumpkin(addr_r.pk_d.x, addr_r.pk_d.y));

        let in_note0 = Note {
            value: 600,
            owner_pk_x: addr0.pk_d.x,
            owner_pk_y: addr0.pk_d.y,
            blinding: FieldElement::from_hex("0x1111222233334444").unwrap(),
        };
        let in_note1 = Note {
            value: 450,
            owner_pk_x: addr1.pk_d.x,
            owner_pk_y: addr1.pk_d.y,
            blinding: FieldElement::from_hex("0x5555666677778888").unwrap(),
        };
        let cm0 = compute_note_commitment(&in_note0);
        let cm1 = compute_note_commitment(&in_note1);

        // Insert zero placeholders up to leaf 5 and leaf 12 matching Noir fixture
        let mut tree = MerkleTree::new();
        for idx in 0..13u32 {
            let leaf = if idx == 5 {
                cm0
            } else if idx == 12 {
                cm1
            } else {
                FieldElement::zero()
            };
            tree.insert(leaf).unwrap();
        }
        assert_eq!(
            tree.root().to_hex(),
            "28f4e975b18ada68f13c17cf274ce75da4bfd504cd68c48f3cad0b041d33319a"
        );

        let nf0 = compute_nullifier(sender.nk, cm0, 5);
        let nf1 = compute_nullifier(sender.nk, cm1, 12);
        assert_eq!(
            nf0.to_hex(),
            "2ffa29893d12d6939e267ef5e221fbeb943cabb56fa1cf30b597d02ce204a081"
        );
        assert_eq!(
            nf1.to_hex(),
            "231f5662716a0eb32d8ac9039b83689481736700e3899812f84a4d39766768b4"
        );

        let out_note0 = Note {
            value: 800,
            owner_pk_x: addr_r.pk_d.x,
            owner_pk_y: addr_r.pk_d.y,
            blinding: FieldElement::from_hex("0xaaaa1111bbbb2222").unwrap(),
        };
        let out_note1 = Note {
            value: 240,
            owner_pk_x: addr1.pk_d.x,
            owner_pk_y: addr1.pk_d.y,
            blinding: FieldElement::from_hex("0xcccc3333dddd4444").unwrap(),
        };
        assert_eq!(
            compute_note_commitment(&out_note0).to_hex(),
            "250cfd34af8b484be336c5fbb4604057e03a2daffede5aba6dcd5de22941e020"
        );
        assert_eq!(
            compute_note_commitment(&out_note1).to_hex(),
            "09eb55acd087d16766437ee9848003843548c5b71953bfa6113a336f352cab20"
        );
    }
}

