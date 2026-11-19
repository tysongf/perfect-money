mod types;
mod crypto;
mod merkle;

use std::embedded_curve_ops::EmbeddedCurvePoint;
use types::{MERKLE_DEPTH, Note};
use crypto::{
    assert_on_grumpkin, compute_note_commitment, compute_nullifier, derive_ak,
    derive_diversified_pk, derive_diversifier_x, derive_ivk, derive_nk,
};
use merkle::compute_merkle_root;

fn main(
    // Public inputs
    merkle_root: pub Field,
    nullifiers: pub [Field; 2],
    out_commitments: pub [Field; 2],
    fee: pub u64,
    tx_binding_hash: pub Field,

    // Private inputs
    ask: Field,
    in_notes: [Note; 2],
    in_diversifiers: [Field; 2],
    in_g_d_nonces: [u8; 2],
    in_g_d_ys: [Field; 2],
    in_leaf_indices: [u32; 2],
    in_merkle_paths: [[Field; MERKLE_DEPTH]; 2],
    out_notes: [Note; 2],
) {
    assert(tx_binding_hash != 0, "Missing tx_binding_hash");
    assert(ask != 0, "Zero spend key");

    let ak = derive_ak(ask);
    let nk = derive_nk(ask);
    let ivk = derive_ivk(ak, nk);
    assert(ivk != 0, "Zero ivk");

    // 1. Validate inputs: deterministic nullifier, diversified key ownership, Merkle membership
    for i in 0..2 {
        let note = in_notes[i];
        let cm = compute_note_commitment(note);
        let expected_nf = compute_nullifier(nk, cm, in_leaf_indices[i]);
        assert(nullifiers[i] == expected_nf, "Invalid nullifier");

        let is_real = note.value > 0;
        let g_d_x = derive_diversifier_x(in_diversifiers[i], in_g_d_nonces[i]);
        if is_real {
            assert_on_grumpkin(g_d_x, in_g_d_ys[i]);
        }

        // Feed a guaranteed on-curve point for dummy inputs so MSM executes cleanly.
        let effective_g_d = if is_real {
            EmbeddedCurvePoint::new(g_d_x, in_g_d_ys[i])
        } else {
            EmbeddedCurvePoint::generator()
        };
        let pk_d = derive_diversified_pk(ivk, effective_g_d);
        if is_real {
            assert(note.owner_pk_x == pk_d.x, "Unauthorized spend");
            assert(note.owner_pk_y == pk_d.y, "Unauthorized spend");
        }

        let computed_root = compute_merkle_root(cm, in_leaf_indices[i], in_merkle_paths[i]);
        if is_real {
            assert(computed_root == merkle_root, "Invalid Merkle inclusion proof");
        }
    }

    // Prevent spending the exact same note twice in one JoinSplit
    assert(nullifiers[0] != nullifiers[1], "Duplicate nullifiers");

    // 2. Validate output commitments and on-curve recipient pubkeys for non-zero notes
    for j in 0..2 {
        let out_note = out_notes[j];
        if out_note.value > 0 {
            assert_on_grumpkin(out_note.owner_pk_x, out_note.owner_pk_y);
        }
        let out_cm = compute_note_commitment(out_note);
        assert(out_commitments[j] == out_cm, "Invalid output commitment");
    }

    // 3. Strict value conservation in u128 to prevent BN254 scalar wrap-around
    let total_in: u128 = (in_notes[0].value as u128) + (in_notes[1].value as u128);
    let total_out: u128 =
        (out_notes[0].value as u128) + (out_notes[1].value as u128) + (fee as u128);
    assert(total_in == total_out, "Value conservation violated");
}

mod tests {
    use std::embedded_curve_ops::EmbeddedCurvePoint;
    use crate::crypto::{
        compute_note_commitment, compute_nullifier, derive_ak, derive_diversified_pk,
        derive_diversifier_x, derive_ivk, derive_nk, hash_merkle_node,
    };
    use crate::main;
    use crate::types::{MERKLE_DEPTH, Note};

    global TEST_SENDER_ASK: Field = 123456789;
    global TEST_RECIP_ASK: Field = 987654321;

    // Precomputed y-coordinates on Grumpkin (y^2 = x^3 - 17 mod p_BN254) for test diversifiers:
    // d=1001, nonce=1
    global DIV0_Y: Field =
        0x1388e9af76fcc13c00e320824551d6d044b32a25b4c4feaeddffdfd624caeae7;
    // d=1002, nonce=5
    global DIV1_Y: Field =
        0x0e419362ff37e51b15f5d0efb6efa5ff222437087fcca260aede20eaf6956b7d;
    // d=2001, nonce=0
    global RECIP_DIV_Y: Field =
        0x2ed24f09cc682979c6c133459d473d71876b2546bb9e019c67343de3d55de297;

    pub struct TxFixture {
        merkle_root: Field,
        nullifiers: [Field; 2],
        out_commitments: [Field; 2],
        fee: u64,
        tx_binding_hash: Field,
        ask: Field,
        in_notes: [Note; 2],
        in_diversifiers: [Field; 2],
        in_g_d_nonces: [u8; 2],
        in_g_d_ys: [Field; 2],
        in_leaf_indices: [u32; 2],
        in_merkle_paths: [[Field; MERKLE_DEPTH]; 2],
        out_notes: [Note; 2],
    }

    pub fn run_fixture(f: TxFixture) {
        main(
            f.merkle_root,
            f.nullifiers,
            f.out_commitments,
            f.fee,
            f.tx_binding_hash,
            f.ask,
            f.in_notes,
            f.in_diversifiers,
            f.in_g_d_nonces,
            f.in_g_d_ys,
            f.in_leaf_indices,
            f.in_merkle_paths,
            f.out_notes,
        );
    }

    pub fn build_two_in_two_out_fixture() -> TxFixture {
        let ak_s = derive_ak(TEST_SENDER_ASK);
        let nk_s = derive_nk(TEST_SENDER_ASK);
        let ivk_s = derive_ivk(ak_s, nk_s);

        let d0: Field = 1001;
        let n0: u8 = 1;
        let gx0 = derive_diversifier_x(d0, n0);
        let pk0 = derive_diversified_pk(ivk_s, EmbeddedCurvePoint::new(gx0, DIV0_Y));

        let d1: Field = 1002;
        let n1: u8 = 5;
        let gx1 = derive_diversifier_x(d1, n1);
        let pk1 = derive_diversified_pk(ivk_s, EmbeddedCurvePoint::new(gx1, DIV1_Y));

        let ak_r = derive_ak(TEST_RECIP_ASK);
        let nk_r = derive_nk(TEST_RECIP_ASK);
        let ivk_r = derive_ivk(ak_r, nk_r);
        let gx_r = derive_diversifier_x(2001, 0);
        let pk_r = derive_diversified_pk(ivk_r, EmbeddedCurvePoint::new(gx_r, RECIP_DIV_Y));

        let in_note0 = Note {
            value: 600,
            owner_pk_x: pk0.x,
            owner_pk_y: pk0.y,
            blinding: 0x1111222233334444,
        };
        let in_note1 = Note {
            value: 450,
            owner_pk_x: pk1.x,
            owner_pk_y: pk1.y,
            blinding: 0x5555666677778888,
        };

        let cm0 = compute_note_commitment(in_note0);
        let cm1 = compute_note_commitment(in_note1);

        // Two leaves at indices 5 (0b0101) and 12 (0b1100), sharing sibling at level 3
        let mut zeros: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
        for i in 1..MERKLE_DEPTH {
            zeros[i] = hash_merkle_node(zeros[i - 1], zeros[i - 1]);
        }

        let mut cur0 = cm0;
        cur0 = hash_merkle_node(zeros[0], cur0);
        cur0 = hash_merkle_node(cur0, zeros[1]);
        cur0 = hash_merkle_node(zeros[2], cur0);

        let mut cur1 = cm1;
        cur1 = hash_merkle_node(cur1, zeros[0]);
        cur1 = hash_merkle_node(cur1, zeros[1]);
        cur1 = hash_merkle_node(zeros[2], cur1);

        let mut path0 = zeros;
        let mut path1 = zeros;
        path0[3] = cur1;
        path1[3] = cur0;

        let mut root = hash_merkle_node(cur0, cur1);
        for lvl in 4..MERKLE_DEPTH {
            root = hash_merkle_node(root, zeros[lvl]);
        }

        let nf0 = compute_nullifier(nk_s, cm0, 5);
        let nf1 = compute_nullifier(nk_s, cm1, 12);

        let out_note0 = Note {
            value: 800,
            owner_pk_x: pk_r.x,
            owner_pk_y: pk_r.y,
            blinding: 0xaaaa1111bbbb2222,
        };
        let out_note1 = Note {
            value: 240,
            owner_pk_x: pk1.x,
            owner_pk_y: pk1.y,
            blinding: 0xcccc3333dddd4444,
        };

        TxFixture {
            merkle_root: root,
            nullifiers: [nf0, nf1],
            out_commitments: [
                compute_note_commitment(out_note0),
                compute_note_commitment(out_note1),
            ],
            fee: 10,
            tx_binding_hash: 0x9999888877776666,
            ask: TEST_SENDER_ASK,
            in_notes: [in_note0, in_note1],
            in_diversifiers: [d0, d1],
            in_g_d_nonces: [n0, n1],
            in_g_d_ys: [DIV0_Y, DIV1_Y],
            in_leaf_indices: [5, 12],
            in_merkle_paths: [path0, path1],
            out_notes: [out_note0, out_note1],
        }
    }

    pub fn build_one_in_two_out_dummy_fixture() -> TxFixture {
        let mut f = build_two_in_two_out_fixture();
        let nk_s = derive_nk(TEST_SENDER_ASK);

        // Single leaf at index 5 in an otherwise empty tree
        let cm0 = compute_note_commitment(f.in_notes[0]);
        let mut zeros: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
        for i in 1..MERKLE_DEPTH {
            zeros[i] = hash_merkle_node(zeros[i - 1], zeros[i - 1]);
        }
        let mut root = cm0;
        root = hash_merkle_node(zeros[0], root);
        root = hash_merkle_node(root, zeros[1]);
        root = hash_merkle_node(zeros[2], root);
        for lvl in 3..MERKLE_DEPTH {
            root = hash_merkle_node(root, zeros[lvl]);
        }

        // Replace input 1 with a zero-value dummy note with randomized blinding
        let dummy_note = Note {
            value: 0,
            owner_pk_x: 0,
            owner_pk_y: 0,
            blinding: 0xdeadbeefcafebabe,
        };
        let dummy_cm = compute_note_commitment(dummy_note);

        f.merkle_root = root;
        f.in_notes[1] = dummy_note;
        f.in_diversifiers[1] = 0;
        f.in_g_d_nonces[1] = 0;
        f.in_g_d_ys[1] = 0;
        f.in_leaf_indices[1] = 0;
        f.in_merkle_paths[0] = zeros;
        f.in_merkle_paths[1] = [0; MERKLE_DEPTH];
        f.nullifiers[1] = compute_nullifier(nk_s, dummy_cm, 0);

        // Rebalance outputs: 600 in = 500 + 90 + 10 fee
        f.out_notes[0].value = 500;
        f.out_notes[1].value = 90;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        f.out_commitments[1] = compute_note_commitment(f.out_notes[1]);
        f
    }

    #[test]
    fn test_valid_2_in_2_out_diversified_transfer() {
        let f = build_two_in_two_out_fixture();
        run_fixture(f);
    }

    #[test]
    fn test_valid_1_in_2_out_with_dummy_input() {
        let f = build_one_in_two_out_dummy_fixture();
        run_fixture(f);
    }

    #[test]
    fn test_valid_zero_value_change_output() {
        let mut f = build_one_in_two_out_dummy_fixture();
        // Spend full 600 into out_notes[0] = 590, fee = 10, out_notes[1] = 0 dummy change
        f.out_notes[0].value = 590;
        f.out_notes[1] = Note {
            value: 0,
            owner_pk_x: 0,
            owner_pk_y: 0,
            blinding: 0x1234abcd5678ef01,
        };
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        f.out_commitments[1] = compute_note_commitment(f.out_notes[1]);
        run_fixture(f);
    }

    #[test(should_fail_with = "Unauthorized spend")]
    fn test_unauthorized_spend_wrong_ask_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.ask = TEST_RECIP_ASK;
        // Recompute nullifiers for the wrong ask to isolate ownership check
        let nk_bad = derive_nk(TEST_RECIP_ASK);
        f.nullifiers[0] = compute_nullifier(nk_bad, compute_note_commitment(f.in_notes[0]), f.in_leaf_indices[0]);
        f.nullifiers[1] = compute_nullifier(nk_bad, compute_note_commitment(f.in_notes[1]), f.in_leaf_indices[1]);
        run_fixture(f);
    }

    #[test(should_fail_with = "Point not on Grumpkin curve")]
    fn test_invalid_diversifier_point_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.in_g_d_ys[0] += 1;
        run_fixture(f);
    }

    #[test(should_fail_with = "Invalid Merkle inclusion proof")]
    fn test_invalid_merkle_proof_sibling_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.in_merkle_paths[0][0] += 1;
        run_fixture(f);
    }

    #[test(should_fail_with = "Invalid Merkle inclusion proof")]
    fn test_tampered_leaf_index_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.in_leaf_indices[0] = 6;
        let nk_s = derive_nk(TEST_SENDER_ASK);
        f.nullifiers[0] = compute_nullifier(nk_s, compute_note_commitment(f.in_notes[0]), 6);
        run_fixture(f);
    }

    #[test(should_fail_with = "Duplicate nullifiers")]
    fn test_duplicate_nullifiers_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.in_notes[1] = f.in_notes[0];
        f.in_diversifiers[1] = f.in_diversifiers[0];
        f.in_g_d_nonces[1] = f.in_g_d_nonces[0];
        f.in_g_d_ys[1] = f.in_g_d_ys[0];
        f.in_leaf_indices[1] = f.in_leaf_indices[0];
        f.in_merkle_paths[1] = f.in_merkle_paths[0];
        f.nullifiers[1] = f.nullifiers[0];
        // Rebalance outputs to 1200 total so only duplicate nullifier triggers failure
        f.out_notes[0].value = 1000;
        f.out_notes[1].value = 190;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        f.out_commitments[1] = compute_note_commitment(f.out_notes[1]);
        run_fixture(f);
    }

    #[test(should_fail_with = "Value conservation violated")]
    fn test_value_inflation_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.out_notes[0].value += 1;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        run_fixture(f);
    }

    #[test(should_fail_with = "Missing tx_binding_hash")]
    fn test_zero_tx_binding_hash_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.tx_binding_hash = 0;
        run_fixture(f);
    }

    #[test(should_fail_with = "Point not on Grumpkin curve")]
    fn test_off_curve_output_pubkey_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.out_notes[0].owner_pk_y += 1;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        run_fixture(f);
    }

    #[test(should_fail_with = "Zero spend key")]
    fn test_zero_ask_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.ask = 0;
        run_fixture(f);
    }

    #[test(should_fail_with = "Point cannot have y == 0")]
    fn test_output_y_zero_fails() {
        let mut f = build_two_in_two_out_fixture();
        f.out_notes[0].owner_pk_y = 0;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        run_fixture(f);
    }

    #[test]
    fn test_u64_max_value_conservation() {
        let mut f = build_two_in_two_out_fixture();
        let max_u64: u64 = 18446744073709551615;
        let nk_s = derive_nk(TEST_SENDER_ASK);

        f.in_notes[0].value = max_u64;
        f.in_notes[1].value = max_u64;
        let cm0 = compute_note_commitment(f.in_notes[0]);
        let cm1 = compute_note_commitment(f.in_notes[1]);

        let mut zeros: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
        for i in 1..MERKLE_DEPTH {
            zeros[i] = hash_merkle_node(zeros[i - 1], zeros[i - 1]);
        }
        let mut cur0 = cm0;
        cur0 = hash_merkle_node(zeros[0], cur0);
        cur0 = hash_merkle_node(cur0, zeros[1]);
        cur0 = hash_merkle_node(zeros[2], cur0);

        let mut cur1 = cm1;
        cur1 = hash_merkle_node(cur1, zeros[0]);
        cur1 = hash_merkle_node(cur1, zeros[1]);
        cur1 = hash_merkle_node(zeros[2], cur1);

        f.in_merkle_paths[0][3] = cur1;
        f.in_merkle_paths[1][3] = cur0;
        let mut root = hash_merkle_node(cur0, cur1);
        for lvl in 4..MERKLE_DEPTH {
            root = hash_merkle_node(root, zeros[lvl]);
        }
        f.merkle_root = root;
        f.nullifiers[0] = compute_nullifier(nk_s, cm0, f.in_leaf_indices[0]);
        f.nullifiers[1] = compute_nullifier(nk_s, cm1, f.in_leaf_indices[1]);

        // Conservation: max_u64 + max_u64 == (max_u64 - 10) + max_u64 + 10
        f.out_notes[0].value = max_u64 - 10;
        f.out_notes[1].value = max_u64;
        f.fee = 10;
        f.out_commitments[0] = compute_note_commitment(f.out_notes[0]);
        f.out_commitments[1] = compute_note_commitment(f.out_notes[1]);
        run_fixture(f);
    }
}
