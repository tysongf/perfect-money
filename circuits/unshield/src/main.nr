use std::embedded_curve_ops::EmbeddedCurvePoint;
use common::crypto::{
    assert_on_grumpkin, compute_note_commitment, compute_nullifier, derive_ak,
    derive_diversified_pk, derive_diversifier_x, derive_ivk, derive_nk,
};
use common::merkle::compute_merkle_root;
use common::types::{MERKLE_DEPTH, Note};

fn main(
    // Public inputs
    merkle_root: pub Field,
    nullifier: pub Field,
    change_commitment: pub Field,
    burn_amount: pub u64,
    fee: pub u64,
    tx_binding_hash: pub Field,

    // Private inputs
    ask: Field,
    in_note: Note,
    in_diversifier: Field,
    in_g_d_nonce: u8,
    in_g_d_y: Field,
    in_leaf_index: u32,
    in_merkle_path: [Field; MERKLE_DEPTH],
    change_note: Note,
) {
    assert(tx_binding_hash != 0, "Missing tx_binding_hash");
    assert(ask != 0, "Zero spend key");
    assert(burn_amount > 0, "Burn amount must be positive");

    let ak = derive_ak(ask);
    let nk = derive_nk(ask);
    let ivk = derive_ivk(ak, nk);
    assert(ivk != 0, "Zero ivk");

    // 1. Validate spent note ownership, deterministic nullifier, and Merkle membership
    let cm = compute_note_commitment(in_note);
    let expected_nf = compute_nullifier(nk, cm, in_leaf_index);
    assert(nullifier == expected_nf, "Invalid nullifier");

    let g_d_x = derive_diversifier_x(in_diversifier, in_g_d_nonce);
    assert_on_grumpkin(g_d_x, in_g_d_y);
    let pk_d = derive_diversified_pk(ivk, EmbeddedCurvePoint::new(g_d_x, in_g_d_y));
    assert(in_note.owner_pk_x == pk_d.x, "Unauthorized spend");
    assert(in_note.owner_pk_y == pk_d.y, "Unauthorized spend");

    let computed_root = compute_merkle_root(cm, in_leaf_index, in_merkle_path);
    assert(computed_root == merkle_root, "Invalid Merkle inclusion proof");

    // 2. Validate change commitment and on-curve key if change is non-zero
    if change_note.value > 0 {
        assert_on_grumpkin(change_note.owner_pk_x, change_note.owner_pk_y);
    }
    assert(change_commitment == compute_note_commitment(change_note), "Invalid change commitment");

    // 3. Strict value conservation in u128 to prevent u64 or BN254 wrap-around
    let total_in: u128 = in_note.value as u128;
    let total_out: u128 = (burn_amount as u128) + (change_note.value as u128) + (fee as u128);
    assert(total_in == total_out, "Value conservation violated");
}

mod tests {
    use std::embedded_curve_ops::EmbeddedCurvePoint;
    use common::crypto::{
        compute_note_commitment, compute_nullifier, derive_ak, derive_diversified_pk,
        derive_diversifier_x, derive_ivk, derive_nk, hash_merkle_node,
    };
    use common::types::{MERKLE_DEPTH, Note};
    use crate::main;

    global TEST_SENDER_ASK: Field = 123456789;
    global TEST_WRONG_ASK: Field = 987654321;
    global DIV0_Y: Field =
        0x1388e9af76fcc13c00e320824551d6d044b32a25b4c4feaeddffdfd624caeae7;

    pub struct UnshieldFixture {
        merkle_root: Field,
        nullifier: Field,
        change_commitment: Field,
        burn_amount: u64,
        fee: u64,
        tx_binding_hash: Field,
        ask: Field,
        in_note: Note,
        in_diversifier: Field,
        in_g_d_nonce: u8,
        in_g_d_y: Field,
        in_leaf_index: u32,
        in_merkle_path: [Field; MERKLE_DEPTH],
        change_note: Note,
    }

    pub fn build_merkle_for_leaf_5(cm: Field) -> (Field, [Field; MERKLE_DEPTH]) {
        let mut zeros: [Field; MERKLE_DEPTH] = [0; MERKLE_DEPTH];
        for i in 1..MERKLE_DEPTH {
            zeros[i] = hash_merkle_node(zeros[i - 1], zeros[i - 1]);
        }
        let mut root = cm;
        root = hash_merkle_node(zeros[0], root);
        root = hash_merkle_node(root, zeros[1]);
        root = hash_merkle_node(zeros[2], root);
        for lvl in 3..MERKLE_DEPTH {
            root = hash_merkle_node(root, zeros[lvl]);
        }
        (root, zeros)
    }

    pub fn build_valid_fixture() -> UnshieldFixture {
        let ak = derive_ak(TEST_SENDER_ASK);
        let nk = derive_nk(TEST_SENDER_ASK);
        let ivk = derive_ivk(ak, nk);

        let d0: Field = 1001;
        let n0: u8 = 1;
        let gx = derive_diversifier_x(d0, n0);
        let pk = derive_diversified_pk(ivk, EmbeddedCurvePoint::new(gx, DIV0_Y));

        let in_note = Note {
            value: 600,
            owner_pk_x: pk.x,
            owner_pk_y: pk.y,
            blinding: 0x1111222233334444,
        };
        let cm = compute_note_commitment(in_note);
        let (root, path) = build_merkle_for_leaf_5(cm);
        let nf = compute_nullifier(nk, cm, 5);

        let change_note = Note {
            value: 190,
            owner_pk_x: pk.x,
            owner_pk_y: pk.y,
            blinding: 0x2222333344445555,
        };

        UnshieldFixture {
            merkle_root: root,
            nullifier: nf,
            change_commitment: compute_note_commitment(change_note),
            burn_amount: 400,
            fee: 10,
            tx_binding_hash: 0x8888777766665555,
            ask: TEST_SENDER_ASK,
            in_note,
            in_diversifier: d0,
            in_g_d_nonce: n0,
            in_g_d_y: DIV0_Y,
            in_leaf_index: 5,
            in_merkle_path: path,
            change_note,
        }
    }

    pub fn run_fixture(f: UnshieldFixture) {
        main(
            f.merkle_root,
            f.nullifier,
            f.change_commitment,
            f.burn_amount,
            f.fee,
            f.tx_binding_hash,
            f.ask,
            f.in_note,
            f.in_diversifier,
            f.in_g_d_nonce,
            f.in_g_d_y,
            f.in_leaf_index,
            f.in_merkle_path,
            f.change_note,
        );
    }

    #[test]
    fn test_valid_unshield_with_change_and_fee() {
        run_fixture(build_valid_fixture());
    }

    #[test]
    fn test_valid_full_unshield_zero_change() {
        let mut f = build_valid_fixture();
        f.burn_amount = 590;
        f.fee = 10;
        f.change_note = Note {
            value: 0,
            owner_pk_x: 0,
            owner_pk_y: 0,
            blinding: 0x9999000011112222,
        };
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test]
    fn test_valid_zero_fee_unshield() {
        let mut f = build_valid_fixture();
        f.burn_amount = 410;
        f.fee = 0;
        run_fixture(f);
    }

    #[test]
    fn test_u64_max_unshield() {
        let mut f = build_valid_fixture();
        let max_u64: u64 = 18446744073709551615;
        let nk = derive_nk(TEST_SENDER_ASK);

        f.in_note.value = max_u64;
        let cm = compute_note_commitment(f.in_note);
        let (root, path) = build_merkle_for_leaf_5(cm);
        f.merkle_root = root;
        f.in_merkle_path = path;
        f.nullifier = compute_nullifier(nk, cm, 5);

        f.burn_amount = max_u64 - 10;
        f.change_note.value = 0;
        f.change_note.owner_pk_x = 0;
        f.change_note.owner_pk_y = 0;
        f.fee = 10;
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Burn amount must be positive")]
    fn test_zero_burn_amount_fails() {
        let mut f = build_valid_fixture();
        f.burn_amount = 0;
        f.change_note.value = 590;
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Unauthorized spend")]
    fn test_unauthorized_spend_wrong_ask_fails() {
        let mut f = build_valid_fixture();
        f.ask = TEST_WRONG_ASK;
        let nk_bad = derive_nk(TEST_WRONG_ASK);
        f.nullifier = compute_nullifier(nk_bad, compute_note_commitment(f.in_note), f.in_leaf_index);
        run_fixture(f);
    }

    #[test(should_fail_with = "Point not on Grumpkin curve")]
    fn test_invalid_diversifier_point_fails() {
        let mut f = build_valid_fixture();
        f.in_g_d_y += 1;
        run_fixture(f);
    }

    #[test(should_fail_with = "Invalid Merkle inclusion proof")]
    fn test_invalid_merkle_proof_sibling_fails() {
        let mut f = build_valid_fixture();
        f.in_merkle_path[0] += 1;
        run_fixture(f);
    }

    #[test(should_fail_with = "Invalid Merkle inclusion proof")]
    fn test_tampered_leaf_index_fails() {
        let mut f = build_valid_fixture();
        f.in_leaf_index = 6;
        let nk = derive_nk(TEST_SENDER_ASK);
        f.nullifier = compute_nullifier(nk, compute_note_commitment(f.in_note), 6);
        run_fixture(f);
    }

    #[test(should_fail_with = "Value conservation violated")]
    fn test_value_inflation_fails() {
        let mut f = build_valid_fixture();
        f.burn_amount += 1;
        run_fixture(f);
    }

    #[test(should_fail_with = "Value conservation violated")]
    fn test_u64_overflow_attempt_fails() {
        let mut f = build_valid_fixture();
        // Attempt u64 wrap: (2^64 - 1) + 601 + 0 != 600 in u128
        f.burn_amount = 18446744073709551615;
        f.change_note.value = 601;
        f.fee = 0;
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Missing tx_binding_hash")]
    fn test_zero_tx_binding_hash_fails() {
        let mut f = build_valid_fixture();
        f.tx_binding_hash = 0;
        run_fixture(f);
    }

    #[test(should_fail_with = "Point not on Grumpkin curve")]
    fn test_off_curve_change_pubkey_fails() {
        let mut f = build_valid_fixture();
        f.change_note.owner_pk_y += 1;
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Point cannot have y == 0")]
    fn test_zero_y_change_pubkey_fails() {
        let mut f = build_valid_fixture();
        f.change_note.owner_pk_y = 0;
        f.change_commitment = compute_note_commitment(f.change_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Zero spend key")]
    fn test_zero_ask_fails() {
        let mut f = build_valid_fixture();
        f.ask = 0;
        run_fixture(f);
    }
}

