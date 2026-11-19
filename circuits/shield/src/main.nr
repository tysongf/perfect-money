use common::crypto::{assert_on_grumpkin, compute_note_commitment};
use common::types::Note;

fn main(
    // Public inputs
    mint_amount: pub u64,
    out_commitment: pub Field,
    tx_binding_hash: pub Field,

    // Private inputs
    out_note: Note,
) {
    assert(tx_binding_hash != 0, "Missing tx_binding_hash");
    assert(mint_amount > 0, "Mint amount must be positive");
    assert(out_note.value == mint_amount, "Minted value mismatch");
    assert_on_grumpkin(out_note.owner_pk_x, out_note.owner_pk_y);
    assert(out_commitment == compute_note_commitment(out_note), "Invalid output commitment");
}

mod tests {
    use std::embedded_curve_ops::EmbeddedCurvePoint;
    use common::crypto::{
        compute_note_commitment, derive_ak, derive_diversified_pk, derive_diversifier_x,
        derive_ivk, derive_nk,
    };
    use common::types::Note;
    use crate::main;

    global TEST_RECIP_ASK: Field = 123456789;
    global DIV0_Y: Field =
        0x1388e9af76fcc13c00e320824551d6d044b32a25b4c4feaeddffdfd624caeae7;

    pub struct ShieldFixture {
        mint_amount: u64,
        out_commitment: Field,
        tx_binding_hash: Field,
        out_note: Note,
    }

    pub fn build_valid_fixture() -> ShieldFixture {
        let ak = derive_ak(TEST_RECIP_ASK);
        let nk = derive_nk(TEST_RECIP_ASK);
        let ivk = derive_ivk(ak, nk);
        let gx = derive_diversifier_x(1001, 1);
        let pk = derive_diversified_pk(ivk, EmbeddedCurvePoint::new(gx, DIV0_Y));

        let note = Note {
            value: 600,
            owner_pk_x: pk.x,
            owner_pk_y: pk.y,
            blinding: 0x1111222233334444,
        };
        ShieldFixture {
            mint_amount: 600,
            out_commitment: compute_note_commitment(note),
            tx_binding_hash: 0x7777666655554444,
            out_note: note,
        }
    }

    pub fn run_fixture(f: ShieldFixture) {
        main(f.mint_amount, f.out_commitment, f.tx_binding_hash, f.out_note);
    }

    #[test]
    fn test_valid_shield() {
        run_fixture(build_valid_fixture());
    }

    #[test]
    fn test_u64_max_shield() {
        let mut f = build_valid_fixture();
        let max_u64: u64 = 18446744073709551615;
        f.mint_amount = max_u64;
        f.out_note.value = max_u64;
        f.out_commitment = compute_note_commitment(f.out_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Mint amount must be positive")]
    fn test_zero_mint_amount_fails() {
        let mut f = build_valid_fixture();
        f.mint_amount = 0;
        f.out_note.value = 0;
        f.out_commitment = compute_note_commitment(f.out_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Minted value mismatch")]
    fn test_mint_value_mismatch_fails() {
        let mut f = build_valid_fixture();
        f.out_note.value += 1;
        f.out_commitment = compute_note_commitment(f.out_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Point not on Grumpkin curve")]
    fn test_off_curve_owner_pk_fails() {
        let mut f = build_valid_fixture();
        f.out_note.owner_pk_y += 1;
        f.out_commitment = compute_note_commitment(f.out_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Point cannot have y == 0")]
    fn test_zero_y_owner_pk_fails() {
        let mut f = build_valid_fixture();
        f.out_note.owner_pk_y = 0;
        f.out_commitment = compute_note_commitment(f.out_note);
        run_fixture(f);
    }

    #[test(should_fail_with = "Missing tx_binding_hash")]
    fn test_zero_tx_binding_hash_fails() {
        let mut f = build_valid_fixture();
        f.tx_binding_hash = 0;
        run_fixture(f);
    }

    #[test(should_fail_with = "Invalid output commitment")]
    fn test_wrong_out_commitment_fails() {
        let mut f = build_valid_fixture();
        f.out_commitment += 1;
        run_fixture(f);
    }
}

