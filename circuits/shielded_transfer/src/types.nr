pub global MERKLE_DEPTH: u32 = 32;

// Domain separation constants for Poseidon2 hash contexts
pub global DOMAIN_NK: Field = 1;
pub global DOMAIN_IVK: Field = 2;
pub global DOMAIN_DIVERSIFIER: Field = 3;
pub global DOMAIN_NOTE_COMMITMENT: Field = 4;
pub global DOMAIN_NULLIFIER: Field = 5;
pub global DOMAIN_MERKLE_NODE: Field = 6;
pub global DOMAIN_SUPPLY_MINT_BURN: Field = 7;

// Grumpkin curve equation over BN254 scalar field: y^2 = x^3 - 17
pub global GRUMPKIN_NEG_B: Field = 17;

pub struct Note {
    pub value: u64,
    pub owner_pk_x: Field,
    pub owner_pk_y: Field,
    pub blinding: Field,
}

