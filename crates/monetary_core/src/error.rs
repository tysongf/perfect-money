use ledger_core::LedgerError;
use thiserror::Error;

/// Errors returned by the fixed-point monetary, oracle, and vault state machines.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum MonetaryError {
    #[error("division by zero")]
    DivisionByZero,
    #[error("fixed-point math overflow")]
    MathOverflow,
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("invalid basket weights: {0}")]
    InvalidBasketWeights(String),
    #[error("basket weight shift for {asset} ({delta}) exceeds constitutional cap {max_shift}")]
    WeightShiftExceedsCap {
        asset: String,
        delta: u128,
        max_shift: u128,
    },
    #[error("non-positive price for asset {0}")]
    NonPositivePrice(String),
    #[error("unexpected oracle phase: expected {expected}, got {actual}")]
    UnexpectedOraclePhase {
        expected: &'static str,
        actual: String,
    },
    #[error("oracle round {0} is already active")]
    RoundAlreadyActive(u64),
    #[error("oracle round is already disputed")]
    RoundAlreadyDisputed,
    #[error("dispute bond {provided} is below minimum {minimum}")]
    DisputeBondTooLow { provided: u128, minimum: u128 },
    #[error("invalid reveal commitment or non-positive price")]
    InvalidRevealCommitment,
    #[error("cannot compute weighted median of empty or zero-weight set")]
    EmptyWeightedMedian,
    #[error("unknown collateral branch: {0}")]
    UnknownBranch(String),
    #[error("unknown vault: {0}")]
    UnknownVault(String),
    #[error("vault owner or branch mismatch")]
    VaultOwnerOrBranchMismatch,
    #[error("borrow rate {rate} is below minimum floor {floor}")]
    BorrowRateBelowFloor { rate: u128, floor: u128 },
    #[error("collateral ratio {cr} for branch {branch} is below minimum {mcr}")]
    CollateralRatioBelowMcr {
        branch: String,
        cr: u128,
        mcr: u128,
    },
    #[error("insufficient {kind}: requested {requested}, available {available}")]
    InsufficientBalance {
        kind: &'static str,
        requested: u128,
        available: u128,
    },
    #[error("monetary conservation invariant violated: {0}")]
    ConservationViolation(String),
    #[error("ledger bridge error: {0}")]
    Ledger(#[from] LedgerError),
}

