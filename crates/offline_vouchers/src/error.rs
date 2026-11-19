use ledger_core::LedgerError;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VoucherError {
    #[error("invalid ECDSA signature")]
    InvalidSignature,
    #[error("non-canonical high-S ECDSA signature rejected")]
    NonCanonicalHighS,
    #[error("invalid compressed P-256 public key")]
    InvalidPublicKey,
    #[error("unsupported voucher format version: {0}")]
    InvalidVersion(u16),
    #[error("untrusted vendor attestation CA: {0}")]
    UntrustedVendorCa(String),
    #[error("hardware attestation expired")]
    AttestationExpired,
    #[error("hardware attestation not yet valid")]
    AttestationNotYetValid,
    #[error("hardware attestation certificate serial is revoked")]
    CertificateRevoked,
    #[error("pocket is permanently revoked due to hardware compromise or equivocation")]
    PocketRevoked,
    #[error("pocket not registered")]
    PocketNotFound,
    #[error("pocket has been cooperatively closed")]
    PocketClosed,
    #[error("pocket is in uncooperative drain cooldown")]
    PocketDraining,
    #[error("pocket is not in draining state")]
    PocketNotDraining,
    #[error("drain cooldown still active until {unlock_at} (now={now})")]
    DrainCooldownActive { unlock_at: u64, now: u64 },
    #[error("chain_id mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u64, got: u64 },
    #[error("pocket_id does not match derived hash of chain_id and device_pk")]
    PocketIdMismatch,
    #[error("device_pk mismatch against registered pocket")]
    DeviceKeyMismatch,
    #[error("pocket cap exceeded: requested {requested}, max {cap}")]
    CapExceeded { requested: u128, cap: u64 },
    #[error("invalid pocket policy: {0}")]
    InvalidPolicy(String),
    #[error("insufficient pocket escrow balance: requested {requested}, available {available}")]
    InsufficientPocketBalance { requested: u64, available: u64 },
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("invalid monotonic counter {0}")]
    InvalidCounter(u64),
    #[error("cumulative_spent regressed below prior counter spend")]
    CumulativeSpentRegression,
    #[error("voucher expired at {expires_at} (now={now})")]
    VoucherExpired { expires_at: u64, now: u64 },
    #[error("voucher issued in future beyond skew limit ({issued_at} vs now={now})")]
    VoucherNotYetValid { issued_at: u64, now: u64 },
    #[error("voucher TTL exceeds policy maximum")]
    VoucherTtlTooLong,
    #[error("voucher final holder does not match expected recipient_pk")]
    RecipientMismatch,
    #[error("voucher hop count {hops} exceeds allowed max {max_hops}")]
    HopLimitExceeded { hops: usize, max_hops: usize },
    #[error("invalid hop endorsement chain: {0}")]
    InvalidHopChain(String),
    #[error("voucher counter {0} already settled (replay rejected)")]
    VoucherAlreadySettled(u64),
    #[error("hardware equivocation detected at counter {counter}")]
    EquivocationDetected { counter: u64 },
    #[error("invalid equivocation fraud proof")]
    InvalidEquivocationProof,
    #[error("transaction tx_binding_hash mismatch")]
    TxBindingHashMismatch,
    #[error("settlement mint_amount mismatch: expected {expected}, got {got}")]
    SettlementAmountMismatch { expected: u64, got: u64 },
    #[error("cooperative close final_cumulative_spent below already settled amount")]
    CloseSpentRegression,
    #[error("insufficient victim compensation pool: requested {requested}, available {available}")]
    InsufficientVictimCompensation { requested: u64, available: u128 },
    #[error("wire codec error: {0}")]
    WireError(String),
    #[error("offline transport error: {0}")]
    TransportError(String),
    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),
}

