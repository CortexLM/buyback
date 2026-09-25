use crate::state::PaymentState;

/// Crate error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("chain: {0}")]
    Chain(String),
    #[error("store: {0}")]
    Store(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("config: {0}")]
    Config(String),
    #[error("invalid state transition {from:?} -> {to:?}")]
    InvalidTransition {
        from: PaymentState,
        to: PaymentState,
    },
    #[error("payment {0} not found")]
    NotFound(String),
    #[error("concurrent update of payment {0}")]
    Conflict(String),
    #[error("insufficient funds: {0}")]
    Insufficient(String),
    #[error("expected event {0} not found in finalized block")]
    EventMissing(&'static str),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub(crate) fn chain_err(e: impl std::fmt::Display) -> Error {
    Error::Chain(e.to_string())
}
