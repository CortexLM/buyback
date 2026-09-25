#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

pub mod chain;
pub mod config;
pub mod engine;
pub mod error;
#[cfg(feature = "http")]
pub mod http;
pub mod keys;
pub mod recovery;
pub mod state;
pub mod store;
pub mod units;
#[cfg(feature = "webhook")]
pub mod webhook;

pub use chain::{Chain, ChainCall, Network};
pub use config::{AutoAmount, AutoBuyback, Config, Destroy};
pub use engine::{Action, CreatePayment, Engine};
pub use error::{Error, Result};
pub use keys::{MasterKey, PaymentWallet, TreasuryKeySource};
pub use state::{BuybackReceipt, PaymentRequest, PaymentState, PaymentStatus, TxRef};
#[cfg(feature = "sqlite")]
pub use store::SqliteStore;
pub use store::{FileStore, Store, open_store};
