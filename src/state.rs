//! Payment record and its persistent state machine.
//!
//! ```text
//! pending ──► detected ──► funded ──► swept ──► settled
//!    │            │           │          │
//!    ▼            └───────────┴──────────┴──► failed ──(retry)──► state it failed in
//! expired ──(force_sweep)──► detected
//! ```
//! Every transition is persisted with an optimistic version check before the next chain action.

use crate::keys::SealedSecret;
use crate::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentState {
    /// Waiting for at least the minimum amount on the deposit address.
    Pending,
    /// Minimum reached; treasury is about to send fee TAO.
    Detected,
    /// Deposit wallet holds enough TAO for its sweep fees.
    Funded,
    /// All alpha moved to the treasury coldkey.
    Swept,
    /// Consolidated, dust returned, callbacks fired. Terminal.
    Settled,
    /// Gave up after `max_attempts`; `retry` resumes. Terminal until retried.
    Failed,
    /// Expired below the minimum. `force_sweep` collects any partial payment.
    Expired,
}

impl PaymentState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Detected => "detected",
            Self::Funded => "funded",
            Self::Swept => "swept",
            Self::Settled => "settled",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }

    /// States the watcher keeps driving.
    pub fn is_active(self) -> bool {
        matches!(
            self,
            Self::Pending | Self::Detected | Self::Funded | Self::Swept
        )
    }

    pub fn can_transition(self, to: Self) -> bool {
        use PaymentState::*;
        matches!(
            (self, to),
            (Pending, Detected | Expired | Failed)
                | (Detected, Funded | Failed)
                | (Funded, Swept | Failed)
                | (Swept, Settled | Failed)
                | (Failed, Detected | Funded | Swept)
                | (Expired, Detected)
        )
    }
}

/// Receipt of one finalized extrinsic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRef {
    pub action: String,
    pub tx_hash: String,
    pub block_hash: String,
    pub amount: u64,
}

/// Result of a buyback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuybackReceipt {
    pub netuid: u16,
    pub tao_spent: u64,
    pub alpha_bought: u64,
    pub limit_price: u64,
    pub stake_tx: TxRef,
    /// `burn_alpha` or `recycle_alpha` tx, when requested.
    pub destroy_tx: Option<TxRef>,
    pub alpha_destroyed: u64,
}

/// Explicit additional treasury capital, snapshotted when the job is created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuybackBudget {
    pub amount_rao: u64,
    pub currency: String,
    pub source: String,
    pub netuid: u16,
    pub destroy: crate::config::Destroy,
    pub hotkey: String,
}
impl BuybackBudget {
    pub fn validate(&self) -> Result<()> {
        crate::keys::parse_ss58(&self.hotkey)?;
        if (self.netuid == 0 && self.destroy != crate::config::Destroy::Keep)
            || self.amount_rao < crate::engine::MIN_STAKE_RAO
            || self.currency != "TAO"
            || self.source.trim().is_empty()
            || self.source.len() > 128
        {
            return Err(Error::Config(
                "explicit TAO buyback budget/source required".into(),
            ));
        }
        Ok(())
    }
}

/// Immutable execution identity; absent on legacy records, never inferred during resume.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobIdentity {
    pub genesis_hash: String,
    pub treasury: String,
    pub treasury_hotkey: String,
    pub consolidate: bool,
    pub return_dust: bool,
}

/// Full persisted record. Contains the sealed wallet secret: never return it to clients, use
/// [`PaymentStatus`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentRecord {
    pub id: String,
    pub address: String,
    pub netuid: u16,
    pub min_alpha: u64,
    pub min_tao: Option<u64>,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: PaymentState,
    /// Optimistic-concurrency version, bumped on every write.
    pub version: u64,
    pub sealed_secret: SealedSecret,
    pub metadata: Option<serde_json::Value>,
    pub callback_url: Option<String>,
    pub detected_alpha: u64,
    pub detected_tao: u64,
    pub funded_tao: u64,
    pub swept_alpha: u64,
    pub txs: Vec<TxRef>,
    pub buyback: Option<BuybackReceipt>,
    #[serde(default)]
    pub buyback_budget: Option<BuybackBudget>,
    /// None identifies legacy jobs requiring explicit migration.
    #[serde(default)]
    pub auto_required: Option<bool>,
    #[serde(default)]
    pub identity: Option<JobIdentity>,
    pub attempts: u32,
    pub next_attempt_at: u64,
    pub last_error: Option<String>,
    pub failed_from: Option<PaymentState>,
    /// Extrinsic journaled *before* broadcast. While set, no new action is taken for this record
    /// until the pending one is proven included or dead (see `Engine::resolve_pending`).
    pub pending: Option<crate::chain::PendingTx>,
    /// Finalized intent with unexpected events; explicit repair required, never retry blindly.
    #[serde(default)]
    pub quarantined: Option<crate::chain::PendingTx>,
    /// `(hotkey ss58, alpha)` positions moved to the treasury coldkey by the sweep.
    pub swept_positions: Vec<(String, u64)>,
    /// How many of `swept_positions` were moved onto the treasury hotkey.
    pub consolidated: usize,
    pub dust_returned: bool,
    /// Requested auto-buyback completed with a validated receipt.
    pub buyback_done: bool,
    pub notified: bool,
    pub updated_at: u64,
    /// Hard derivation path of a deterministic wallet (`//opentype//deposit//7`). When set the
    /// engine derives the key from its seed; `sealed_secret` is a backup copy.
    #[serde(default)]
    pub derivation_path: Option<String>,
}

impl PaymentRecord {
    /// Move to `to`, checking the transition table.
    pub fn transition(&mut self, to: PaymentState) -> Result<()> {
        // A failed record may only resume the step it failed in.
        let resume_ok = self.state != PaymentState::Failed
            || self.failed_from == Some(to)
            || (self.failed_from == Some(PaymentState::Pending) && to == PaymentState::Detected);
        if !self.state.can_transition(to) || !resume_ok {
            return Err(Error::InvalidTransition {
                from: self.state,
                to,
            });
        }
        if to == PaymentState::Failed {
            self.failed_from = Some(self.state);
        }
        self.state = to;
        self.attempts = 0;
        self.next_attempt_at = 0;
        if to != PaymentState::Failed {
            self.last_error = None;
        }
        Ok(())
    }

    /// Record a failed attempt; after `max_attempts` the record goes to `Failed`.
    /// Backoff: 5 s * 2^attempts, capped at 10 min.
    pub fn record_failure(&mut self, err: &str, max_attempts: u32, now: u64) {
        self.attempts += 1;
        self.last_error = Some(err.chars().take(500).collect());
        self.next_attempt_at = now + (5u64 << self.attempts.min(7)).min(600);
        if self.attempts >= max_attempts && self.state.can_transition(PaymentState::Failed) {
            self.failed_from = Some(self.state);
            self.state = PaymentState::Failed;
        }
    }

    pub fn status(&self) -> PaymentStatus {
        PaymentStatus {
            id: self.id.clone(),
            address: self.address.clone(),
            netuid: self.netuid,
            min_alpha: self.min_alpha,
            min_tao: self.min_tao,
            created_at: self.created_at,
            expires_at: self.expires_at,
            state: self.state,
            detected_alpha: self.detected_alpha,
            detected_tao: self.detected_tao,
            funded_tao: self.funded_tao,
            swept_alpha: self.swept_alpha,
            txs: self.txs.clone(),
            buyback: self.buyback.clone(),
            last_error: self.last_error.clone(),
            metadata: self.metadata.clone(),
        }
    }
}

/// Public view of a payment (no secrets).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PaymentStatus {
    pub id: String,
    pub address: String,
    pub netuid: u16,
    pub min_alpha: u64,
    pub min_tao: Option<u64>,
    pub created_at: u64,
    pub expires_at: u64,
    pub state: PaymentState,
    pub detected_alpha: u64,
    pub detected_tao: u64,
    pub funded_tao: u64,
    pub swept_alpha: u64,
    pub txs: Vec<TxRef>,
    pub buyback: Option<BuybackReceipt>,
    pub last_error: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// What a client gets back from `create_payment`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub id: String,
    /// SS58 (prefix 42) coldkey to `transfer_stake` alpha to.
    pub address: String,
    pub netuid: u16,
    /// Minimum alpha, in rao (1 alpha = 1e9).
    pub min_alpha: u64,
    /// Minimum TAO in rao, when TAO payments are accepted.
    pub min_tao: Option<u64>,
    /// Unix seconds.
    pub expires_at: u64,
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn test_record(id: &str) -> PaymentRecord {
    PaymentRecord {
        id: id.into(),
        address: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".into(),
        netuid: 1,
        min_alpha: 1_000_000_000,
        min_tao: None,
        created_at: 0,
        expires_at: 100,
        state: PaymentState::Pending,
        version: 0,
        sealed_secret: SealedSecret {
            v: 1,
            nonce: "00".into(),
            ct: "00".into(),
            kid: None,
        },
        metadata: None,
        callback_url: None,
        detected_alpha: 0,
        detected_tao: 0,
        funded_tao: 0,
        swept_alpha: 0,
        txs: vec![],
        buyback: None,
        buyback_budget: None,
        auto_required: Some(false),
        identity: None,
        attempts: 0,
        next_attempt_at: 0,
        last_error: None,
        failed_from: None,
        pending: None,
        quarantined: None,
        swept_positions: vec![],
        consolidated: 0,
        dust_returned: false,
        buyback_done: false,
        notified: false,
        updated_at: 0,
        derivation_path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::PaymentState::*;
    use super::*;

    const ALL: [PaymentState; 7] = [Pending, Detected, Funded, Swept, Settled, Failed, Expired];

    #[test]
    fn happy_path() {
        let mut r = test_record("a");
        for s in [Detected, Funded, Swept, Settled] {
            r.transition(s).unwrap();
        }
        assert_eq!(r.state, Settled);
        assert!(!r.state.is_active());
    }

    #[test]
    fn no_skipping_or_going_back() {
        let mut r = test_record("a");
        assert!(r.transition(Funded).is_err());
        assert!(r.transition(Swept).is_err());
        assert!(r.transition(Settled).is_err());
        r.transition(Detected).unwrap();
        assert!(r.transition(Pending).is_err());
        assert!(r.transition(Detected).is_err(), "no self loops");
    }

    #[test]
    fn settled_is_final() {
        for to in ALL {
            assert!(!Settled.can_transition(to), "{to:?}");
        }
    }

    #[test]
    fn sweep_happens_exactly_once_per_path() {
        // Swept can only be entered from Funded (or a retry of a failure that happened in Swept's
        // predecessor); there is no path Swept -> ... -> Funded, so the sweep step cannot re-run
        // after success.
        let mut reach = std::collections::HashSet::new();
        let mut stack = vec![Swept];
        while let Some(s) = stack.pop() {
            for to in ALL {
                // Failed only resumes its own step (checked on the record, below).
                if s != Failed && s.can_transition(to) && reach.insert(to) {
                    stack.push(to);
                }
            }
        }
        assert!(!reach.contains(&Funded));
        assert!(!reach.contains(&Detected));

        let mut r = test_record("a");
        for s in [Detected, Funded, Swept] {
            r.transition(s).unwrap();
        }
        r.transition(Failed).unwrap();
        assert!(r.transition(Funded).is_err());
        assert!(r.transition(Detected).is_err());
        r.transition(Swept).unwrap();
    }

    #[test]
    fn failures_back_off_then_fail_then_retry() {
        let mut r = test_record("a");
        r.transition(Detected).unwrap();
        r.transition(Funded).unwrap();
        r.record_failure("boom", 3, 1000);
        assert_eq!((r.state, r.attempts, r.next_attempt_at), (Funded, 1, 1010));
        r.record_failure("boom", 3, 1000);
        assert_eq!(r.next_attempt_at, 1020);
        r.record_failure("boom", 3, 1000);
        assert_eq!(r.state, Failed);
        assert_eq!(r.failed_from, Some(Funded));
        r.transition(Funded).unwrap();
        assert_eq!((r.attempts, r.last_error.as_deref()), (0, None));
    }

    #[test]
    fn expiry_and_force_sweep() {
        let mut r = test_record("a");
        r.transition(Expired).unwrap();
        assert!(!r.state.is_active());
        r.transition(Detected).unwrap();
    }
}
