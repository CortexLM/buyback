//! The payment engine: creates payment wallets, watches the chain, sweeps, settles and buys back.
//!
//! # Restart safety and no double spend
//! Every extrinsic is **journaled before broadcast**: the engine builds and signs the transaction,
//! writes `{action, signer, nonce, tx_hash, birth_block}` to [`PaymentRecord::pending`] with a
//! compare-and-swap on the record version, and only then submits it. While `pending` is set, the
//! record takes no new action. After a crash, a timeout or an RPC error, the pending entry is
//! resolved against finalized chain state ([`Chain::find_pending`]):
//! * our tx hash found in finalized blocks: apply its events (success or dispatch failure);
//! * complete finalized scan proves absence after the mortality window: drop and rebuild;
//! * otherwise: wait.
//!
//! Treasury funding and buybacks are therefore sent at most once per step, and the sweep moves
//! only the stake that is live in the wallet at build time (a replay fails on chain with
//! `NotEnoughStakeToWithdraw`, it cannot move funds twice).

use crate::chain::{
    Chain, ChainCall, EventSummary, FinalizedTx, PendingOutcome, PendingTx, PreparedTx,
};
use crate::config::{AutoBuyback, Config, Destroy};
use crate::keys::{self, DerivationSeed, Keyring, PaymentWallet};
use crate::state::{
    BuybackReceipt, PaymentRecord, PaymentRequest, PaymentState, PaymentStatus, TxRef, now,
};
use crate::store::Store;
use crate::units;
use crate::{Error, Result};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use subxt::utils::AccountId32;
use subxt_signer::sr25519::Keypair;
use tokio::sync::{Mutex, broadcast};

/// Why a journaled extrinsic was sent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Action {
    /// Treasury -> payment wallet, fee TAO.
    Fund,
    /// Payment wallet -> treasury coldkey, `transfer_stake` of the position on `hotkey`.
    Sweep { hotkey: String },
    /// Treasury `move_stake` from `hotkey` to the treasury hotkey.
    Consolidate { hotkey: String },
    /// Payment wallet `transfer_all` back to the treasury.
    ReturnDust,
    /// Treasury `add_stake_limit` (auto buyback).
    BuyStake { netuid: u16, limit_price: u64 },
    /// Treasury `burn_alpha` / `recycle_alpha` (auto buyback).
    Destroy { netuid: u16, recycle: bool },
}

/// Options for [`Engine::create_payment`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CreatePayment {
    /// Override the configured minimum alpha (rao).
    pub min_alpha: Option<u64>,
    /// Override expiry (seconds from now).
    pub expiry_secs: Option<u64>,
    /// Opaque data echoed back in status and callbacks (e.g. your order id).
    pub metadata: Option<serde_json::Value>,
    /// Webhook for this payment (needs the `webhook` feature).
    pub callback_url: Option<String>,
}

pub struct Engine<C = Chain> {
    chain: C,
    store: Arc<dyn Store>,
    keyring: Arc<Keyring>,
    /// Root of deterministic wallets; records with a `derivation_path` are opened from it.
    seed: Option<Arc<DerivationSeed>>,
    treasury: Keypair,
    cfg: Config,
    treasury_lock: Mutex<()>,
    events: broadcast::Sender<PaymentStatus>,
    #[cfg(feature = "webhook")]
    webhook: Option<crate::webhook::Webhook>,
}

impl<C: EngineRpc> Engine<C> {
    pub fn new(
        chain: C,
        store: Arc<dyn Store>,
        keyring: impl Into<Keyring>,
        treasury: Keypair,
        cfg: Config,
    ) -> Self {
        Self {
            chain,
            store,
            keyring: Arc::new(keyring.into()),
            seed: None,
            treasury,
            cfg,
            treasury_lock: Mutex::new(()),
            events: broadcast::channel(256).0,
            #[cfg(feature = "webhook")]
            webhook: None,
        }
    }

    /// Open records that carry a `derivation_path` from this seed instead of their sealed copy.
    pub fn with_seed(mut self, seed: Arc<DerivationSeed>) -> Self {
        self.seed = Some(seed);
        self
    }

    /// Sign webhook bodies with this secret (HMAC-SHA256, header `X-Buyback-Signature`).
    #[cfg(feature = "webhook")]
    pub fn with_webhook_secret(mut self, secret: impl Into<Vec<u8>>) -> Self {
        self.webhook = Some(crate::webhook::Webhook::new(secret.into()));
        self
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn chain(&self) -> &C {
        &self.chain
    }

    pub fn treasury_account(&self) -> AccountId32 {
        self.treasury.public_key().to_account_id()
    }

    /// In-process callback: every settlement (and failure/expiry) is broadcast here.
    pub fn subscribe(&self) -> broadcast::Receiver<PaymentStatus> {
        self.events.subscribe()
    }

    // ------------------------------------------------------------------ requests

    /// Create a payment request backed by a brand-new wallet.
    pub async fn create_payment(&self, opts: CreatePayment) -> Result<PaymentRequest> {
        self.store.require_signing().await?;
        let wallet = PaymentWallet::generate()?;
        let id = uuid::Uuid::new_v4().to_string();
        let address = keys::ss58(&wallet.account_id());
        let sealed = wallet.seal_with(&self.keyring, &keys::wallet_aad(&id, &address))?;
        drop(wallet);
        let t = now();
        let rec = PaymentRecord {
            id: id.clone(),
            address: address.clone(),
            netuid: self.cfg.netuid,
            min_alpha: opts.min_alpha.unwrap_or(self.cfg.min_alpha),
            min_tao: self.cfg.min_tao,
            created_at: t,
            expires_at: t + opts.expiry_secs.unwrap_or(self.cfg.expiry_secs),
            state: PaymentState::Pending,
            version: 0,
            sealed_secret: sealed,
            metadata: opts.metadata,
            callback_url: opts.callback_url.or_else(|| self.cfg.webhook_url.clone()),
            detected_alpha: 0,
            detected_tao: 0,
            funded_tao: 0,
            swept_alpha: 0,
            txs: vec![],
            buyback: None,
            buyback_budget: self.cfg.buyback_budget.clone(),
            auto_required: Some(self.cfg.buyback_budget.is_some()),
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
            updated_at: t,
            derivation_path: None,
        };
        if matches!(self.cfg.auto, AutoBuyback::On { .. }) && rec.buyback_budget.is_none() {
            return Err(Error::Config("explicit job buyback budget required".into()));
        }
        if let Some(budget) = &rec.buyback_budget {
            budget.validate()?;
        }
        self.store.insert(&rec).await?;
        tracing::info!(id = %id, address = %address, "payment request created");
        Ok(PaymentRequest {
            id,
            address,
            netuid: rec.netuid,
            min_alpha: rec.min_alpha,
            min_tao: rec.min_tao,
            expires_at: rec.expires_at,
        })
    }

    /// Sweep everything on `netuid` held by the deterministic wallet at `derivation_path` (a
    /// permanent deposit address). The job starts in `detected`: the treasury funds fees, the
    /// wallet `transfer_stake`s every position to the treasury, then consolidation, dust return
    /// and the auto buyback run as for a payment. Each step is journaled, so a crash or a retry
    /// never sends twice.
    ///
    /// `id` must be unique; the caller keeps at most one open job per address. Fails unless the
    /// seed derives exactly `expected_address`.
    pub async fn create_sweep_job(
        &self,
        id: &str,
        derivation_path: &str,
        expected_address: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<PaymentStatus> {
        self.store.require_signing().await?;
        let seed = self
            .seed
            .as_ref()
            .ok_or_else(|| Error::Config("sweep jobs need a derivation seed".into()))?;
        let wallet = seed.wallet(derivation_path)?;
        let address = keys::ss58(&wallet.account_id());
        if address != expected_address {
            return Err(Error::Crypto(
                "derived address does not match the expected one".into(),
            ));
        }
        // A sealed copy is kept as well; the seed stays authoritative.
        let sealed = wallet.seal_with(&self.keyring, &keys::wallet_aad(id, &address))?;
        drop(wallet);
        let t = now();
        let rec = PaymentRecord {
            id: id.into(),
            address,
            netuid: self.cfg.netuid,
            min_alpha: 0,
            min_tao: None,
            created_at: t,
            expires_at: u64::MAX,
            state: PaymentState::Detected,
            version: 0,
            sealed_secret: sealed,
            metadata,
            callback_url: None,
            detected_alpha: 0,
            detected_tao: 0,
            funded_tao: 0,
            swept_alpha: 0,
            txs: vec![],
            buyback: None,
            buyback_budget: self.cfg.buyback_budget.clone(),
            auto_required: Some(self.cfg.buyback_budget.is_some()),
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
            updated_at: t,
            derivation_path: Some(derivation_path.into()),
        };
        if matches!(self.cfg.auto, AutoBuyback::On { .. }) && rec.buyback_budget.is_none() {
            return Err(Error::Config("explicit job buyback budget required".into()));
        }
        if let Some(budget) = &rec.buyback_budget {
            budget.validate()?;
        }
        self.store.insert(&rec).await?;
        tracing::info!(id, address = %rec.address, "sweep job created");
        Ok(rec.status())
    }

    pub async fn status(&self, id: &str) -> Result<PaymentStatus> {
        self.store
            .get(id)
            .await?
            .map(|r| r.status())
            .ok_or_else(|| Error::NotFound(id.into()))
    }

    /// Resume a `failed` payment from the step it failed in.
    pub async fn retry(&self, id: &str) -> Result<PaymentStatus> {
        let mut r = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(id.into()))?;
        if r.quarantined.is_some() {
            return Err(Error::Store(
                "finalized receipt mismatch requires explicit repair".into(),
            ));
        }
        let to = match r.failed_from {
            Some(PaymentState::Pending) | None => PaymentState::Detected,
            Some(s) => s,
        };
        r.transition(to)?;
        Ok(self.store.update(&r).await?.status())
    }

    /// Sweep an `expired` payment that received less than the minimum.
    pub async fn force_sweep(&self, id: &str) -> Result<PaymentStatus> {
        let mut r = self
            .store
            .get(id)
            .await?
            .ok_or_else(|| Error::NotFound(id.into()))?;
        r.transition(PaymentState::Detected)?;
        Ok(self.store.update(&r).await?.status())
    }

    // ------------------------------------------------------------------ driver

    /// Follow finalized blocks forever, driving every open payment on each one. Reconnects on
    /// stream errors.
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.chain.finalized_blocks().await {
                Ok(mut blocks) => {
                    while let Some(b) = blocks.next().await {
                        match b {
                            Ok(n) => {
                                tracing::debug!(block = n, "finalized");
                                if let Err(e) = self.tick().await {
                                    tracing::warn!(error = %e, "tick failed");
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "block stream error");
                                break;
                            }
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "subscribe failed"),
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
    }

    /// One pass over all open payments. Returns how many were advanced.
    pub async fn tick(&self) -> Result<usize> {
        use PaymentState::*;
        let recs = self
            .store
            .list(&[Pending, Detected, Funded, Swept, Settled, Failed])
            .await?;
        let t = now();
        let mut n = 0;
        // Batch the balance reads of pending payments into one runtime-API call.
        let pending: Vec<AccountId32> = recs
            .iter()
            .filter(|r| r.state == Pending && r.pending.is_none())
            .filter_map(|r| keys::parse_ss58(&r.address).ok())
            .collect();
        let positions = if pending.is_empty() {
            Default::default()
        } else {
            self.chain.stake_positions_many(&pending).await?
        };
        for r in recs {
            if r.pending.is_none()
                && (r.state == Failed || r.state == Settled && r.notified || r.next_attempt_at > t)
            {
                continue;
            }
            let id = r.id.clone();
            match self.step(r, &positions).await {
                Ok(true) => n += 1,
                Ok(false) => {}
                Err(Error::Conflict(_)) => tracing::debug!(id, "concurrent update, skipping"),
                Err(e) => tracing::warn!(id, error = %e, "step failed"),
            }
        }
        Ok(n)
    }

    /// Advance one payment by at most one chain action. Returns whether anything changed.
    async fn step(
        &self,
        mut r: PaymentRecord,
        positions: &std::collections::BTreeMap<AccountId32, Vec<crate::chain::StakePosition>>,
    ) -> Result<bool> {
        if r.quarantined.is_some() {
            return Ok(false);
        }
        if r.pending.is_none()
            && (r.auto_required.is_none()
                || (r.auto_required == Some(true) && r.buyback_budget.is_none()))
        {
            return Err(Error::Config(
                "job policy migration required before processing".into(),
            ));
        }
        if let Some(p) = r.pending.clone() {
            return self.resolve_pending(r, p).await;
        }
        let res = match r.state {
            PaymentState::Pending => return self.step_pending(r, positions).await,
            PaymentState::Detected => self.step_detected(&mut r).await,
            PaymentState::Funded => self.step_funded(&mut r).await,
            PaymentState::Swept => self.step_swept(&mut r).await,
            PaymentState::Settled => return self.notify(r).await.map(|_| true),
            _ => return Ok(false),
        };
        match res {
            Ok(changed) => Ok(changed),
            Err(Error::Conflict(id)) => Err(Error::Conflict(id)),
            Err(e) => {
                // Re-read: the journaling write may have bumped the version.
                let mut cur = self
                    .store
                    .get(&r.id)
                    .await?
                    .ok_or_else(|| Error::NotFound(r.id.clone()))?;
                // An uncertain broadcast is not a failed economic action. Reconcile first.
                if cur.pending.is_some() {
                    return Err(e);
                }
                cur.record_failure(&e.to_string(), self.cfg.max_attempts, now());
                let cur = self.store.update(&cur).await?;
                self.announce_if_final(&cur);
                Err(e)
            }
        }
    }

    async fn step_pending(
        &self,
        mut r: PaymentRecord,
        positions: &std::collections::BTreeMap<AccountId32, Vec<crate::chain::StakePosition>>,
    ) -> Result<bool> {
        let who = keys::parse_ss58(&r.address)?;
        let alpha: u64 = positions
            .get(&who)
            .map(|v| {
                v.iter()
                    .filter(|p| p.netuid == r.netuid)
                    .map(|p| p.alpha)
                    .sum()
            })
            .unwrap_or(0);
        let tao = if r.min_tao.is_some() {
            self.chain.free_balance(&who).await?
        } else {
            0
        };
        let tao_ok = r.min_tao.is_some_and(|m| tao >= m);
        if alpha >= r.min_alpha || tao_ok {
            r.detected_alpha = alpha;
            r.detected_tao = if tao_ok { tao } else { 0 };
            r.transition(PaymentState::Detected)?;
            tracing::info!(id = %r.id, alpha, tao, "payment detected");
            self.store.update(&r).await?;
            return Ok(true);
        }
        if now() > r.expires_at {
            r.detected_alpha = alpha;
            r.transition(PaymentState::Expired)?;
            let r = self.store.update(&r).await?;
            self.announce_if_final(&r);
            return Ok(true);
        }
        Ok(false)
    }

    /// Detected: send the payment wallet exactly the fee TAO it needs.
    async fn step_detected(&self, r: &mut PaymentRecord) -> Result<bool> {
        let wallet = self.wallet(r)?;
        let who = wallet.account_id();
        let (alpha, pos) = self.chain.alpha_on(&who, r.netuid).await?;
        let (free, _) = self.chain.account(&who).await?;
        r.detected_alpha = r.detected_alpha.max(alpha);
        let treasury = self.treasury_account();
        let mut fees = 0u64;
        let floor = self.sweep_floor(r.netuid).await?;
        for p in pos.iter().filter(|p| p.alpha >= floor) {
            let call = ChainCall::TransferStake {
                dest_coldkey: treasury,
                hotkey: p.hotkey,
                netuid: r.netuid,
                alpha: p.alpha,
            };
            fees = fees.saturating_add(self.chain.estimate_fee(&call, wallet.keypair()).await?);
        }
        let ed = self.chain.existential_deposit().await?;
        // A TAO payment pays its own fees; alpha-only wallets need funding.
        let need = if pos.is_empty() {
            0
        } else {
            units::funding_needed(fees, self.cfg.fee_margin_bps, ed, free)
        };
        if need == 0 {
            r.transition(PaymentState::Funded)?;
            *r = self.store.update(r).await?;
            return Ok(true);
        }
        let call = ChainCall::TransferTao {
            dest: who,
            amount: need,
        };
        let signer = self.treasury.clone();
        let _g = self.treasury_lock.lock().await;
        self.send(r, Action::Fund, &call, &signer).await
    }

    /// Funded: move every alpha position on the payment netuid to the treasury coldkey.
    async fn step_funded(&self, r: &mut PaymentRecord) -> Result<bool> {
        let wallet = self.wallet(r)?;
        let (_, pos) = self.chain.alpha_on(&wallet.account_id(), r.netuid).await?;
        let floor = self.sweep_floor(r.netuid).await?;
        // Each hotkey position is swept once: a staked position keeps earning emissions, and
        // chasing them would never terminate. What accrues after the sweep stays as dust.
        let done: Vec<&str> = r.swept_positions.iter().map(|(h, _)| h.as_str()).collect();
        let Some(p) = pos
            .into_iter()
            .find(|p| p.alpha >= floor && !done.contains(&keys::ss58(&p.hotkey).as_str()))
        else {
            r.transition(PaymentState::Swept)?;
            *r = self.store.update(r).await?;
            tracing::info!(id = %r.id, alpha = r.swept_alpha, "swept");
            return Ok(true);
        };
        let call = ChainCall::TransferStake {
            dest_coldkey: self.treasury_account(),
            hotkey: p.hotkey,
            netuid: r.netuid,
            alpha: p.alpha,
        };
        let action = Action::Sweep {
            hotkey: keys::ss58(&p.hotkey),
        };
        self.send(r, action, &call, wallet.keypair()).await
    }

    /// Swept: consolidate onto the treasury hotkey, return dust, auto-buyback, then settle.
    async fn step_swept(&self, r: &mut PaymentRecord) -> Result<bool> {
        let treasury = self.treasury_account();
        // 1. consolidate
        if self.cfg.consolidate {
            while r.consolidated < r.swept_positions.len() {
                let hk = keys::parse_ss58(&r.swept_positions[r.consolidated].0)?;
                let live = if hk == self.cfg.treasury_hotkey {
                    0
                } else {
                    self.chain.alpha_of(&hk, &treasury, r.netuid).await?
                };
                if live == 0 {
                    r.consolidated += 1;
                    *r = self.store.update(r).await?;
                    continue;
                }
                let call = ChainCall::MoveStake {
                    from_hotkey: hk,
                    to_hotkey: self.cfg.treasury_hotkey,
                    netuid: r.netuid,
                    alpha: live,
                };
                let signer = self.treasury.clone();
                let _g = self.treasury_lock.lock().await;
                return self
                    .send(
                        r,
                        Action::Consolidate {
                            hotkey: keys::ss58(&hk),
                        },
                        &call,
                        &signer,
                    )
                    .await;
            }
        }
        // 2. dust / TAO payment back to the treasury
        if !r.dust_returned && (self.cfg.return_dust || r.detected_tao > 0) {
            let wallet = self.wallet(r)?;
            let free = self.chain.free_balance(&wallet.account_id()).await?;
            if free > 0 {
                let call = ChainCall::TransferAll { dest: treasury };
                return self
                    .send(r, Action::ReturnDust, &call, wallet.keypair())
                    .await;
            }
            r.dust_returned = true;
        }
        // 3. automatic buyback
        let required = r
            .auto_required
            .ok_or_else(|| Error::Config("legacy job policy requires explicit migration".into()))?;
        if required && r.buyback_budget.is_none() {
            return Err(Error::Config("required job budget missing".into()));
        }
        if required && r.buyback_done {
            validate_completed_buyback(r)?;
        }
        if !r.buyback_done
            && (r.buyback_budget.is_some() || matches!(self.cfg.auto, AutoBuyback::On { .. }))
        {
            return self.step_auto_buyback(r).await;
        }
        r.transition(PaymentState::Settled)?;
        *r = self.store.update(r).await?;
        tracing::info!(id = %r.id, "settled");
        let rec = r.clone();
        self.notify(rec).await?;
        Ok(true)
    }

    async fn step_auto_buyback(&self, r: &mut PaymentRecord) -> Result<bool> {
        let budget = r
            .buyback_budget
            .clone()
            .ok_or_else(|| Error::Config("job has no explicit buyback budget; blocked".into()))?;
        budget.validate()?;
        let netuid = budget.netuid;
        let destroy = budget.destroy;
        // second half: destroy what was bought
        if let Some(b) = &r.buyback {
            if b.tao_spent != budget.amount_rao || b.netuid != budget.netuid {
                return Err(Error::Store(
                    "purchase receipt disagrees with job budget".into(),
                ));
            }
            if b.alpha_bought == 0 {
                return Err(Error::Insufficient(
                    "buyback produced no alpha; completion blocked".into(),
                ));
            }
            if b.destroy_tx.is_some() && b.alpha_destroyed != b.alpha_bought {
                return Err(Error::Store(
                    "incomplete burn receipt; completion blocked".into(),
                ));
            }
            if destroy == Destroy::Keep || b.destroy_tx.is_some() {
                r.buyback_done = true;
                *r = self.store.update(r).await?;
                return Ok(true);
            }
            let call = destroy_call(
                destroy,
                keys::parse_ss58(&budget.hotkey)?,
                netuid,
                b.alpha_bought,
            );
            let signer = self.treasury.clone();
            let _g = self.treasury_lock.lock().await;
            let action = Action::Destroy {
                netuid,
                recycle: destroy == Destroy::Recycle,
            };
            return self.send(r, action, &call, &signer).await;
        }
        let _g = self.treasury_lock.lock().await;
        let tao = strict_buyback_amount(budget.amount_rao, self.spendable().await?)?;
        let limit_price =
            units::buy_limit_price(self.chain.alpha_price(netuid).await?, self.cfg.slippage_bps);
        let call = ChainCall::AddStakeLimit {
            hotkey: keys::parse_ss58(&budget.hotkey)?,
            netuid,
            tao,
            limit_price,
            allow_partial: false,
        };
        let signer = self.treasury.clone();
        self.send(
            r,
            Action::BuyStake {
                netuid,
                limit_price,
            },
            &call,
            &signer,
        )
        .await
    }

    /// Smallest position worth sweeping: `sweep_dust`, and at least 1.5x the chain minimum stake
    /// (0.002 TAO) converted to alpha at spot, below which `transfer_stake` fails `AmountTooLow`.
    async fn sweep_floor(&self, netuid: u16) -> Result<u64> {
        let price = self.chain.alpha_price(netuid).await?.max(1);
        let min_alpha =
            (MIN_STAKE_RAO as u128 * 3 / 2 * units::RAO_PER_TAO as u128 / price as u128) as u64;
        Ok(self.cfg.sweep_dust.max(min_alpha))
    }

    /// Journal, submit, wait for finalization, apply.
    async fn send(
        &self,
        r: &mut PaymentRecord,
        action: Action,
        call: &ChainCall,
        signer: &Keypair,
    ) -> Result<bool> {
        send_journaled(&self.chain, self.store.as_ref(), r, action, call, signer).await
    }

    async fn resolve_pending(&self, mut r: PaymentRecord, p: PendingTx) -> Result<bool> {
        let changed = reconcile_journaled(
            &self.chain,
            self.store.as_ref(),
            &mut r,
            &p,
            self.cfg.max_attempts,
        )
        .await?;
        if changed {
            self.announce_if_final(&r);
        }
        Ok(changed)
    }

    fn apply(r: &mut PaymentRecord, tx: TxRef, s: &EventSummary) -> Result<()> {
        let action = r
            .pending
            .take()
            .map(|p| p.action)
            .ok_or_else(|| Error::Store("apply without pending".into()))?;
        match &action {
            Action::Fund => {
                r.funded_tao += tx.amount;
                r.transition(PaymentState::Funded)?;
            }
            Action::Sweep { hotkey } => {
                if !s.has(crate::chain::PALLET, "StakeTransferred") {
                    return Err(Error::EventMissing("StakeTransferred"));
                }
                r.swept_alpha += tx.amount;
                r.swept_positions.push((hotkey.clone(), tx.amount));
            }
            Action::Consolidate { .. } => r.consolidated += 1,
            Action::ReturnDust => r.dust_returned = true,
            Action::BuyStake {
                netuid,
                limit_price,
            } => {
                let (tao, alpha) = s.stake_added.ok_or(Error::EventMissing("StakeAdded"))?;
                if tao != tx.amount || alpha == 0 {
                    return Err(Error::Store(
                        "purchase does not match full requested budget".into(),
                    ));
                }
                r.buyback = Some(BuybackReceipt {
                    netuid: *netuid,
                    tao_spent: tao,
                    alpha_bought: alpha,
                    limit_price: *limit_price,
                    stake_tx: tx.clone(),
                    destroy_tx: None,
                    alpha_destroyed: 0,
                });
            }
            Action::Destroy { .. } => {
                let destroyed = s
                    .alpha_destroyed
                    .ok_or(Error::EventMissing("AlphaBurned/AlphaRecycled"))?;
                let b = r
                    .buyback
                    .as_mut()
                    .ok_or_else(|| Error::Store("burn without purchase receipt".into()))?;
                if destroyed != b.alpha_bought || destroyed == 0 {
                    return Err(Error::Store(
                        "burn amount does not match purchased alpha".into(),
                    ));
                }
                b.destroy_tx = Some(tx.clone());
                b.alpha_destroyed = destroyed;
                r.buyback_done = true;
            }
        }
        r.attempts = 0;
        r.next_attempt_at = 0;
        r.last_error = None;
        r.txs.push(tx);
        Ok(())
    }

    fn wallet(&self, r: &PaymentRecord) -> Result<PaymentWallet> {
        let w = match (&r.derivation_path, &self.seed) {
            (Some(path), Some(seed)) => seed.wallet(path)?,
            _ => PaymentWallet::unseal_with(
                &self.keyring,
                &r.sealed_secret,
                &keys::wallet_aad(&r.id, &r.address),
            )?,
        };
        if keys::ss58(&w.account_id()) != r.address {
            return Err(Error::Crypto("sealed wallet does not match address".into()));
        }
        Ok(w)
    }

    fn announce_if_final(&self, r: &PaymentRecord) {
        if matches!(r.state, PaymentState::Failed | PaymentState::Expired) {
            let _ = self.events.send(r.status());
        }
    }

    async fn notify(&self, r: PaymentRecord) -> Result<()> {
        let st = r.status();
        let _ = self.events.send(st.clone());
        #[cfg(feature = "webhook")]
        if let (Some(url), Some(w)) = (&r.callback_url, &self.webhook)
            && let Err(e) = w.post(url, &st).await
        {
            tracing::warn!(id = %r.id, error = %e, "webhook failed; will retry");
            let mut cur = r;
            cur.next_attempt_at = now() + 30;
            self.store.update(&cur).await?;
            return Ok(());
        }
        let mut cur = r;
        cur.notified = true;
        self.store.update(&cur).await?;
        Ok(())
    }

    // ------------------------------------------------------------------ buybacks

    /// Make sure `treasury_hotkey` exists on chain and is owned by the treasury coldkey, creating
    /// it with `try_associate_hotkey` if needed. Staking, `move_stake` and `burn_alpha` all fail
    /// with `HotKeyAccountNotExists` otherwise. Call once at startup.
    pub async fn ensure_treasury_hotkey(&self) -> Result<()> {
        let hk = &self.cfg.treasury_hotkey;
        match self.chain.hotkey_owner(hk).await? {
            Some(o) if o == self.treasury_account() => Ok(()),
            Some(o) => {
                // Staking to a hotkey you do not own works but delegates to its owner (take
                // applies) and `burn_alpha` still works; warn loudly rather than fail.
                tracing::warn!(hotkey = %keys::ss58(hk), owner = %keys::ss58(&o), "treasury hotkey is owned by another coldkey");
                Ok(())
            }
            None => {
                let _g = self.treasury_lock.lock().await;
                let call = ChainCall::AssociateHotkey { hotkey: *hk };
                self.chain.submit(&call, &self.treasury).await?;
                tracing::info!(hotkey = %keys::ss58(hk), "treasury hotkey associated");
                Ok(())
            }
        }
    }

    /// Treasury TAO available to `buyback_all`: free minus `fee_reserve` minus existential deposit.
    pub async fn spendable(&self) -> Result<u64> {
        let free = self.chain.free_balance(&self.treasury_account()).await?;
        Ok(units::spendable(
            free,
            self.cfg.fee_reserve,
            self.chain.existential_deposit().await?,
        ))
    }

    /// Spend `amount_tao` rao of treasury TAO on alpha of `buyback_netuid` (default 100) with
    /// `add_stake_limit` at `spot * (1 + slippage)`. The alpha stays staked to the treasury hotkey.
    pub async fn buyback(&self, amount_tao: u64) -> Result<BuybackReceipt> {
        self.buyback_with(amount_tao, Destroy::Keep).await
    }

    /// [`Self::buyback`] then `burn_alpha` of exactly the alpha bought.
    pub async fn buyback_and_burn(&self, amount_tao: u64) -> Result<BuybackReceipt> {
        self.buyback_with(amount_tao, Destroy::Burn).await
    }

    /// [`Self::buyback`] then `recycle_alpha` of exactly the alpha bought.
    pub async fn buyback_and_recycle(&self, amount_tao: u64) -> Result<BuybackReceipt> {
        self.buyback_with(amount_tao, Destroy::Recycle).await
    }

    /// Buy back with the whole spendable treasury balance.
    pub async fn buyback_all(&self, destroy: Destroy) -> Result<BuybackReceipt> {
        let amount = self.spendable().await?;
        self.buyback_with(amount, destroy).await
    }

    /// Standalone buyback. Not journaled: on an error the caller must check the treasury's
    /// stake/balance (e.g. `buyback status`) before retrying.
    pub async fn buyback_with(&self, amount_tao: u64, destroy: Destroy) -> Result<BuybackReceipt> {
        let _g = self.treasury_lock.lock().await;
        let netuid = self.cfg.buyback_netuid;
        let spendable = self.spendable().await?;
        if amount_tao == 0 || amount_tao > spendable {
            return Err(Error::Insufficient(format!(
                "buyback of {} TAO, spendable {} TAO (fee reserve {})",
                units::format_amount(amount_tao),
                units::format_amount(spendable),
                units::format_amount(self.cfg.fee_reserve)
            )));
        }
        let price = self.chain.alpha_price(netuid).await?;
        let limit_price = units::buy_limit_price(price, self.cfg.slippage_bps);
        let hotkey = self.cfg.treasury_hotkey;
        let buy = ChainCall::AddStakeLimit {
            hotkey,
            netuid,
            tao: amount_tao,
            limit_price,
            allow_partial: self.cfg.allow_partial,
        };
        let f = self.chain.submit(&buy, &self.treasury).await?;
        let (tao_spent, alpha_bought) = f
            .summary
            .stake_added
            .ok_or(Error::EventMissing("StakeAdded"))?;
        let mut receipt = BuybackReceipt {
            netuid,
            tao_spent,
            alpha_bought,
            limit_price,
            stake_tx: f.tx,
            destroy_tx: None,
            alpha_destroyed: 0,
        };
        if destroy != Destroy::Keep && alpha_bought > 0 {
            let call = destroy_call(destroy, hotkey, netuid, alpha_bought);
            let d = self.chain.submit(&call, &self.treasury).await?;
            receipt.alpha_destroyed = d
                .summary
                .alpha_destroyed
                .ok_or(Error::EventMissing("AlphaBurned"))?;
            receipt.destroy_tx = Some(d.tx);
        }
        tracing::info!(?receipt, "buyback done");
        Ok(receipt)
    }
}

/// Subtensor `DefaultMinStake` (0.002 TAO) on current runtimes; smaller stakes fail `AmountTooLow`.
pub const MIN_STAKE_RAO: u64 = 2_000_000;

fn destroy_call(destroy: Destroy, hotkey: AccountId32, netuid: u16, alpha: u64) -> ChainCall {
    match destroy {
        Destroy::Recycle => ChainCall::RecycleAlpha {
            hotkey,
            netuid,
            alpha,
        },
        _ => ChainCall::BurnAlpha {
            hotkey,
            netuid,
            alpha,
        },
    }
}

fn action_name(a: &Action) -> &'static str {
    match a {
        Action::Fund => "transfer_keep_alive",
        Action::Sweep { .. } => "transfer_stake",
        Action::Consolidate { .. } => "move_stake",
        Action::ReturnDust => "transfer_all",
        Action::BuyStake { .. } => "add_stake_limit",
        Action::Destroy { recycle: true, .. } => "recycle_alpha",
        Action::Destroy { .. } => "burn_alpha",
    }
}

/// Engine transport, injectable for offline state-machine tests.
#[async_trait::async_trait]
pub trait EngineRpc: TransactionRpc {
    async fn free_balance(&self, who: &AccountId32) -> Result<u64>;
    async fn account(&self, who: &AccountId32) -> Result<(u64, u32)>;
    async fn alpha_on(
        &self,
        who: &AccountId32,
        netuid: u16,
    ) -> Result<(u64, Vec<crate::chain::StakePosition>)>;
    async fn alpha_of(
        &self,
        hotkey: &AccountId32,
        coldkey: &AccountId32,
        netuid: u16,
    ) -> Result<u64>;
    async fn estimate_fee(&self, call: &ChainCall, signer: &Keypair) -> Result<u64>;
    async fn existential_deposit(&self) -> Result<u64>;
    async fn alpha_price(&self, netuid: u16) -> Result<u64>;
    async fn hotkey_owner(&self, hotkey: &AccountId32) -> Result<Option<AccountId32>>;
    async fn stake_positions_many(
        &self,
        coldkeys: &[AccountId32],
    ) -> Result<std::collections::BTreeMap<AccountId32, Vec<crate::chain::StakePosition>>>;
    async fn submit(&self, call: &ChainCall, signer: &Keypair) -> Result<FinalizedTx>;
    async fn finalized_blocks(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Result<u64>> + Send>>>;
}
#[async_trait::async_trait]
impl EngineRpc for Chain {
    async fn free_balance(&self, who: &AccountId32) -> Result<u64> {
        Chain::free_balance(self, who).await
    }
    async fn account(&self, who: &AccountId32) -> Result<(u64, u32)> {
        Chain::account(self, who).await
    }
    async fn alpha_on(
        &self,
        who: &AccountId32,
        netuid: u16,
    ) -> Result<(u64, Vec<crate::chain::StakePosition>)> {
        Chain::alpha_on(self, who, netuid).await
    }
    async fn alpha_of(
        &self,
        hotkey: &AccountId32,
        coldkey: &AccountId32,
        netuid: u16,
    ) -> Result<u64> {
        Chain::alpha_of(self, hotkey, coldkey, netuid).await
    }
    async fn estimate_fee(&self, call: &ChainCall, signer: &Keypair) -> Result<u64> {
        Chain::estimate_fee(self, call, signer).await
    }
    async fn existential_deposit(&self) -> Result<u64> {
        Chain::existential_deposit(self).await
    }
    async fn alpha_price(&self, netuid: u16) -> Result<u64> {
        Chain::alpha_price(self, netuid).await
    }
    async fn hotkey_owner(&self, hotkey: &AccountId32) -> Result<Option<AccountId32>> {
        Chain::hotkey_owner(self, hotkey).await
    }
    async fn stake_positions_many(
        &self,
        coldkeys: &[AccountId32],
    ) -> Result<std::collections::BTreeMap<AccountId32, Vec<crate::chain::StakePosition>>> {
        Chain::stake_positions_many(self, coldkeys).await
    }
    async fn submit(&self, call: &ChainCall, signer: &Keypair) -> Result<FinalizedTx> {
        Chain::submit(self, call, signer).await
    }
    async fn finalized_blocks(
        &self,
    ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Result<u64>> + Send>>> {
        Ok(Box::pin(Chain::finalized_blocks(self).await?))
    }
}
/// Narrow transaction seam; tests supply no network client or live signer.
#[async_trait::async_trait]
pub trait TransactionRpc: Send + Sync {
    async fn prepare(&self, call: &ChainCall, signer: &Keypair) -> Result<PreparedTx>;
    async fn broadcast(&self, tx: &PreparedTx) -> Result<FinalizedTx>;
    async fn find_pending(&self, tx: &PendingTx) -> Result<PendingOutcome>;
}
#[async_trait::async_trait]
impl TransactionRpc for Chain {
    async fn prepare(&self, call: &ChainCall, signer: &Keypair) -> Result<PreparedTx> {
        Chain::prepare(self, call, signer).await
    }
    async fn broadcast(&self, tx: &PreparedTx) -> Result<FinalizedTx> {
        Chain::broadcast(self, tx).await
    }
    async fn find_pending(&self, tx: &PendingTx) -> Result<PendingOutcome> {
        Chain::find_pending(self, tx).await
    }
}
async fn send_journaled(
    rpc: &dyn TransactionRpc,
    store: &dyn Store,
    r: &mut PaymentRecord,
    action: Action,
    call: &ChainCall,
    signer: &Keypair,
) -> Result<bool> {
    if r.pending.is_some() {
        return Err(Error::Store(
            "reconcile pending transaction before preparing another".into(),
        ));
    }
    let signer_address = keys::ss58(&signer.public_key().to_account_id());
    let reservation = store.reserve_signer_for_record(&signer_address, r).await?;
    // A crash or prepare error leaves an orphan reservation: never expire it automatically.
    let prepared = rpc.prepare(call, signer).await?;
    if prepared.signer != signer_address {
        return Err(Error::Store("prepared signer mismatch".into()));
    }
    let mut journal = r.clone();
    journal.pending = Some(PendingTx {
        action,
        reservation: Some(reservation),
        signer: prepared.signer.clone(),
        nonce: prepared.nonce,
        tx_hash: prepared.tx_hash.clone(),
        birth_block: prepared.birth_block,
        amount: call.amount(),
    });
    *r = store.update(&journal).await?;
    let finalized = rpc.broadcast(&prepared).await?;
    let mut applied = r.clone();
    Engine::<Chain>::apply(&mut applied, finalized.tx, &finalized.summary)?;
    *r = store.update(&applied).await?;
    Ok(true)
}
async fn reconcile_journaled(
    rpc: &dyn TransactionRpc,
    store: &dyn Store,
    r: &mut PaymentRecord,
    pending: &PendingTx,
    max_attempts: u32,
) -> Result<bool> {
    if r.pending.as_ref() != Some(pending) {
        return Err(Error::Store("pending journal mismatch".into()));
    }
    match rpc.find_pending(pending).await? {
        PendingOutcome::Wait => Ok(false),
        PendingOutcome::Dead => {
            let mut applied = r.clone();
            applied.pending = None;
            *r = store.update(&applied).await?;
            Ok(true)
        }
        PendingOutcome::Included {
            block_hash,
            summary,
        } => {
            let tx = TxRef {
                action: action_name(&pending.action).into(),
                tx_hash: pending.tx_hash.clone(),
                block_hash,
                amount: pending.amount,
            };
            let mut applied = r.clone();
            if summary.failed {
                applied.pending = None;
                applied.record_failure(
                    "journaled transaction failed on finalized chain",
                    max_attempts,
                    now(),
                );
            } else {
                if let Err(error) = Engine::<Chain>::apply(&mut applied, tx.clone(), &summary) {
                    applied = r.clone();
                    applied.pending = None;
                    applied.quarantined = Some(pending.clone());
                    applied.txs.push(tx);
                    applied.record_failure(
                        &format!("finalized receipt mismatch: {error}"),
                        1,
                        now(),
                    );
                }
            }
            *r = store.update(&applied).await?;
            Ok(true)
        }
    }
}

fn validate_completed_buyback(r: &PaymentRecord) -> Result<()> {
    let budget = r
        .buyback_budget
        .as_ref()
        .ok_or_else(|| Error::Store("missing job budget".into()))?;
    budget.validate()?;
    let receipt = r
        .buyback
        .as_ref()
        .ok_or_else(|| Error::Store("missing purchase receipt".into()))?;
    if receipt.tao_spent != budget.amount_rao
        || receipt.netuid != budget.netuid
        || receipt.alpha_bought == 0
        || receipt.stake_tx.block_hash.is_empty()
        || (budget.destroy != Destroy::Keep
            && (receipt.alpha_destroyed != receipt.alpha_bought
                || receipt.destroy_tx.as_ref().is_none_or(|tx| {
                    tx.block_hash.is_empty()
                        || tx.action
                            != if budget.destroy == Destroy::Burn {
                                "burn_alpha"
                            } else {
                                "recycle_alpha"
                            }
                })))
    {
        return Err(Error::Store("incomplete job buyback receipt".into()));
    }
    Ok(())
}

fn strict_buyback_amount(requested: u64, spendable: u64) -> Result<u64> {
    if requested < MIN_STAKE_RAO {
        return Err(Error::Insufficient(
            "buyback budget below minimum; blocked, not skipped".into(),
        ));
    }
    if requested > spendable {
        return Err(Error::Insufficient(
            "full buyback budget unavailable; no partial spend".into(),
        ));
    }
    Ok(requested)
}

#[cfg(test)]
mod strict_budget_tests {
    use super::*;
    #[test]
    fn no_silent_clamp_or_skipped_success() {
        assert!(strict_buyback_amount(0, u64::MAX).is_err());
        assert!(strict_buyback_amount(MIN_STAKE_RAO - 1, u64::MAX).is_err());
        assert!(strict_buyback_amount(MIN_STAKE_RAO, MIN_STAKE_RAO - 1).is_err());
        assert_eq!(
            strict_buyback_amount(MIN_STAKE_RAO, MIN_STAKE_RAO).unwrap(),
            MIN_STAKE_RAO
        );
        assert_eq!(
            strict_buyback_amount(MIN_STAKE_RAO, u64::MAX).unwrap(),
            MIN_STAKE_RAO
        );
    }
}

#[cfg(all(test, feature = "sqlite"))]
mod journal_rpc_tests {
    use super::*;
    use crate::{keys::MasterKey, store::SqliteStore};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct LostReply {
        broadcasts: AtomicUsize,
        summary: EventSummary,
        lookup: AtomicUsize,
        dead: bool,
    }
    #[async_trait::async_trait]
    impl TransactionRpc for LostReply {
        async fn prepare(&self, call: &ChainCall, signer: &Keypair) -> Result<PreparedTx> {
            Ok(PreparedTx {
                call: call.clone(),
                signer: keys::ss58(&signer.public_key().to_account_id()),
                nonce: 7,
                tx_hash: format!("hash-{}", self.broadcasts.load(Ordering::SeqCst)),
                birth_block: 100,
                bytes: vec![],
            })
        }
        async fn broadcast(&self, _: &PreparedTx) -> Result<FinalizedTx> {
            self.broadcasts.fetch_add(1, Ordering::SeqCst);
            Err(Error::Chain("connection lost after inclusion".into()))
        }
        async fn find_pending(&self, _: &PendingTx) -> Result<PendingOutcome> {
            if self.dead {
                return Ok(PendingOutcome::Dead);
            }
            match self.lookup.fetch_add(1, Ordering::SeqCst) {
                0 => return Err(Error::Chain("intermittent RPC".into())),
                1 => return Ok(PendingOutcome::Wait),
                _ => {}
            }
            Ok(PendingOutcome::Included {
                block_hash: "finalized-test-block".into(),
                summary: self.summary.clone(),
            })
        }
    }
    #[tokio::test]
    async fn durable_journal_recovers_lost_replies_without_rebroadcast() {
        let dir = std::env::temp_dir().join(format!("buyback-journal-{}", uuid::Uuid::new_v4()));
        let store = SqliteStore::open(&dir).unwrap();
        let wallet = PaymentWallet::generate().unwrap();
        let sealed = wallet
            .seal_with(&MasterKey::generate().into(), b"test")
            .unwrap();
        let mut rec:PaymentRecord=serde_json::from_value(serde_json::json!({
            "id":"simulation","address":keys::ss58(&wallet.account_id()),"netuid":100,
            "min_alpha":0,"min_tao":null,"created_at":1,"expires_at":9999999999u64,
            "state":"detected","version":0,"sealed_secret":sealed,"metadata":null,"callback_url":null,
            "detected_alpha":0,"detected_tao":0,"funded_tao":0,"swept_alpha":0,"txs":[],"buyback":null,
            "attempts":0,"next_attempt_at":0,"last_error":null,"failed_from":null,"pending":null,
            "swept_positions":[],"consolidated":0,"dust_returned":false,"buyback_done":false,"notified":false,"updated_at":1
        })).unwrap();
        store.insert(&rec).await.unwrap();
        let who = wallet.account_id();
        let steps = [
            (
                Action::Fund,
                ChainCall::TransferTao {
                    dest: who,
                    amount: 3_000_000,
                },
                EventSummary::default(),
            ),
            (
                Action::Sweep {
                    hotkey: keys::ss58(&who),
                },
                ChainCall::TransferStake {
                    dest_coldkey: who,
                    hotkey: who,
                    netuid: 100,
                    alpha: 10,
                },
                EventSummary {
                    names: vec![(crate::chain::PALLET.into(), "StakeTransferred".into())],
                    ..Default::default()
                },
            ),
            (
                Action::BuyStake {
                    netuid: 100,
                    limit_price: 1,
                },
                ChainCall::AddStakeLimit {
                    hotkey: who,
                    netuid: 100,
                    tao: MIN_STAKE_RAO,
                    limit_price: 1,
                    allow_partial: false,
                },
                EventSummary {
                    stake_added: Some((MIN_STAKE_RAO, 20)),
                    ..Default::default()
                },
            ),
            (
                Action::Destroy {
                    netuid: 100,
                    recycle: false,
                },
                ChainCall::BurnAlpha {
                    hotkey: who,
                    netuid: 100,
                    alpha: 20,
                },
                EventSummary {
                    alpha_destroyed: Some(20),
                    ..Default::default()
                },
            ),
        ];
        for (action, call, summary) in steps {
            let rpc = LostReply {
                broadcasts: AtomicUsize::new(0),
                summary,
                lookup: AtomicUsize::new(0),
                dead: false,
            };
            assert!(
                send_journaled(
                    &rpc,
                    &store,
                    &mut rec,
                    action.clone(),
                    &call,
                    wallet.keypair()
                )
                .await
                .is_err()
            );
            // A new store instance models process loss; only disk journal survives.
            let reopened = SqliteStore::open(&dir).unwrap();
            rec = reopened.get("simulation").await.unwrap().unwrap();
            let pending = rec.pending.clone().unwrap();
            assert_eq!(pending.action, action);
            assert_eq!(pending.tx_hash, "hash-0");
            assert!(
                send_journaled(&rpc, &reopened, &mut rec, action, &call, wallet.keypair())
                    .await
                    .is_err()
            );
            assert_eq!(rpc.broadcasts.load(Ordering::SeqCst), 1);
            let before = rec.version;
            assert!(
                reconcile_journaled(&rpc, &reopened, &mut rec, &pending, 8)
                    .await
                    .is_err()
            );
            assert!(
                !reconcile_journaled(&rpc, &reopened, &mut rec, &pending, 8)
                    .await
                    .unwrap()
            );
            assert_eq!(rec.version, before);
            assert_eq!(
                reopened.get("simulation").await.unwrap().unwrap().pending,
                Some(pending.clone())
            );
            assert!(
                reconcile_journaled(&rpc, &reopened, &mut rec, &pending, 8)
                    .await
                    .unwrap()
            );
            assert!(rec.pending.is_none());
            assert!(
                reconcile_journaled(&rpc, &reopened, &mut rec, &pending, 8)
                    .await
                    .is_err()
            );
            if rec.state == PaymentState::Funded && rec.swept_alpha > 0 {
                rec.transition(PaymentState::Swept).unwrap();
                rec = reopened.update(&rec).await.unwrap();
            }
        }
        assert_eq!(rec.txs.len(), 4);
        assert_eq!(rec.swept_alpha, 10);
        assert_eq!(rec.buyback.as_ref().unwrap().tao_spent, MIN_STAKE_RAO);
        assert_eq!(rec.buyback.as_ref().unwrap().alpha_destroyed, 20);
        assert!(rec.buyback_done);
        rec.transition(PaymentState::Settled).unwrap();
        store.update(&rec).await.unwrap();
        drop(store);
        std::fs::remove_file(dir).unwrap();
    }
    #[tokio::test]
    async fn stale_journal_cannot_broadcast() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("store.db")).unwrap();
        let mut rec = crate::state::test_record("stale");
        store.insert(&rec).await.unwrap();
        store.update(&rec).await.unwrap();
        let rpc = LostReply {
            broadcasts: AtomicUsize::new(0),
            summary: EventSummary::default(),
            lookup: AtomicUsize::new(2),
            dead: false,
        };
        let wallet = PaymentWallet::generate().unwrap();
        let call = ChainCall::TransferTao {
            dest: wallet.account_id(),
            amount: 1,
        };
        assert!(matches!(
            send_journaled(
                &rpc,
                &store,
                &mut rec,
                Action::Fund,
                &call,
                wallet.keypair()
            )
            .await,
            Err(Error::Conflict(_))
        ));
        assert_eq!(rpc.broadcasts.load(Ordering::SeqCst), 0);
        assert!(rec.pending.is_none());
        assert!(
            store
                .reserve_signer(&keys::ss58(&wallet.account_id()), "next")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn invalid_finalized_burn_quarantines_job_and_releases_signer() {
        let dir = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(dir.path().join("store.db")).unwrap();
        let mut rec = crate::state::test_record("burn");
        rec.state = PaymentState::Swept;
        let tx = TxRef {
            action: "add_stake_limit".into(),
            tx_hash: "buy".into(),
            block_hash: "block".into(),
            amount: MIN_STAKE_RAO,
        };
        rec.buyback = Some(BuybackReceipt {
            netuid: 100,
            tao_spent: MIN_STAKE_RAO,
            alpha_bought: 20,
            limit_price: 1,
            stake_tx: tx,
            destroy_tx: None,
            alpha_destroyed: 0,
        });
        let pending = PendingTx {
            action: Action::Destroy {
                netuid: 100,
                recycle: false,
            },
            reservation: Some(store.reserve_signer("test-only", "burn").await.unwrap()),
            signer: "test-only".into(),
            nonce: 1,
            tx_hash: "burn".into(),
            birth_block: 100,
            amount: 20,
        };
        rec.pending = Some(pending.clone());
        store.insert(&rec).await.unwrap();
        let rpc = LostReply {
            broadcasts: AtomicUsize::new(0),
            summary: EventSummary {
                alpha_destroyed: Some(19),
                ..Default::default()
            },
            lookup: AtomicUsize::new(2),
            dead: false,
        };
        assert!(
            reconcile_journaled(&rpc, &store, &mut rec, &pending, 8)
                .await
                .unwrap()
        );
        let stored = store.get("burn").await.unwrap().unwrap();
        assert!(stored.pending.is_none());
        assert_eq!(stored.quarantined, Some(pending));
        assert!(!stored.buyback_done);
        assert_eq!(stored.state, PaymentState::Failed);
        assert_eq!(stored.txs.len(), 1);
        assert!(
            store
                .reserve_signer("test-only", "another-job")
                .await
                .is_ok()
        );
        assert_eq!(rpc.broadcasts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn verified_dead_intent_releases_signer_without_completion() {
        let store = SqliteStore::in_memory().unwrap();
        let mut rec = crate::state::test_record("dead");
        let pending = PendingTx {
            action: Action::Fund,
            reservation: Some(store.reserve_signer("signer", "dead").await.unwrap()),
            signer: "signer".into(),
            nonce: 1,
            tx_hash: "dead-hash".into(),
            birth_block: 1,
            amount: 1,
        };
        rec.pending = Some(pending.clone());
        store.insert(&rec).await.unwrap();
        let rpc = LostReply {
            broadcasts: AtomicUsize::new(0),
            summary: EventSummary::default(),
            lookup: AtomicUsize::new(0),
            dead: true,
        };
        assert!(
            reconcile_journaled(&rpc, &store, &mut rec, &pending, 8)
                .await
                .unwrap()
        );
        assert!(rec.pending.is_none());
        assert!(!rec.buyback_done);
        assert!(store.reserve_signer("signer", "next").await.is_ok());
        assert_eq!(rpc.broadcasts.load(Ordering::SeqCst), 0);
    }
    struct SimulatedChain {
        broadcasts: AtomicUsize,
        hotkey: AccountId32,
        result: std::sync::Mutex<EventSummary>,
    }
    #[async_trait::async_trait]
    impl TransactionRpc for SimulatedChain {
        async fn prepare(&self, call: &ChainCall, signer: &Keypair) -> Result<PreparedTx> {
            let nonce = self.broadcasts.load(Ordering::SeqCst) as u64;
            Ok(PreparedTx {
                call: call.clone(),
                signer: keys::ss58(&signer.public_key().to_account_id()),
                nonce,
                tx_hash: format!("simulated-{nonce}"),
                birth_block: 100,
                bytes: vec![],
            })
        }
        async fn broadcast(&self, tx: &PreparedTx) -> Result<FinalizedTx> {
            self.broadcasts.fetch_add(1, Ordering::SeqCst);
            let mut summary = EventSummary::default();
            match &tx.call {
                ChainCall::TransferTao { .. } => {}
                ChainCall::TransferStake { .. } => summary
                    .names
                    .push((crate::chain::PALLET.into(), "StakeTransferred".into())),
                ChainCall::AddStakeLimit {
                    tao, allow_partial, ..
                } => {
                    assert!(!allow_partial);
                    summary.stake_added = Some((*tao, 20));
                }
                ChainCall::BurnAlpha { alpha, .. } => summary.alpha_destroyed = Some(*alpha),
                _ => panic!("unexpected simulated action"),
            }
            *self.result.lock().unwrap() = summary;
            Err(Error::Chain("simulated lost broadcast response".into()))
        }
        async fn find_pending(&self, _: &PendingTx) -> Result<PendingOutcome> {
            Ok(PendingOutcome::Included {
                block_hash: "simulated-finalized-block".into(),
                summary: self.result.lock().unwrap().clone(),
            })
        }
    }
    #[async_trait::async_trait]
    impl EngineRpc for Arc<SimulatedChain> {
        async fn free_balance(&self, _: &AccountId32) -> Result<u64> {
            Ok(1_000_000_000)
        }
        async fn account(&self, _: &AccountId32) -> Result<(u64, u32)> {
            Ok((0, 0))
        }
        async fn alpha_on(
            &self,
            _: &AccountId32,
            netuid: u16,
        ) -> Result<(u64, Vec<crate::chain::StakePosition>)> {
            Ok((
                1_000_000_000,
                vec![crate::chain::StakePosition {
                    hotkey: self.hotkey,
                    netuid,
                    alpha: 1_000_000_000,
                }],
            ))
        }
        async fn alpha_of(&self, _: &AccountId32, _: &AccountId32, _: u16) -> Result<u64> {
            panic!("consolidation disabled")
        }
        async fn estimate_fee(&self, _: &ChainCall, _: &Keypair) -> Result<u64> {
            Ok(100)
        }
        async fn existential_deposit(&self) -> Result<u64> {
            Ok(100)
        }
        async fn alpha_price(&self, _: u16) -> Result<u64> {
            Ok(1_000_000_000)
        }
        async fn hotkey_owner(&self, _: &AccountId32) -> Result<Option<AccountId32>> {
            panic!("no association")
        }
        async fn stake_positions_many(
            &self,
            _: &[AccountId32],
        ) -> Result<std::collections::BTreeMap<AccountId32, Vec<crate::chain::StakePosition>>>
        {
            panic!("starts at detected")
        }
        async fn submit(&self, _: &ChainCall, _: &Keypair) -> Result<FinalizedTx> {
            panic!("unjournaled submit prohibited")
        }
        async fn finalized_blocks(
            &self,
        ) -> Result<std::pin::Pin<Box<dyn futures::Stream<Item = Result<u64>> + Send>>> {
            panic!("test drives tick")
        }
    }
    #[async_trait::async_trait]
    impl TransactionRpc for Arc<SimulatedChain> {
        async fn prepare(&self, c: &ChainCall, s: &Keypair) -> Result<PreparedTx> {
            self.as_ref().prepare(c, s).await
        }
        async fn broadcast(&self, t: &PreparedTx) -> Result<FinalizedTx> {
            self.as_ref().broadcast(t).await
        }
        async fn find_pending(&self, t: &PendingTx) -> Result<PendingOutcome> {
            self.as_ref().find_pending(t).await
        }
    }
    #[tokio::test]
    async fn engine_ticks_complete_after_each_lost_response_and_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.db");
        let wallet = PaymentWallet::generate().unwrap();
        let treasury = PaymentWallet::generate().unwrap();
        let keyring: Keyring = MasterKey::from_bytes([42; 32]).into();
        let mut rec = crate::state::test_record("engine");
        rec.netuid = 100;
        rec.auto_required = Some(true);
        rec.address = keys::ss58(&wallet.account_id());
        rec.sealed_secret = wallet
            .seal_with(&keyring, &keys::wallet_aad(&rec.id, &rec.address))
            .unwrap();
        rec.state = PaymentState::Detected;
        rec.buyback_budget = Some(crate::state::BuybackBudget {
            amount_rao: MIN_STAKE_RAO,
            currency: "TAO".into(),
            source: "explicit-test-allocation".into(),
            hotkey: keys::ss58(&treasury.account_id()),
            netuid: 100,
            destroy: Destroy::Burn,
        });
        SqliteStore::open(&path)
            .unwrap()
            .insert(&rec)
            .await
            .unwrap();
        let rpc = Arc::new(SimulatedChain {
            broadcasts: AtomicUsize::new(0),
            hotkey: treasury.account_id(),
            result: std::sync::Mutex::new(EventSummary::default()),
        });
        let mut cfg = Config::new("unused", 100, treasury.account_id());
        cfg.consolidate = false;
        cfg.return_dust = false;
        // Runtime defaults deliberately differ: the persisted job budget wins.
        cfg.buyback_budget = None;
        for _ in 0..12 {
            let store = Arc::new(SqliteStore::open(&path).unwrap());
            let engine = Engine::new(
                rpc.clone(),
                store.clone(),
                MasterKey::from_bytes([42; 32]),
                treasury.keypair().clone(),
                cfg.clone(),
            );
            engine.tick().await.unwrap();
            rec = store.get("engine").await.unwrap().unwrap();
            if rec.state == PaymentState::Settled {
                break;
            }
        }
        assert_eq!(rec.state, PaymentState::Settled);
        assert!(rec.buyback_done);
        assert_eq!(rpc.broadcasts.load(Ordering::SeqCst), 4);
        assert_eq!(rec.txs.len(), 4);
        assert_eq!(rec.buyback.as_ref().unwrap().tao_spent, MIN_STAKE_RAO);
        assert_eq!(rec.buyback.as_ref().unwrap().alpha_destroyed, 20);
        assert!(rec.pending.is_none());
        let store = SqliteStore::open(&path).unwrap();
        assert!(
            store
                .reserve_signer(&keys::ss58(&treasury.account_id()), "next-job")
                .await
                .is_ok()
        );
        rec.buyback_budget.as_mut().unwrap().amount_rao += 1;
        assert!(store.update(&rec).await.is_err());
    }
}
