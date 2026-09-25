//! The payment engine: creates payment wallets, watches the chain, sweeps, settles and buys back.
//!
//! # Restart safety and no double spend
//! Every extrinsic is **journaled before broadcast**: the engine builds and signs the transaction,
//! writes `{action, signer, nonce, tx_hash, birth_block}` to [`PaymentRecord::pending`] with a
//! compare-and-swap on the record version, and only then submits it. While `pending` is set, the
//! record takes no new action. After a crash, a timeout or an RPC error, the pending entry is
//! resolved against finalized chain state ([`Chain::find_pending`]):
//! * nonce consumed by *our* tx hash: apply its events (success or dispatch failure);
//! * nonce not consumed and the tx's mortality window (64 blocks) has passed: it can never be
//!   included, so it is dropped and the step is rebuilt;
//! * otherwise: wait.
//!
//! Treasury funding and buybacks are therefore sent at most once per step, and the sweep moves
//! only the stake that is live in the wallet at build time (a replay fails on chain with
//! `NotEnoughStakeToWithdraw`, it cannot move funds twice).

use crate::chain::{Chain, ChainCall, EventSummary, PendingOutcome, PendingTx};
use crate::config::{AutoAmount, AutoBuyback, Config, Destroy};
use crate::keys::{self, MasterKey, PaymentWallet};
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

pub struct Engine {
    chain: Chain,
    store: Arc<dyn Store>,
    master: Arc<MasterKey>,
    treasury: Keypair,
    cfg: Config,
    treasury_lock: Mutex<()>,
    events: broadcast::Sender<PaymentStatus>,
    #[cfg(feature = "webhook")]
    webhook: Option<crate::webhook::Webhook>,
}

impl Engine {
    pub fn new(
        chain: Chain,
        store: Arc<dyn Store>,
        master: MasterKey,
        treasury: Keypair,
        cfg: Config,
    ) -> Self {
        Self {
            chain,
            store,
            master: Arc::new(master),
            treasury,
            cfg,
            treasury_lock: Mutex::new(()),
            events: broadcast::channel(256).0,
            #[cfg(feature = "webhook")]
            webhook: None,
        }
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

    pub fn chain(&self) -> &Chain {
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
    pub fn create_payment(&self, opts: CreatePayment) -> Result<PaymentRequest> {
        let wallet = PaymentWallet::generate()?;
        let id = uuid::Uuid::new_v4().to_string();
        let address = keys::ss58(&wallet.account_id());
        let sealed = wallet.seal(&self.master, &keys::wallet_aad(&id, &address))?;
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
            attempts: 0,
            next_attempt_at: 0,
            last_error: None,
            failed_from: None,
            pending: None,
            swept_positions: vec![],
            consolidated: 0,
            dust_returned: false,
            buyback_done: false,
            notified: false,
            updated_at: t,
        };
        self.store.insert(&rec)?;
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

    pub fn status(&self, id: &str) -> Result<PaymentStatus> {
        self.store
            .get(id)?
            .map(|r| r.status())
            .ok_or_else(|| Error::NotFound(id.into()))
    }

    /// Resume a `failed` payment from the step it failed in.
    pub fn retry(&self, id: &str) -> Result<PaymentStatus> {
        let mut r = self
            .store
            .get(id)?
            .ok_or_else(|| Error::NotFound(id.into()))?;
        let to = match r.failed_from {
            Some(PaymentState::Pending) | None => PaymentState::Detected,
            Some(s) => s,
        };
        r.transition(to)?;
        Ok(self.store.update(&r)?.status())
    }

    /// Sweep an `expired` payment that received less than the minimum.
    pub fn force_sweep(&self, id: &str) -> Result<PaymentStatus> {
        let mut r = self
            .store
            .get(id)?
            .ok_or_else(|| Error::NotFound(id.into()))?;
        r.transition(PaymentState::Detected)?;
        Ok(self.store.update(&r)?.status())
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
            .list(&[Pending, Detected, Funded, Swept, Settled])?;
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
            if r.state == Settled && r.notified || r.next_attempt_at > t {
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
                    .get(&r.id)?
                    .ok_or_else(|| Error::NotFound(r.id.clone()))?;
                cur.record_failure(&e.to_string(), self.cfg.max_attempts, now());
                let cur = self.store.update(&cur)?;
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
            self.store.update(&r)?;
            return Ok(true);
        }
        if now() > r.expires_at {
            r.detected_alpha = alpha;
            r.transition(PaymentState::Expired)?;
            let r = self.store.update(&r)?;
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
            *r = self.store.update(r)?;
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
            *r = self.store.update(r)?;
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
                    *r = self.store.update(r)?;
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
        if let (AutoBuyback::On { destroy, amount }, false) = (self.cfg.auto, r.buyback_done) {
            return self.step_auto_buyback(r, destroy, amount).await;
        }
        r.transition(PaymentState::Settled)?;
        *r = self.store.update(r)?;
        tracing::info!(id = %r.id, "settled");
        let rec = r.clone();
        self.notify(rec).await?;
        Ok(true)
    }

    async fn step_auto_buyback(
        &self,
        r: &mut PaymentRecord,
        destroy: Destroy,
        amount: AutoAmount,
    ) -> Result<bool> {
        let netuid = self.cfg.buyback_netuid;
        // second half: destroy what was bought
        if let Some(b) = &r.buyback {
            if destroy == Destroy::Keep || b.destroy_tx.is_some() || b.alpha_bought == 0 {
                r.buyback_done = true;
                *r = self.store.update(r)?;
                return Ok(true);
            }
            let call = destroy_call(destroy, self.cfg.treasury_hotkey, netuid, b.alpha_bought);
            let signer = self.treasury.clone();
            let _g = self.treasury_lock.lock().await;
            let action = Action::Destroy {
                netuid,
                recycle: destroy == Destroy::Recycle,
            };
            return self.send(r, action, &call, &signer).await;
        }
        let _g = self.treasury_lock.lock().await;
        let tao = match amount {
            AutoAmount::All => self.spendable().await?,
            AutoAmount::Fixed(v) => v,
            AutoAmount::PaymentValueBps(bps) => {
                let price = self.chain.alpha_price(r.netuid).await?;
                let value =
                    units::alpha_value_in_tao(r.swept_alpha, price).saturating_add(r.detected_tao);
                (value as u128 * bps as u128 / units::BPS as u128) as u64
            }
        };
        let tao = tao.min(self.spendable().await?);
        if tao < MIN_STAKE_RAO {
            tracing::warn!(id = %r.id, tao, "auto buyback skipped: amount below minimum stake");
            r.buyback_done = true;
            *r = self.store.update(r)?;
            return Ok(true);
        }
        let limit_price =
            units::buy_limit_price(self.chain.alpha_price(netuid).await?, self.cfg.slippage_bps);
        let call = ChainCall::AddStakeLimit {
            hotkey: self.cfg.treasury_hotkey,
            netuid,
            tao,
            limit_price,
            allow_partial: self.cfg.allow_partial,
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
        let signer_ss58 = keys::ss58(&signer.public_key().to_account_id());
        let store = &self.store;
        let amount = call.amount();
        let mut journaled: Option<PaymentRecord> = None;
        let res = self
            .chain
            .submit(call, signer, |nonce, tx_hash, birth_block| {
                let mut j = r.clone();
                j.pending = Some(PendingTx {
                    action: action.clone(),
                    signer: signer_ss58.clone(),
                    nonce,
                    tx_hash: tx_hash.into(),
                    birth_block,
                    amount,
                });
                journaled = Some(store.update(&j)?);
                Ok(())
            })
            .await;
        if let Some(j) = journaled {
            *r = j;
        }
        let ftx = res?;
        self.apply(r, ftx.tx, &ftx.summary)?;
        *r = self.store.update(r)?;
        Ok(true)
    }

    /// Resolve a journaled tx against finalized chain state.
    async fn resolve_pending(&self, mut r: PaymentRecord, p: PendingTx) -> Result<bool> {
        match self.chain.find_pending(&p).await? {
            PendingOutcome::Wait => Ok(false),
            PendingOutcome::Dead => {
                tracing::warn!(id = %r.id, tx = %p.tx_hash, "journaled tx expired unincluded; rebuilding step");
                r.pending = None;
                self.store.update(&r)?;
                Ok(true)
            }
            PendingOutcome::Included {
                block_hash,
                summary,
            } => {
                let tx = TxRef {
                    action: action_name(&p.action).into(),
                    tx_hash: p.tx_hash.clone(),
                    block_hash,
                    amount: p.amount,
                };
                if summary.failed {
                    r.pending = None;
                    r.record_failure(
                        &format!("{} failed on chain in {}", tx.action, tx.block_hash),
                        self.cfg.max_attempts,
                        now(),
                    );
                } else {
                    self.apply(&mut r, tx, &summary)?;
                }
                let r = self.store.update(&r)?;
                self.announce_if_final(&r);
                Ok(true)
            }
        }
    }

    /// Apply the effects of a successful journaled tx to the record.
    fn apply(&self, r: &mut PaymentRecord, tx: TxRef, s: &EventSummary) -> Result<()> {
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
                if let Some(b) = r.buyback.as_mut() {
                    b.destroy_tx = Some(tx.clone());
                    b.alpha_destroyed = destroyed;
                }
                r.buyback_done = true;
            }
        }
        r.attempts = 0;
        r.last_error = None;
        r.txs.push(tx);
        Ok(())
    }

    fn wallet(&self, r: &PaymentRecord) -> Result<PaymentWallet> {
        let w = PaymentWallet::unseal(
            &self.master,
            &r.sealed_secret,
            &keys::wallet_aad(&r.id, &r.address),
        )?;
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
            self.store.update(&cur)?;
            return Ok(());
        }
        let mut cur = r;
        cur.notified = true;
        self.store.update(&cur)?;
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
                self.chain
                    .submit(&call, &self.treasury, |_, _, _| Ok(()))
                    .await?;
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
        let f = self
            .chain
            .submit(&buy, &self.treasury, |_, _, _| Ok(()))
            .await?;
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
            let d = self
                .chain
                .submit(&call, &self.treasury, |_, _, _| Ok(()))
                .await?;
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
