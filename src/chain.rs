//! Thin, dynamic (metadata-driven) subtensor client built on `subxt`.
//!
//! No static codegen: every call is resolved against the metadata the node serves, and
//! [`Chain::verify_metadata`] fails fast if a call or event this crate relies on is missing or
//! has different argument names. Every write waits for finalization and checks for the expected
//! pallet event.
//!
//! Units: all amounts are `u64` rao. TAO balances are stored on chain as `u64` inside `u128`-like
//! `TaoBalance`; alpha as `AlphaBalance(u64)`. 1 TAO = 1 alpha = 1e9 rao.

use crate::error::chain_err;
use crate::state::TxRef;
use crate::{Error, Result};
use futures::StreamExt;
use scale_decode::DecodeAsType;
use serde::{Deserialize, Serialize};
use subxt::dynamic::{self, Value};
use subxt::utils::AccountId32;
use subxt::{OnlineClient, SubstrateConfig};
use subxt_signer::sr25519::Keypair;

pub type Client = OnlineClient<SubstrateConfig>;

pub const PALLET: &str = "SubtensorModule";

/// Calls this crate submits, with the argument names it expects (checked against metadata).
pub const REQUIRED_CALLS: &[(&str, &str, &[&str])] = &[
    ("Balances", "transfer_keep_alive", &["dest", "value"]),
    ("Balances", "transfer_all", &["dest", "keep_alive"]),
    (
        PALLET,
        "transfer_stake",
        &[
            "destination_coldkey",
            "hotkey",
            "origin_netuid",
            "destination_netuid",
            "alpha_amount",
        ],
    ),
    (
        PALLET,
        "move_stake",
        &[
            "origin_hotkey",
            "destination_hotkey",
            "origin_netuid",
            "destination_netuid",
            "alpha_amount",
        ],
    ),
    (
        PALLET,
        "add_stake_limit",
        &[
            "hotkey",
            "netuid",
            "amount_staked",
            "limit_price",
            "allow_partial",
        ],
    ),
    (PALLET, "burn_alpha", &["hotkey", "amount", "netuid"]),
    (PALLET, "recycle_alpha", &["hotkey", "amount", "netuid"]),
    (PALLET, "try_associate_hotkey", &["hotkey"]),
];

/// Events this crate asserts on.
pub const REQUIRED_EVENTS: &[(&str, &str)] = &[
    ("Balances", "Transfer"),
    (PALLET, "StakeTransferred"),
    (PALLET, "StakeMoved"),
    (PALLET, "StakeAdded"),
    (PALLET, "AlphaBurned"),
    (PALLET, "AlphaRecycled"),
];

/// Network presets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Network {
    Finney,
    Test,
    Local,
    Custom(String),
}

impl Network {
    pub fn url(&self) -> &str {
        match self {
            Self::Finney => "wss://entrypoint-finney.opentensor.ai:443",
            Self::Test => "wss://test.finney.opentensor.ai:443",
            Self::Local => "ws://127.0.0.1:9944",
            Self::Custom(u) => u,
        }
    }
}

impl std::str::FromStr for Network {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "finney" | "mainnet" => Self::Finney,
            "test" | "testnet" => Self::Test,
            "local" | "localnet" => Self::Local,
            u if u.starts_with("ws://") || u.starts_with("wss://") => Self::Custom(u.into()),
            _ => return Err(Error::Config(format!("unknown network {s:?}"))),
        })
    }
}

/// One stake position of a coldkey (from `StakeInfoRuntimeApi`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StakePosition {
    pub hotkey: AccountId32,
    pub netuid: u16,
    pub alpha: u64,
}

#[derive(DecodeAsType)]
struct RawStakeInfo {
    hotkey: AccountId32,
    netuid: u16,
    stake: u64,
}

#[derive(DecodeAsType)]
struct AccountInfo {
    nonce: u32,
    data: AccountData,
}
#[derive(DecodeAsType)]
struct AccountData {
    free: u64,
}

/// Numbers extracted from the events of one extrinsic.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventSummary {
    /// `(pallet, event)` names, in order.
    pub names: Vec<(String, String)>,
    /// `System.ExtrinsicFailed` seen.
    pub failed: bool,
    /// `StakeAdded`: (tao_in, alpha_out).
    pub stake_added: Option<(u64, u64)>,
    /// `AlphaBurned` / `AlphaRecycled` amount.
    pub alpha_destroyed: Option<u64>,
    /// `StakeTransferred` / `StakeMoved` TAO-equivalent amount.
    pub stake_moved_tao: Option<u64>,
    /// `Balances.Transfer` amount.
    pub transferred: Option<u64>,
}

impl EventSummary {
    pub fn has(&self, pallet: &str, name: &str) -> bool {
        self.names.iter().any(|(p, n)| p == pallet && n == name)
    }

    fn from_events<'a>(
        evs: impl Iterator<
            Item = std::result::Result<
                subxt::events::Event<'a, SubstrateConfig>,
                subxt::error::EventsError,
            >,
        >,
    ) -> Result<Self> {
        type A = AccountId32;
        let mut s = Self::default();
        for ev in evs {
            let ev = ev.map_err(chain_err)?;
            let (p, n) = (ev.pallet_name(), ev.event_name());
            match (p, n) {
                ("System", "ExtrinsicFailed") => s.failed = true,
                (PALLET, "StakeAdded") => {
                    let (_, _, tao, alpha, _, _) = ev
                        .decode_fields_unchecked_as::<(A, A, u64, u64, u16, u64)>()
                        .map_err(chain_err)?;
                    s.stake_added = Some((tao, alpha));
                }
                (PALLET, "AlphaBurned" | "AlphaRecycled") => {
                    let (_, _, amount, _) = ev
                        .decode_fields_unchecked_as::<(A, A, u64, u16)>()
                        .map_err(chain_err)?;
                    s.alpha_destroyed = Some(amount);
                }
                (PALLET, "StakeTransferred") => {
                    let f = ev
                        .decode_fields_unchecked_as::<(A, A, A, u16, u16, u64)>()
                        .map_err(chain_err)?;
                    s.stake_moved_tao = Some(f.5);
                }
                (PALLET, "StakeMoved") => {
                    let f = ev
                        .decode_fields_unchecked_as::<(A, A, u16, A, u16, u64)>()
                        .map_err(chain_err)?;
                    s.stake_moved_tao = Some(f.5);
                }
                ("Balances", "Transfer") => {
                    let (_, _, amount) = ev
                        .decode_fields_unchecked_as::<(A, A, u64)>()
                        .map_err(chain_err)?;
                    s.transferred = Some(s.transferred.unwrap_or(0) + amount);
                }
                _ => {}
            }
            s.names.push((p.to_string(), n.to_string()));
        }
        Ok(s)
    }
}

/// A finalized, successful extrinsic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedTx {
    pub tx: TxRef,
    pub summary: EventSummary,
}

/// Extrinsic journaled before broadcast (restart safety, see README).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTx {
    /// What the transaction does; decides how its result is applied.
    pub action: crate::engine::Action,
    pub signer: String,
    pub nonce: u64,
    pub tx_hash: String,
    /// Finalized block number the tx was built at; it is mortal for [`MORTALITY`] blocks.
    pub birth_block: u64,
    pub amount: u64,
}

/// Mortality (blocks) of every extrinsic we send. After `birth + MORTALITY` a tx that is not in
/// a finalized block can never be included.
pub const MORTALITY: u64 = 64;

/// Outcome of looking for a journaled tx on chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Still possibly in flight: do nothing yet.
    Wait,
    /// Can never be included any more: safe to rebuild.
    Dead,
    /// Included in a finalized block (successfully or not).
    Included {
        block_hash: String,
        summary: EventSummary,
    },
}

/// Subtensor client.
#[derive(Clone)]
pub struct Chain {
    api: Client,
}

impl Chain {
    pub async fn connect(url: &str) -> Result<Self> {
        let api = if url.starts_with("ws://") {
            Client::from_insecure_url(url).await
        } else {
            Client::from_url(url).await
        }
        .map_err(chain_err)?;
        Ok(Self { api })
    }

    pub fn api(&self) -> &Client {
        &self.api
    }

    /// Check every call and event this crate uses exists with the expected argument names.
    /// Returns human-readable evidence lines (`SubtensorModule.burn_alpha #102(hotkey, amount, netuid)`).
    pub async fn verify_metadata(&self) -> Result<Vec<String>> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let md = at.metadata();
        let mut out = vec![format!("spec_version {}", at.spec_version())];
        for (pallet, call, args) in REQUIRED_CALLS {
            let p = md
                .pallet_by_name(pallet)
                .ok_or_else(|| Error::Chain(format!("pallet {pallet} missing")))?;
            let v = p.call_variant_by_name(call).ok_or_else(|| {
                Error::Chain(format!("call {pallet}.{call} missing from runtime"))
            })?;
            let names: Vec<&str> = v.fields.iter().filter_map(|f| f.name.as_deref()).collect();
            if names != *args {
                return Err(Error::Chain(format!(
                    "call {pallet}.{call} has args {names:?}, expected {args:?}"
                )));
            }
            out.push(format!(
                "call {pallet}.{call} #{}({})",
                v.index,
                names.join(", ")
            ));
        }
        for (pallet, ev) in REQUIRED_EVENTS {
            let p = md
                .pallet_by_name(pallet)
                .ok_or_else(|| Error::Chain(format!("pallet {pallet} missing")))?;
            let v = p
                .event_variants()
                .and_then(|vs| vs.iter().find(|v| v.name == *ev))
                .ok_or_else(|| Error::Chain(format!("event {pallet}.{ev} missing")))?;
            out.push(format!("event {pallet}.{ev} #{}", v.index));
        }
        Ok(out)
    }

    pub async fn best_finalized_number(&self) -> Result<u64> {
        Ok(self
            .api
            .at_current_block()
            .await
            .map_err(chain_err)?
            .block_number())
    }

    /// Free TAO (rao) and system nonce of `who` at the latest finalized block.
    pub async fn account(&self, who: &AccountId32) -> Result<(u64, u32)> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let addr = dynamic::storage::<(AccountId32,), AccountInfo>("System", "Account");
        match at
            .storage()
            .try_fetch(addr, (*who,))
            .await
            .map_err(chain_err)?
        {
            Some(v) => {
                let info = v.decode().map_err(chain_err)?;
                Ok((info.data.free, info.nonce))
            }
            None => Ok((0, 0)),
        }
    }

    pub async fn free_balance(&self, who: &AccountId32) -> Result<u64> {
        Ok(self.account(who).await?.0)
    }

    pub async fn existential_deposit(&self) -> Result<u64> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        at.constants()
            .entry(dynamic::constant::<u64>("Balances", "ExistentialDeposit"))
            .map_err(chain_err)
    }

    /// All stake positions of `coldkey` (via `StakeInfoRuntimeApi_get_stake_info_for_coldkey`).
    pub async fn stake_positions(&self, coldkey: &AccountId32) -> Result<Vec<StakePosition>> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let call = dynamic::runtime_api_call::<_, Vec<RawStakeInfo>>(
            "StakeInfoRuntimeApi",
            "get_stake_info_for_coldkey",
            (*coldkey,),
        );
        let raw = at.runtime_apis().call(call).await.map_err(chain_err)?;
        Ok(raw
            .into_iter()
            .filter(|r| r.stake > 0)
            .map(|r| StakePosition {
                hotkey: r.hotkey,
                netuid: r.netuid,
                alpha: r.stake,
            })
            .collect())
    }

    /// Alpha held by `coldkey` on `netuid`, summed over hotkeys.
    pub async fn alpha_on(
        &self,
        coldkey: &AccountId32,
        netuid: u16,
    ) -> Result<(u64, Vec<StakePosition>)> {
        let pos: Vec<_> = self
            .stake_positions(coldkey)
            .await?
            .into_iter()
            .filter(|p| p.netuid == netuid)
            .collect();
        Ok((pos.iter().map(|p| p.alpha).sum(), pos))
    }

    /// Alpha of an exact (hotkey, coldkey, netuid) position.
    pub async fn alpha_of(
        &self,
        hotkey: &AccountId32,
        coldkey: &AccountId32,
        netuid: u16,
    ) -> Result<u64> {
        Ok(self
            .stake_positions(coldkey)
            .await?
            .into_iter()
            .filter(|p| p.netuid == netuid && &p.hotkey == hotkey)
            .map(|p| p.alpha)
            .sum())
    }

    /// Spot price, rao of TAO per 1 alpha (`SwapRuntimeApi_current_alpha_price`).
    pub async fn alpha_price(&self, netuid: u16) -> Result<u64> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let call =
            dynamic::runtime_api_call::<_, u64>("SwapRuntimeApi", "current_alpha_price", (netuid,));
        at.runtime_apis().call(call).await.map_err(chain_err)
    }

    /// Estimated fee (rao) of `call` signed by `signer`, via `TransactionPaymentApi_query_info`.
    pub async fn estimate_fee(&self, call: &ChainCall, signer: &Keypair) -> Result<u64> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let payload = call.payload();
        let mut txc = at.tx();
        let tx = txc
            .create_signed(&payload, signer, Default::default())
            .await
            .map_err(chain_err)?;
        // subxt's `partial_fee_estimate` assumes a u128 balance; subtensor's `TaoBalance` is u64,
        // so decode `RuntimeDispatchInfo { weight: (Compact<u64>, Compact<u64>), class: u8,
        // partial_fee }` ourselves and accept either width.
        let mut params = tx.encoded().to_vec();
        codec::Encode::encode_to(&(tx.encoded().len() as u32), &mut params);
        let out = at
            .runtime_apis()
            .call_raw("TransactionPaymentApi_query_info", Some(&params))
            .await
            .map_err(chain_err)?;
        decode_partial_fee(&out)
    }

    /// Sign, submit, wait for finalization, require success and the call's expected event.
    /// `on_submitted(nonce, tx_hash, birth_block)` runs *before* the extrinsic is broadcast so the caller can persist it.
    pub async fn submit(
        &self,
        call: &ChainCall,
        signer: &Keypair,
        on_submitted: impl FnOnce(u64, &str, u64) -> Result<()>,
    ) -> Result<FinalizedTx> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let payload = call.payload();
        let who = signer.public_key().to_account_id();
        let mut txc = at.tx();
        let nonce = txc.account_nonce(&who).await.map_err(chain_err)?;
        let params = subxt::config::SubstrateExtrinsicParamsBuilder::<SubstrateConfig>::new()
            .nonce(nonce)
            .mortal(64)
            .build();
        let tx = txc
            .create_signed(&payload, signer, params)
            .await
            .map_err(chain_err)?;
        let tx_hash = format!("{:?}", tx.hash());
        on_submitted(nonce, &tx_hash, at.block_number())?;
        let in_block = tx
            .submit_and_watch()
            .await
            .map_err(chain_err)?
            .wait_for_finalized()
            .await
            .map_err(chain_err)?;
        let block_hash = format!("{:?}", in_block.block_hash());
        let evs = in_block
            .wait_for_success()
            .await
            .map_err(|e| Error::Chain(format!("{} failed in {block_hash}: {e}", call.name())))?;
        let summary = EventSummary::from_events(evs.iter())?;
        let res = FinalizedTx {
            tx: TxRef {
                action: call.name().into(),
                tx_hash,
                block_hash,
                amount: call.amount(),
            },
            summary,
        };
        let (p, e) = call.expected_event();
        if !res.summary.has(p, e) {
            return Err(Error::EventMissing(e));
        }
        tracing::info!(action = call.name(), tx = %res.tx.tx_hash, block = %res.tx.block_hash, "finalized");
        Ok(res)
    }

    /// Coldkey owning `hotkey` (`SubtensorModule.Owner`), `None` if the hotkey account does not
    /// exist (staking to it would fail with `HotKeyAccountNotExists`).
    pub async fn hotkey_owner(&self, hotkey: &AccountId32) -> Result<Option<AccountId32>> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let addr = dynamic::storage::<(AccountId32,), AccountId32>(PALLET, "Owner");
        let owner = at
            .storage()
            .fetch(addr, (*hotkey,))
            .await
            .map_err(chain_err)?
            .decode()
            .map_err(chain_err)?;
        // ValueQuery default is the all-zero account.
        Ok((owner.0 != [0u8; 32]).then_some(owner))
    }

    /// Stake positions of many coldkeys at once (`get_stake_info_for_coldkeys`).
    pub async fn stake_positions_many(
        &self,
        coldkeys: &[AccountId32],
    ) -> Result<std::collections::BTreeMap<AccountId32, Vec<StakePosition>>> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let mut out = std::collections::BTreeMap::new();
        for chunk in coldkeys.chunks(64) {
            let call = dynamic::runtime_api_call::<_, Vec<(AccountId32, Vec<RawStakeInfo>)>>(
                "StakeInfoRuntimeApi",
                "get_stake_info_for_coldkeys",
                (chunk.to_vec(),),
            );
            for (ck, infos) in at.runtime_apis().call(call).await.map_err(chain_err)? {
                let pos = infos
                    .into_iter()
                    .filter(|r| r.stake > 0)
                    .map(|r| StakePosition {
                        hotkey: r.hotkey,
                        netuid: r.netuid,
                        alpha: r.stake,
                    })
                    .collect();
                out.insert(ck, pos);
            }
        }
        Ok(out)
    }

    /// Look for a journaled extrinsic in finalized blocks `birth ..= birth + MORTALITY`.
    pub async fn find_pending(&self, p: &PendingTx) -> Result<PendingOutcome> {
        let signer = crate::keys::parse_ss58(&p.signer)?;
        let (_, nonce) = self.account(&signer).await?;
        let head = self.best_finalized_number().await?;
        let horizon = p.birth_block + MORTALITY + 1;
        if (nonce as u64) <= p.nonce {
            // Nonce unused on finalized state: the tx is not included (yet).
            return Ok(if head > horizon {
                PendingOutcome::Dead
            } else {
                PendingOutcome::Wait
            });
        }
        // Nonce consumed: find which tx used it.
        for n in p.birth_block..=head.min(horizon) {
            let at = self.api.at_block(n).await.map_err(chain_err)?;
            let exts = at.extrinsics().fetch().await.map_err(chain_err)?;
            for ext in exts.iter() {
                let ext = ext.map_err(chain_err)?;
                if format!("{:?}", ext.hash()) == p.tx_hash {
                    let evs = ext.events().await.map_err(chain_err)?;
                    return Ok(PendingOutcome::Included {
                        block_hash: format!("{:?}", at.block_hash()),
                        summary: EventSummary::from_events(evs.iter())?,
                    });
                }
            }
        }
        // Nonce consumed by a different transaction (the key is used elsewhere): ours is dead.
        Ok(if head > horizon {
            PendingOutcome::Dead
        } else {
            PendingOutcome::Wait
        })
    }

    /// Stream of finalized block numbers.
    pub async fn finalized_blocks(
        &self,
    ) -> Result<impl futures::Stream<Item = Result<u64>> + use<>> {
        let s = self.api.stream_blocks().await.map_err(chain_err)?;
        Ok(s.map(|b| b.map(|b| b.number()).map_err(chain_err)))
    }
}

/// Decode `partial_fee` from SCALE `RuntimeDispatchInfo` bytes (u64 or u128 balance).
pub fn decode_partial_fee(bytes: &[u8]) -> Result<u64> {
    use codec::{Compact, Decode};
    let bad = || Error::Chain("cannot decode RuntimeDispatchInfo".into());
    let mut cur = bytes;
    <(Compact<u64>, Compact<u64>, u8)>::decode(&mut cur).map_err(|_| bad())?;
    match cur.len() {
        8 => u64::decode(&mut cur).map_err(|_| bad()),
        16 => u64::try_from(u128::decode(&mut cur).map_err(|_| bad())?).map_err(|_| bad()),
        _ => Err(bad()),
    }
}

/// Every extrinsic this crate sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainCall {
    /// `Balances.transfer_keep_alive(dest, value)`
    TransferTao { dest: AccountId32, amount: u64 },
    /// `Balances.transfer_all(dest, keep_alive: false)`: sends everything and reaps the account.
    TransferAll { dest: AccountId32 },
    /// `SubtensorModule.transfer_stake(destination_coldkey, hotkey, origin_netuid, destination_netuid, alpha_amount)`
    TransferStake {
        dest_coldkey: AccountId32,
        hotkey: AccountId32,
        netuid: u16,
        alpha: u64,
    },
    /// `SubtensorModule.move_stake(origin_hotkey, destination_hotkey, origin_netuid, destination_netuid, alpha_amount)`
    MoveStake {
        from_hotkey: AccountId32,
        to_hotkey: AccountId32,
        netuid: u16,
        alpha: u64,
    },
    /// `SubtensorModule.add_stake_limit(hotkey, netuid, amount_staked, limit_price, allow_partial)`
    AddStakeLimit {
        hotkey: AccountId32,
        netuid: u16,
        tao: u64,
        limit_price: u64,
        allow_partial: bool,
    },
    /// `SubtensorModule.try_associate_hotkey(hotkey)`: creates the hotkey account owned by the signer.
    AssociateHotkey { hotkey: AccountId32 },
    /// `SubtensorModule.burn_alpha(hotkey, amount, netuid)`
    BurnAlpha {
        hotkey: AccountId32,
        netuid: u16,
        alpha: u64,
    },
    /// `SubtensorModule.recycle_alpha(hotkey, amount, netuid)`
    RecycleAlpha {
        hotkey: AccountId32,
        netuid: u16,
        alpha: u64,
    },
}

fn acct(a: &AccountId32) -> Value {
    Value::from_bytes(a.0)
}

impl ChainCall {
    pub fn name(&self) -> &'static str {
        match self {
            Self::TransferTao { .. } => "transfer_keep_alive",
            Self::TransferAll { .. } => "transfer_all",
            Self::TransferStake { .. } => "transfer_stake",
            Self::MoveStake { .. } => "move_stake",
            Self::AddStakeLimit { .. } => "add_stake_limit",
            Self::BurnAlpha { .. } => "burn_alpha",
            Self::RecycleAlpha { .. } => "recycle_alpha",
            Self::AssociateHotkey { .. } => "try_associate_hotkey",
        }
    }

    pub fn expected_event(&self) -> (&'static str, &'static str) {
        match self {
            Self::TransferTao { .. } | Self::TransferAll { .. } => ("Balances", "Transfer"),
            Self::TransferStake { .. } => (PALLET, "StakeTransferred"),
            Self::MoveStake { .. } => (PALLET, "StakeMoved"),
            Self::AddStakeLimit { .. } => (PALLET, "StakeAdded"),
            Self::BurnAlpha { .. } => (PALLET, "AlphaBurned"),
            Self::RecycleAlpha { .. } => (PALLET, "AlphaRecycled"),
            // Emits no pallet event; success is checked via ExtrinsicSuccess.
            Self::AssociateHotkey { .. } => ("System", "ExtrinsicSuccess"),
        }
    }

    /// Amount moved by the call, rao (0 for `transfer_all` / `try_associate_hotkey`).
    pub fn amount(&self) -> u64 {
        match self {
            Self::TransferTao { amount, .. } => *amount,
            Self::TransferStake { alpha, .. }
            | Self::MoveStake { alpha, .. }
            | Self::BurnAlpha { alpha, .. }
            | Self::RecycleAlpha { alpha, .. } => *alpha,
            Self::AddStakeLimit { tao, .. } => *tao,
            Self::TransferAll { .. } | Self::AssociateHotkey { .. } => 0,
        }
    }

    fn payload(&self) -> subxt::transactions::DynamicPayload<Vec<Value>> {
        let (pallet, args): (&str, Vec<Value>) = match self {
            Self::TransferTao { dest, amount } => (
                "Balances",
                vec![
                    Value::unnamed_variant("Id", [acct(dest)]),
                    Value::u128(*amount as u128),
                ],
            ),
            Self::TransferAll { dest } => (
                "Balances",
                vec![
                    Value::unnamed_variant("Id", [acct(dest)]),
                    Value::bool(false),
                ],
            ),
            Self::TransferStake {
                dest_coldkey,
                hotkey,
                netuid,
                alpha,
            } => (
                PALLET,
                vec![
                    acct(dest_coldkey),
                    acct(hotkey),
                    (*netuid).into(),
                    (*netuid).into(),
                    (*alpha).into(),
                ],
            ),
            Self::MoveStake {
                from_hotkey,
                to_hotkey,
                netuid,
                alpha,
            } => (
                PALLET,
                vec![
                    acct(from_hotkey),
                    acct(to_hotkey),
                    (*netuid).into(),
                    (*netuid).into(),
                    (*alpha).into(),
                ],
            ),
            Self::AddStakeLimit {
                hotkey,
                netuid,
                tao,
                limit_price,
                allow_partial,
            } => (
                PALLET,
                vec![
                    acct(hotkey),
                    (*netuid).into(),
                    (*tao).into(),
                    (*limit_price).into(),
                    Value::bool(*allow_partial),
                ],
            ),
            Self::AssociateHotkey { hotkey } => (PALLET, vec![acct(hotkey)]),
            Self::BurnAlpha {
                hotkey,
                netuid,
                alpha,
            }
            | Self::RecycleAlpha {
                hotkey,
                netuid,
                alpha,
            } => (
                PALLET,
                vec![acct(hotkey), (*alpha).into(), (*netuid).into()],
            ),
        };
        dynamic::tx(pallet, self.name(), args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codec::{Compact, Encode};

    #[test]
    fn partial_fee_u64_and_u128() {
        let head = (Compact(123u64), Compact(4u64), 0u8).encode();
        let mut a = head.clone();
        a.extend(55_000u64.encode());
        assert_eq!(decode_partial_fee(&a).unwrap(), 55_000);
        let mut b = head.clone();
        b.extend(66_000u128.encode());
        assert_eq!(decode_partial_fee(&b).unwrap(), 66_000);
        assert!(decode_partial_fee(&head).is_err());
    }

    #[test]
    fn network_parse() {
        assert_eq!(
            "finney".parse::<Network>().unwrap().url(),
            "wss://entrypoint-finney.opentensor.ai:443"
        );
        assert_eq!(
            "local".parse::<Network>().unwrap().url(),
            "ws://127.0.0.1:9944"
        );
        assert!("nope".parse::<Network>().is_err());
    }
}
