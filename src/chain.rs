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

/// A signed, not yet broadcast extrinsic.
#[derive(Clone, Debug)]
pub struct PreparedTx {
    pub call: ChainCall,
    pub signer: String,
    pub nonce: u64,
    pub tx_hash: String,
    pub birth_block: u64,
    pub bytes: Vec<u8>,
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
    rpc: subxt::rpcs::RpcClient,
}

/// One RPC endpoint, optionally with a bearer key sent on the websocket handshake.
#[derive(Clone)]
pub struct Endpoint {
    pub url: String,
    /// Sent as `Authorization: Bearer <key>`. Never logged.
    pub bearer: Option<zeroize::Zeroizing<String>>,
}

impl std::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Endpoint")
            .field("url", &self.url)
            .field("bearer", &self.bearer.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Endpoint {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            bearer: None,
        }
    }

    pub fn with_bearer(mut self, key: impl Into<String>) -> Self {
        let k: String = key.into();
        self.bearer = (!k.trim().is_empty()).then(|| zeroize::Zeroizing::new(k.trim().to_string()));
        self
    }
}

impl Chain {
    pub async fn connect(url: &str) -> Result<Self> {
        Self::connect_endpoint(&Endpoint::new(url)).await
    }

    /// Connect to one endpoint. `wss://` required unless the host is loopback.
    pub async fn connect_endpoint(ep: &Endpoint) -> Result<Self> {
        use jsonrpsee::client_transport::ws::{Url, WsTransportClientBuilder};
        let url = Url::parse(&ep.url).map_err(|_| Error::Config(format!("bad RPC url {:?}", ep.url)))?;
        let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1" | "[::1]"));
        match url.scheme() {
            "wss" => {}
            "ws" if loopback => {}
            _ => return Err(Error::Config(format!("RPC url {:?} must be wss:// (ws:// only on loopback)", ep.url))),
        }
        let mut headers = jsonrpsee::client_transport::ws::HeaderMap::new();
        if let Some(key) = &ep.bearer {
            let mut v = jsonrpsee::client_transport::ws::HeaderValue::from_str(&format!("Bearer {}", key.as_str()))
                .map_err(|_| Error::Config("RPC key is not a valid header value".into()))?;
            v.set_sensitive(true);
            headers.insert("authorization", v);
        }
        let (tx, rx) = WsTransportClientBuilder {
            headers,
            connection_timeout: std::time::Duration::from_secs(15),
            ..Default::default()
        }
        .build(url)
        .await
        // The transport error can echo the handshake; keep only the url.
        .map_err(|_| Error::Chain(format!("cannot connect to {}", redact_url(&ep.url))))?;
        let client = jsonrpsee::core::client::ClientBuilder::default()
            .request_timeout(std::time::Duration::from_secs(60))
            .max_buffer_capacity_per_subscription(4096)
            .build_with_tokio(tx, rx);
        let rpc = subxt::rpcs::RpcClient::new(client);
        let api = Client::from_rpc_client(rpc.clone()).await.map_err(chain_err)?;
        Ok(Self { api, rpc })
    }

    /// Try each endpoint in order (with `attempts` rounds and backoff) and return the first that
    /// connects and answers a finalized head. Callers reconnect through this on stream errors.
    pub async fn connect_any(endpoints: &[Endpoint], attempts: u32) -> Result<Self> {
        let mut last = Error::Config("no RPC endpoint configured".into());
        for round in 0..attempts.max(1) {
            for ep in endpoints {
                match Self::connect_endpoint(ep).await {
                    Ok(c) => match c.best_finalized_number().await {
                        Ok(_) => return Ok(c),
                        Err(e) => last = e,
                    },
                    Err(e) => last = e,
                }
                tracing::warn!(url = %redact_url(&ep.url), round, "RPC endpoint unavailable, trying next");
            }
            tokio::time::sleep(std::time::Duration::from_secs(2u64 << round.min(4))).await;
        }
        Err(last)
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

    /// Slow EMA of the subnet price, rao of TAO per alpha (`SubnetMovingPrice`, I96F32).
    /// Cannot be moved within one block, which makes it a manipulation-resistant cap on spot.
    pub async fn moving_alpha_price(&self, netuid: u16) -> Result<u64> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        moving_price_at(&at, netuid).await
    }

    /// Best (not yet finalized) head number: a block here has one confirmation.
    pub async fn best_number(&self) -> Result<u64> {
        #[derive(serde::Deserialize)]
        struct Header {
            number: String,
        }
        let h: Header = self
            .rpc
            .request("chain_getHeader", subxt::rpcs::rpc_params![Option::<String>::None])
            .await
            .map_err(chain_err)?;
        u64::from_str_radix(h.number.trim_start_matches("0x"), 16)
            .map_err(|_| Error::Chain("bad best header number".into()))
    }

    /// Finalized head: (number, hash hex).
    pub async fn finalized_head(&self) -> Result<(u64, String)> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        Ok((at.block_number(), format!("{:?}", at.block_hash())))
    }

    /// Canonical block hash at `number` on the finalized chain (legacy `chain_getBlockHash`).
    pub async fn block_hash_at(&self, number: u64) -> Result<Option<String>> {
        let at = match self.api.at_block(number).await {
            Ok(at) => at,
            Err(_) => return Ok(None),
        };
        Ok(Some(format!("{:?}", at.block_hash())))
    }

    /// Every stake that landed on one of `watched` coldkeys in block `number`, from
    /// `SubtensorModule.StakeAdded` events emitted while applying signed extrinsics (a same-subnet
    /// `transfer_stake`, and the restake half of a cross-subnet one). The price columns are this
    /// block's spot and moving price of each deposit's subnet.
    pub async fn deposits_in_block(
        &self,
        number: u64,
        watched: &std::collections::BTreeSet<AccountId32>,
    ) -> Result<BlockDeposits> {
        use subxt::events::Phase;
        let at = self.api.at_block(number).await.map_err(chain_err)?;
        let block_hash = format!("{:?}", at.block_hash());
        let mut out = BlockDeposits {
            number,
            block_hash,
            deposits: vec![],
        };
        if watched.is_empty() {
            return Ok(out);
        }
        let events = at.events().fetch().await.map_err(chain_err)?;
        let mut hits = vec![];
        for ev in events.iter() {
            let ev = ev.map_err(chain_err)?;
            if ev.pallet_name() != PALLET || ev.event_name() != "StakeAdded" {
                continue;
            }
            let Phase::ApplyExtrinsic(xt) = ev.phase() else {
                continue;
            };
            let (coldkey, hotkey, tao, alpha, netuid, _fee) = ev
                .decode_fields_unchecked_as::<(AccountId32, AccountId32, u64, u64, u16, u64)>()
                .map_err(chain_err)?;
            if watched.contains(&coldkey) {
                hits.push((xt, ev.index(), coldkey, hotkey, tao, alpha, netuid));
            }
        }
        if hits.is_empty() {
            return Ok(out);
        }
        let exts = at.extrinsics().fetch().await.map_err(chain_err)?;
        let mut hashes = std::collections::HashMap::new();
        let mut ok = std::collections::HashSet::new();
        for ext in exts.iter() {
            let ext = ext.map_err(chain_err)?;
            hashes.insert(ext.index() as u32, (format!("{:?}", ext.hash()), ext.address_bytes().map(|b| b.to_vec())));
        }
        // Only extrinsics that succeeded count (their events would be rolled back otherwise, but
        // be explicit).
        for ev in events.iter() {
            let ev = ev.map_err(chain_err)?;
            if let (Phase::ApplyExtrinsic(i), "System", "ExtrinsicSuccess") =
                (ev.phase(), ev.pallet_name(), ev.event_name())
            {
                ok.insert(i);
            }
        }
        let mut prices = std::collections::HashMap::new();
        for (xt, event_index, coldkey, hotkey, tao, alpha, netuid) in hits {
            if !ok.contains(&xt) {
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(e) = prices.entry(netuid) {
                let spot_call = dynamic::runtime_api_call::<_, u64>(
                    "SwapRuntimeApi",
                    "current_alpha_price",
                    (netuid,),
                );
                let spot = at.runtime_apis().call(spot_call).await.map_err(chain_err)?;
                let moving = moving_price_at(&at, netuid).await?;
                e.insert((spot, moving));
            }
            let (spot, moving) = prices[&netuid];
            let (hash, from) = hashes.get(&xt).cloned().unwrap_or_default();
            out.deposits.push(Deposit {
                block_number: number,
                block_hash: out.block_hash.clone(),
                extrinsic_index: xt,
                event_index,
                extrinsic_hash: hash,
                from: from.and_then(|b| signer_of(&b)),
                coldkey,
                hotkey,
                netuid,
                alpha,
                tao_value: tao,
                spot_price: spot,
                moving_price: moving,
            });
        }
        Ok(out)
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

    /// Build and sign `call` with an explicit nonce, mortal for [`MORTALITY`] blocks. Nothing is
    /// sent: persist [`PreparedTx::journal`] first, then [`Chain::broadcast`].
    pub async fn prepare(&self, call: &ChainCall, signer: &Keypair) -> Result<PreparedTx> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let payload = call.payload();
        let who = signer.public_key().to_account_id();
        let mut txc = at.tx();
        let nonce = txc.account_nonce(&who).await.map_err(chain_err)?;
        let params = subxt::config::SubstrateExtrinsicParamsBuilder::<SubstrateConfig>::new()
            .nonce(nonce)
            .mortal(MORTALITY)
            .build();
        let tx = txc
            .create_signed(&payload, signer, params)
            .await
            .map_err(chain_err)?;
        Ok(PreparedTx {
            call: call.clone(),
            signer: crate::keys::ss58(&who),
            nonce,
            tx_hash: format!("{:?}", tx.hash()),
            birth_block: at.block_number(),
            bytes: tx.encoded().to_vec(),
        })
    }

    /// Broadcast a prepared tx, wait for finalization, require success and the expected event.
    pub async fn broadcast(&self, p: &PreparedTx) -> Result<FinalizedTx> {
        let at = self.api.at_current_block().await.map_err(chain_err)?;
        let tx = at.tx().from_bytes(p.bytes.clone());
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
            .map_err(|e| Error::Chain(format!("{} failed in {block_hash}: {e}", p.call.name())))?;
        let summary = EventSummary::from_events(evs.iter())?;
        let res = FinalizedTx {
            tx: TxRef {
                action: p.call.name().into(),
                tx_hash: p.tx_hash.clone(),
                block_hash,
                amount: p.call.amount(),
            },
            summary,
        };
        let (pal, e) = p.call.expected_event();
        if !res.summary.has(pal, e) {
            return Err(Error::EventMissing(e));
        }
        tracing::info!(action = p.call.name(), tx = %res.tx.tx_hash, block = %res.tx.block_hash, "finalized");
        Ok(res)
    }

    /// Prepare and broadcast without a journal (operator actions).
    pub async fn submit(&self, call: &ChainCall, signer: &Keypair) -> Result<FinalizedTx> {
        let p = self.prepare(call, signer).await?;
        self.broadcast(&p).await
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

async fn moving_price_at(
    at: &subxt::client::ClientAtBlock<SubstrateConfig, subxt::client::OnlineClientAtBlockImpl<SubstrateConfig>>,
    netuid: u16,
) -> Result<u64> {
    let addr = dynamic::storage::<(u16,), scale_value::Value>(PALLET, "SubnetMovingPrice");
    let v = at
        .storage()
        .fetch(addr, (netuid,))
        .await
        .map_err(chain_err)?
        .decode()
        .map_err(chain_err)?;
    i96f32_to_rao(&v)
}

/// `I96F32 { bits: i128 }` (TAO per alpha) as rao of TAO per alpha.
fn i96f32_to_rao(v: &scale_value::Value) -> Result<u64> {
    use scale_value::{Primitive, ValueDef};
    fn find(v: &scale_value::Value) -> Option<i128> {
        match &v.value {
            ValueDef::Primitive(Primitive::I128(b)) => Some(*b),
            ValueDef::Primitive(Primitive::U128(b)) => i128::try_from(*b).ok(),
            ValueDef::Composite(c) => c.values().find_map(find),
            _ => None,
        }
    }
    let bits = find(v).ok_or_else(|| Error::Chain("cannot decode SubnetMovingPrice".into()))?;
    if bits <= 0 {
        return Ok(0);
    }
    Ok(fixed_bits_to_rao(bits as u128, 32))
}

/// `bits / 2^frac` TAO per alpha, as rao (floor), saturating.
pub fn fixed_bits_to_rao(bits: u128, frac: u32) -> u64 {
    let whole = bits >> frac;
    let part = bits & ((1u128 << frac) - 1);
    let rao = whole
        .saturating_mul(crate::units::RAO_PER_TAO as u128)
        .saturating_add((part * crate::units::RAO_PER_TAO as u128) >> frac);
    u64::try_from(rao).unwrap_or(u64::MAX)
}

/// The signer of an extrinsic from its SCALE `MultiAddress` bytes (`Id` variant only).
fn signer_of(address: &[u8]) -> Option<AccountId32> {
    match address {
        [0, rest @ ..] if rest.len() == 32 => Some(AccountId32(rest.try_into().ok()?)),
        _ => None,
    }
}

/// Keep scheme and host of an RPC URL (a key could sit in a path or query).
pub fn redact_url(url: &str) -> String {
    match url.split_once("://") {
        Some((scheme, rest)) => {
            let host = rest.split(['/', '?', '#']).next().unwrap_or("");
            let host = host.rsplit('@').next().unwrap_or(host);
            format!("{scheme}://{host}")
        }
        None => "<invalid url>".into(),
    }
}

/// Deposits found in one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockDeposits {
    pub number: u64,
    pub block_hash: String,
    pub deposits: Vec<Deposit>,
}

/// One stake credited to a watched coldkey (`StakeAdded` in a successful signed extrinsic).
/// Unique per `(block_hash, event_index)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    pub block_number: u64,
    pub block_hash: String,
    pub extrinsic_index: u32,
    pub event_index: u32,
    pub extrinsic_hash: String,
    /// Signer of the extrinsic, when it is a plain account.
    pub from: Option<AccountId32>,
    pub coldkey: AccountId32,
    pub hotkey: AccountId32,
    pub netuid: u16,
    /// Alpha added to the position, rao.
    pub alpha: u64,
    /// TAO value the chain reported for it (spot at the time of the transfer), rao.
    pub tao_value: u64,
    /// Spot and moving price of `netuid` at this block, rao of TAO per alpha.
    pub spot_price: u64,
    pub moving_price: u64,
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
    fn fixed_point_prices() {
        // 0.5 TAO/alpha in I96F32
        assert_eq!(fixed_bits_to_rao(1u128 << 31, 32), 500_000_000);
        assert_eq!(fixed_bits_to_rao(3u128 << 32, 32), 3_000_000_000);
        assert_eq!(fixed_bits_to_rao(0, 32), 0);
        assert_eq!(fixed_bits_to_rao(u128::MAX, 32), u64::MAX);
    }

    #[test]
    fn urls_are_redacted_and_endpoint_debug_hides_key() {
        assert_eq!(redact_url("wss://rpc.example.io/v1?key=abc"), "wss://rpc.example.io");
        assert_eq!(redact_url("wss://user:pw@host:443/x"), "wss://host:443");
        let ep = Endpoint::new("wss://x").with_bearer("s3cr3t");
        assert!(!format!("{ep:?}").contains("s3cr3t"));
        assert!(Endpoint::new("wss://x").with_bearer("  ").bearer.is_none());
    }

    #[tokio::test]
    async fn plaintext_remote_rpc_is_refused() {
        let e = Chain::connect_endpoint(&Endpoint::new("ws://example.com:9944")).await.err().unwrap();
        assert!(e.to_string().contains("wss"));
    }

    #[test]
    fn signer_decoding() {
        let mut b = vec![0u8];
        b.extend([7u8; 32]);
        assert_eq!(signer_of(&b), Some(AccountId32([7; 32])));
        assert_eq!(signer_of(&[1u8; 21]), None);
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
