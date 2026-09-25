//! Engine configuration.

use crate::units::RAO_PER_TAO;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

/// What to do with alpha bought by a buyback.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destroy {
    /// Keep the alpha staked on the treasury hotkey.
    Keep,
    /// `burn_alpha`: removes the stake; subnet `SubnetAlphaOut` is unchanged (see README).
    Burn,
    /// `recycle_alpha`: removes the stake and decreases `SubnetAlphaOut` (see README).
    Recycle,
}

/// Automatic buyback after each settled payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoBuyback {
    Off,
    On {
        destroy: Destroy,
        amount: AutoAmount,
    },
}

/// How much TAO an automatic buyback spends.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoAmount {
    /// Whole treasury balance minus `fee_reserve` (same as `buyback_all`).
    All,
    /// A fixed amount of rao.
    Fixed(u64),
    /// TAO value of the swept payment at the payment subnet's spot price, in basis points
    /// (10_000 = 100 %). TAO payments count at face value.
    PaymentValueBps(u64),
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Websocket endpoint.
    pub url: String,
    /// Subnet the payments are made in (alpha of this netuid).
    pub netuid: u16,
    /// Minimum alpha per payment, rao. Default 1 alpha.
    pub min_alpha: u64,
    /// Also accept plain TAO transfers of at least this many rao. `None` = alpha only.
    pub min_tao: Option<u64>,
    /// Seconds a payment request stays open.
    pub expiry_secs: u64,
    /// Coldkey that receives swept alpha and funds fees (its keypair is passed separately).
    pub treasury_hotkey: AccountId32,
    /// Positions smaller than this (rao) are left in the payment wallet: emissions keep adding
    /// tiny amounts to a staked position and re-sweeping each costs a fee. Default 0.001 alpha.
    pub sweep_dust: u64,
    /// Move swept stake from the payer's hotkey onto `treasury_hotkey` with `move_stake`.
    pub consolidate: bool,
    /// Send leftover TAO in the payment wallet back to the treasury (`transfer_all`).
    pub return_dust: bool,
    /// Safety margin on fee estimates, basis points. Default 5000 (+50 %).
    pub fee_margin_bps: u64,
    /// TAO kept in the treasury by `buyback_all`, rao.
    pub fee_reserve: u64,
    /// Subnet the buyback buys on. Default 100.
    pub buyback_netuid: u16,
    /// Max price increase accepted by `add_stake_limit`, basis points. Default 100 (1 %).
    pub slippage_bps: u64,
    /// Let `add_stake_limit` fill partially up to the limit price instead of failing.
    pub allow_partial: bool,
    pub auto: AutoBuyback,
    /// Required explicit additional capital for automatic jobs; frozen at creation.
    pub buyback_budget: Option<crate::state::BuybackBudget>,
    /// Attempts per step before a payment goes to `failed`.
    pub max_attempts: u32,
    /// Default webhook for settled payments (per-request `callback_url` overrides).
    pub webhook_url: Option<String>,
}

impl Config {
    /// Defaults for everything but the endpoint, netuid and treasury hotkey.
    pub fn new(url: impl Into<String>, netuid: u16, treasury_hotkey: AccountId32) -> Self {
        Self {
            url: url.into(),
            netuid,
            min_alpha: RAO_PER_TAO,
            min_tao: None,
            expiry_secs: 24 * 3600,
            treasury_hotkey,
            sweep_dust: RAO_PER_TAO / 1000,
            consolidate: true,
            return_dust: true,
            fee_margin_bps: 5_000,
            fee_reserve: RAO_PER_TAO / 10,
            buyback_netuid: 100,
            slippage_bps: 100,
            allow_partial: false,
            auto: AutoBuyback::Off,
            buyback_budget: None,
            max_attempts: 8,
            webhook_url: None,
        }
    }
}
