//! `buyback` CLI. Every option also reads from an env var (`--help` lists them).

use bittensor_buyback::{
    AutoAmount, AutoBuyback, Chain, Config, CreatePayment, Destroy, Engine, MasterKey, Network,
    TreasuryKeySource, keys, open_store, units,
};
use clap::{Args, Parser, Subcommand};
use std::sync::Arc;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    version,
    about = "Bittensor alpha payments with automatic sweeps and buybacks"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Common {
    /// finney | test | local | ws(s):// URL
    #[arg(long, env = "BUYBACK_NETWORK", default_value = "local")]
    network: String,
    /// Payment subnet
    #[arg(long, env = "BUYBACK_NETUID")]
    netuid: u16,
    /// Store: sqlite:PATH or file:DIR
    #[arg(long, env = "BUYBACK_STORE", default_value = "sqlite:buyback.sqlite")]
    store: String,
    /// Env var holding the 64-hex-char master key
    #[arg(
        long,
        env = "BUYBACK_MASTER_KEY_VAR",
        default_value = "BUYBACK_MASTER_KEY"
    )]
    master_key_var: String,
    /// Env var holding the treasury secret URI / mnemonic
    #[arg(
        long,
        env = "BUYBACK_TREASURY_URI_VAR",
        default_value = "BUYBACK_TREASURY_URI"
    )]
    treasury_uri_var: String,
    /// File holding the treasury mnemonic (instead of the env var)
    #[arg(long, env = "BUYBACK_TREASURY_MNEMONIC_FILE")]
    treasury_mnemonic_file: Option<std::path::PathBuf>,
    /// Sealed treasury keystore (see `seal-treasury`)
    #[arg(long, env = "BUYBACK_TREASURY_KEYSTORE")]
    treasury_keystore: Option<std::path::PathBuf>,
    /// Treasury hotkey SS58 (stake destination). Must be a registered hotkey for buybacks.
    #[arg(long, env = "BUYBACK_TREASURY_HOTKEY")]
    treasury_hotkey: String,
    /// Minimum alpha per payment
    #[arg(long, env = "BUYBACK_MIN_ALPHA", default_value = "1")]
    min_alpha: String,
    /// Also accept TAO payments of at least this amount
    #[arg(long, env = "BUYBACK_MIN_TAO")]
    min_tao: Option<String>,
    /// Payment request lifetime, seconds
    #[arg(long, env = "BUYBACK_EXPIRY_SECS", default_value_t = 86_400)]
    expiry_secs: u64,
    /// Buyback subnet
    #[arg(long, env = "BUYBACK_NETUID_TARGET", default_value_t = 100)]
    buyback_netuid: u16,
    /// Max buy price increase, basis points
    #[arg(long, env = "BUYBACK_SLIPPAGE_BPS", default_value_t = 100)]
    slippage_bps: u64,
    /// Fee estimate safety margin, basis points
    #[arg(long, env = "BUYBACK_FEE_MARGIN_BPS", default_value_t = 5_000)]
    fee_margin_bps: u64,
    /// TAO kept in the treasury by buyback-all
    #[arg(long, env = "BUYBACK_FEE_RESERVE", default_value = "0.1")]
    fee_reserve: String,
    /// Automatic buyback per settled payment: off | keep | burn | recycle
    #[arg(long, env = "BUYBACK_AUTO", default_value = "off")]
    auto: String,
    /// Fixed additional TAO allocation per new job; required when auto is enabled
    #[arg(long, env = "BUYBACK_AUTO_AMOUNT", default_value = "payment")]
    auto_amount: String,
    /// Operator allocation reference for additional treasury capital
    #[arg(long, env = "BUYBACK_AUTO_SOURCE")]
    auto_source: Option<String>,
    /// Default settlement webhook
    #[arg(long, env = "BUYBACK_WEBHOOK_URL")]
    webhook_url: Option<String>,
    /// Refuse to run against finney unless set
    #[arg(long, env = "BUYBACK_ALLOW_MAINNET")]
    allow_mainnet: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Print a fresh random master key (hex). Store it in your secret manager.
    GenMasterKey,
    /// Seal the treasury URI from $BUYBACK_TREASURY_URI into a keystore file.
    SealTreasury {
        #[arg(
            long,
            env = "BUYBACK_MASTER_KEY_VAR",
            default_value = "BUYBACK_MASTER_KEY"
        )]
        master_key_var: String,
        #[arg(
            long,
            env = "BUYBACK_TREASURY_URI_VAR",
            default_value = "BUYBACK_TREASURY_URI"
        )]
        treasury_uri_var: String,
        out: std::path::PathBuf,
    },
    /// Check every call/event used exists in the connected runtime (read-only).
    VerifyMetadata {
        #[arg(long, env = "BUYBACK_NETWORK", default_value = "local")]
        network: String,
    },
    /// Create a payment request.
    Create {
        #[command(flatten)]
        c: Common,
        #[arg(long)]
        metadata: Option<String>,
        #[arg(long)]
        callback_url: Option<String>,
    },
    /// Show a payment.
    Status {
        #[command(flatten)]
        c: Common,
        id: String,
    },
    /// Resume a failed payment.
    Retry {
        #[command(flatten)]
        c: Common,
        id: String,
    },
    /// Sweep an expired, under-paid payment.
    ForceSweep {
        #[command(flatten)]
        c: Common,
        id: String,
    },
    /// Watch finalized blocks and drive all payments (optionally serve HTTP).
    Run {
        #[command(flatten)]
        c: Common,
        /// Serve the HTTP API on this address (needs the `http` feature)
        #[arg(long, env = "BUYBACK_LISTEN")]
        listen: Option<String>,
    },
    /// Buy alpha on the buyback subnet with treasury TAO.
    Buyback {
        #[command(flatten)]
        c: Common,
        /// TAO amount, or `all`
        amount: String,
        /// keep | burn | recycle
        #[arg(long, default_value = "keep")]
        then: String,
    },
    /// Treasury balances.
    Balances {
        #[command(flatten)]
        c: Common,
    },
}

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn destroy(s: &str) -> R<Destroy> {
    Ok(match s {
        "keep" => Destroy::Keep,
        "burn" => Destroy::Burn,
        "recycle" => Destroy::Recycle,
        _ => return Err(format!("expected keep|burn|recycle, got {s}").into()),
    })
}

async fn engine(c: &Common) -> R<Engine> {
    let net: Network = c.network.parse()?;
    if net == Network::Finney && !c.allow_mainnet {
        return Err(
            "refusing to use finney without --allow-mainnet / BUYBACK_ALLOW_MAINNET".into(),
        );
    }
    let master = MasterKey::from_env(&c.master_key_var)?;
    let src = match (&c.treasury_keystore, &c.treasury_mnemonic_file) {
        (Some(p), _) => TreasuryKeySource::EncryptedKeystore(p.clone()),
        (None, Some(p)) => TreasuryKeySource::MnemonicFile(p.clone()),
        _ => TreasuryKeySource::EnvUri(c.treasury_uri_var.clone()),
    };
    let treasury = src.load(Some(&master))?;
    let mut cfg = Config::new(net.url(), c.netuid, keys::parse_ss58(&c.treasury_hotkey)?);
    cfg.min_alpha = units::parse_amount(&c.min_alpha)?;
    cfg.min_tao = c.min_tao.as_deref().map(units::parse_amount).transpose()?;
    cfg.expiry_secs = c.expiry_secs;
    cfg.buyback_netuid = c.buyback_netuid;
    cfg.slippage_bps = c.slippage_bps;
    cfg.fee_margin_bps = c.fee_margin_bps;
    cfg.fee_reserve = units::parse_amount(&c.fee_reserve)?;
    cfg.webhook_url = c.webhook_url.clone();
    if c.auto != "off" {
        let amount = units::parse_amount(&c.auto_amount)?;
        let destroy = destroy(&c.auto)?;
        let budget = bittensor_buyback::state::BuybackBudget {
            amount_rao: amount,
            currency: "TAO".into(),
            hotkey: c.treasury_hotkey.clone(),
            source: c
                .auto_source
                .clone()
                .ok_or("--auto-source required for automatic buyback")?,
            netuid: c.buyback_netuid,
            destroy,
        };
        budget.validate()?;
        cfg.buyback_budget = Some(budget);
        cfg.auto = AutoBuyback::On {
            destroy,
            amount: AutoAmount::Fixed(amount),
        };
    }
    let chain = Chain::connect(net.url()).await?;
    let store: Arc<dyn bittensor_buyback::Store> = Arc::from(open_store(&c.store)?);
    #[allow(unused_mut)]
    let mut e = Engine::new(chain, store, master, treasury, cfg);
    #[cfg(feature = "webhook")]
    if let Ok(s) = std::env::var("BUYBACK_WEBHOOK_SECRET") {
        e = e.with_webhook_secret(s.into_bytes());
    }
    Ok(e)
}

fn print(v: &impl serde::Serialize) -> R<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

#[tokio::main]
async fn main() -> R<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match Cli::parse().cmd {
        Cmd::GenMasterKey => println!("{}", *MasterKey::generate().to_hex()),
        Cmd::SealTreasury {
            master_key_var,
            treasury_uri_var,
            out,
        } => {
            let master = MasterKey::from_env(&master_key_var)?;
            let uri = Zeroizing::new(
                std::env::var(&treasury_uri_var)
                    .map_err(|_| format!("{treasury_uri_var} not set"))?,
            );
            let kp = keys::keypair_from_uri(uri.trim())?;
            let sealed = master.seal(uri.trim().as_bytes(), keys::TREASURY_AAD)?;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            use std::io::Write;
            opts.open(&out)?
                .write_all(serde_json::to_string(&sealed)?.as_bytes())?;
            eprintln!(
                "sealed treasury {} -> {}",
                keys::ss58(&kp.public_key().to_account_id()),
                out.display()
            );
        }
        Cmd::VerifyMetadata { network } => {
            let net: Network = network.parse()?;
            for line in Chain::connect(net.url()).await?.verify_metadata().await? {
                println!("{line}");
            }
        }
        Cmd::Create {
            c,
            metadata,
            callback_url,
        } => {
            let e = engine(&c).await?;
            let metadata =
                metadata.map(|m| serde_json::from_str(&m).unwrap_or(serde_json::Value::String(m)));
            print(
                &e.create_payment(CreatePayment {
                    metadata,
                    callback_url,
                    ..Default::default()
                })
                .await?,
            )?;
        }
        Cmd::Status { c, id } => print(&engine(&c).await?.status(&id).await?)?,
        Cmd::Retry { c, id } => print(&engine(&c).await?.retry(&id).await?)?,
        Cmd::ForceSweep { c, id } => print(&engine(&c).await?.force_sweep(&id).await?)?,
        Cmd::Run { c, listen } => {
            let e = Arc::new(engine(&c).await?);
            for line in e.chain().verify_metadata().await? {
                tracing::info!("{line}");
            }
            e.ensure_treasury_hotkey().await?;
            if let Some(addr) = listen {
                #[cfg(feature = "http")]
                {
                    let l = tokio::net::TcpListener::bind(&addr).await?;
                    tracing::info!(%addr, "http listening");
                    let app = bittensor_buyback::http::router(e.clone());
                    tokio::spawn(async move { axum::serve(l, app).await });
                }
                #[cfg(not(feature = "http"))]
                return Err(format!("--listen {addr} needs the `http` feature").into());
            }
            e.run().await?;
        }
        Cmd::Buyback { .. } => {
            return Err(bittensor_buyback::Error::Config(
                "standalone buyback disabled; use a durable payment/sweep job with an explicit buyback budget".into(),
            ).into());
        }
        Cmd::Balances { c } => {
            let e = engine(&c).await?;
            let t = e.treasury_account();
            let free = e.chain().free_balance(&t).await?;
            let pos = e.chain().stake_positions(&t).await?;
            print(&serde_json::json!({
                "treasury": keys::ss58(&t),
                "free_tao": units::format_amount(free),
                "spendable_tao": units::format_amount(e.spendable().await?),
                "stake": pos.iter().map(|p| serde_json::json!({
                    "hotkey": keys::ss58(&p.hotkey), "netuid": p.netuid, "alpha": units::format_amount(p.alpha)
                })).collect::<Vec<_>>(),
            }))?;
        }
    }
    Ok(())
}
