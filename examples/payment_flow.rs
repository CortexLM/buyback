//! Create a payment request and drive it until it settles.
//!
//! ```sh
//! export BUYBACK_MASTER_KEY=$(cargo run -q --bin buyback -- gen-master-key)
//! export BUYBACK_TREASURY_URI=//Bob          # localnet only; use a real mnemonic elsewhere
//! cargo run --example payment_flow -- ws://127.0.0.1:9944 2 <treasury-hotkey-ss58>
//! ```
use bittensor_buyback::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| Network::Local.url().into());
    let netuid: u16 = args.next().and_then(|n| n.parse().ok()).unwrap_or(1);
    let hotkey = keys::parse_ss58(&args.next().expect("treasury hotkey ss58"))?;

    let chain = Chain::connect(&url).await?;
    chain.verify_metadata().await?;
    let store: Arc<dyn Store> = Arc::new(FileStore::open("./payments")?);
    let treasury = TreasuryKeySource::EnvUri("BUYBACK_TREASURY_URI".into()).load(None)?;
    let mut cfg = Config::new(url, netuid, hotkey);
    cfg.auto = AutoBuyback::On {
        destroy: Destroy::Burn,
        amount: AutoAmount::PaymentValueBps(10_000),
    };
    let engine = Arc::new(Engine::new(
        chain,
        store,
        MasterKey::from_env("BUYBACK_MASTER_KEY")?,
        treasury,
        cfg,
    ));
    engine.ensure_treasury_hotkey().await?;

    let req = engine.create_payment(CreatePayment::default())?;
    println!(
        "send >= {} alpha on netuid {} to {} (transfer_stake)",
        units::format_amount(req.min_alpha),
        req.netuid,
        req.address
    );

    let mut settled = engine.subscribe();
    let runner = engine.clone();
    tokio::spawn(async move { runner.run().await });
    while let Ok(st) = settled.recv().await {
        if st.id == req.id {
            println!("{}", serde_json::to_string_pretty(&st).unwrap());
            break;
        }
    }
    Ok(())
}
