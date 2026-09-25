//! One-off buyback-and-burn of 1 TAO on netuid 100 (or $BUYBACK_NETUID_TARGET).
//!
//! ```sh
//! BUYBACK_TREASURY_URI=//Bob cargo run --example buyback -- ws://127.0.0.1:9944 <treasury-hotkey-ss58>
//! ```
use bittensor_buyback::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let url = args.next().unwrap_or_else(|| Network::Local.url().into());
    let hotkey = keys::parse_ss58(&args.next().expect("treasury hotkey ss58"))?;
    let chain = Chain::connect(&url).await?;
    let treasury = TreasuryKeySource::EnvUri("BUYBACK_TREASURY_URI".into()).load(None)?;
    let mut cfg = Config::new(url, 0, hotkey);
    if let Ok(n) = std::env::var("BUYBACK_NETUID_TARGET") {
        cfg.buyback_netuid = n.parse().map_err(|_| Error::Config("bad netuid".into()))?;
    }
    let store: Arc<dyn Store> = Arc::new(FileStore::open(
        std::env::temp_dir().join("buyback-example"),
    )?);
    let engine = Engine::new(chain, store, MasterKey::generate(), treasury, cfg);
    engine.ensure_treasury_hotkey().await?;
    let r = engine.buyback_and_burn(units::RAO_PER_TAO).await?;
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
    Ok(())
}
