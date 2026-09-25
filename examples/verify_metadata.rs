//! Read-only: check the calls/events this crate uses against a live runtime, then print
//! the head and the subnet price. Never signs or submits anything.
//!
//! `cargo run --example verify_metadata -- finney [netuid]`
//! `BITTENSOR_RPC_URL` / `BITTENSOR_RPC_API_KEY` override the network URL (bearer auth);
//! `BITTENSOR_RPC_FALLBACKS` (comma-separated, keyless) are tried after it.
use bittensor_buyback::{Chain, Network, chain::Endpoint, units::format_amount};

#[tokio::main]
async fn main() -> bittensor_buyback::Result<()> {
    let mut args = std::env::args().skip(1);
    let net: Network = args.next().unwrap_or_else(|| "test".into()).parse()?;
    let netuid: u16 = args.next().and_then(|s| s.parse().ok()).unwrap_or(100);
    let mut eps = Vec::new();
    match std::env::var("BITTENSOR_RPC_URL") {
        Ok(url) => {
            let mut ep = Endpoint::new(url);
            if let Ok(k) = std::env::var("BITTENSOR_RPC_API_KEY") {
                ep = ep.with_bearer(k);
            }
            eps.push(ep);
        }
        Err(_) => eps.push(Endpoint::new(net.url())),
    }
    for f in std::env::var("BITTENSOR_RPC_FALLBACKS")
        .unwrap_or_default()
        .split(',')
    {
        if !f.trim().is_empty() {
            eps.push(Endpoint::new(f.trim()));
        }
    }
    let chain = Chain::connect_any(&eps, 3).await?;
    for line in chain.verify_metadata().await? {
        println!("{line}");
    }
    let (n, h) = chain.finalized_head().await?;
    println!("finalized #{n} {h}, best #{}", chain.best_number().await?);
    println!(
        "netuid {netuid}: spot {} TAO/alpha, moving {} TAO/alpha",
        format_amount(chain.alpha_price(netuid).await?),
        format_amount(chain.moving_alpha_price(netuid).await?)
    );
    Ok(())
}
