//! Read-only: check the calls/events this crate uses against a live runtime.
//! `cargo run --example verify_metadata -- finney`
use bittensor_buyback::{Chain, Network};

#[tokio::main]
async fn main() -> bittensor_buyback::Result<()> {
    let net: Network = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "test".into())
        .parse()?;
    for line in Chain::connect(net.url()).await?.verify_metadata().await? {
        println!("{line}");
    }
    Ok(())
}
