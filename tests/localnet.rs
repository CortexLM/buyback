//! End-to-end test against a local subtensor (`ghcr.io/opentensor/subtensor-localnet`).
//!
//! ```sh
//! docker run -d -p 9944:9944 ghcr.io/opentensor/subtensor-localnet:devnet-ready True
//! cargo test --all-features --test localnet -- --nocapture
//! ```
//! Enabled by the `localnet-tests` feature; `BUYBACK_LOCALNET_URL` overrides the endpoint.
//! Uses only the well-known dev accounts (//Alice, //Bob and derivations).
#![cfg(feature = "localnet-tests")]

use bittensor_buyback::chain::Chain;
use bittensor_buyback::keys::keypair_from_uri;
use bittensor_buyback::units::{RAO_PER_TAO, format_amount};
use bittensor_buyback::*;
use std::sync::Arc;
use std::time::Duration;
use subxt::dynamic::{self, Value};
use subxt::utils::AccountId32;
use subxt_signer::sr25519::Keypair;

// ponytail: these fixtures share Alice and global subnet registration state;
// serialize this test binary until each fixture has an isolated local chain.
static LOCALNET: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn url() -> String {
    std::env::var("BUYBACK_LOCALNET_URL").unwrap_or_else(|_| "ws://127.0.0.1:9944".into())
}

fn id(k: &Keypair) -> AccountId32 {
    k.public_key().to_account_id()
}

/// Submit a raw SubtensorModule call and return its events (pallet, name, fields-string).
async fn raw(
    chain: &Chain,
    signer: &Keypair,
    call: &str,
    args: Vec<Value>,
) -> Vec<(String, String, String)> {
    let at = chain.api().at_current_block().await.unwrap();
    let tx = dynamic::tx("SubtensorModule", call, args);
    let evs = at
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await
        .unwrap()
        .wait_for_finalized_success()
        .await
        .unwrap_or_else(|e| panic!("{call}: {e}"));
    evs.iter()
        .map(|e| {
            let e = e.unwrap();
            let f = e
                .decode_fields_unchecked_as::<subxt::ext::scale_value::Composite<()>>()
                .map(|v| v.to_string())
                .unwrap_or_default();
            (e.pallet_name().into(), e.event_name().into(), f)
        })
        .collect()
}

/// Register a subnet owned by `owner` with `hotkey`, enable it, return its netuid.
/// `env` names a variable that can pin an existing netuid instead (reruns on a long-lived
/// localnet: the registration lock cost doubles with each new subnet).
async fn new_subnet(chain: &Chain, owner: &Keypair, hotkey: &Keypair, env: &str) -> u16 {
    if let Some(n) = std::env::var(env).ok().and_then(|v| v.parse().ok()) {
        return n;
    }
    let evs = raw(
        chain,
        owner,
        "register_network",
        vec![Value::from_bytes(id(hotkey).0)],
    )
    .await;
    let (_, _, f) = evs
        .iter()
        .find(|(_, n, _)| n == "NetworkAdded")
        .expect("NetworkAdded");
    // fields render as "(<netuid>, <mechanism>)"
    let netuid: u16 = f
        .trim_matches(|c| c == '(' || c == ')')
        .split(',')
        .next()
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    raw(chain, owner, "start_call", vec![netuid.into()]).await;
    netuid
}

#[tokio::test(flavor = "multi_thread")]
async fn full_flow() {
    let _chain_guard = LOCALNET.lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,bittensor_buyback=debug")
        .try_init();
    let chain = Chain::connect(&url()).await.expect("localnet reachable");
    for l in chain.verify_metadata().await.unwrap() {
        println!("metadata: {l}");
    }

    let payer = keypair_from_uri("//Alice").unwrap();
    let payer_hk = keypair_from_uri("//Alice//buyback-hk").unwrap();
    let treasury = keypair_from_uri("//Bob").unwrap();
    // Not a neuron anywhere: receives no emissions, so balance deltas are exact.
    let treasury_hk = keypair_from_uri("//Bob//treasury-hk").unwrap();
    let owner_hk = keypair_from_uri("//Bob//owner-hk").unwrap();

    // Payment subnet (owned by the payer) and a buyback subnet standing in for netuid 100.
    let pay_net = new_subnet(&chain, &payer, &payer_hk, "BUYBACK_TEST_PAY_NETUID").await;
    let buy_net = new_subnet(&chain, &treasury, &owner_hk, "BUYBACK_TEST_BUY_NETUID").await;
    println!("payment netuid {pay_net}, buyback netuid {buy_net}");

    // Payer buys 5 TAO worth of alpha on the payment subnet.
    raw(
        &chain,
        &payer,
        "add_stake",
        vec![
            Value::from_bytes(id(&payer_hk).0),
            pay_net.into(),
            (5 * RAO_PER_TAO).into(),
        ],
    )
    .await;
    let (payer_alpha, _) = chain.alpha_on(&id(&payer), pay_net).await.unwrap();
    assert!(payer_alpha > 2 * RAO_PER_TAO, "payer alpha {payer_alpha}");

    // Engine.
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.path().join("db.sqlite")).unwrap());
    let mut cfg = Config::new(url(), pay_net, id(&treasury_hk));
    cfg.buyback_netuid = buy_net;
    cfg.slippage_bps = 500;
    cfg.fee_reserve = RAO_PER_TAO;
    cfg.auto = AutoBuyback::On {
        destroy: Destroy::Burn,
        amount: AutoAmount::Fixed(RAO_PER_TAO / 2),
    };
    cfg.buyback_budget = Some(bittensor_buyback::state::BuybackBudget {
        amount_rao: RAO_PER_TAO / 2,
        currency: "TAO".into(),
        source: "localnet-test-allocation".into(),
        hotkey: keys::ss58(&id(&treasury_hk)),
        netuid: buy_net,
        destroy: Destroy::Burn,
    });
    let master_hex = MasterKey::generate().to_hex();
    let engine = Arc::new(Engine::new(
        chain.clone(),
        store.clone(),
        MasterKey::from_hex(&master_hex).unwrap(),
        treasury.clone(),
        cfg.clone(),
    ));
    let mut settled = engine.subscribe();
    // Explicit isolated-localnet provisioning, never engine startup behavior.
    if chain
        .hotkey_owner(&id(&treasury_hk))
        .await
        .unwrap()
        .is_none()
    {
        assert!(engine.ensure_treasury_hotkey().await.is_err());
        raw(
            &chain,
            &treasury,
            "try_associate_hotkey",
            vec![Value::from_bytes(id(&treasury_hk).0)],
        )
        .await;
    }
    engine.ensure_treasury_hotkey().await.unwrap();
    assert_eq!(
        chain.hotkey_owner(&id(&treasury_hk)).await.unwrap(),
        Some(id(&treasury))
    );
    engine.ensure_treasury_hotkey().await.unwrap(); // idempotent

    let req = engine
        .create_payment(CreatePayment::default())
        .await
        .unwrap();
    println!("payment request: {}", serde_json::to_string(&req).unwrap());
    assert_eq!(req.min_alpha, RAO_PER_TAO);
    let deposit = keys::parse_ss58(&req.address).unwrap();

    // Below the minimum: stays pending.
    engine.tick().await.unwrap();
    assert_eq!(
        engine.status(&req.id).await.unwrap().state,
        PaymentState::Pending
    );

    let tre = id(&treasury);
    let tre_tao_0 = chain.free_balance(&tre).await.unwrap();
    let tre_alpha_0 = chain
        .alpha_of(&id(&treasury_hk), &tre, pay_net)
        .await
        .unwrap();

    // Payer transfer_stake's 2 alpha to the deposit address.
    let pay_amount = 2 * RAO_PER_TAO;
    let evs = raw(
        &chain,
        &payer,
        "transfer_stake",
        vec![
            Value::from_bytes(deposit.0),
            Value::from_bytes(id(&payer_hk).0),
            pay_net.into(),
            pay_net.into(),
            pay_amount.into(),
        ],
    )
    .await;
    assert!(evs.iter().any(|(_, n, _)| n == "StakeTransferred"));
    let (dep_alpha, _) = chain.alpha_on(&deposit, pay_net).await.unwrap();
    println!("deposit wallet holds {} alpha", format_amount(dep_alpha));

    // Drive the state machine; simulate a restart halfway by building a second engine on the
    // same store (the first one is dropped).
    let mut restarted = false;
    let mut engine = engine;
    for i in 0..40 {
        engine.tick().await.unwrap();
        let st = engine.status(&req.id).await.unwrap();
        println!("tick {i}: {:?} txs={}", st.state, st.txs.len());
        if st.state == PaymentState::Settled {
            break;
        }
        assert_ne!(st.state, PaymentState::Failed, "{:?}", st.last_error);
        if !restarted && st.state == PaymentState::Funded {
            restarted = true;
            engine = Arc::new(Engine::new(
                chain.clone(),
                store.clone(),
                MasterKey::from_hex(&master_hex).unwrap(),
                treasury.clone(),
                cfg.clone(),
            ));
            settled = engine.subscribe();
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let st = engine.status(&req.id).await.unwrap();
    assert_eq!(st.state, PaymentState::Settled, "{st:#?}");
    let note = settled.try_recv().expect("settlement broadcast");
    assert_eq!(note.id, req.id);

    // Deposit wallet emptied (alpha and TAO dust), treasury received the alpha on its hotkey.
    let (dep_alpha_after, _) = chain.alpha_on(&deposit, pay_net).await.unwrap();
    let dep_tao_after = chain.free_balance(&deposit).await.unwrap();
    let tre_alpha_1 = chain
        .alpha_of(&id(&treasury_hk), &tre, pay_net)
        .await
        .unwrap();
    let tre_tao_1 = chain.free_balance(&tre).await.unwrap();
    println!("--- sweep ---");
    for t in &st.txs {
        println!(
            "{:<20} {} block {} amount {}",
            t.action,
            t.tx_hash,
            t.block_hash,
            format_amount(t.amount)
        );
    }
    println!(
        "deposit alpha: {} -> {}",
        format_amount(dep_alpha),
        format_amount(dep_alpha_after)
    );
    println!("deposit tao dust after: {}", format_amount(dep_tao_after));
    println!(
        "treasury alpha on netuid {pay_net} (treasury hotkey): {} -> {}",
        format_amount(tre_alpha_0),
        format_amount(tre_alpha_1)
    );
    println!(
        "treasury TAO: {} -> {}",
        format_amount(tre_tao_0),
        format_amount(tre_tao_1)
    );
    // Emissions keep accruing on the (now treasury-irrelevant) position after the one sweep; on
    // fast-blocks localnet that is a lot. The payment itself is fully swept:
    assert!(
        st.swept_alpha >= pay_amount - 1,
        "swept {} of {pay_amount}",
        st.swept_alpha
    );
    assert_eq!(
        st.txs
            .iter()
            .filter(|t| t.action == "transfer_stake")
            .count(),
        1,
        "swept exactly once"
    );
    assert_eq!(dep_tao_after, 0, "dust returned, account reaped");
    assert!(st.swept_alpha >= RAO_PER_TAO);
    // move_stake within a subnet can lose a rao to share rounding
    assert!(
        tre_alpha_1 + 2 >= tre_alpha_0 + st.swept_alpha,
        "{tre_alpha_1} vs {} ",
        st.swept_alpha
    );
    assert!(st.txs.iter().any(|t| t.action == "transfer_stake"));
    assert!(st.txs.iter().any(|t| t.action == "move_stake"));
    // auto buyback-and-burn after settlement
    let bb = st.buyback.clone().expect("auto buyback ran");
    println!("auto buyback: {bb:?}");
    assert_eq!(bb.netuid, buy_net);
    assert!(bb.alpha_bought > 0 && bb.alpha_destroyed == bb.alpha_bought);

    // The same payment is never swept twice: more ticks are no-ops.
    let n_tx = st.txs.len();
    engine.tick().await.unwrap();
    assert_eq!(engine.status(&req.id).await.unwrap().txs.len(), n_tx);

    // --- crash after broadcast: the fee transfer is on chain but the process died before
    // recording it. On restart the journal entry is resolved from chain state, and the treasury
    // is not charged twice.
    let req2 = engine
        .create_payment(CreatePayment::default())
        .await
        .unwrap();
    let dep2 = keys::parse_ss58(&req2.address).unwrap();
    raw(
        &chain,
        &payer,
        "transfer_stake",
        vec![
            Value::from_bytes(dep2.0),
            Value::from_bytes(id(&payer_hk).0),
            pay_net.into(),
            pay_net.into(),
            (RAO_PER_TAO * 3 / 2).into(),
        ],
    )
    .await;
    engine.tick().await.unwrap();
    assert_eq!(
        engine.status(&req2.id).await.unwrap().state,
        PaymentState::Detected
    );
    let fee_tao = RAO_PER_TAO / 100;
    let reservation = store
        .reserve_signer(&keys::ss58(&id(&treasury)), &req2.id)
        .await
        .unwrap();
    let prepared = chain
        .prepare(
            &ChainCall::TransferTao {
                dest: dep2,
                amount: fee_tao,
            },
            &treasury,
        )
        .await
        .unwrap();
    let journal = Some(bittensor_buyback::chain::PendingTx {
        reservation: Some(reservation),
        action: Action::Fund,
        signer: keys::ss58(&id(&treasury)),
        nonce: prepared.nonce,
        tx_hash: prepared.tx_hash.clone(),
        birth_block: prepared.birth_block,
        amount: fee_tao,
    });
    let mut rec = store.get(&req2.id).await.unwrap().unwrap();
    rec.pending = journal;
    store.update(&rec).await.unwrap();
    chain.broadcast(&prepared).await.unwrap();
    let engine2 = Arc::new(Engine::new(
        chain.clone(),
        store.clone(),
        MasterKey::from_hex(&master_hex).unwrap(),
        treasury.clone(),
        cfg.clone(),
    ));
    for _ in 0..30 {
        engine2.tick().await.unwrap();
        let s = engine2.status(&req2.id).await.unwrap();
        if s.state == PaymentState::Settled {
            break;
        }
        assert_ne!(s.state, PaymentState::Failed, "{:?}", s.last_error);
    }
    let s2 = engine2.status(&req2.id).await.unwrap();
    println!(
        "--- crash recovery ---\n{:?} funded {} txs {:?}",
        s2.state,
        format_amount(s2.funded_tao),
        s2.txs.iter().map(|t| &t.action).collect::<Vec<_>>()
    );
    assert_eq!(s2.state, PaymentState::Settled);
    assert_eq!(s2.funded_tao, fee_tao, "fee sent exactly once");
    assert_eq!(
        s2.txs
            .iter()
            .filter(|t| t.action == "transfer_keep_alive")
            .count(),
        1
    );
    assert!(s2.swept_alpha >= RAO_PER_TAO);

    // Standalone wrappers cannot bypass the durable job protocol.
    let balance = chain.free_balance(&tre).await.unwrap();
    for result in [
        engine.buyback(RAO_PER_TAO).await,
        engine.buyback_and_burn(RAO_PER_TAO).await,
        engine.buyback_and_recycle(RAO_PER_TAO).await,
        engine.buyback_all(Destroy::Burn).await,
        engine.buyback_with(RAO_PER_TAO, Destroy::Keep).await,
    ] {
        assert!(matches!(result, Err(Error::Config(_))));
    }
    assert_eq!(chain.free_balance(&tre).await.unwrap(), balance);
}

/// Static deposit address: a deterministic wallet receives two `transfer_stake`s, the block
/// scanner finds each exactly once with its price, and one sweep job moves everything to the
/// treasury and burns a buyback.
#[tokio::test(flavor = "multi_thread")]
async fn static_address_scan_and_sweep() {
    let _chain_guard = LOCALNET.lock().await;
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,bittensor_buyback=debug")
        .try_init();
    let chain = Chain::connect_any(&[chain::Endpoint::new(url())], 2)
        .await
        .expect("localnet reachable");
    let payer = keypair_from_uri("//Charlie").unwrap();
    let payer_hk = keypair_from_uri("//Charlie//hk").unwrap();
    let treasury = keypair_from_uri("//Dave").unwrap();
    let treasury_hk = keypair_from_uri("//Dave//treasury-hk").unwrap();
    let owner_hk = keypair_from_uri("//Dave//owner-hk").unwrap();
    // Subnet lock cost doubles per registration: top both up from //Alice with a quarter of
    // her free balance each.
    let alice = keypair_from_uri("//Alice").unwrap();
    let alice_free = chain.free_balance(&id(&alice)).await.unwrap();
    for who in [&payer, &treasury] {
        chain
            .submit(
                &ChainCall::TransferTao {
                    dest: id(who),
                    amount: alice_free / 4,
                },
                &alice,
            )
            .await
            .unwrap();
    }
    let pay_net = new_subnet(&chain, &payer, &payer_hk, "BUYBACK_TEST_PAY_NETUID2").await;
    let buy_net = new_subnet(&chain, &treasury, &owner_hk, "BUYBACK_TEST_BUY_NETUID2").await;
    raw(
        &chain,
        &payer,
        "add_stake",
        vec![
            Value::from_bytes(id(&payer_hk).0),
            pay_net.into(),
            (5 * RAO_PER_TAO).into(),
        ],
    )
    .await;

    // Deterministic deposit wallet: a fresh random seed per run, so reruns start clean.
    let phrase = bip39::Mnemonic::from_entropy(&rand_bytes())
        .unwrap()
        .to_string();
    let seed = Arc::new(keys::DerivationSeed::from_phrase(&phrase).unwrap());
    let path = "//opentype//deposit//0";
    let dep = seed.wallet(path).unwrap().account_id();
    assert_eq!(
        dep,
        keypair_from_uri(&format!("{phrase}{path}"))
            .unwrap()
            .public_key()
            .to_account_id(),
        "matches the substrate URI derivation"
    );
    let watched: std::collections::BTreeSet<_> = [dep].into();

    // Two deposits in two blocks.
    let mut found = vec![];
    for amount in [RAO_PER_TAO, RAO_PER_TAO / 2] {
        let from = chain.best_finalized_number().await.unwrap();
        raw(
            &chain,
            &payer,
            "transfer_stake",
            vec![
                Value::from_bytes(dep.0),
                Value::from_bytes(id(&payer_hk).0),
                pay_net.into(),
                pay_net.into(),
                amount.into(),
            ],
        )
        .await;
        let to = chain.best_finalized_number().await.unwrap();
        assert!(chain.best_number().await.unwrap() >= to);
        let mut hits = vec![];
        for n in from..=to {
            hits.extend(chain.deposits_in_block(n, &watched).await.unwrap().deposits);
        }
        assert_eq!(hits.len(), 1, "exactly one deposit per transfer: {hits:?}");
        let d = &hits[0];
        assert_eq!((d.coldkey, d.netuid, d.alpha), (dep, pay_net, amount));
        assert_eq!(d.from, Some(id(&payer)));
        assert!(d.spot_price > 0 && d.tao_value > 0);
        // value reported by the chain is alpha x spot
        let expect = (amount as u128 * d.spot_price as u128 / RAO_PER_TAO as u128) as u64;
        assert!(
            d.tao_value.abs_diff(expect) <= 1,
            "{} vs {expect}",
            d.tao_value
        );
        // re-scanning the same block yields the same event identity (idempotency key)
        let again = chain
            .deposits_in_block(d.block_number, &watched)
            .await
            .unwrap();
        assert_eq!(again.deposits, vec![d.clone()]);
        assert_eq!(
            chain.block_hash_at(d.block_number).await.unwrap(),
            Some(d.block_hash.clone())
        );
        found.push(d.clone());
    }
    let total: u64 = found.iter().map(|d| d.alpha).sum();
    println!("deposits: {found:?}");

    // Sweep job from the seed.
    let dir = tempfile::tempdir().unwrap();
    let store: Arc<dyn Store> = Arc::new(SqliteStore::open(dir.path().join("db.sqlite")).unwrap());
    let mut cfg = Config::new(url(), pay_net, id(&treasury_hk));
    cfg.buyback_netuid = buy_net;
    cfg.slippage_bps = 500;
    cfg.fee_reserve = RAO_PER_TAO;
    cfg.auto = AutoBuyback::On {
        destroy: Destroy::Burn,
        amount: AutoAmount::Fixed(RAO_PER_TAO / 4),
    };
    cfg.buyback_budget = Some(bittensor_buyback::state::BuybackBudget {
        amount_rao: RAO_PER_TAO / 4,
        currency: "TAO".into(),
        source: "localnet-test-allocation".into(),
        hotkey: keys::ss58(&id(&treasury_hk)),
        netuid: buy_net,
        destroy: Destroy::Burn,
    });
    let engine = Engine::new(
        chain.clone(),
        store.clone(),
        MasterKey::generate(),
        treasury.clone(),
        cfg,
    )
    .with_seed(seed.clone());
    // Explicit isolated-localnet provisioning, never engine startup behavior.
    if chain
        .hotkey_owner(&id(&treasury_hk))
        .await
        .unwrap()
        .is_none()
    {
        assert!(engine.ensure_treasury_hotkey().await.is_err());
        raw(
            &chain,
            &treasury,
            "try_associate_hotkey",
            vec![Value::from_bytes(id(&treasury_hk).0)],
        )
        .await;
    }
    engine.ensure_treasury_hotkey().await.unwrap();
    // wrong expected address is refused before anything is stored
    assert!(
        engine
            .create_sweep_job("job-x", path, &keys::ss58(&id(&payer)), None)
            .await
            .is_err()
    );
    let st = engine
        .create_sweep_job("job-1", path, &keys::ss58(&dep), None)
        .await
        .unwrap();
    assert_eq!(st.state, PaymentState::Detected);
    let (t_alpha_before, _) = chain.alpha_on(&id(&treasury), pay_net).await.unwrap();
    for _ in 0..40 {
        engine.tick().await.unwrap();
        if engine.status("job-1").await.unwrap().state == PaymentState::Settled {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let st = engine.status("job-1").await.unwrap();
    assert_eq!(st.state, PaymentState::Settled, "{st:?}");
    // Staked alpha accrues emissions between deposit and sweep, so the sweep can move more.
    assert!(st.swept_alpha >= total, "{} < {total}", st.swept_alpha);
    let b = st.buyback.as_ref().expect("buyback ran");
    assert!(b.alpha_destroyed > 0 && b.destroy_tx.is_some());
    let (left, _) = chain.alpha_on(&dep, pay_net).await.unwrap();
    // Emissions keep accruing after the one-shot sweep; that dust is swept by the next job.
    assert!(left < st.swept_alpha, "deposit address swept ({left} left)");
    let (t_alpha_after, _) = chain.alpha_on(&id(&treasury), pay_net).await.unwrap();
    assert!(
        t_alpha_after >= t_alpha_before,
        "treasury received the alpha"
    );
    println!(
        "sweep job: {} txs, {} alpha swept, {} alpha burned",
        st.txs.len(),
        format_amount(st.swept_alpha),
        format_amount(b.alpha_destroyed)
    );
}

fn rand_bytes() -> [u8; 32] {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    b
}
