//! Explicit legacy recovery. No signing API is reachable from this module.
//!
//! The archive is a trusted, authenticated RPC source, not a light-client proof.
//! Operators must stop ALL old emitters and attest a historical mortality bound;
//! the chain cannot prove that an unpublished immortal signature does not exist.
use crate::{
    Chain, ChainCall, Error, Result, keys,
    state::{BuybackBudget, PaymentRecord, PaymentState, TxRef},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyManifest {
    pub job: String,
    pub version: u64,
    pub genesis_hash: String,
    pub treasury: String,
    pub treasury_hotkey: String,
    pub consolidate: bool,
    pub return_dust: bool,
    #[serde(deserialize_with = "Deserialize::deserialize")]
    pub budget: Option<BuybackBudget>,
    /// First block covering every old emission, including those absent from the DB.
    pub first_block: u64,
    /// Finalized block at which all old signing processes were stopped.
    pub stopped_at: u64,
    /// Historical maximum lifetime in blocks, NOT the current engine default.
    pub maximum_mortality: u64,
    /// Audit reference for shutdown, complete scan start, and historical mortality evidence.
    pub operator_attestation: String,
    /// Explicit acceptance of the off-chain assumption; not an archive verification flag.
    pub all_old_emitters_stopped_no_immortal_signatures: bool,
    /// Complete chronological emission list for BOTH signers over the scan interval.
    pub transactions: Vec<LegacyTransaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LegacyTransaction {
    pub block: u64,
    pub index: usize,
    pub signer: String,
    pub nonce: u64,
    pub receipt: TxRef,
    pub call: ChainCall,
}

#[derive(Clone, Debug, Serialize)]
pub struct RecoveryReport {
    pub job: String,
    pub previous_version: u64,
    pub genesis_hash: String,
    pub finalized_block: u64,
    pub finalized_hash: String,
    pub transactions: usize,
    pub applied: bool,
}

pub(crate) fn validate_manifest(r: &PaymentRecord, m: &LegacyManifest) -> Result<()> {
    let bad = || {
        Error::Store(
            "legacy recovery requires a complete audited manifest and unresolved-free record"
                .into(),
        )
    };
    if r.id != m.job || r.version != m.version {
        return Err(Error::Conflict(m.job.clone()));
    }
    if r.identity.is_some()
        || (r.auto_required.is_some()
            && (r.auto_required != Some(m.budget.is_some()) || r.buyback_budget != m.budget))
        || r.pending.is_some()
        || r.quarantined.is_some()
        || r.notified
        || (m.transactions.is_empty()
            && !matches!(r.state, PaymentState::Pending | PaymentState::Detected))
        || m.transactions.len() > 4096
        || m.first_block == 0
        || m.first_block > m.stopped_at
        || m.maximum_mortality == 0
        || m.maximum_mortality > 65536
        || !m.all_old_emitters_stopped_no_immortal_signatures
        || m.operator_attestation.trim().len() < 16
        || m.operator_attestation.len() > 4096
        || !matches!(
            r.state,
            PaymentState::Pending
                | PaymentState::Detected
                | PaymentState::Funded
                | PaymentState::Swept
                | PaymentState::Failed
        )
        || (r.state == PaymentState::Failed
            && !matches!(
                r.failed_from,
                Some(PaymentState::Funded | PaymentState::Swept)
            ))
    {
        return Err(bad());
    }
    if matches!(r.state, PaymentState::Pending | PaymentState::Detected)
        && (!m.transactions.is_empty()
            || r.funded_tao != 0
            || r.swept_alpha != 0
            || !r.swept_positions.is_empty()
            || r.consolidated != 0
            || r.dust_returned
            || r.buyback.is_some()
            || r.buyback_done)
    {
        return Err(bad());
    }
    let treasury = keys::parse_ss58(&m.treasury)?;
    let deposit = keys::parse_ss58(&r.address)?;
    keys::parse_ss58(&m.treasury_hotkey)?;
    if treasury == deposit
        || keys::ss58(&treasury) != m.treasury
        || keys::ss58(&deposit) != r.address
    {
        return Err(bad());
    }
    if let Some(b) = &m.budget {
        b.validate()?;
    }
    let mut last = None;
    let mut hashes = std::collections::BTreeSet::new();
    let mut nonces = std::collections::BTreeSet::new();
    for t in &m.transactions {
        if t.block < m.first_block
            || t.block > m.stopped_at
            || last.is_some_and(|p| p >= (t.block, t.index))
            || !hashes.insert(&t.receipt.tx_hash)
            || !nonces.insert((&t.signer, t.nonce))
            || (t.signer != m.treasury && t.signer != r.address)
            || t.receipt.action != t.call.name()
            || t.receipt.amount != t.call.amount()
        {
            return Err(bad());
        }
        last = Some((t.block, t.index));
    }
    // ponytail: only complete stored receipts are importable; missing/ambiguous evidence stays blocked.
    if m.transactions.iter().map(|t| &t.receipt).ne(r.txs.iter()) {
        return Err(bad());
    }
    Ok(())
}

/// Read-only archive dry run. Applying requires a fresh scan under SQLite signer fences.
pub async fn dry_run(
    chain: &Chain,
    record: &PaymentRecord,
    manifest: &LegacyManifest,
) -> Result<RecoveryReport> {
    verify(chain, record, manifest)
        .await
        .map(|(_, report)| report)
}

pub(crate) async fn verify(
    chain: &Chain,
    r: &PaymentRecord,
    m: &LegacyManifest,
) -> Result<(PaymentRecord, RecoveryReport)> {
    validate_manifest(r, m)?;
    let summaries = chain.verify_legacy_archive(r, m).await?;
    replay(r, m, summaries)
}

fn replay(
    r: &PaymentRecord,
    m: &LegacyManifest,
    summaries: (Vec<crate::chain::EventSummary>, u64, String),
) -> Result<(PaymentRecord, RecoveryReport)> {
    validate_manifest(r, m)?;
    if summaries.0.len() != m.transactions.len() {
        return Err(Error::Store("missing archived receipts".into()));
    }
    let treasury = keys::parse_ss58(&m.treasury)?;
    let deposit = keys::parse_ss58(&r.address)?;
    let hotkey = keys::parse_ss58(&m.treasury_hotkey)?;
    let mut funded = 0u64;
    let mut positions = Vec::new();
    let mut consolidated = 0usize;
    let mut dust = false;
    let mut post_sweep = false;
    let mut buyback: Option<crate::state::BuybackReceipt> = None;
    for (t, s) in m.transactions.iter().zip(&summaries.0) {
        let signer = keys::parse_ss58(&t.signer)?;
        let invalid =
            || Error::Store("legacy call, events or stage disagrees with audited job".into());
        let (p, e) = t.call.expected_event();
        if s.failed || !s.has("System", "ExtrinsicSuccess") || !s.has(p, e) {
            return Err(invalid());
        }
        match &t.call {
            ChainCall::TransferTao { dest, amount }
                if signer == treasury
                    && *dest == deposit
                    && funded == 0
                    && positions.is_empty()
                    && !dust
                    && buyback.is_none()
                    && *amount > 0 =>
            {
                if s.transferred != Some(*amount) {
                    return Err(invalid());
                }
                funded = *amount;
            }
            ChainCall::TransferStake {
                dest_coldkey,
                hotkey: source,
                netuid,
                alpha,
            } if signer == deposit
                && *dest_coldkey == treasury
                && *netuid == r.netuid
                && !post_sweep
                && consolidated == 0
                && !dust
                && buyback.is_none()
                && *alpha > 0 =>
            {
                let source = keys::ss58(source);
                if positions.iter().any(|(h, _)| h == &source) {
                    return Err(invalid());
                }
                positions.push((source, *alpha));
            }
            ChainCall::MoveStake {
                from_hotkey,
                to_hotkey,
                netuid,
                alpha,
            } if m.consolidate
                && signer == treasury
                && *to_hotkey == hotkey
                && *netuid == r.netuid
                && !dust
                && buyback.is_none() =>
            {
                if positions.get(consolidated) != Some(&(keys::ss58(from_hotkey), *alpha)) {
                    return Err(invalid());
                }
                post_sweep = true;
                consolidated += 1;
            }
            ChainCall::TransferAll { dest }
                if (m.return_dust || r.detected_tao > 0)
                    && signer == deposit
                    && *dest == treasury
                    && !dust
                    && buyback.is_none() =>
            {
                if m.consolidate && consolidated != positions.len() {
                    return Err(invalid());
                }
                post_sweep = true;
                dust = true;
            }
            ChainCall::AddStakeLimit {
                hotkey: target,
                netuid,
                tao,
                limit_price,
                allow_partial: false,
            } if signer == treasury && buyback.is_none() => {
                if (m.consolidate && consolidated != positions.len())
                    || ((m.return_dust || r.detected_tao > 0) && !dust)
                {
                    return Err(invalid());
                }
                post_sweep = true;
                let b = m.budget.as_ref().ok_or_else(invalid)?;
                let (spent, bought) = s.stake_added.ok_or_else(invalid)?;
                if keys::ss58(target) != b.hotkey
                    || *netuid != b.netuid
                    || *tao != b.amount_rao
                    || spent != *tao
                    || bought == 0
                {
                    return Err(invalid());
                }
                buyback = Some(crate::state::BuybackReceipt {
                    netuid: *netuid,
                    tao_spent: spent,
                    alpha_bought: bought,
                    limit_price: *limit_price,
                    stake_tx: t.receipt.clone(),
                    destroy_tx: None,
                    alpha_destroyed: 0,
                });
            }
            ChainCall::BurnAlpha {
                hotkey: target,
                netuid,
                alpha,
            }
            | ChainCall::RecycleAlpha {
                hotkey: target,
                netuid,
                alpha,
            } if signer == treasury => {
                let b = m.budget.as_ref().ok_or_else(invalid)?;
                let receipt = buyback.as_mut().ok_or_else(invalid)?;
                let destroy = if matches!(t.call, ChainCall::BurnAlpha { .. }) {
                    crate::Destroy::Burn
                } else {
                    crate::Destroy::Recycle
                };
                if b.destroy != destroy
                    || keys::ss58(target) != b.hotkey
                    || *netuid != b.netuid
                    || receipt.destroy_tx.is_some()
                    || *alpha != receipt.alpha_bought
                    || s.alpha_destroyed != Some(*alpha)
                {
                    return Err(invalid());
                }
                receipt.destroy_tx = Some(t.receipt.clone());
                receipt.alpha_destroyed = *alpha;
            }
            _ => return Err(invalid()),
        }
    }
    let total = positions
        .iter()
        .try_fold(0u64, |a, (_, b)| a.checked_add(*b))
        .ok_or_else(|| Error::Store("legacy amount overflow".into()))?;
    let done = buyback.as_ref().is_some_and(|b| {
        b.destroy_tx.is_some()
            || m.budget
                .as_ref()
                .is_some_and(|p| p.destroy == crate::Destroy::Keep)
    });
    let stage = r
        .failed_from
        .filter(|_| r.state == PaymentState::Failed)
        .unwrap_or(r.state);
    if (stage == PaymentState::Funded
        && (consolidated != 0 || dust || buyback.is_some() || r.buyback_done))
        || funded != r.funded_tao
        || positions != r.swept_positions
        || total != r.swept_alpha
        || consolidated != r.consolidated
        || dust != r.dust_returned
        || buyback != r.buyback
        || (r.buyback_done && !done)
    {
        return Err(Error::Store(
            "legacy receipts do not reproduce stored accounting".into(),
        ));
    }
    let mut next = r.clone();
    next.identity = Some(crate::state::JobIdentity {
        genesis_hash: m.genesis_hash.clone(),
        treasury: m.treasury.clone(),
        treasury_hotkey: m.treasury_hotkey.clone(),
        consolidate: m.consolidate,
        return_dust: m.return_dust,
    });
    next.auto_required = Some(m.budget.is_some());
    next.buyback_budget = m.budget.clone();
    // State, receipts, attempts and sealed wallet are preserved; retry remains an explicit operation.
    let report = RecoveryReport {
        job: r.id.clone(),
        previous_version: r.version,
        genesis_hash: m.genesis_hash.clone(),
        finalized_block: summaries.1,
        finalized_hash: summaries.2,
        transactions: m.transactions.len(),
        applied: false,
    };
    Ok((next, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (PaymentRecord, LegacyManifest, crate::chain::EventSummary) {
        let mut r = crate::state::test_record("legacy");
        let treasury = keys::keypair_from_uri("//Bob")
            .unwrap()
            .public_key()
            .to_account_id();
        r.auto_required = None;
        r.state = PaymentState::Funded;
        r.funded_tao = 123;
        let call = ChainCall::TransferTao {
            dest: keys::parse_ss58(&r.address).unwrap(),
            amount: 123,
        };
        let receipt = TxRef {
            action: call.name().into(),
            tx_hash: "hash".into(),
            block_hash: "block".into(),
            amount: 123,
        };
        r.txs.push(receipt.clone());
        let m = LegacyManifest {
            job: r.id.clone(),
            version: r.version,
            genesis_hash: "test-genesis".into(),
            treasury: keys::ss58(&treasury),
            treasury_hotkey: keys::ss58(&treasury),
            consolidate: false,
            return_dust: false,
            budget: None,
            first_block: 1,
            stopped_at: 2,
            maximum_mortality: 128,
            operator_attestation: "offline shutdown and historical mortality evidence".into(),
            all_old_emitters_stopped_no_immortal_signatures: true,
            transactions: vec![LegacyTransaction {
                block: 2,
                index: 0,
                signer: keys::ss58(&treasury),
                nonce: 0,
                receipt,
                call,
            }],
        };
        let s = crate::chain::EventSummary {
            names: vec![
                ("System".into(), "ExtrinsicSuccess".into()),
                ("Balances".into(), "Transfer".into()),
            ],
            transferred: Some(123),
            ..Default::default()
        };
        (r, m, s)
    }
    #[test]
    fn pristine_identity_requires_explicit_history_and_configuration() {
        let (mut r, mut m, _) = fixture();
        r.state = PaymentState::Detected;
        r.funded_tao = 0;
        r.txs.clear();
        m.transactions.clear();
        let (next, _) = replay(&r, &m, (vec![], 200, "anchor".into())).unwrap();
        assert_eq!(next.identity.unwrap().genesis_hash, "test-genesis");
        let mut json = serde_json::to_value(&m).unwrap();
        json.as_object_mut().unwrap().remove("consolidate");
        assert!(serde_json::from_value::<LegacyManifest>(json).is_err());
        m.operator_attestation.clear();
        assert!(validate_manifest(&r, &m).is_err());
    }

    #[test]
    fn replay_preserves_evidence_and_rejects_missing_proof() {
        let (r, m, s) = fixture();
        let before = serde_json::to_value(&r).unwrap();
        let (next, report) = replay(&r, &m, (vec![s.clone()], 200, "anchor".into())).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), before);
        assert_eq!(next.txs, r.txs);
        assert_eq!(next.version, r.version);
        assert_eq!(next.state, r.state);
        assert_eq!(next.identity.unwrap().genesis_hash, m.genesis_hash);
        assert!(!report.applied);
        assert!(replay(&r, &m, (vec![], 200, "anchor".into())).is_err());
        let mut invalid = s;
        invalid.transferred = Some(122);
        assert!(replay(&r, &m, (vec![invalid], 200, "anchor".into())).is_err());
        for case in 0..6 {
            let mut bad = m.clone();
            match case {
                0 => bad.maximum_mortality = 0,
                1 => bad.all_old_emitters_stopped_no_immortal_signatures = false,
                2 => bad.operator_attestation.clear(),
                3 => bad.transactions.clear(),
                4 => bad.transactions[0].receipt.amount += 1,
                _ => bad.version += 1,
            }
            assert!(validate_manifest(&r, &bad).is_err());
        }
        let mut json = serde_json::to_value(&m).unwrap();
        json["verified"] = true.into();
        assert!(serde_json::from_value::<LegacyManifest>(json).is_err());
    }
}

#[cfg(all(test, feature = "localnet-tests", feature = "sqlite"))]
mod localnet_recovery {
    use super::*;
    use crate::Store;
    #[tokio::test]
    async fn archive_dry_run_apply_and_repeated_import() {
        // Local endpoint only; never accept an environment override for this signing fixture.
        let chain = Chain::connect("ws://127.0.0.1:9944").await.unwrap();
        let alice = keys::keypair_from_uri("//Alice").unwrap();
        let treasury = crate::PaymentWallet::generate().unwrap();
        let deposit = crate::PaymentWallet::generate().unwrap();
        chain
            .submit(
                &ChainCall::TransferTao {
                    dest: treasury.account_id(),
                    amount: 1_000_000_000,
                },
                &alice,
            )
            .await
            .unwrap();
        let mut r = crate::state::test_record("archive-recovery");
        r.address = keys::ss58(&deposit.account_id());
        let keyring: crate::keys::Keyring = crate::MasterKey::from_bytes([42; 32]).into();
        r.sealed_secret = deposit
            .seal_with(&keyring, &keys::wallet_aad(&r.id, &r.address))
            .unwrap();
        r.auto_required = None;
        r.state = PaymentState::Funded;
        r.funded_tao = 10_000_000;
        let call = ChainCall::TransferTao {
            dest: deposit.account_id(),
            amount: r.funded_tao,
        };
        let prepared = chain.prepare(&call, treasury.keypair()).await.unwrap();
        let finalized = chain.broadcast(&prepared).await.unwrap();
        r.txs.push(finalized.tx.clone());
        let (stopped, _) = chain.finalized_head().await.unwrap();
        let mut location = None;
        for block in prepared.birth_block..=stopped {
            let at = chain.api().at_block(block).await.unwrap();
            let exts = at.extrinsics().fetch().await.unwrap();
            for ext in exts.iter() {
                let ext = ext.unwrap();
                if format!("{:?}", ext.hash()) == prepared.tx_hash {
                    location = Some((block, ext.index()));
                }
            }
        }
        let (block, index) = location.unwrap();
        let m = LegacyManifest {
            job: r.id.clone(),
            version: r.version,
            genesis_hash: chain.genesis_hash(),
            treasury: keys::ss58(&treasury.account_id()),
            treasury_hotkey: keys::ss58(&treasury.account_id()),
            consolidate: false,
            return_dust: false,
            budget: None,
            first_block: prepared.birth_block,
            stopped_at: stopped,
            maximum_mortality: 64,
            operator_attestation:
                "isolated random localnet signer; only prepare uses encoded 64-block mortality"
                    .into(),
            all_old_emitters_stopped_no_immortal_signatures: true,
            transactions: vec![LegacyTransaction {
                block,
                index,
                signer: prepared.signer,
                nonce: prepared.nonce,
                receipt: finalized.tx,
                call,
            }],
        };
        // No further emission from either random signer. Bound waiting rather than weakening evidence.
        tokio::time::timeout(std::time::Duration::from_secs(600), async {
            while chain.finalized_head().await.unwrap().0 <= stopped + 65 {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        })
        .await
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recovery.db");
        let mut store = crate::SqliteStore::open(&path).unwrap();
        store.insert(&r).await.unwrap();
        let before = serde_json::to_value(store.get(&r.id).await.unwrap()).unwrap();
        let read_only = crate::SqliteStore::open_read_only(&path).unwrap();
        assert!(!dry_run(&chain, &r, &m).await.unwrap().applied);
        assert_eq!(
            serde_json::to_value(read_only.get(&r.id).await.unwrap()).unwrap(),
            before
        );
        let mut wrong = m.clone();
        wrong.genesis_hash = "wrong".into();
        assert!(store.recover_legacy(&chain, &wrong).await.is_err());
        assert_eq!(
            serde_json::to_value(store.get(&r.id).await.unwrap()).unwrap(),
            before
        );
        let peer = crate::SqliteStore::open(&path).unwrap();
        let token = peer.reserve_signer(&m.treasury, "other-job").await.unwrap();
        assert!(store.recover_legacy(&chain, &m).await.is_err());
        peer.cancel_preparation(&m.treasury, "other-job", &token)
            .await
            .unwrap();
        // A canceled import drops the uncommitted SQLite transaction; no policy is installed.
        let mut import = Box::pin(store.recover_legacy(&chain, &m));
        assert!(futures::poll!(import.as_mut()).is_pending());
        drop(import);
        assert_eq!(
            serde_json::to_value(peer.get(&r.id).await.unwrap()).unwrap(),
            before
        );
        assert!(store.recover_legacy(&chain, &m).await.unwrap().applied);
        assert!(store.recover_legacy(&chain, &m).await.is_err());
        assert!(store.update(&r).await.is_err());
        drop(store);
        let record = crate::SqliteStore::open(&path)
            .unwrap()
            .get(&r.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.version, r.version + 1);
        assert_eq!(record.txs, r.txs);
        assert_eq!(
            record.identity.as_ref().unwrap().genesis_hash,
            m.genesis_hash
        );
        let nonce_before = chain.account(&treasury.account_id()).await.unwrap().1;
        let mut cfg =
            crate::Config::new("ws://127.0.0.1:9944", record.netuid, treasury.account_id());
        cfg.consolidate = false;
        cfg.return_dust = false;
        let store = std::sync::Arc::new(crate::SqliteStore::open(&path).unwrap());
        let engine = crate::Engine::new(
            chain,
            store.clone(),
            crate::MasterKey::from_bytes([42; 32]),
            treasury.keypair().clone(),
            cfg,
        );
        for _ in 0..3 {
            engine.tick().await.unwrap();
        }
        assert_eq!(
            store.get(&r.id).await.unwrap().unwrap().state,
            PaymentState::Settled
        );
        assert_eq!(
            engine
                .chain()
                .account(&treasury.account_id())
                .await
                .unwrap()
                .1,
            nonce_before
        );
    }
}

#[cfg(all(test, feature = "sqlite", unix))]
mod crash_tests {
    use crate::Store;
    #[test]
    fn recovery_transaction_child() {
        let Ok(path) = std::env::var("BUYBACK_RECOVERY_CRASH_DB") else {
            return;
        };
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute_batch("BEGIN IMMEDIATE; UPDATE payments SET version=99; CREATE TABLE legacy_recoveries(job TEXT); INSERT INTO legacy_recoveries VALUES ('uncommitted');").unwrap();
        std::fs::write(format!("{path}.ready"), b"ready").unwrap();
        std::thread::sleep(std::time::Duration::from_secs(60));
        panic!("parent must kill the process before commit");
    }
    #[tokio::test]
    async fn killed_writer_preserves_record_and_signer_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("crash.db");
        let store = crate::SqliteStore::open(&path).unwrap();
        let r = crate::state::test_record("crash");
        store.insert(&r).await.unwrap();
        let token = store.reserve_signer("signer", &r.id).await.unwrap();
        drop(store);
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "recovery::crash_tests::recovery_transaction_child",
                "--nocapture",
            ])
            .env("BUYBACK_RECOVERY_CRASH_DB", &path)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let ready = format!("{}.ready", path.display());
        for _ in 0..200 {
            if std::path::Path::new(&ready).exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let reached = std::path::Path::new(&ready).exists();
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(reached, "child must reach uncommitted transaction");
        let reopened = crate::SqliteStore::open(&path).unwrap();
        assert_eq!(
            serde_json::to_value(reopened.get(&r.id).await.unwrap().unwrap()).unwrap(),
            serde_json::to_value(&r).unwrap()
        );
        assert!(reopened.reserve_signer("signer", "other").await.is_err());
        let c = rusqlite::Connection::open(&path).unwrap();
        let persisted: String = c
            .query_row(
                "SELECT token FROM signer_reservations WHERE signer='signer'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(persisted, token);
        let audit: bool = c
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='legacy_recoveries')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!audit);
    }
}
