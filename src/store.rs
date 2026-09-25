//! Persistence behind the [`Store`] trait: a JSON-file store and a SQLite store.
//!
//! Both implement compare-and-swap on [`PaymentRecord::version`], so two engines sharing a store
//! cannot both advance the same record.

use crate::state::{PaymentRecord, PaymentState};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Async so a database-backed store (e.g. PostgreSQL) can implement it directly.
#[async_trait::async_trait]
pub trait Store: Send + Sync + 'static {
    async fn require_signing(&self) -> Result<()> {
        Err(Error::Store(
            "shared signer reservations unsupported; requests disabled".into(),
        ))
    }
    async fn reserve_signer_for_record(
        &self,
        _signer: &str,
        _rec: &PaymentRecord,
    ) -> Result<String> {
        Err(Error::Store("atomic signer reservation unsupported".into()))
    }

    /// Exclusive durable signer ownership, BEFORE nonce selection. No leases or automatic expiry.
    /// Implementations must atomically release only when the matching journal is resolved.
    async fn reserve_signer(&self, _signer: &str, _job: &str) -> Result<String> {
        Err(Error::Store(
            "shared durable signer reservations unsupported; signing disabled".into(),
        ))
    }
    /// Only the live preparing caller may release its token before any broadcast.
    /// Never use this for crash recovery, journal-write errors, or pending transactions.
    async fn cancel_preparation(&self, _signer: &str, _job: &str, _token: &str) -> Result<()> {
        Err(Error::Store("preparation cancellation unsupported".into()))
    }
    /// Explicit operator migration of a pristine legacy record, never a runtime default.
    async fn migrate_legacy_policy(
        &self,
        _id: &str,
        _version: u64,
        _budget: Option<crate::state::BuybackBudget>,
    ) -> Result<PaymentRecord> {
        Err(Error::Store("legacy policy migration unsupported".into()))
    }
    /// Insert a new record (version 0). Fails if the id exists.
    async fn insert(&self, rec: &PaymentRecord) -> Result<()>;
    async fn get(&self, id: &str) -> Result<Option<PaymentRecord>>;
    /// Records in the given states.
    async fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>>;
    /// Write `rec` if the stored version equals `rec.version`; returns the record with its new
    /// version. [`Error::Conflict`] otherwise.
    async fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord>;
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
}

fn migrated_policy(
    mut rec: PaymentRecord,
    version: u64,
    budget: Option<crate::state::BuybackBudget>,
) -> Result<PaymentRecord> {
    if rec.version != version {
        return Err(Error::Conflict(rec.id));
    }
    if rec.auto_required.is_some()
        || rec.buyback_budget.is_some()
        || rec.pending.is_some()
        || rec.quarantined.is_some()
        || !rec.txs.is_empty()
        || rec.buyback.is_some()
        || rec.buyback_done
        || rec.funded_tao != 0
        || rec.swept_alpha != 0
        || !rec.swept_positions.is_empty()
        || rec.consolidated != 0
        || rec.dust_returned
        || !matches!(rec.state, PaymentState::Pending | PaymentState::Detected)
    {
        return Err(Error::Store(
            "legacy job has policy or execution evidence; manual reconciliation required".into(),
        ));
    }
    if let Some(b) = &budget {
        b.validate()?;
    }
    rec.auto_required = Some(budget.is_some());
    rec.buyback_budget = budget;
    rec.version = rec
        .version
        .checked_add(1)
        .ok_or_else(|| Error::Store("version overflow".into()))?;
    rec.updated_at = crate::state::now();
    Ok(rec)
}

/// One JSON file per payment in a directory (mode 0700 on unix). Atomic writes via rename.
/// Single-process only: CAS is guarded by an in-process mutex.
pub struct FileStore {
    dir: PathBuf,
    lock: Mutex<()>,
}

impl FileStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).map_err(store_err)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .map_err(store_err)?;
        }
        Ok(Self {
            dir,
            lock: Mutex::new(()),
        })
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(Error::Store(format!("invalid id {id:?}")));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    fn read(&self, path: &Path) -> Result<Option<PaymentRecord>> {
        match std::fs::read(path) {
            Ok(b) => serde_json::from_slice(&b).map(Some).map_err(store_err),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(store_err(e)),
        }
    }

    fn write(&self, path: &Path, rec: &PaymentRecord) -> Result<()> {
        let tmp = path.with_extension("json.tmp");
        {
            use std::io::Write;
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(&tmp).map_err(store_err)?;
            f.write_all(&serde_json::to_vec_pretty(rec).map_err(store_err)?)
                .map_err(store_err)?;
            f.sync_all().map_err(store_err)?;
        }
        std::fs::rename(&tmp, path).map_err(store_err)?;
        // Persist the directory entry before a journaled transaction can broadcast.
        #[cfg(unix)]
        std::fs::File::open(&self.dir)
            .and_then(|dir| dir.sync_all())
            .map_err(store_err)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Store for FileStore {
    async fn migrate_legacy_policy(
        &self,
        id: &str,
        version: u64,
        budget: Option<crate::state::BuybackBudget>,
    ) -> Result<PaymentRecord> {
        let _g = self.lock.lock().map_err(store_err)?;
        let path = self.path(id)?;
        let previous = self
            .read(&path)?
            .ok_or_else(|| Error::NotFound(id.into()))?;
        let next = migrated_policy(previous, version, budget)?;
        self.write(&path, &next)?;
        Ok(next)
    }
    async fn insert(&self, rec: &PaymentRecord) -> Result<()> {
        let _g = self.lock.lock().map_err(store_err)?;
        let p = self.path(&rec.id)?;
        if p.exists() {
            return Err(Error::Store(format!("{} exists", rec.id)));
        }
        self.write(&p, rec)
    }

    async fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
        self.read(&self.path(id)?)
    }

    async fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
        let mut out = vec![];
        for e in std::fs::read_dir(&self.dir).map_err(store_err)? {
            let p = e.map_err(store_err)?.path();
            if p.extension().is_some_and(|x| x == "json")
                && let Some(r) = self.read(&p)?
                && states.contains(&r.state)
            {
                out.push(r);
            }
        }
        out.sort_by_key(|r| r.created_at);
        Ok(out)
    }

    async fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        let _g = self.lock.lock().map_err(store_err)?;
        let p = self.path(&rec.id)?;
        let cur = self
            .read(&p)?
            .ok_or_else(|| Error::NotFound(rec.id.clone()))?;
        if cur.buyback_budget != rec.buyback_budget || cur.auto_required != rec.auto_required {
            return Err(Error::Store("immutable job budget".into()));
        }
        if cur.version != rec.version {
            return Err(Error::Conflict(rec.id.clone()));
        }
        let mut next = rec.clone();
        next.version += 1;
        next.updated_at = crate::state::now();
        self.write(&p, &next)?;
        Ok(next)
    }
}

/// SQLite store (WAL). Safe to share between processes; CAS is a conditional UPDATE.
#[cfg(feature = "sqlite")]
pub struct SqliteStore {
    conn: Mutex<rusqlite::Connection>,
}

#[cfg(feature = "sqlite")]
impl SqliteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = rusqlite::Connection::open(path).map_err(store_err)?;
        Self::init(conn)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(rusqlite::Connection::open_in_memory().map_err(store_err)?)
    }

    fn init(conn: rusqlite::Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
             CREATE TABLE IF NOT EXISTS signer_reservations (
               signer TEXT PRIMARY KEY, job TEXT NOT NULL, token TEXT NOT NULL UNIQUE);
             CREATE TABLE IF NOT EXISTS payments (
               id TEXT PRIMARY KEY, state TEXT NOT NULL, version INTEGER NOT NULL,
               created_at INTEGER NOT NULL, record TEXT NOT NULL);
             CREATE INDEX IF NOT EXISTS payments_state ON payments(state);",
        )
        .map_err(store_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
    fn reserve(&self, signer: &str, job: &str, version: Option<u64>) -> Result<String> {
        let mut c = self.conn.lock().map_err(store_err)?;
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store_err)?;
        if let Some(version) = version {
            let current: Option<i64> = {
                use rusqlite::OptionalExtension;
                tx.query_row("SELECT version FROM payments WHERE id=?1", [job], |r| {
                    r.get(0)
                })
                .optional()
                .map_err(store_err)?
            };
            if current != i64::try_from(version).ok() {
                return Err(Error::Conflict(job.into()));
            }
        }
        // Legacy journals also fence the signer; migration cannot make uncertainty disappear.
        let pending: bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM payments WHERE json_extract(record,'$.pending.signer')=?1)",[signer],|r|r.get(0)).map_err(store_err)?;
        if pending {
            return Err(Error::Conflict("unresolved signer journal".into()));
        }
        let token = uuid::Uuid::new_v4().to_string();
        let count = tx
            .execute(
                "INSERT OR IGNORE INTO signer_reservations(signer,job,token) VALUES (?1,?2,?3)",
                rusqlite::params![signer, job, token],
            )
            .map_err(store_err)?;
        if count != 1 {
            return Err(Error::Conflict(format!("signer {signer} reserved")));
        }
        tx.commit().map_err(store_err)?;
        Ok(token)
    }
}

#[cfg(feature = "sqlite")]
#[async_trait::async_trait]
impl Store for SqliteStore {
    async fn require_signing(&self) -> Result<()> {
        Ok(())
    }
    async fn reserve_signer_for_record(&self, signer: &str, rec: &PaymentRecord) -> Result<String> {
        self.reserve(signer, &rec.id, Some(rec.version))
    }
    async fn reserve_signer(&self, signer: &str, job: &str) -> Result<String> {
        self.reserve(signer, job, None)
    }

    async fn cancel_preparation(&self, signer: &str, job: &str, token: &str) -> Result<()> {
        let mut c = self.conn.lock().map_err(store_err)?;
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let removed = tx.execute(
            "DELETE FROM signer_reservations WHERE signer=?1 AND job=?2 AND token=?3 AND NOT EXISTS (SELECT 1 FROM payments WHERE json_extract(record,'$.pending.signer')=?1 OR (id=?2 AND json_type(record,'$.pending')='object'))",
            rusqlite::params![signer,job,token],
        ).map_err(store_err)?;
        if removed != 1 {
            return Err(Error::Conflict(
                "preparation token or pending journal changed".into(),
            ));
        }
        tx.commit().map_err(store_err)
    }
    async fn migrate_legacy_policy(
        &self,
        id: &str,
        version: u64,
        budget: Option<crate::state::BuybackBudget>,
    ) -> Result<PaymentRecord> {
        let mut c = self.conn.lock().map_err(store_err)?;
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let reserved: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM signer_reservations WHERE job=?1)",
                [id],
                |r| r.get(0),
            )
            .map_err(store_err)?;
        if reserved {
            return Err(Error::Conflict("job has a signer reservation".into()));
        }
        let json: String = tx
            .query_row("SELECT record FROM payments WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .map_err(store_err)?;
        let next = migrated_policy(
            serde_json::from_str(&json).map_err(store_err)?,
            version,
            budget,
        )?;
        tx.execute(
            "UPDATE payments SET version=?1,record=?2 WHERE id=?3",
            rusqlite::params![
                i64::try_from(next.version).map_err(store_err)?,
                serde_json::to_string(&next).map_err(store_err)?,
                id
            ],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(next)
    }
    async fn insert(&self, rec: &PaymentRecord) -> Result<()> {
        let c = self.conn.lock().map_err(store_err)?;
        c.execute(
            "INSERT INTO payments (id, state, version, created_at, record) VALUES (?1,?2,?3,?4,?5)",
            rusqlite::params![
                rec.id,
                rec.state.as_str(),
                rec.version as i64,
                rec.created_at as i64,
                serde_json::to_string(rec).map_err(store_err)?
            ],
        )
        .map_err(store_err)?;
        Ok(())
    }

    async fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
        let c = self.conn.lock().map_err(store_err)?;
        let mut st = c
            .prepare("SELECT record FROM payments WHERE id = ?1")
            .map_err(store_err)?;
        let mut rows = st.query([id]).map_err(store_err)?;
        match rows.next().map_err(store_err)? {
            Some(row) => {
                let s: String = row.get(0).map_err(store_err)?;
                serde_json::from_str(&s).map(Some).map_err(store_err)
            }
            None => Ok(None),
        }
    }

    async fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
        let c = self.conn.lock().map_err(store_err)?;
        let mut st = c
            .prepare("SELECT record, state FROM payments ORDER BY created_at")
            .map_err(store_err)?;
        let wanted: Vec<&str> = states.iter().map(|s| s.as_str()).collect();
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(store_err)?;
        let mut out = vec![];
        for row in rows {
            let (rec, state) = row.map_err(store_err)?;
            if wanted.contains(&state.as_str()) {
                out.push(serde_json::from_str(&rec).map_err(store_err)?);
            }
        }
        Ok(out)
    }

    async fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        let mut c = self.conn.lock().map_err(store_err)?;
        let tx = c
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(store_err)?;
        let previous: String = tx
            .query_row("SELECT record FROM payments WHERE id=?1", [&rec.id], |r| {
                r.get(0)
            })
            .map_err(|e| {
                if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                    Error::NotFound(rec.id.clone())
                } else {
                    store_err(e)
                }
            })?;
        let previous: PaymentRecord = serde_json::from_str(&previous).map_err(store_err)?;
        if previous.version != rec.version {
            return Err(Error::Conflict(rec.id.clone()));
        }
        if previous.buyback_budget != rec.buyback_budget
            || previous.auto_required != rec.auto_required
        {
            return Err(Error::Store("immutable job budget".into()));
        }
        if let Some(p) = &rec.pending {
            let token = p.reservation.as_deref().ok_or_else(|| {
                Error::Store("legacy journal requires manual reconciliation".into())
            })?;
            let owned: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM signer_reservations WHERE signer=?1 AND job=?2 AND token=?3)",rusqlite::params![p.signer,rec.id,token],|r|r.get(0)).map_err(store_err)?;
            if !owned {
                return Err(Error::Store("signer reservation mismatch".into()));
            }
        }
        if let Some(p) = &previous.pending {
            if rec.pending.is_some() && rec.pending != previous.pending {
                return Err(Error::Store("cannot replace unresolved journal".into()));
            }
            if rec.pending.is_none() {
                let token = p.reservation.as_deref().ok_or_else(|| {
                    Error::Store("legacy journal requires manual reconciliation".into())
                })?;
                let removed = tx
                    .execute(
                        "DELETE FROM signer_reservations WHERE signer=?1 AND job=?2 AND token=?3",
                        rusqlite::params![p.signer, rec.id, token],
                    )
                    .map_err(store_err)?;
                if removed != 1 {
                    return Err(Error::Store("signer reservation mismatch".into()));
                }
            }
        }
        let mut next = rec.clone();
        next.version = next
            .version
            .checked_add(1)
            .ok_or_else(|| Error::Store("version overflow".into()))?;
        next.updated_at = crate::state::now();
        tx.execute(
            "UPDATE payments SET state=?1,version=?2,record=?3 WHERE id=?4",
            rusqlite::params![
                next.state.as_str(),
                next.version as i64,
                serde_json::to_string(&next).map_err(store_err)?,
                next.id
            ],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)?;
        Ok(next)
    }
}

/// Open a store from a spec: `sqlite:<path>`, `file:<dir>`, or a bare path (sqlite).
pub fn open_store(spec: &str) -> Result<Box<dyn Store>> {
    if let Some(dir) = spec.strip_prefix("file:") {
        return Ok(Box::new(FileStore::open(dir)?));
    }
    #[cfg(feature = "sqlite")]
    {
        let path = spec.strip_prefix("sqlite:").unwrap_or(spec);
        Ok(Box::new(SqliteStore::open(path)?))
    }
    #[cfg(not(feature = "sqlite"))]
    Err(Error::Config(
        "sqlite feature disabled; use file:<dir>".into(),
    ))
}

#[async_trait::async_trait]
impl<S: Store + ?Sized> Store for Box<S> {
    async fn require_signing(&self) -> Result<()> {
        (**self).require_signing().await
    }
    async fn reserve_signer_for_record(&self, s: &str, r: &PaymentRecord) -> Result<String> {
        (**self).reserve_signer_for_record(s, r).await
    }

    async fn reserve_signer(&self, signer: &str, job: &str) -> Result<String> {
        (**self).reserve_signer(signer, job).await
    }

    async fn cancel_preparation(&self, s: &str, j: &str, t: &str) -> Result<()> {
        (**self).cancel_preparation(s, j, t).await
    }
    async fn migrate_legacy_policy(
        &self,
        id: &str,
        v: u64,
        b: Option<crate::state::BuybackBudget>,
    ) -> Result<PaymentRecord> {
        (**self).migrate_legacy_policy(id, v, b).await
    }
    async fn insert(&self, rec: &PaymentRecord) -> Result<()> {
        (**self).insert(rec).await
    }
    async fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
        (**self).get(id).await
    }
    async fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
        (**self).list(states).await
    }
    async fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        (**self).update(rec).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_record;

    #[tokio::test]
    async fn explicit_legacy_policy_migration_preserves_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let file = FileStore::open(dir.path()).unwrap();
        #[allow(unused_mut)]
        let mut stores: Vec<Box<dyn Store>> = vec![Box::new(file)];
        #[cfg(feature = "sqlite")]
        stores.push(Box::new(SqliteStore::in_memory().unwrap()));
        for store in stores {
            let mut legacy = test_record("legacy-policy");
            legacy.auto_required = None;
            store.insert(&legacy).await.unwrap();
            assert!(
                store
                    .migrate_legacy_policy(&legacy.id, 1, None)
                    .await
                    .is_err()
            );
            let migrated = store
                .migrate_legacy_policy(&legacy.id, 0, None)
                .await
                .unwrap();
            assert_eq!(migrated.auto_required, Some(false));
            assert_eq!(migrated.version, 1);
            assert!(
                store
                    .migrate_legacy_policy(&legacy.id, 1, None)
                    .await
                    .is_err()
            );
            let mut evidence = legacy.clone();
            evidence.id = "legacy-evidence".into();
            evidence.funded_tao = 1;
            store.insert(&evidence).await.unwrap();
            assert!(
                store
                    .migrate_legacy_policy(&evidence.id, 0, None)
                    .await
                    .is_err()
            );
            assert_eq!(
                store.get(&evidence.id).await.unwrap().unwrap().funded_tao,
                1
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn preparation_cancellation_requires_current_token_and_no_journal() {
        let store = SqliteStore::in_memory().unwrap();
        let mut rec = test_record("prepare-cancel");
        rec.auto_required = None;
        store.insert(&rec).await.unwrap();
        let token = store
            .reserve_signer_for_record("signer", &rec)
            .await
            .unwrap();
        assert!(
            store
                .migrate_legacy_policy(&rec.id, rec.version, None)
                .await
                .is_err()
        );
        assert!(
            store
                .cancel_preparation("signer", &rec.id, "wrong")
                .await
                .is_err()
        );
        store
            .cancel_preparation("signer", &rec.id, &token)
            .await
            .unwrap();
        let replacement = store
            .reserve_signer_for_record("signer", &rec)
            .await
            .unwrap();
        assert!(
            store
                .cancel_preparation("signer", &rec.id, &token)
                .await
                .is_err()
        );
        rec.pending = Some(crate::chain::PendingTx {
            action: crate::engine::Action::Fund,
            reservation: Some(replacement.clone()),
            signer: "signer".into(),
            nonce: 0,
            tx_hash: "hash".into(),
            birth_block: 1,
            amount: 1,
        });
        store.update(&rec).await.unwrap();
        assert!(
            store
                .cancel_preparation("signer", &rec.id, &replacement)
                .await
                .is_err()
        );
        assert!(store.reserve_signer("signer", "other").await.is_err());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn legacy_migration_fences_stale_reservers_and_freezes_validated_budget() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("migration.sqlite");
        let first = SqliteStore::open(&path).unwrap();
        let second = SqliteStore::open(&path).unwrap();
        let mut rec = test_record("legacy-budget");
        rec.auto_required = None;
        first.insert(&rec).await.unwrap();
        let mut budget = crate::state::BuybackBudget {
            amount_rao: 0,
            currency: "TAO".into(),
            source: "operator-allocation".into(),
            netuid: 100,
            destroy: crate::config::Destroy::Burn,
            hotkey: crate::keys::ss58(
                &crate::keys::keypair_from_uri("//Bob")
                    .unwrap()
                    .public_key()
                    .to_account_id(),
            ),
        };
        assert!(
            first
                .migrate_legacy_policy(&rec.id, 0, Some(budget.clone()))
                .await
                .is_err()
        );
        budget.amount_rao = crate::engine::MIN_STAKE_RAO;
        let migrated = first
            .migrate_legacy_policy(&rec.id, 0, Some(budget.clone()))
            .await
            .unwrap();
        assert_eq!(migrated.auto_required, Some(true));
        assert_eq!(
            second.get(&rec.id).await.unwrap().unwrap().buyback_budget,
            Some(budget)
        );
        assert!(
            second
                .reserve_signer_for_record("signer", &rec)
                .await
                .is_err()
        );
        let mut changed = migrated;
        changed.buyback_budget = None;
        assert!(second.update(&changed).await.is_err());
    }

    async fn exercise(s: &dyn Store) {
        let r = test_record("p-1");
        s.insert(&r).await.unwrap();
        assert!(s.insert(&r).await.is_err(), "duplicate insert");
        let mut got = s.get("p-1").await.unwrap().unwrap();
        assert_eq!(got.version, 0);
        got.transition(PaymentState::Detected).unwrap();
        let v1 = s.update(&got).await.unwrap();
        assert_eq!(v1.version, 1);
        // stale writer loses
        assert!(matches!(s.update(&got).await, Err(Error::Conflict(_))));
        assert_eq!(
            s.get("p-1").await.unwrap().unwrap().state,
            PaymentState::Detected
        );
        s.insert(&test_record("p-2")).await.unwrap();
        assert_eq!(s.list(&[PaymentState::Pending]).await.unwrap().len(), 1);
        assert_eq!(
            s.list(&[PaymentState::Pending, PaymentState::Detected])
                .await
                .unwrap()
                .len(),
            2
        );
        assert!(s.get("nope").await.unwrap().is_none());
        let mut ghost = test_record("ghost");
        ghost.version = 0;
        assert!(matches!(s.update(&ghost).await, Err(Error::NotFound(_))));
    }

    #[tokio::test]
    async fn file_store() {
        let d = tempfile::tempdir().unwrap();
        let s = FileStore::open(d.path()).unwrap();
        exercise(&s).await;
        assert!(s.get("../etc/passwd").await.is_err());
        // survives reopen (restart)
        let s2 = FileStore::open(d.path()).unwrap();
        assert_eq!(s2.get("p-1").await.unwrap().unwrap().version, 1);
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn sqlite_store() {
        exercise(&SqliteStore::in_memory().unwrap()).await;
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db.sqlite");
        exercise(&SqliteStore::open(&path).unwrap()).await;
        assert_eq!(
            SqliteStore::open(&path)
                .unwrap()
                .get("p-1")
                .await
                .unwrap()
                .unwrap()
                .version,
            1
        );
    }
    #[cfg(feature = "sqlite")]
    #[test]
    fn reservation_child_process() {
        let Ok(path) = std::env::var("BUYBACK_RESERVATION_TEST_DB") else {
            return;
        };
        let job = std::env::var("BUYBACK_RESERVATION_TEST_JOB").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let store = SqliteStore::open(&path).unwrap();
        let won = rt
            .block_on(store.reserve_signer("shared-signer", &job))
            .is_ok();
        if won {
            std::fs::write(format!("{path}.{job}.won"), b"reserved").unwrap();
        }
        // Simulates process death immediately after durable reservation, before journal.
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn two_processes_one_signer_orphan_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.db");
        drop(SqliteStore::open(&path).unwrap());
        let exe = std::env::current_exe().unwrap();
        let mut children = vec![];
        for job in ["job-a", "job-b"] {
            children.push(
                std::process::Command::new(&exe)
                    .args(["--exact", "store::tests::reservation_child_process"])
                    .env("BUYBACK_RESERVATION_TEST_DB", &path)
                    .env("BUYBACK_RESERVATION_TEST_JOB", job)
                    .stdout(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            );
        }
        for mut child in children {
            assert!(child.wait().unwrap().success());
        }
        let winners = ["job-a", "job-b"]
            .iter()
            .filter(|job| std::path::Path::new(&format!("{}.{}.won", path.display(), job)).exists())
            .count();
        assert_eq!(winners, 1);
        let restarted = SqliteStore::open(&path).unwrap();
        for job in ["job-a", "job-b", "job-c"] {
            assert!(
                restarted
                    .reserve_signer("shared-signer", job)
                    .await
                    .is_err()
            );
        }
        assert!(
            restarted
                .reserve_signer("different-signer", "job-c")
                .await
                .is_ok()
        );
    }
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn legacy_pending_signer_is_quarantined_on_upgrade() {
        let store = SqliteStore::in_memory().unwrap();
        let mut rec = test_record("legacy");
        rec.pending = Some(crate::chain::PendingTx {
            action: crate::engine::Action::Fund,
            reservation: None,
            signer: "legacy-signer".into(),
            nonce: 1,
            tx_hash: "hash".into(),
            birth_block: 10,
            amount: 1,
        });
        store.insert(&rec).await.unwrap();
        assert!(
            store
                .reserve_signer("legacy-signer", "new-job")
                .await
                .is_err()
        );
        assert!(
            store
                .reserve_signer("other-signer", "new-job")
                .await
                .is_ok()
        );
        assert!(
            FileStore::open(tempfile::tempdir().unwrap().path())
                .unwrap()
                .require_signing()
                .await
                .is_err()
        );
    }
}
