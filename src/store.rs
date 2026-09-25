//! Persistence behind the [`Store`] trait: a JSON-file store and a SQLite store.
//!
//! Both implement compare-and-swap on [`PaymentRecord::version`], so two engines sharing a store
//! cannot both advance the same record.

use crate::state::{PaymentRecord, PaymentState};
use crate::{Error, Result};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub trait Store: Send + Sync + 'static {
    /// Insert a new record (version 0). Fails if the id exists.
    fn insert(&self, rec: &PaymentRecord) -> Result<()>;
    fn get(&self, id: &str) -> Result<Option<PaymentRecord>>;
    /// Records in the given states.
    fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>>;
    /// Write `rec` if the stored version equals `rec.version`; returns the record with its new
    /// version. [`Error::Conflict`] otherwise.
    fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord>;
}

fn store_err(e: impl std::fmt::Display) -> Error {
    Error::Store(e.to_string())
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
        std::fs::rename(&tmp, path).map_err(store_err)
    }
}

impl Store for FileStore {
    fn insert(&self, rec: &PaymentRecord) -> Result<()> {
        let _g = self.lock.lock().map_err(store_err)?;
        let p = self.path(&rec.id)?;
        if p.exists() {
            return Err(Error::Store(format!("{} exists", rec.id)));
        }
        self.write(&p, rec)
    }

    fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
        self.read(&self.path(id)?)
    }

    fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
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

    fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        let _g = self.lock.lock().map_err(store_err)?;
        let p = self.path(&rec.id)?;
        let cur = self
            .read(&p)?
            .ok_or_else(|| Error::NotFound(rec.id.clone()))?;
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
            "PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
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
}

#[cfg(feature = "sqlite")]
impl Store for SqliteStore {
    fn insert(&self, rec: &PaymentRecord) -> Result<()> {
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

    fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
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

    fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
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

    fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        let c = self.conn.lock().map_err(store_err)?;
        let mut next = rec.clone();
        next.version += 1;
        next.updated_at = crate::state::now();
        let n = c
            .execute(
                "UPDATE payments SET state=?1, version=?2, record=?3 WHERE id=?4 AND version=?5",
                rusqlite::params![
                    next.state.as_str(),
                    next.version as i64,
                    serde_json::to_string(&next).map_err(store_err)?,
                    rec.id,
                    rec.version as i64
                ],
            )
            .map_err(store_err)?;
        match n {
            1 => Ok(next),
            _ if self_exists(&c, &rec.id)? => Err(Error::Conflict(rec.id.clone())),
            _ => Err(Error::NotFound(rec.id.clone())),
        }
    }
}

#[cfg(feature = "sqlite")]
fn self_exists(c: &rusqlite::Connection, id: &str) -> Result<bool> {
    c.query_row("SELECT count(*) FROM payments WHERE id=?1", [id], |r| {
        r.get::<_, i64>(0)
    })
    .map(|n| n > 0)
    .map_err(store_err)
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

impl<S: Store + ?Sized> Store for Box<S> {
    fn insert(&self, rec: &PaymentRecord) -> Result<()> {
        (**self).insert(rec)
    }
    fn get(&self, id: &str) -> Result<Option<PaymentRecord>> {
        (**self).get(id)
    }
    fn list(&self, states: &[PaymentState]) -> Result<Vec<PaymentRecord>> {
        (**self).list(states)
    }
    fn update(&self, rec: &PaymentRecord) -> Result<PaymentRecord> {
        (**self).update(rec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_record;

    fn exercise(s: &dyn Store) {
        let r = test_record("p-1");
        s.insert(&r).unwrap();
        assert!(s.insert(&r).is_err(), "duplicate insert");
        let mut got = s.get("p-1").unwrap().unwrap();
        assert_eq!(got.version, 0);
        got.transition(PaymentState::Detected).unwrap();
        let v1 = s.update(&got).unwrap();
        assert_eq!(v1.version, 1);
        // stale writer loses
        assert!(matches!(s.update(&got), Err(Error::Conflict(_))));
        assert_eq!(s.get("p-1").unwrap().unwrap().state, PaymentState::Detected);
        s.insert(&test_record("p-2")).unwrap();
        assert_eq!(s.list(&[PaymentState::Pending]).unwrap().len(), 1);
        assert_eq!(
            s.list(&[PaymentState::Pending, PaymentState::Detected])
                .unwrap()
                .len(),
            2
        );
        assert!(s.get("nope").unwrap().is_none());
        let mut ghost = test_record("ghost");
        ghost.version = 0;
        assert!(matches!(s.update(&ghost), Err(Error::NotFound(_))));
    }

    #[test]
    fn file_store() {
        let d = tempfile::tempdir().unwrap();
        let s = FileStore::open(d.path()).unwrap();
        exercise(&s);
        assert!(s.get("../etc/passwd").is_err());
        // survives reopen (restart)
        let s2 = FileStore::open(d.path()).unwrap();
        assert_eq!(s2.get("p-1").unwrap().unwrap().version, 1);
    }

    #[cfg(feature = "sqlite")]
    #[test]
    fn sqlite_store() {
        exercise(&SqliteStore::in_memory().unwrap());
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("db.sqlite");
        exercise(&SqliteStore::open(&path).unwrap());
        assert_eq!(
            SqliteStore::open(&path)
                .unwrap()
                .get("p-1")
                .unwrap()
                .unwrap()
                .version,
            1
        );
    }
}
