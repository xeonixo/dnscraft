//! SQLite connection wrapper (single writer; every call runs via `spawn_blocking`).

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use super::db_err;
use super::migrations::{migrate, schema_version};
use crate::clock::{Clock, unix_seconds};
use crate::error::ControlApiError;

/// A handle to the control-api SQLite database.
///
/// A single writer [`Connection`] is shared behind a `Mutex`; every operation
/// runs on the blocking pool so the async runtime is never blocked on SQLite.
/// Timestamps come from an injected [`Clock`] (ADR-0005), never from
/// [`std::time::SystemTime::now`] directly.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
    clock: Arc<dyn Clock>,
}

impl Db {
    /// Opens (and migrates) a database file at `path`.
    pub async fn open(path: &Path, clock: Arc<dyn Clock>) -> Result<Self, ControlApiError> {
        let path = path.to_owned();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, ControlApiError> {
            let existed = path.exists();
            prepare_path(&path).map_err(io_err)?;
            let mut conn = Connection::open(&path).map_err(db_err)?;
            // 0600 before WAL so the -wal/-shm sidecars inherit the same mode.
            tighten_file(&path, existed).map_err(io_err)?;
            apply_pragmas(&mut conn, true)?;
            tighten_sidecars(&path).map_err(io_err)?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }

    /// Opens a fresh in-memory database (tests).
    pub async fn open_in_memory(clock: Arc<dyn Clock>) -> Result<Self, ControlApiError> {
        let conn = tokio::task::spawn_blocking(|| -> Result<Connection, ControlApiError> {
            let mut conn = Connection::open_in_memory().map_err(db_err)?;
            apply_pragmas(&mut conn, false)?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
        })
    }

    /// Current unix seconds according to the injected clock.
    pub fn now_unix(&self) -> i64 {
        unix_seconds(self.clock.now())
    }

    /// Current schema version (`PRAGMA user_version`).
    pub async fn schema_version(&self) -> Result<i64, ControlApiError> {
        self.with_conn(|conn| schema_version(conn)).await
    }

    /// Stores a new config snapshot and returns its auto-assigned version.
    pub async fn config_version_insert(&self, snapshot: &str) -> Result<i64, ControlApiError> {
        let snapshot = snapshot.to_owned();
        let created_at = self.now_unix();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO config_versions (snapshot, created_at) VALUES (?1, ?2)",
                params![snapshot, created_at],
            )
            .map_err(db_err)?;
            Ok(conn.last_insert_rowid())
        })
        .await
    }

    /// Loads the snapshot of a stored config version, or `None` when absent.
    pub async fn config_version_load(
        &self,
        version: i64,
    ) -> Result<Option<String>, ControlApiError> {
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT snapshot FROM config_versions WHERE version = ?1",
                params![version],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_err)
        })
        .await
    }

    /// Highest stored config version, or `None` when no snapshot has been stored.
    pub async fn config_version_max(&self) -> Result<Option<i64>, ControlApiError> {
        self.with_conn(move |conn| {
            conn.query_row("SELECT MAX(version) FROM config_versions", [], |row| {
                row.get::<_, Option<i64>>(0)
            })
            .map_err(db_err)
        })
        .await
    }

    /// Inserts a query-log row (minimal columns; expanded by A12).
    pub async fn query_log_insert(
        &self,
        id: &str,
        time: i64,
        node_id: &str,
        source_ip: &str,
        query_name: &str,
    ) -> Result<(), ControlApiError> {
        let id = id.to_owned();
        let node_id = node_id.to_owned();
        let source_ip = source_ip.to_owned();
        let query_name = query_name.to_owned();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO query_log (id, time, node_id, source_ip, query_name)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![id, time, node_id, source_ip, query_name],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await
    }

    /// Counts query-log rows whose `query_name` equals `name` exactly (bound parameter).
    pub async fn query_log_count_by_name(&self, name: &str) -> Result<i64, ControlApiError> {
        let name = name.to_owned();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT COUNT(*) FROM query_log WHERE query_name = ?1",
                params![name],
                |row| row.get(0),
            )
            .map_err(db_err)
        })
        .await
    }

    /// Runs `f` on the shared connection from the blocking pool.
    pub(crate) async fn with_conn<T, F>(&self, f: F) -> Result<T, ControlApiError>
    where
        F: FnOnce(&mut Connection) -> Result<T, ControlApiError> + Send + 'static,
        T: Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = match conn.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            f(&mut guard)
        })
        .await
        .map_err(join_err)?
    }
}

/// Maps a blocking-pool join failure to the internal error code.
fn join_err(err: tokio::task::JoinError) -> ControlApiError {
    ControlApiError::Internal {
        message: err.to_string(),
    }
}

/// Applies the control-api SQLite durability and integrity pragmas.
///
/// WAL is file-only: an in-memory database keeps its `memory` journal mode.
/// `synchronous=NORMAL` (safe under WAL), a 5 s `busy_timeout`, and enforced
/// foreign keys apply to both.
fn apply_pragmas(conn: &mut Connection, wal: bool) -> Result<(), ControlApiError> {
    let sql = if wal {
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;"
    } else {
        "PRAGMA synchronous = NORMAL;
         PRAGMA busy_timeout = 5000;
         PRAGMA foreign_keys = ON;"
    };
    conn.execute_batch(sql).map_err(db_err)
}

/// Maps an I/O error to the internal error code.
fn io_err(err: std::io::Error) -> ControlApiError {
    ControlApiError::Internal {
        message: err.to_string(),
    }
}

/// Creates the data directory with mode 0700 when it does not exist yet.
///
/// An already-existing directory is left untouched (the operator may point at a
/// shared or otherwise-configured location); only directories this call creates
/// are forced to 0700, independent of umask.
fn prepare_path(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty())
        && !dir.exists()
    {
        std::fs::create_dir_all(dir)?;
        set_mode(dir, 0o700)?;
    }
    Ok(())
}

/// Sets `path` to mode 0600 if it is currently wider, warning when `warn` is
/// set (used for a pre-existing database file).
fn tighten_file(path: &Path, warn: bool) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let current = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if current != 0o600 {
        if warn {
            tracing::warn!(
                path = %path.display(),
                from = format!("{current:o}"),
                "tightening database file permissions to 0600"
            );
        }
        set_mode(path, 0o600)?;
    }
    Ok(())
}

/// Forces `path` to the exact unix `mode` (owner/group/other bits).
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

/// Tightens any existing `-wal`/`-shm` sidecars to 0600.
fn tighten_sidecars(path: &Path) -> std::io::Result<()> {
    let base = path.to_string_lossy();
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{base}{suffix}"));
        tighten_file(&sidecar, false)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::clock::{ManualClock, SystemClock};

    fn temp_db_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "dnscraft-api-pragmas-{}-{nanos}.db",
            std::process::id()
        ))
    }

    #[tokio::test]
    async fn config_version_created_at_comes_from_injected_clock() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();

        let version = db.config_version_insert("{\"v\":1}").await.unwrap();
        let created_at: i64 = db
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT created_at FROM config_versions WHERE version = ?1",
                    params![version],
                    |row| row.get(0),
                )
                .map_err(db_err)
            })
            .await
            .unwrap();
        assert_eq!(created_at, 1_700_000_000);
    }

    #[tokio::test]
    async fn file_db_sets_wal_and_durability_pragmas() {
        let path = temp_db_path();
        let db = Db::open(&path, Arc::new(SystemClock)).await.unwrap();
        let (journal, synchronous, busy_timeout, foreign_keys) = db
            .with_conn(|conn| {
                let journal: String = conn
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                    .map_err(db_err)?;
                let synchronous: i64 = conn
                    .query_row("PRAGMA synchronous", [], |row| row.get(0))
                    .map_err(db_err)?;
                let busy_timeout: i64 = conn
                    .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
                    .map_err(db_err)?;
                let foreign_keys: i64 = conn
                    .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                    .map_err(db_err)?;
                Ok((journal, synchronous, busy_timeout, foreign_keys))
            })
            .await
            .unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        assert_eq!(synchronous, 1); // NORMAL
        assert_eq!(busy_timeout, 5000);
        assert_eq!(foreign_keys, 1);
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn in_memory_db_keeps_memory_journal_mode() {
        let db = Db::open_in_memory(Arc::new(SystemClock)).await.unwrap();
        let (journal, synchronous, busy_timeout, foreign_keys) = db
            .with_conn(|conn| {
                let journal: String = conn
                    .query_row("PRAGMA journal_mode", [], |row| row.get(0))
                    .map_err(db_err)?;
                let synchronous: i64 = conn
                    .query_row("PRAGMA synchronous", [], |row| row.get(0))
                    .map_err(db_err)?;
                let busy_timeout: i64 = conn
                    .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
                    .map_err(db_err)?;
                let foreign_keys: i64 = conn
                    .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                    .map_err(db_err)?;
                Ok((journal, synchronous, busy_timeout, foreign_keys))
            })
            .await
            .unwrap();
        assert_eq!(journal.to_ascii_lowercase(), "memory");
        assert_eq!(synchronous, 1); // NORMAL
        assert_eq!(busy_timeout, 5000);
        assert_eq!(foreign_keys, 1);
    }

    #[tokio::test]
    async fn file_permissions_are_0600_and_dir_0700_regardless_of_umask() {
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("dnscraft-api-perm-{}-{nanos}", std::process::id()));
        let path = dir.join("data.db");

        let db = Db::open(&path, Arc::new(SystemClock)).await.unwrap();
        // A write materializes the -wal/-shm sidecars.
        db.config_version_insert("{\"v\":1}").await.unwrap();

        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&dir), 0o700);
        let base = path.to_string_lossy();
        for suffix in ["-wal", "-shm"] {
            let sidecar = PathBuf::from(format!("{base}{suffix}"));
            assert!(sidecar.exists(), "missing sidecar {suffix}");
            assert_eq!(mode(&sidecar), 0o600, "sidecar {suffix} not 0600");
        }

        drop(db);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
