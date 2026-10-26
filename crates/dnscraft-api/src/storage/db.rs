//! SQLite connection wrapper (single writer; every call runs via `spawn_blocking`).

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, params};

use super::db_err;
use super::migrations::{migrate, schema_version};
use crate::error::ControlApiError;

/// A handle to the control-api SQLite database.
///
/// A single writer [`Connection`] is shared behind a `Mutex`; every operation
/// runs on the blocking pool so the async runtime is never blocked on SQLite.
#[derive(Clone)]
pub struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    /// Opens (and migrates) a database file at `path`.
    pub async fn open(path: &Path) -> Result<Self, ControlApiError> {
        let path = path.to_owned();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, ControlApiError> {
            let mut conn = Connection::open(&path).map_err(db_err)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")
                .map_err(db_err)?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Opens a fresh in-memory database (tests).
    pub async fn open_in_memory() -> Result<Self, ControlApiError> {
        let conn = tokio::task::spawn_blocking(|| -> Result<Connection, ControlApiError> {
            let mut conn = Connection::open_in_memory().map_err(db_err)?;
            conn.execute_batch("PRAGMA foreign_keys = ON;")
                .map_err(db_err)?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Current schema version (`PRAGMA user_version`).
    pub async fn schema_version(&self) -> Result<i64, ControlApiError> {
        self.with_conn(|conn| schema_version(conn)).await
    }

    /// Stores a new config snapshot and returns its auto-assigned version.
    pub async fn config_version_insert(&self, snapshot: &str) -> Result<i64, ControlApiError> {
        let snapshot = snapshot.to_owned();
        self.with_conn(move |conn| {
            conn.execute(
                "INSERT INTO config_versions (snapshot, created_at) VALUES (?1, ?2)",
                params![snapshot, unix_now()],
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

/// Current wall-clock time as unix seconds.
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
