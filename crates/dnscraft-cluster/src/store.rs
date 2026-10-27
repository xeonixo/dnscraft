//! Durable master-side state: node registry and one-time join tokens.
//!
//! Both live in one SQLite database in the master's data directory, using the
//! same versioned-migration pattern as `dnscraft-api` (`PRAGMA user_version`,
//! one migration per index). Every call runs on the blocking pool so the async
//! runtime is never blocked on SQLite. Join tokens are stored **only** as
//! SHA-256 hashes; the plaintext exists in [`MintedJoinToken`] until dropped.

use std::fmt;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use dnscraft_common::clock::Clock;
use dnscraft_common::secret::Secret;
use rusqlite::{Connection, OptionalExtension, params};

use crate::config::validate_node_id;
use crate::error::ClusterError;

/// Ordered migrations; index `i` is schema version `i + 1`.
const MIGRATIONS: &[&str] = &[
    // v1: node registry + one-time join tokens. The token hash is the primary
    // key, so a replay can never create a second usable row.
    "CREATE TABLE IF NOT EXISTS cluster_nodes (
        node_id                 TEXT PRIMARY KEY,
        fingerprint             TEXT NOT NULL,
        joined_at               INTEGER NOT NULL,
        last_seen               INTEGER,
        applied_config_version  INTEGER,
        revoked                 INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS join_tokens (
        token_hash  TEXT PRIMARY KEY,
        node_id     TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS join_tokens_node_idx ON join_tokens(node_id);",
];

/// One registered cluster node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterNode {
    /// Node identity (lowercase DNS label).
    pub node_id: String,
    /// SHA-256 fingerprint of the node certificate (lowercase hex).
    pub fingerprint: String,
    /// Unix seconds when the node joined.
    pub joined_at: i64,
    /// Unix seconds of the last authenticated connection.
    pub last_seen: Option<i64>,
    /// Last config version the node acknowledged.
    pub applied_config_version: Option<i64>,
    /// Revoked nodes are rejected on their next connection.
    pub revoked: bool,
}

/// A freshly minted join token. The plaintext is shown once and never stored;
/// dropping this value zeroizes it.
#[derive(Clone)]
pub struct MintedJoinToken {
    token: Secret,
    node_id: String,
    expires_at: i64,
}

impl MintedJoinToken {
    /// The one-time plaintext token (`cluster.<hidden>`; never log this).
    pub fn expose(&self) -> &str {
        self.token.expose()
    }

    /// The `node_id` this token is bound to.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Unix seconds after which the token is rejected.
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

impl fmt::Debug for MintedJoinToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MintedJoinToken")
            .field("token", &"[redacted]")
            .field("node_id", &self.node_id)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// SQLite-backed master registry: `cluster_nodes` + `join_tokens`.
#[derive(Clone)]
pub struct ClusterStore {
    conn: Arc<Mutex<Connection>>,
    clock: Arc<dyn Clock>,
    token_ttl: Duration,
}

impl ClusterStore {
    /// Opens (and migrates) the database at `path`.
    ///
    /// `token_ttl` is the lifetime applied by [`Self::mint_join_token`]
    /// (`cluster.join.token_ttl`, default 15 min).
    pub async fn open(
        path: &std::path::Path,
        clock: Arc<dyn Clock>,
        token_ttl: Duration,
    ) -> Result<Self, ClusterError> {
        let path = path.to_owned();
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, ClusterError> {
            let existed = path.exists();
            prepare_parent(&path)?;
            if !existed {
                create_file_0600(&path)?;
            }
            let mut conn = Connection::open(&path).map_err(db_err)?;
            tighten_file(&path)?;
            apply_pragmas(&mut conn, true)?;
            migrate(&mut conn)?;
            Ok(conn)
        })
        .await
        .map_err(join_err)??;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            clock,
            token_ttl,
        })
    }

    /// Opens a fresh in-memory database (tests).
    pub async fn open_in_memory(
        clock: Arc<dyn Clock>,
        token_ttl: Duration,
    ) -> Result<Self, ClusterError> {
        let conn = tokio::task::spawn_blocking(|| -> Result<Connection, ClusterError> {
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
            token_ttl,
        })
    }

    /// Mints a one-time join token bound to `node_id`.
    ///
    /// The token is 32 random bytes (64 hex chars); only its SHA-256 hash is
    /// stored. Minting for an already registered node is rejected.
    pub async fn mint_join_token(&self, node_id: &str) -> Result<MintedJoinToken, ClusterError> {
        validate_node_id(node_id)?;
        let token = random_token()?;
        let token_hash = crate::sha256_hex(token.as_bytes());
        let now = self.now_unix();
        let expires_at = now.saturating_add(duration_seconds(self.token_ttl));
        let bound_node = node_id.to_owned();

        self.with_conn(move |conn| {
            let already: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM cluster_nodes WHERE node_id = ?1",
                    params![bound_node],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_err)?;
            if already.is_some() {
                return Err(ClusterError::NodeAlreadyJoined {
                    node_id: bound_node,
                });
            }
            conn.execute(
                "INSERT INTO join_tokens (token_hash, node_id, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![token_hash, bound_node, now, expires_at],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await?;

        Ok(MintedJoinToken {
            token: Secret::new(token),
            node_id: node_id.to_owned(),
            expires_at,
        })
    }

    /// Consumes a join token for `node_id`.
    ///
    /// A token is valid at most once, only for its bound `node_id`, and only
    /// before `expires_at`. An expired token is consumed and reported as
    /// expired; a wrong `node_id` leaves the token intact.
    pub async fn redeem_join_token(&self, token: &str, node_id: &str) -> Result<(), ClusterError> {
        let token_hash = crate::sha256_hex(token.as_bytes());
        let now = self.now_unix();
        let bound_node = node_id.to_owned();

        self.with_conn(move |conn| {
            let tx = conn.transaction().map_err(db_err)?;
            let row: Option<(String, i64)> = tx
                .query_row(
                    "SELECT node_id, expires_at FROM join_tokens WHERE token_hash = ?1",
                    params![token_hash],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(db_err)?;
            let Some((stored_node, expires_at)) = row else {
                return Err(ClusterError::JoinTokenInvalid);
            };
            if stored_node != bound_node {
                return Err(ClusterError::JoinTokenInvalid);
            }
            // One-time: consume before reporting expiry or success.
            tx.execute(
                "DELETE FROM join_tokens WHERE token_hash = ?1",
                params![token_hash],
            )
            .map_err(db_err)?;
            tx.commit().map_err(db_err)?;
            if now >= expires_at {
                return Err(ClusterError::JoinTokenExpired);
            }
            Ok(())
        })
        .await
    }

    /// Registers a joined node and its certificate fingerprint.
    pub async fn register_node(
        &self,
        node_id: &str,
        fingerprint: &str,
    ) -> Result<ClusterNode, ClusterError> {
        validate_node_id(node_id)?;
        let joined_at = self.now_unix();
        let node = ClusterNode {
            node_id: node_id.to_owned(),
            fingerprint: fingerprint.to_owned(),
            joined_at,
            last_seen: Some(joined_at),
            applied_config_version: None,
            revoked: false,
        };
        let insert = node.clone();
        self.with_conn(move |conn| {
            let already: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM cluster_nodes WHERE node_id = ?1",
                    params![insert.node_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_err)?;
            if already.is_some() {
                return Err(ClusterError::NodeAlreadyJoined {
                    node_id: insert.node_id.clone(),
                });
            }
            conn.execute(
                "INSERT INTO cluster_nodes
                    (node_id, fingerprint, joined_at, last_seen, applied_config_version, revoked)
                 VALUES (?1, ?2, ?3, ?4, ?5, 0)",
                params![
                    insert.node_id,
                    insert.fingerprint,
                    insert.joined_at,
                    insert.last_seen,
                    insert.applied_config_version
                ],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await?;
        Ok(node)
    }

    /// Loads one registered node, if present.
    pub async fn get_node(&self, node_id: &str) -> Result<Option<ClusterNode>, ClusterError> {
        let node_id = node_id.to_owned();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT node_id, fingerprint, joined_at, last_seen,
                        applied_config_version, revoked
                 FROM cluster_nodes WHERE node_id = ?1",
                params![node_id],
                node_from_row,
            )
            .optional()
            .map_err(db_err)
        })
        .await
    }

    /// Lists registered nodes ordered by `node_id`.
    pub async fn list_nodes(&self) -> Result<Vec<ClusterNode>, ClusterError> {
        self.with_conn(|conn| {
            let mut statement = conn
                .prepare(
                    "SELECT node_id, fingerprint, joined_at, last_seen,
                            applied_config_version, revoked
                     FROM cluster_nodes ORDER BY node_id",
                )
                .map_err(db_err)?;
            let rows = statement.query_map([], node_from_row).map_err(db_err)?;
            rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
        })
        .await
    }

    /// Records an authenticated connection from `node_id`.
    pub async fn mark_seen(&self, node_id: &str) -> Result<(), ClusterError> {
        let now = self.now_unix();
        let node_id = node_id.to_owned();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE cluster_nodes SET last_seen = ?1 WHERE node_id = ?2",
                    params![now, node_id],
                )
                .map_err(db_err)?;
            if changed == 0 {
                return Err(ClusterError::NodeUnknown { node_id });
            }
            Ok(())
        })
        .await
    }

    /// Records the config version a node acknowledged.
    pub async fn set_applied_config_version(
        &self,
        node_id: &str,
        version: i64,
    ) -> Result<(), ClusterError> {
        let node_id = node_id.to_owned();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE cluster_nodes SET applied_config_version = ?1 WHERE node_id = ?2",
                    params![version, node_id],
                )
                .map_err(db_err)?;
            if changed == 0 {
                return Err(ClusterError::NodeUnknown { node_id });
            }
            Ok(())
        })
        .await
    }

    /// Revokes a node. Its next connection is rejected with
    /// `cluster.node.revoked`.
    pub async fn revoke(&self, node_id: &str) -> Result<(), ClusterError> {
        let node_id = node_id.to_owned();
        self.with_conn(move |conn| {
            let changed = conn
                .execute(
                    "UPDATE cluster_nodes SET revoked = 1 WHERE node_id = ?1",
                    params![node_id],
                )
                .map_err(db_err)?;
            if changed == 0 {
                return Err(ClusterError::NodeUnknown { node_id });
            }
            Ok(())
        })
        .await
    }

    fn now_unix(&self) -> i64 {
        unix_seconds(self.clock.now())
    }

    /// Runs `f` on the shared connection from the blocking pool.
    async fn with_conn<T, F>(&self, f: F) -> Result<T, ClusterError>
    where
        F: FnOnce(&mut Connection) -> Result<T, ClusterError> + Send + 'static,
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

fn node_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ClusterNode> {
    Ok(ClusterNode {
        node_id: row.get(0)?,
        fingerprint: row.get(1)?,
        joined_at: row.get(2)?,
        last_seen: row.get(3)?,
        applied_config_version: row.get(4)?,
        revoked: row.get::<_, i64>(5)? != 0,
    })
}

/// 32 random bytes, lowercase hex (64 characters).
fn random_token() -> Result<String, ClusterError> {
    use ring::rand::SecureRandom;

    let mut bytes = [0_u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|error| ClusterError::Internal {
            message: format!("join token randomness: {error}"),
        })?;
    Ok(crate::hex(&bytes))
}

fn unix_seconds(time: SystemTime) -> i64 {
    match time.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => -(error.duration().as_secs() as i64),
    }
}

fn duration_seconds(duration: Duration) -> i64 {
    i64::try_from(duration.as_secs()).unwrap_or(i64::MAX)
}

fn db_err(error: rusqlite::Error) -> ClusterError {
    ClusterError::Internal {
        message: error.to_string(),
    }
}

fn join_err(error: tokio::task::JoinError) -> ClusterError {
    ClusterError::Internal {
        message: error.to_string(),
    }
}

fn io_err(error: std::io::Error) -> ClusterError {
    ClusterError::Internal {
        message: error.to_string(),
    }
}

/// Applies migrations newer than `PRAGMA user_version`.
fn migrate(conn: &mut Connection) -> Result<(), ClusterError> {
    let tx = conn.transaction().map_err(db_err)?;
    let current: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_err)?;
    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let target = (index + 1) as i64;
        if current < target {
            tx.execute_batch(sql).map_err(db_err)?;
            tx.pragma_update(None, "user_version", target)
                .map_err(db_err)?;
        }
    }
    tx.commit().map_err(db_err)
}

/// SQLite durability/integrity pragmas (WAL for file databases only).
fn apply_pragmas(conn: &mut Connection, wal: bool) -> Result<(), ClusterError> {
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

/// Creates the database's parent directory with mode 0700 when it is new.
fn prepare_parent(path: &std::path::Path) -> Result<(), ClusterError> {
    if let Some(parent) = path.parent().filter(|dir| !dir.as_os_str().is_empty())
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(io_err)?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(io_err)?;
    }
    Ok(())
}

/// Creates a fresh database file with mode 0600 before SQLite opens it.
fn create_file_0600(path: &std::path::Path) -> Result<(), ClusterError> {
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).mode(0o600);
    options.open(path).map_err(io_err)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io_err)
}

/// Forces an existing database file back to 0600.
fn tighten_file(path: &std::path::Path) -> Result<(), ClusterError> {
    if !path.exists() {
        return Ok(());
    }
    let current = std::fs::metadata(path)
        .map_err(io_err)?
        .permissions()
        .mode()
        & 0o777;
    if current != 0o600 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io_err)?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use dnscraft_common::clock::ManualClock;

    use super::*;

    const TTL: Duration = Duration::from_secs(15 * 60);

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ))
    }

    async fn store(clock: Arc<ManualClock>) -> ClusterStore {
        ClusterStore::open_in_memory(clock, TTL).await.unwrap()
    }

    #[tokio::test]
    async fn join_token_is_one_time_and_bound_to_node_id() {
        let store = store(clock()).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        assert_eq!(minted.node_id(), "node-a");
        assert_eq!(minted.expose().len(), 64);

        // Bound to node_id: another node cannot redeem it, and the token stays.
        let error = store
            .redeem_join_token(minted.expose(), "node-b")
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
        store
            .redeem_join_token(minted.expose(), "node-a")
            .await
            .unwrap();

        // One-time: the second redemption is invalid.
        let error = store
            .redeem_join_token(minted.expose(), "node-a")
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
    }

    #[tokio::test]
    async fn join_token_expires_after_ttl() {
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        assert_eq!(minted.expires_at(), 1_700_000_000 + 900);

        clock.advance(TTL);
        let error = store
            .redeem_join_token(minted.expose(), "node-a")
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_expired");

        // Expired tokens are consumed, not reusable.
        let error = store
            .redeem_join_token(minted.expose(), "node-a")
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
    }

    #[tokio::test]
    async fn join_token_store_holds_only_the_hash() {
        let store = store(clock()).await;
        let minted = store.mint_join_token("node-a").await.unwrap();
        let expected_hash = crate::sha256_hex(minted.expose().as_bytes());

        let rows: Vec<String> = store
            .with_conn(|conn| {
                let mut statement = conn
                    .prepare("SELECT token_hash FROM join_tokens")
                    .map_err(db_err)?;
                let rows = statement.query_map([], |row| row.get(0)).map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
            .unwrap();
        assert_eq!(rows, vec![expected_hash]);
        assert!(!rows[0].contains(minted.expose()));
        assert!(!format!("{minted:?}").contains(minted.expose()));
    }

    #[tokio::test]
    async fn unknown_token_is_invalid() {
        let store = store(clock()).await;
        let error = store
            .redeem_join_token("not-a-real-token", "node-a")
            .await
            .unwrap_err();
        assert_eq!(error.code(), "cluster.join.token_invalid");
    }

    #[tokio::test]
    async fn token_cannot_be_minted_for_a_registered_node() {
        let store = store(clock()).await;
        store.register_node("node-a", "aa").await.unwrap();
        let error = store.mint_join_token("node-a").await.unwrap_err();
        assert_eq!(error.code(), "cluster.node.already_joined");
    }

    #[tokio::test]
    async fn registry_records_fingerprint_and_revoke() {
        let clock = clock();
        let store = store(Arc::clone(&clock)).await;
        let node = store.register_node("node-a", "abc123").await.unwrap();
        assert_eq!(node.fingerprint, "abc123");
        assert_eq!(node.joined_at, 1_700_000_000);
        assert_eq!(node.last_seen, Some(1_700_000_000));
        assert_eq!(node.applied_config_version, None);
        assert!(!node.revoked);

        clock.advance(Duration::from_secs(30));
        store.mark_seen("node-a").await.unwrap();
        store
            .set_applied_config_version("node-a", 42)
            .await
            .unwrap();
        let node = store.get_node("node-a").await.unwrap().unwrap();
        assert_eq!(node.last_seen, Some(1_700_000_030));
        assert_eq!(node.applied_config_version, Some(42));

        store.revoke("node-a").await.unwrap();
        let node = store.get_node("node-a").await.unwrap().unwrap();
        assert!(node.revoked);
        assert_eq!(store.list_nodes().await.unwrap().len(), 1);

        let error = store.revoke("node-missing").await.unwrap_err();
        assert_eq!(error.code(), "cluster.node.unknown");
        let error = store.mark_seen("node-missing").await.unwrap_err();
        assert_eq!(error.code(), "cluster.node.unknown");
    }

    #[tokio::test]
    async fn duplicate_registration_is_rejected() {
        let store = store(clock()).await;
        store.register_node("node-a", "aa").await.unwrap();
        let error = store.register_node("node-a", "bb").await.unwrap_err();
        assert_eq!(error.code(), "cluster.node.already_joined");
        assert_eq!(
            store.get_node("node-a").await.unwrap().unwrap().fingerprint,
            "aa"
        );
    }

    #[tokio::test]
    async fn registry_survives_reopen() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-cluster-store-{}-{nanos}",
            std::process::id()
        ));
        let path = dir.join("cluster.db");

        let store = ClusterStore::open(&path, clock(), TTL).await.unwrap();
        store.register_node("node-a", "fingerprint").await.unwrap();
        drop(store);

        let reopened = ClusterStore::open(&path, clock(), TTL).await.unwrap();
        let node = reopened.get_node("node-a").await.unwrap().unwrap();
        assert_eq!(node.fingerprint, "fingerprint");

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn invalid_node_id_is_rejected() {
        let store = store(clock()).await;
        let error = store.mint_join_token("Node-A").await.unwrap_err();
        assert_eq!(error.code(), "cluster.role.invalid");
        let error = store.register_node("node.a", "aa").await.unwrap_err();
        assert_eq!(error.code(), "cluster.role.invalid");
    }
}
