//! Durable sub-node offline write queue.
//!
//! While the master is unreachable a sub-node may buffer **config-mutating**
//! writes that carry both an `Idempotency-Key` and an `If-Match`. The queue is
//! one SQLite table in the node's data directory: the enqueue transaction
//! commits before the `202 Accepted` is returned, so a crash afterwards cannot
//! lose the write.
//!
//! Replay is strict FIFO and reuses the master's [`WriteExecutor`] transport.
//! A `409 control_api.config.version` marks the head write `conflict` and stops
//! replay; later writes are `blocked` because they were built on the conflicted
//! version. Idempotency keys are passed through unchanged, so a replay after an
//! ambiguous acknowledgement is deduplicated by the master.
//!
//! Request bodies and actors are opaque: they are stored and forwarded
//! verbatim, never logged. Routes whose body carries credential material
//! (currently `PUT /api/v1/tls`) are refused rather than queued, because the
//! queue cannot redact a body without corrupting its replay. The HTTP status
//! mapping (`202`/`400`/`503`) belongs to the caller; the queue only reports
//! what happened.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_common::clock::{add_duration, wait_until};
use rusqlite::{OptionalExtension, params};
use serde::Serialize;
use serde_json::Value;

use crate::client::Backoff;
use crate::config::{
    DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX, OfflineWritesConfig,
};
use crate::error::ClusterError;
use crate::relay::{RelayedActor, WriteExecutor, WriteRelay};
use crate::store::{ClusterStore, db_err, duration_seconds};

/// The `409` code the master returns when `If-Match` is stale.
const CONFIG_VERSION_CONFLICT: &str = "control_api.config.version";

/// Write routes whose bodies carry credential material the queue must never
/// persist. `PUT /api/v1/tls` embeds provider credentials (ACME, DNS,
/// notification secrets); the queue stores bodies verbatim, so such a write is
/// refused instead of stored in plaintext. Redacting it is not an option: the
/// replayed body would then apply wrong credentials on the master.
const SECRET_BEARING_PATHS: [&str; 1] = ["/api/v1/tls"];

fn carries_secrets(method: &str, path: &str) -> bool {
    method.eq_ignore_ascii_case("PUT") && SECRET_BEARING_PATHS.contains(&path.trim_end_matches('/'))
}

/// Lifecycle state of a buffered offline write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineWriteState {
    /// Waiting for replay.
    Pending,
    /// Behind a conflicted write; never replayed.
    Blocked,
    /// Replay returned `409 control_api.config.version`; not applied.
    Conflict,
    /// Replay returned another 4xx; not applied.
    Failed,
    /// Replay returned 2xx; applied by the master.
    Applied,
    /// Exceeded `max_age` and was dropped.
    Expired,
}

impl OfflineWriteState {
    /// Stable spelling used in the database and status payloads.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Blocked => "blocked",
            Self::Conflict => "conflict",
            Self::Failed => "failed",
            Self::Applied => "applied",
            Self::Expired => "expired",
        }
    }

    fn from_db(value: &str) -> Result<Self, ClusterError> {
        match value {
            "pending" => Ok(Self::Pending),
            "blocked" => Ok(Self::Blocked),
            "conflict" => Ok(Self::Conflict),
            "failed" => Ok(Self::Failed),
            "applied" => Ok(Self::Applied),
            "expired" => Ok(Self::Expired),
            other => Err(ClusterError::Internal {
                message: format!("unknown offline write state {other}"),
            }),
        }
    }
}

/// Fields of the `202 Accepted` payload for an accepted offline write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedWrite {
    /// Stable request id carried into replay.
    pub request_id: String,
    /// Always [`OfflineWriteState::Pending`] at enqueue time.
    pub state: OfflineWriteState,
    /// Unix seconds when the write was committed to the queue.
    pub queued_at: i64,
    /// Unix seconds after which the write is dropped.
    pub expires_at: i64,
}

/// Result of asking the queue to buffer a write.
///
/// The caller maps these to HTTP: [`Queued`](Self::Queued) → `202`,
/// [`Rejected`](Self::Rejected) → `400
/// cluster.offline_write_requires_idempotency`, [`Full`](Self::Full) and
/// [`Disabled`](Self::Disabled) → `503`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Committed to SQLite; answer `202` with these fields.
    Queued(QueuedWrite),
    /// Offline buffering is disabled; relay and report `cluster.master_unavailable`.
    Disabled,
    /// Missing `Idempotency-Key` or `If-Match`, or a secret-bearing route that
    /// must never be persisted (see [`SECRET_BEARING_PATHS`]).
    Rejected,
    /// `queue_max_entries` reached.
    Full,
}

/// Per-`request_id` view of one queued write (body and actor omitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflineWriteEntry {
    /// Stable request id.
    pub request_id: String,
    /// Caller-supplied idempotency key.
    pub idempotency_key: String,
    /// Caller-supplied `If-Match`.
    pub if_match: String,
    /// Canonical write method.
    pub method: String,
    /// Canonical write path.
    pub path: String,
    /// Unix seconds when the write was queued.
    pub enqueued_at: i64,
    /// Current lifecycle state.
    pub state: OfflineWriteState,
    /// Number of transport attempts made so far.
    pub attempts: u32,
}

/// Counters for every state in the queue (status surface).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OfflineQueueStatus {
    /// Waiting for replay.
    pub pending: u32,
    /// Blocked behind an earlier conflict.
    pub blocked: u32,
    /// Replay hit a stale `If-Match`.
    pub conflict: u32,
    /// Replay hit another 4xx.
    pub failed: u32,
    /// Applied by the master.
    pub applied: u32,
    /// Dropped for exceeding `max_age`.
    pub expired: u32,
}

/// What one [`OfflineWriteQueue::replay_all`] pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Writes marked `applied`.
    pub applied: u32,
    /// Writes marked `failed` (other 4xx).
    pub failed: u32,
    /// Writes dropped for age.
    pub expired: u32,
    /// Writes marked `blocked` behind a conflict.
    pub blocked: u32,
    /// The request id that hit the head-of-line conflict, if any.
    pub conflict: Option<String>,
}

/// Sub-node hook that re-checks a queued actor before replay.
///
/// The local auth state is the closest available authority: the master cannot
/// verify the sub-node's credential, and a write queued while a token was valid
/// must not be replayed after that token was revoked. The implementation reads
/// the replicated auth snapshot; it never sees plaintext credentials.
#[async_trait::async_trait]
pub trait ActorValidator: Send + Sync {
    /// Whether `actor` still resolves to a live credential with its scope.
    async fn is_valid(&self, actor: &RelayedActor) -> Result<bool, ClusterError>;
}

/// SQLite-backed FIFO queue for writes buffered while the master is down.
#[derive(Clone)]
pub struct OfflineWriteQueue {
    store: ClusterStore,
    config: OfflineWritesConfig,
    validator: Option<Arc<dyn ActorValidator>>,
}

impl OfflineWriteQueue {
    /// Wraps the node's existing [`ClusterStore`] (the queue is a table in it).
    pub fn new(store: ClusterStore, config: OfflineWritesConfig) -> Self {
        Self {
            store,
            config,
            validator: None,
        }
    }

    /// Re-checks queued actors against `validator` before every replay.
    ///
    /// A stale row is marked [`OfflineWriteState::Expired`] and never sent.
    pub fn with_actor_validator(mut self, validator: Arc<dyn ActorValidator>) -> Self {
        self.validator = Some(validator);
        self
    }

    /// Commits `relay` to the queue in one transaction.
    ///
    /// Accepted only when buffering is enabled and the write carries both an
    /// idempotency key and an `If-Match`; the persisted row keeps the original
    /// method, path, opaque body and actor for replay.
    pub async fn enqueue(&self, relay: WriteRelay) -> Result<EnqueueOutcome, ClusterError> {
        if !self.config.enabled {
            return Ok(EnqueueOutcome::Disabled);
        }
        if relay.idempotency_key.is_none() || relay.if_match.is_none() {
            return Ok(EnqueueOutcome::Rejected);
        }
        if carries_secrets(&relay.method, &relay.path) {
            return Ok(EnqueueOutcome::Rejected);
        }

        let queued_at = self.store.now_unix();
        let expires_at = queued_at.saturating_add(duration_seconds(self.config.max_age));
        let body = encode(&relay.body)?;
        let actor = encode(&relay.actor)?;
        let request_id = relay.request_id.clone();
        let idempotency_key = relay.idempotency_key.clone().unwrap_or_default();
        let if_match = relay.if_match.clone().unwrap_or_default();
        let method = relay.method.clone();
        let path = relay.path.clone();
        let max_entries = i64::from(self.config.queue_max_entries);

        let inserted = self
            .store
            .with_conn(move |conn| {
                let tx = conn.transaction().map_err(db_err)?;
                let active: i64 = tx
                    .query_row(
                        "SELECT COUNT(*) FROM offline_writes
                         WHERE state NOT IN ('applied', 'expired')",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(db_err)?;
                if active >= max_entries {
                    return Ok(false);
                }
                tx.execute(
                    "INSERT INTO offline_writes
                        (request_id, idempotency_key, if_match, method, path,
                         body, actor, enqueued_at, state, attempts)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
                    params![
                        request_id,
                        idempotency_key,
                        if_match,
                        method,
                        path,
                        body,
                        actor,
                        queued_at,
                        OfflineWriteState::Pending.as_str(),
                    ],
                )
                .map_err(db_err)?;
                tx.commit().map_err(db_err)?;
                Ok(true)
            })
            .await?;

        if !inserted {
            return Ok(EnqueueOutcome::Full);
        }
        Ok(EnqueueOutcome::Queued(QueuedWrite {
            request_id: relay.request_id,
            state: OfflineWriteState::Pending,
            queued_at,
            expires_at,
        }))
    }

    /// Replays pending writes in strict FIFO order through `executor`.
    ///
    /// Expired rows are dropped first. Each write is sent with its original
    /// `Idempotency-Key` and `If-Match`; 5xx and transport failures are retried
    /// with exponential backoff until the row's `max_age` deadline. A stale
    /// `If-Match` (`409 control_api.config.version`) marks that write
    /// `conflict`, marks every later pending write `blocked`, and stops.
    pub async fn replay_all(
        &self,
        executor: &dyn WriteExecutor,
    ) -> Result<ReplayOutcome, ClusterError> {
        let mut outcome = ReplayOutcome {
            expired: self.expire_old().await?,
            ..ReplayOutcome::default()
        };

        while let Some(row) = self.next_pending().await? {
            // A credential revoked while the write was queued must not replay.
            if let Some(validator) = &self.validator
                && !validator.is_valid(&row.relay.actor).await?
            {
                self.set_state(&row.relay.request_id, OfflineWriteState::Expired)
                    .await?;
                outcome.expired += 1;
                continue;
            }
            match self.send_with_retry(executor, &row).await? {
                SendOutcome::Applied => {
                    self.set_state(&row.relay.request_id, OfflineWriteState::Applied)
                        .await?;
                    outcome.applied += 1;
                }
                SendOutcome::Failed => {
                    self.set_state(&row.relay.request_id, OfflineWriteState::Failed)
                        .await?;
                    outcome.failed += 1;
                }
                SendOutcome::Expired => {
                    self.set_state(&row.relay.request_id, OfflineWriteState::Expired)
                        .await?;
                    outcome.expired += 1;
                }
                SendOutcome::Conflict => {
                    self.set_state(&row.relay.request_id, OfflineWriteState::Conflict)
                        .await?;
                    outcome.conflict = Some(row.relay.request_id.clone());
                    outcome.blocked = self.block_pending().await?;
                    break;
                }
            }
        }
        Ok(outcome)
    }

    /// Counts queued writes by state.
    pub async fn status(&self) -> Result<OfflineQueueStatus, ClusterError> {
        let rows: Vec<(String, i64)> = self
            .store
            .with_conn(|conn| {
                let mut statement = conn
                    .prepare("SELECT state, COUNT(*) FROM offline_writes GROUP BY state")
                    .map_err(db_err)?;
                let rows = statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await?;

        let mut status = OfflineQueueStatus::default();
        for (state, count) in rows {
            let count = u32::try_from(count).unwrap_or(u32::MAX);
            match OfflineWriteState::from_db(&state)? {
                OfflineWriteState::Pending => status.pending = count,
                OfflineWriteState::Blocked => status.blocked = count,
                OfflineWriteState::Conflict => status.conflict = count,
                OfflineWriteState::Failed => status.failed = count,
                OfflineWriteState::Applied => status.applied = count,
                OfflineWriteState::Expired => status.expired = count,
            }
        }
        Ok(status)
    }

    /// Loads one queued write's state, if the `request_id` is known.
    pub async fn get(&self, request_id: &str) -> Result<Option<OfflineWriteEntry>, ClusterError> {
        let request_id = request_id.to_owned();
        let row = self
            .store
            .with_conn(move |conn| {
                conn.query_row(
                    "SELECT request_id, idempotency_key, if_match, method, path,
                            enqueued_at, state, attempts
                     FROM offline_writes WHERE request_id = ?1",
                    params![request_id],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, i64>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, i64>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(db_err)
            })
            .await?;

        let Some((
            request_id,
            idempotency_key,
            if_match,
            method,
            path,
            enqueued_at,
            state,
            attempts,
        )) = row
        else {
            return Ok(None);
        };
        Ok(Some(OfflineWriteEntry {
            request_id,
            idempotency_key,
            if_match,
            method,
            path,
            enqueued_at,
            state: OfflineWriteState::from_db(&state)?,
            attempts: u32::try_from(attempts).unwrap_or(u32::MAX),
        }))
    }

    /// Sends one row, retrying transient failures until its `max_age` deadline.
    async fn send_with_retry(
        &self,
        executor: &dyn WriteExecutor,
        row: &StoredWrite,
    ) -> Result<SendOutcome, ClusterError> {
        let clock = self.store.clock();
        let deadline = Self::deadline(row.enqueued_at, self.config.max_age);
        let wake = tokio::sync::Notify::new();
        let mut backoff = Backoff::new(DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX);

        loop {
            let started = clock.now();
            if started >= deadline {
                return Ok(SendOutcome::Expired);
            }
            self.record_attempt(&row.relay.request_id).await?;
            let response = executor
                .execute(
                    // Transport-only caller: the master authenticates the
                    // originating node from the mTLS certificate.
                    "",
                    row.relay.actor.clone(),
                    row.relay.method.clone(),
                    row.relay.path.clone(),
                    row.relay.body.clone(),
                    row.relay.if_match.clone(),
                    row.relay.idempotency_key.clone(),
                )
                .await;

            match response {
                Ok(response) if (200..300).contains(&response.status) => {
                    return Ok(SendOutcome::Applied);
                }
                Ok(response) if response.status == 409 && is_version_conflict(&response.body) => {
                    return Ok(SendOutcome::Conflict);
                }
                Ok(response) if (400..500).contains(&response.status) => {
                    return Ok(SendOutcome::Failed);
                }
                // 5xx or transport failure: retry with backoff until `max_age`.
                Ok(_) | Err(_) => {
                    let until = add_duration(started, backoff.next_delay()).min(deadline);
                    wait_until(clock.as_ref(), until, &wake).await;
                }
            }
        }
    }

    /// Drops every unresolved row older than `max_age`.
    async fn expire_old(&self) -> Result<u32, ClusterError> {
        let cutoff = self
            .store
            .now_unix()
            .saturating_sub(duration_seconds(self.config.max_age));
        let changed = self
            .store
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE offline_writes SET state = ?1
                     WHERE state NOT IN ('applied', 'expired') AND enqueued_at <= ?2",
                    params![OfflineWriteState::Expired.as_str(), cutoff],
                )
                .map_err(db_err)
            })
            .await?;
        Ok(changed as u32)
    }

    /// First pending row by insertion order (strict FIFO).
    async fn next_pending(&self) -> Result<Option<StoredWrite>, ClusterError> {
        self.store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT request_id, idempotency_key, if_match, method, path,
                            body, actor, enqueued_at
                     FROM offline_writes WHERE state = 'pending'
                     ORDER BY rowid LIMIT 1",
                    [],
                    stored_from_row,
                )
                .optional()
                .map_err(db_err)
            })
            .await
    }

    async fn record_attempt(&self, request_id: &str) -> Result<(), ClusterError> {
        let request_id = request_id.to_owned();
        self.store
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE offline_writes SET attempts = attempts + 1 WHERE request_id = ?1",
                    params![request_id],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await
    }

    async fn set_state(
        &self,
        request_id: &str,
        state: OfflineWriteState,
    ) -> Result<(), ClusterError> {
        let request_id = request_id.to_owned();
        self.store
            .with_conn(move |conn| {
                conn.execute(
                    "UPDATE offline_writes SET state = ?1 WHERE request_id = ?2",
                    params![state.as_str(), request_id],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await
    }

    /// Marks every still-pending write `blocked` and returns the count.
    async fn block_pending(&self) -> Result<u32, ClusterError> {
        let changed = self
            .store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE offline_writes SET state = ?1 WHERE state = 'pending'",
                    params![OfflineWriteState::Blocked.as_str()],
                )
                .map_err(db_err)
            })
            .await?;
        Ok(changed as u32)
    }

    fn deadline(enqueued_at: i64, max_age: Duration) -> SystemTime {
        let start = SystemTime::UNIX_EPOCH
            + Duration::from_secs(u64::try_from(enqueued_at).unwrap_or_default());
        add_duration(start, max_age)
    }
}

/// One pending row loaded for replay.
struct StoredWrite {
    relay: WriteRelay,
    enqueued_at: i64,
}

/// Terminal classification of one transport attempt.
enum SendOutcome {
    Applied,
    Failed,
    Expired,
    Conflict,
}

fn stored_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredWrite> {
    Ok(StoredWrite {
        relay: WriteRelay {
            request_id: row.get(0)?,
            idempotency_key: Some(row.get(1)?),
            if_match: Some(row.get(2)?),
            method: row.get(3)?,
            path: row.get(4)?,
            body: decode(row, 5)?,
            actor: decode(row, 6)?,
        },
        enqueued_at: row.get(7)?,
    })
}

fn decode<T: serde::de::DeserializeOwned>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<T> {
    let text: String = row.get(index)?;
    serde_json::from_str(&text).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })
}

fn encode<T: Serialize>(value: &T) -> Result<String, ClusterError> {
    serde_json::to_string(value).map_err(|error| ClusterError::Internal {
        message: format!("encode offline write: {error}"),
    })
}

fn is_version_conflict(body: &Value) -> bool {
    body.pointer("/error/code").and_then(Value::as_str) == Some(CONFIG_VERSION_CONFLICT)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use dnscraft_common::clock::{Clock, ManualClock};
    use serde_json::json;

    use super::*;
    use crate::relay::{RelayResponse, RelayedActor};

    /// Rejects every actor (a token revoked while the write was queued).
    struct RevokedValidator;

    #[async_trait::async_trait]
    impl ActorValidator for RevokedValidator {
        async fn is_valid(&self, _actor: &RelayedActor) -> Result<bool, ClusterError> {
            Ok(false)
        }
    }

    const TTL: Duration = Duration::from_secs(15 * 60);
    const NOW: i64 = 1_700_000_000;
    const MAX_AGE: Duration = Duration::from_secs(3600);

    fn config(max_entries: u32) -> OfflineWritesConfig {
        OfflineWritesConfig {
            enabled: true,
            queue_max_entries: max_entries,
            max_age: MAX_AGE,
        }
    }

    fn relay(id: &str) -> WriteRelay {
        WriteRelay {
            request_id: id.to_owned(),
            idempotency_key: Some(format!("key-{id}")),
            if_match: Some("v1".to_owned()),
            method: "PUT".to_owned(),
            path: "/api/v1/config".to_owned(),
            body: json!({ "opaque": "do-not-log" }),
            actor: RelayedActor {
                actor_id: "u1".to_owned(),
                actor_type: "user".to_owned(),
                scope: "admin".to_owned(),
            },
        }
    }

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(
            UNIX_EPOCH + Duration::from_secs(NOW as u64),
        ))
    }

    async fn queue_with(
        config: OfflineWritesConfig,
        clock: Arc<ManualClock>,
    ) -> (OfflineWriteQueue, Arc<ManualClock>) {
        let store = ClusterStore::open_in_memory(clock.clone() as Arc<dyn Clock>, TTL)
            .await
            .unwrap();
        (OfflineWriteQueue::new(store, config), clock)
    }

    async fn queue(max_entries: u32) -> (OfflineWriteQueue, Arc<ManualClock>) {
        queue_with(config(max_entries), clock()).await
    }

    #[derive(Debug, Clone)]
    struct Call {
        method: String,
        path: String,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    }

    #[derive(Default)]
    struct MockExecutor {
        calls: Mutex<Vec<Call>>,
        replies: Mutex<VecDeque<u16>>,
    }

    impl MockExecutor {
        fn with_replies(replies: &[u16]) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                replies: Mutex::new(replies.iter().copied().collect()),
            }
        }

        fn calls(&self) -> Vec<Call> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl WriteExecutor for MockExecutor {
        async fn execute(
            &self,
            _node_id: &str,
            _actor: RelayedActor,
            method: String,
            path: String,
            _body: Value,
            if_match: Option<String>,
            idempotency_key: Option<String>,
        ) -> Result<RelayResponse, ClusterError> {
            self.calls.lock().unwrap().push(Call {
                method,
                path,
                if_match,
                idempotency_key,
            });
            let status = self.replies.lock().unwrap().pop_front().unwrap_or(200);
            let body = if status == 409 {
                json!({ "error": { "code": "control_api.config.version" } })
            } else {
                json!({ "data": {} })
            };
            Ok(RelayResponse { status, body })
        }
    }

    /// Fails the first attempt with a 503 and advances the manual clock past
    /// the backoff, then succeeds.
    struct TransientOnceExecutor {
        clock: Arc<ManualClock>,
        calls: AtomicU32,
    }

    #[async_trait::async_trait]
    impl WriteExecutor for TransientOnceExecutor {
        async fn execute(
            &self,
            _node_id: &str,
            _actor: RelayedActor,
            _method: String,
            _path: String,
            _body: Value,
            _if_match: Option<String>,
            _idempotency_key: Option<String>,
        ) -> Result<RelayResponse, ClusterError> {
            let previous = self.calls.fetch_add(1, Ordering::SeqCst);
            if previous == 0 {
                self.clock.advance(Duration::from_secs(5));
                return Ok(RelayResponse {
                    status: 503,
                    body: json!({ "error": { "code": "cluster.master_unavailable" } }),
                });
            }
            Ok(RelayResponse {
                status: 200,
                body: json!({ "data": {} }),
            })
        }
    }

    #[tokio::test]
    async fn enqueue_requires_idempotency_and_if_match() {
        let (queue, _clock) = queue(10).await;

        let mut no_key = relay("r1");
        no_key.idempotency_key = None;
        assert_eq!(
            queue.enqueue(no_key).await.unwrap(),
            EnqueueOutcome::Rejected
        );

        let mut no_match = relay("r2");
        no_match.if_match = None;
        assert_eq!(
            queue.enqueue(no_match).await.unwrap(),
            EnqueueOutcome::Rejected
        );
        assert_eq!(queue.status().await.unwrap(), OfflineQueueStatus::default());

        let EnqueueOutcome::Queued(queued) = queue.enqueue(relay("r3")).await.unwrap() else {
            panic!("fully keyed write must be queued");
        };
        assert_eq!(queued.request_id, "r3");
        assert_eq!(queued.state, OfflineWriteState::Pending);
        assert_eq!(queued.queued_at, NOW);
        assert_eq!(queued.expires_at, NOW + MAX_AGE.as_secs() as i64);
    }

    #[tokio::test]
    async fn secret_bearing_tls_write_is_never_persisted() {
        let (queue, _clock) = queue(10).await;
        let mut write = relay("tls");
        write.path = "/api/v1/tls".to_owned();
        write.body = json!({
            "dns_provider": { "api_token": "super-secret" },
        });

        assert_eq!(
            queue.enqueue(write).await.unwrap(),
            EnqueueOutcome::Rejected,
            "a credential-bearing body must not enter the plaintext queue"
        );
        assert_eq!(queue.status().await.unwrap(), OfflineQueueStatus::default());
        assert!(queue.get("tls").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn disabled_queue_does_not_buffer() {
        let (queue, _clock) = queue_with(
            OfflineWritesConfig {
                enabled: false,
                ..config(10)
            },
            clock(),
        )
        .await;
        assert_eq!(
            queue.enqueue(relay("r1")).await.unwrap(),
            EnqueueOutcome::Disabled
        );
        assert_eq!(queue.status().await.unwrap(), OfflineQueueStatus::default());
    }

    #[tokio::test]
    async fn queue_cap_returns_full() {
        let (queue, _clock) = queue(2).await;
        assert!(matches!(
            queue.enqueue(relay("a")).await.unwrap(),
            EnqueueOutcome::Queued(_)
        ));
        assert!(matches!(
            queue.enqueue(relay("b")).await.unwrap(),
            EnqueueOutcome::Queued(_)
        ));
        assert_eq!(
            queue.enqueue(relay("c")).await.unwrap(),
            EnqueueOutcome::Full
        );
        assert_eq!(queue.status().await.unwrap().pending, 2);
        assert!(queue.get("c").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn replay_is_strict_fifo_and_keeps_original_keys() {
        let (queue, _clock) = queue(10).await;
        let executor = MockExecutor::default();
        for id in ["a", "b", "c"] {
            queue.enqueue(relay(id)).await.unwrap();
        }

        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.applied, 3);
        assert_eq!(outcome.failed, 0);
        assert_eq!(outcome.expired, 0);
        assert_eq!(outcome.conflict, None);

        let calls = executor.calls();
        assert_eq!(calls.len(), 3);
        let keys: Vec<Option<&str>> = calls
            .iter()
            .map(|call| call.idempotency_key.as_deref())
            .collect();
        assert_eq!(keys, vec![Some("key-a"), Some("key-b"), Some("key-c")]);
        assert!(
            calls
                .iter()
                .all(|call| call.if_match.as_deref() == Some("v1"))
        );
        assert!(calls.iter().all(|call| call.method == "PUT"));
        assert!(calls.iter().all(|call| call.path == "/api/v1/config"));

        assert_eq!(queue.status().await.unwrap().applied, 3);
        let entry = queue.get("b").await.unwrap().unwrap();
        assert_eq!(entry.state, OfflineWriteState::Applied);
        assert_eq!(entry.attempts, 1);
    }

    #[tokio::test]
    async fn conflict_blocks_later_writes_and_stops_replay() {
        let (queue, _clock) = queue(10).await;
        for id in ["a", "b", "c"] {
            queue.enqueue(relay(id)).await.unwrap();
        }
        let executor = MockExecutor::with_replies(&[200, 409]);

        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(outcome.conflict.as_deref(), Some("b"));
        assert_eq!(outcome.blocked, 1);
        // `c` was never sent: replay stopped at the conflict.
        assert_eq!(executor.calls().len(), 2);

        assert_eq!(
            queue.get("a").await.unwrap().unwrap().state,
            OfflineWriteState::Applied
        );
        assert_eq!(
            queue.get("b").await.unwrap().unwrap().state,
            OfflineWriteState::Conflict
        );
        assert_eq!(
            queue.get("c").await.unwrap().unwrap().state,
            OfflineWriteState::Blocked
        );

        // A second pass does not replay the conflicted head or the blocked tail.
        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.applied, 0);
        assert_eq!(executor.calls().len(), 2);
    }

    #[tokio::test]
    async fn other_4xx_marks_failed_and_continues() {
        let (queue, _clock) = queue(10).await;
        for id in ["a", "b"] {
            queue.enqueue(relay(id)).await.unwrap();
        }
        let executor = MockExecutor::with_replies(&[422, 200]);

        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.failed, 1);
        assert_eq!(outcome.applied, 1);
        assert_eq!(
            queue.get("a").await.unwrap().unwrap().state,
            OfflineWriteState::Failed
        );
        assert_eq!(
            queue.get("b").await.unwrap().unwrap().state,
            OfflineWriteState::Applied
        );
    }

    #[tokio::test]
    async fn expired_rows_are_dropped_without_sending() {
        let (queue, clock) = queue(10).await;
        queue.enqueue(relay("a")).await.unwrap();
        clock.advance(MAX_AGE);

        let executor = MockExecutor::default();
        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.expired, 1);
        assert_eq!(outcome.applied, 0);
        assert!(executor.calls().is_empty());
        assert_eq!(
            queue.get("a").await.unwrap().unwrap().state,
            OfflineWriteState::Expired
        );
    }

    #[tokio::test]
    async fn replay_drops_writes_whose_actor_is_no_longer_valid() {
        let (queue, _clock) = queue(10).await;
        let queue = queue.with_actor_validator(Arc::new(RevokedValidator));
        queue.enqueue(relay("a")).await.unwrap();
        let executor = MockExecutor::default();

        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.expired, 1);
        assert_eq!(outcome.applied, 0);
        assert!(
            executor.calls().is_empty(),
            "a stale actor's write must never be submitted"
        );
        assert_eq!(
            queue.get("a").await.unwrap().unwrap().state,
            OfflineWriteState::Expired
        );
    }

    #[tokio::test]
    async fn transient_failure_is_retried_with_backoff() {
        let (queue, clock) = queue(10).await;
        queue.enqueue(relay("a")).await.unwrap();
        let executor = TransientOnceExecutor {
            clock: Arc::clone(&clock),
            calls: AtomicU32::new(0),
        };

        let outcome = queue.replay_all(&executor).await.unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(executor.calls.load(Ordering::SeqCst), 2);
        assert_eq!(queue.get("a").await.unwrap().unwrap().attempts, 2);
    }

    #[tokio::test]
    async fn queue_survives_store_reopen() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-cluster-offline-{}-{nanos}",
            std::process::id()
        ));
        let path = dir.join("cluster.db");
        let clock = clock();

        let store = ClusterStore::open(&path, Arc::clone(&clock) as Arc<dyn Clock>, TTL)
            .await
            .unwrap();
        let queue = OfflineWriteQueue::new(store, config(10));
        queue.enqueue(relay("a")).await.unwrap();
        drop(queue);

        let store = ClusterStore::open(&path, Arc::clone(&clock) as Arc<dyn Clock>, TTL)
            .await
            .unwrap();
        let reopened = OfflineWriteQueue::new(store, config(10));
        assert_eq!(reopened.status().await.unwrap().pending, 1);
        let outcome = reopened.replay_all(&MockExecutor::default()).await.unwrap();
        assert_eq!(outcome.applied, 1);
        assert_eq!(
            reopened.get("a").await.unwrap().unwrap().state,
            OfflineWriteState::Applied
        );

        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
