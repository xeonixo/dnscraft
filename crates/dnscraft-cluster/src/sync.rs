//! Master → sub-node configuration synchronisation.
//!
//! The master pushes **full** snapshots (never deltas) as `config_push`
//! NDJSON records over the mTLS stream. Each push carries a SHA-256 of a
//! canonical encoding of the snapshot; the sub-node recomputes the digest over
//! the received snapshot and only then hands it to its [`ConfigApplier`].
//!
//! The snapshot itself is opaque to this crate: it is carried as
//! [`serde_json::Value`] and never inspected, logged, or formatted by any
//! `Debug` implementation here.
//!
//! [`ConfigSync`] is the master-side registry of connected nodes. It tracks
//! the highest pushed version and the latest acknowledged applied version per
//! node and retries unacknowledged pushes with exponential backoff driven by
//! the injectable [`Clock`] (no wall-clock sleeps).

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime};

use dnscraft_common::clock::{Clock, add_duration, wait_until};
use dnscraft_common::secret::Secret;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use tokio::sync::{Notify, mpsc, watch};

use crate::config::{DEFAULT_RECONNECT_BACKOFF, DEFAULT_RECONNECT_BACKOFF_MAX};
use crate::error::ClusterError;
use crate::relay::RuntimeCommand;

/// A canonical, deterministic byte encoding of a snapshot.
///
/// Object keys are sorted lexicographically at every nesting level; arrays
/// keep their order; strings use standard JSON escaping and numbers their
/// shortest exact representation. The same value always yields the same bytes,
/// independent of the map implementation or insertion order.
///
/// This is the exact byte string hashed for [`ConfigPush::sha256`].
pub fn canonical_snapshot_bytes(snapshot: &Value) -> Result<Vec<u8>, ClusterError> {
    let mut out = Vec::new();
    write_canonical(snapshot, &mut out)?;
    Ok(out)
}

/// Lowercase hex SHA-256 of [`canonical_snapshot_bytes`].
///
/// The master puts this value in [`ConfigPush::sha256`]; a sub-node recomputes
/// it over the received snapshot before applying anything.
pub fn snapshot_digest(snapshot: &Value) -> Result<String, ClusterError> {
    Ok(crate::sha256_hex(&canonical_snapshot_bytes(snapshot)?))
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), ClusterError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => out.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => {
            out.extend_from_slice(encode(string)?.as_bytes());
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(encode(key)?.as_bytes());
                out.push(b':');
                if let Some(item) = map.get(key) {
                    write_canonical(item, out)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn encode(string: &str) -> Result<String, ClusterError> {
    serde_json::to_string(string).map_err(|error| ClusterError::Internal {
        message: format!("encode canonical snapshot string: {error}"),
    })
}

/// First record on a (re)connected stream, sent by the sub-node.
///
/// `last_applied_version` lets the master reconcile immediately: master newer
/// → push, equal → nothing, sub-node newer → the master overwrites it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// Cluster protocol version; must equal [`crate::PROTOCOL_VERSION`].
    pub protocol: u32,
    /// `node_id` the sender believes it is. The master ignores it and uses the
    /// authenticated certificate identity instead.
    pub node_id: String,
    /// Last config version the node has applied, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_applied_version: Option<i64>,
    /// Highest contiguous log sequence the master has acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_acked_log_seq: Option<u64>,
}

/// Master → sub-node full-snapshot push (`config_push`).
///
/// `snapshot` is opaque. Its `Debug` representation is redacted so a stray
/// `{:?}` can never leak configuration content.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// Master `config_version` the snapshot corresponds to.
    pub config_version: i64,
    /// Lowercase hex SHA-256 of [`canonical_snapshot_bytes`] of `snapshot`.
    pub sha256: String,
    /// Complete configuration snapshot.
    pub snapshot: Value,
}

impl ConfigPush {
    /// Builds a push, computing the canonical digest.
    pub fn new(config_version: i64, snapshot: &Value) -> Result<Self, ClusterError> {
        Ok(Self {
            protocol: crate::PROTOCOL_VERSION,
            config_version,
            sha256: snapshot_digest(snapshot)?,
            snapshot: snapshot.clone(),
        })
    }

    /// Recomputes the digest over the received snapshot.
    ///
    /// Mismatch is [`ClusterError::ConfigApply`] (`cluster.config.apply`) and
    /// the snapshot must not be applied.
    pub fn verify_digest(&self) -> Result<(), ClusterError> {
        if snapshot_digest(&self.snapshot)? == self.sha256 {
            Ok(())
        } else {
            Err(ClusterError::ConfigApply {
                message: "config snapshot digest mismatch".to_owned(),
            })
        }
    }
}

impl fmt::Debug for ConfigPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConfigPush")
            .field("protocol", &self.protocol)
            .field("config_version", &self.config_version)
            .field("sha256", &self.sha256)
            .field("snapshot", &"<opaque>")
            .finish()
    }
}

/// Master → sub-node certificate/key push (`cert_push`).
///
/// The chain is a public PEM bundle; the private key is a [`Secret`] that is
/// redacted by [`Debug`] and transmitted only over the already-mTLS stream.
/// `Secret`'s own [`Serialize`] redacts, so the wire form is written explicitly
/// with the key for transport and rebuilt as a `Secret` on receipt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// Certificate chain (PEM), leaf first.
    pub chain_pem: String,
    /// Matching private key (PEM), never logged or formatted.
    #[serde(
        serialize_with = "serialize_secret",
        deserialize_with = "deserialize_secret"
    )]
    pub private_key: Secret,
}

impl fmt::Debug for CertPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CertPush")
            .field("protocol", &self.protocol)
            .field("chain_pem", &self.chain_pem)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

fn serialize_secret<S: Serializer>(secret: &Secret, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(secret.expose())
}

fn deserialize_secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
    Ok(Secret::new(String::deserialize(deserializer)?))
}

/// Master → sub-node encrypted auth-state push (`auth_snapshot`).
///
/// The snapshot is opaque and its [`Debug`] representation is redacted.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthSnapshotPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// Opaque encrypted auth snapshot.
    pub snapshot: Value,
}

impl fmt::Debug for AuthSnapshotPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthSnapshotPush")
            .field("protocol", &self.protocol)
            .field("snapshot", &"<opaque>")
            .finish()
    }
}

/// Sub-node → master acknowledgement of an applied snapshot (`ack`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigAck {
    /// Config version the sub-node actually applied.
    pub applied_version: i64,
}

/// Error payload carried by an `error` stream record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StreamError {
    /// Stable `cluster.<area>.<reason>` code.
    pub code: String,
    /// Optional structured parameters (never snapshot content).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// One NDJSON record exchanged over the cluster stream.
///
/// Serialized as a single JSON object with a `type` tag
/// (`hello`, `config_push`, `cert_push`, `auth_snapshot`, `ack`,
/// `runtime_command`, `error`) followed by a newline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamRecord {
    /// Stream handshake.
    Hello(Hello),
    /// Full configuration snapshot.
    ConfigPush(ConfigPush),
    /// Certificate chain + private key for hot reload.
    CertPush(CertPush),
    /// Encrypted auth-state snapshot.
    #[serde(rename = "auth_snapshot")]
    AuthSnapshotPush(AuthSnapshotPush),
    /// Applied-version acknowledgement.
    #[serde(rename = "ack")]
    Ack(ConfigAck),
    /// Volatile runtime command (never persisted or queued).
    RuntimeCommand(RuntimeCommand),
    /// Terminal stream error.
    Error {
        /// Error code and optional parameters.
        error: StreamError,
    },
}

/// Sub-node hook that applies a received snapshot.
///
/// The implementation owns validation, persistence, leaf-order apply, and
/// rollback: on `Err` the previous version must remain active and the master
/// receives no ack. The cluster crate never inspects the snapshot.
#[async_trait::async_trait]
pub trait ConfigApplier: Send + Sync {
    /// Applies `snapshot` as `version` and returns the applied version.
    async fn apply(&self, version: i64, snapshot: &Value) -> Result<i64, ClusterError>;
}

/// Sub-node hook that installs a pushed certificate/key through the TLS
/// module's hot-reload path.
///
/// A failure is surfaced as [`ClusterError::CertPushFailed`]
/// (`cluster.cert_push.failed`); the key is only ever read via
/// [`Secret::expose`] inside the implementation.
#[async_trait::async_trait]
pub trait CertInstaller: Send + Sync {
    /// Installs `chain_pem` and its `private_key`.
    async fn install(&self, chain_pem: &str, private_key: &Secret) -> Result<(), ClusterError>;
}

/// Sub-node hook that applies a pushed auth snapshot.
///
/// The snapshot is opaque to this crate; the implementation owns decryption
/// and replacement of local auth state.
#[async_trait::async_trait]
pub trait AuthSnapshotApplier: Send + Sync {
    /// Applies an opaque encrypted auth snapshot.
    async fn apply(&self, snapshot: &Value) -> Result<(), ClusterError>;
}

/// Per-node lag snapshot reported by [`ConfigSync::lag`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeLag {
    /// Connected node.
    pub node_id: String,
    /// Highest config version the master has enqueued for the node.
    pub pushed_version: i64,
    /// Latest version the node acknowledged.
    pub applied_version: i64,
    /// `pushed_version - applied_version`, floored at zero.
    pub lag: i64,
}

/// Master-side broadcast, acknowledgement, and retry registry.
///
/// Cheaply shareable (wrapped in [`Arc`] by the server). Every connected
/// stream registers a sender; [`publish`](Self::publish) enqueues one complete
/// [`ConfigPush`] record per node. A background task (started by
/// [`start`](Self::start)) resends the pending push with exponential backoff
/// until the node acks it. Time comes from the injected [`Clock`].
pub struct ConfigSync {
    clock: Arc<dyn Clock>,
    state: Mutex<SyncState>,
    wake: Notify,
}

#[derive(Default)]
struct SyncState {
    current: Option<Arc<ConfigPush>>,
    nodes: HashMap<String, NodeSync>,
}

struct NodeSync {
    tx: mpsc::Sender<StreamRecord>,
    pushed_version: i64,
    acked_version: i64,
    pending: Option<Arc<ConfigPush>>,
    next_attempt: Option<SystemTime>,
    backoff: Duration,
}

impl ConfigSync {
    /// Creates the registry and starts its retry loop.
    ///
    /// The loop exits when `shutdown` flips to `true` or its sender is dropped.
    pub fn start(clock: Arc<dyn Clock>, shutdown: watch::Receiver<bool>) -> Arc<Self> {
        let sync = Arc::new(Self {
            clock,
            state: Mutex::new(SyncState::default()),
            wake: Notify::new(),
        });
        let runner = Arc::clone(&sync);
        tokio::spawn(async move { runner.run(shutdown).await });
        sync
    }

    /// Publishes a full snapshot to every connected node.
    ///
    /// Registration stores the snapshot as the current one; each push is a
    /// single complete record, never a fragment. Nodes already at this version
    /// are skipped.
    pub fn publish(&self, config_version: i64, snapshot: &Value) -> Result<(), ClusterError> {
        let push = Arc::new(ConfigPush::new(config_version, snapshot)?);
        let now = self.clock.now();
        let mut state = self.lock();
        state.current = Some(Arc::clone(&push));
        for node in state.nodes.values_mut() {
            if node.acked_version == config_version {
                continue;
            }
            node.pushed_version = config_version;
            node.pending = Some(Arc::clone(&push));
            node.backoff = DEFAULT_RECONNECT_BACKOFF;
            node.next_attempt = Some(add_duration(now, node.backoff));
            let _ = node.tx.try_send(StreamRecord::ConfigPush((*push).clone()));
        }
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Records an acknowledgement from `node_id`.
    ///
    /// Clears the pending push once the node has caught up so retries stop.
    pub fn ack(&self, node_id: &str, applied_version: i64) {
        let mut state = self.lock();
        if let Some(node) = state.nodes.get_mut(node_id) {
            node.acked_version = node.acked_version.max(applied_version);
            if node
                .pending
                .as_ref()
                .is_some_and(|push| applied_version >= push.config_version)
            {
                node.pending = None;
                node.next_attempt = None;
            }
        }
        drop(state);
        self.wake.notify_one();
    }

    /// The current published config version, if any.
    pub fn current_version(&self) -> Option<i64> {
        self.lock().current.as_ref().map(|push| push.config_version)
    }

    /// Per-node push/ack lag, sorted by `node_id` for deterministic status.
    pub fn lag(&self) -> Vec<NodeLag> {
        let state = self.lock();
        let mut lag = state
            .nodes
            .iter()
            .map(|(node_id, node)| NodeLag {
                node_id: node_id.clone(),
                pushed_version: node.pushed_version,
                applied_version: node.acked_version,
                lag: (node.pushed_version - node.acked_version).max(0),
            })
            .collect::<Vec<_>>();
        lag.sort_unstable_by(|left, right| left.node_id.cmp(&right.node_id));
        lag
    }

    /// Lag for one node, if it is connected.
    pub fn node_lag(&self, node_id: &str) -> Option<NodeLag> {
        self.lag().into_iter().find(|lag| lag.node_id == node_id)
    }

    /// Registers a newly connected stream and reconciles its version.
    ///
    /// - master newer (or the node has none) → push the current snapshot;
    /// - equal → nothing;
    /// - sub-node newer → the master is authoritative and pushes its snapshot
    ///   (master-wins).
    pub(crate) fn register(
        &self,
        node_id: &str,
        last_applied_version: Option<i64>,
        tx: mpsc::Sender<StreamRecord>,
    ) {
        let now = self.clock.now();
        let mut state = self.lock();
        let applied = last_applied_version.unwrap_or(0);
        let mut node = NodeSync {
            tx,
            pushed_version: applied,
            acked_version: applied,
            pending: None,
            next_attempt: None,
            backoff: DEFAULT_RECONNECT_BACKOFF,
        };
        if let Some(push) = state.current.clone()
            && last_applied_version != Some(push.config_version)
        {
            node.pushed_version = push.config_version;
            node.pending = Some(Arc::clone(&push));
            node.next_attempt = Some(add_duration(now, node.backoff));
            let _ = node.tx.try_send(StreamRecord::ConfigPush((*push).clone()));
        }
        state.nodes.insert(node_id.to_owned(), node);
        drop(state);
        self.wake.notify_one();
    }

    /// Removes a disconnected stream; retries for it stop.
    pub(crate) fn unregister(&self, node_id: &str) {
        self.lock().nodes.remove(node_id);
    }

    /// Sends one record to every connected node.
    ///
    /// Best-effort and never retried: a full node queue drops the record, which
    /// is correct for volatile runtime commands (last command wins).
    pub(crate) fn broadcast(&self, record: StreamRecord) {
        for node in self.lock().nodes.values() {
            let _ = node.tx.try_send(record.clone());
        }
    }

    fn lock(&self) -> MutexGuard<'_, SyncState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn run(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            match self.next_retry_deadline() {
                Some(deadline) => {
                    tokio::select! {
                        () = wait_until(self.clock.as_ref(), deadline, &self.wake) => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                    }
                    self.retry_due();
                }
                None => {
                    tokio::select! {
                        () = self.wake.notified() => {}
                        changed = shutdown.changed() => {
                            if changed.is_err() || *shutdown.borrow() {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    fn next_retry_deadline(&self) -> Option<SystemTime> {
        self.lock()
            .nodes
            .values()
            .filter_map(|node| node.next_attempt)
            .min()
    }

    fn retry_due(&self) {
        let now = self.clock.now();
        let mut state = self.lock();
        for node in state.nodes.values_mut() {
            let Some(deadline) = node.next_attempt else {
                continue;
            };
            if deadline > now {
                continue;
            }
            let Some(push) = node.pending.clone() else {
                node.next_attempt = None;
                continue;
            };
            if node.acked_version >= push.config_version {
                node.next_attempt = None;
                continue;
            }
            let _ = node.tx.try_send(StreamRecord::ConfigPush((*push).clone()));
            node.next_attempt = Some(add_duration(now, node.backoff));
            node.backoff = (node.backoff * 2).min(DEFAULT_RECONNECT_BACKOFF_MAX);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_digest_ignores_object_key_order() {
        let left = json!({ "b": [1, 2], "a": { "y": true, "x": null } });
        let right = json!({ "a": { "x": null, "y": true }, "b": [1, 2] });
        assert_eq!(
            canonical_snapshot_bytes(&left).unwrap(),
            canonical_snapshot_bytes(&right).unwrap()
        );
        assert_eq!(
            snapshot_digest(&left).unwrap(),
            snapshot_digest(&right).unwrap()
        );
        assert_ne!(
            snapshot_digest(&left).unwrap(),
            snapshot_digest(&json!({ "b": [2, 1], "a": { "y": true, "x": null } })).unwrap()
        );
    }

    #[test]
    fn digest_is_lowercase_hex_sha256() {
        let digest = snapshot_digest(&json!({ "version": 1 })).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(digest, digest.to_ascii_lowercase());
    }

    #[test]
    fn record_round_trips_as_tagged_ndjson() {
        let hello = StreamRecord::Hello(Hello {
            protocol: 1,
            node_id: "node-a".to_owned(),
            last_applied_version: Some(3),
            last_acked_log_seq: Some(7),
        });
        let line = serde_json::to_string(&hello).unwrap();
        assert!(line.starts_with(r#"{"type":"hello""#));
        assert_eq!(serde_json::from_str::<StreamRecord>(&line).unwrap(), hello);

        let ack = StreamRecord::Ack(ConfigAck { applied_version: 4 });
        let line = serde_json::to_string(&ack).unwrap();
        assert_eq!(line, r#"{"type":"ack","applied_version":4}"#);

        let push = StreamRecord::ConfigPush(ConfigPush::new(2, &json!({ "a": 1 })).unwrap());
        let line = serde_json::to_string(&push).unwrap();
        assert!(line.starts_with(r#"{"type":"config_push""#));
        let decoded: StreamRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded, push);
    }

    #[test]
    fn push_debug_never_prints_the_snapshot() {
        let push = ConfigPush::new(1, &json!({ "secret": "do-not-log" })).unwrap();
        let rendered = format!("{push:?}");
        assert!(!rendered.contains("do-not-log"));
        assert!(rendered.contains("<opaque>"));
    }

    #[test]
    fn cert_push_debug_and_auth_snapshot_never_leak_material() {
        let key_material =
            "-----BEGIN PRIVATE KEY-----\nsuper-secret-key\n-----END PRIVATE KEY-----";
        let cert = CertPush {
            protocol: crate::PROTOCOL_VERSION,
            chain_pem: "chain".to_owned(),
            private_key: Secret::new(key_material),
        };
        for rendered in [
            format!("{cert:?}"),
            format!("{:?}", StreamRecord::CertPush(cert.clone())),
        ] {
            assert!(!rendered.contains("super-secret-key"));
            assert!(rendered.contains("<redacted>"));
        }

        let auth = AuthSnapshotPush {
            protocol: crate::PROTOCOL_VERSION,
            snapshot: json!({ "secret": "do-not-log" }),
        };
        for rendered in [
            format!("{auth:?}"),
            format!("{:?}", StreamRecord::AuthSnapshotPush(auth.clone())),
        ] {
            assert!(!rendered.contains("do-not-log"));
            assert!(rendered.contains("<opaque>"));
        }
    }

    #[test]
    fn cert_push_round_trips_over_the_wire_with_the_key() {
        let key_material =
            "-----BEGIN PRIVATE KEY-----\nsuper-secret-key\n-----END PRIVATE KEY-----";
        let record = StreamRecord::CertPush(CertPush {
            protocol: crate::PROTOCOL_VERSION,
            chain_pem: "chain".to_owned(),
            private_key: Secret::new(key_material),
        });
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.starts_with(r#"{"type":"cert_push""#));
        assert!(line.contains("super-secret-key"));
        let StreamRecord::CertPush(decoded) = serde_json::from_str(&line).unwrap() else {
            panic!("expected cert_push record");
        };
        assert_eq!(decoded.private_key.expose(), key_material);
        assert_eq!(decoded.chain_pem, "chain");

        let auth = StreamRecord::AuthSnapshotPush(AuthSnapshotPush {
            protocol: crate::PROTOCOL_VERSION,
            snapshot: json!({ "epoch": 2 }),
        });
        let line = serde_json::to_string(&auth).unwrap();
        assert!(line.starts_with(r#"{"type":"auth_snapshot""#));
        assert_eq!(serde_json::from_str::<StreamRecord>(&line).unwrap(), auth);
    }

    #[test]
    fn tampered_push_fails_digest_check() {
        let mut push = ConfigPush::new(1, &json!({ "a": 1 })).unwrap();
        push.sha256 = "00".repeat(32);
        assert_eq!(
            push.verify_digest().unwrap_err().code(),
            "cluster.config.apply"
        );
    }
}
