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
use serde::{Deserialize, Serialize};
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
    /// Optional stream features the sender understands (see [`CAP_CLOUDFLARE_TOKEN`]).
    ///
    /// Absent on older nodes: the master never sends a record type a node did
    /// not advertise, because an unknown record ends that node's stream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

/// Capability: the node accepts [`CloudflareTokenPush`] records.
pub const CAP_CLOUDFLARE_TOKEN: &str = "cloudflare_token";

/// Master → DynDNS sub-node Cloudflare API token (`cloudflare_token_push`).
///
/// Never appears in config snapshots, acks, status or logs. Debug redacts it.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudflareTokenPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// Token plaintext, or `null` to clear.
    pub token: Option<String>,
}

impl fmt::Debug for CloudflareTokenPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareTokenPush")
            .field("protocol", &self.protocol)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
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

/// Master → sub-node notice that the TLS certificate was renewed
/// (`tls_renewed`).
///
/// Carries only the names the certificate covers. It never carries key
/// material: a node that receives it generates its own key and requests its
/// own certificate (see [`crate::ClusterClient::request_tls_certificate`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsRenewed {
    /// Cluster protocol version.
    pub protocol: u32,
    /// DNS names the renewed certificate covers.
    pub names: Vec<String>,
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

/// Master → sync_owner UniFi API key (`secret_push`).
///
/// Never appears in config snapshots or acks. Debug redacts the key.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// UniFi profile id (`unifi.api_key.{profile_id}`).
    pub profile_id: String,
    /// API key plaintext, or `null` to clear.
    pub api_key: Option<String>,
}

impl fmt::Debug for SecretPush {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretPush")
            .field("protocol", &self.protocol)
            .field("profile_id", &self.profile_id)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Master → bound nodes UniFi directory snapshot (`clients_directory_push`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClientsDirectoryPush {
    /// Cluster protocol version.
    pub protocol: u32,
    /// UniFi profile id this directory belongs to.
    pub profile_id: String,
    /// Owner-side generation (informational).
    pub generation: u64,
    /// Serialised UniFi observations (cache wire shape).
    pub observations: Value,
    /// Serialised network metadata (cache wire shape).
    pub networks: Value,
}

/// One NDJSON record exchanged over the cluster stream.
///
/// Serialized as a single JSON object with a `type` tag
/// (`hello`, `config_push`, `tls_renewed`, `auth_snapshot`, `ack`,
/// `runtime_command`, `secret_push`, `clients_directory_push`, `error`)
/// followed by a newline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum StreamRecord {
    /// Stream handshake.
    Hello(Hello),
    /// Full configuration snapshot.
    ConfigPush(ConfigPush),
    /// The master's TLS certificate was renewed; request a node-local one.
    TlsRenewed(TlsRenewed),
    /// Encrypted auth-state snapshot.
    #[serde(rename = "auth_snapshot")]
    AuthSnapshotPush(AuthSnapshotPush),
    /// Applied-version acknowledgement.
    #[serde(rename = "ack")]
    Ack(ConfigAck),
    /// Volatile runtime command (never persisted or queued).
    RuntimeCommand(RuntimeCommand),
    /// UniFi API key for the profile's sync_owner only.
    SecretPush(SecretPush),
    /// Cloudflare API token for DynDNS nodes (capability-gated).
    CloudflareTokenPush(CloudflareTokenPush),
    /// UniFi directory snapshot for nodes bound to a profile.
    ClientsDirectoryPush(ClientsDirectoryPush),
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
    next_generation: u64,
    /// Nodes that were sent a Cloudflare token (so a clear can reach them).
    cloudflare_sent: std::collections::HashSet<String>,
}

struct NodeSync {
    /// Per-registration identity, so a stale stream's `unregister` cannot
    /// remove a newer registration for the same node.
    generation: u64,
    tx: mpsc::Sender<StreamRecord>,
    capabilities: Vec<String>,
    pushed_version: i64,
    acked_version: i64,
    pending: Option<Arc<ConfigPush>>,
    /// When the oldest unacknowledged push was sent; cleared by a full ack.
    pending_since: Option<SystemTime>,
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
            node.pending_since.get_or_insert(now);
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
                node.pending_since = None;
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

    /// Connected nodes whose oldest unacknowledged push is at least `timeout`
    /// old (`config_apply_timeout`), sorted by `node_id`.
    pub fn degraded_nodes(&self, timeout: Duration) -> Vec<String> {
        let now = self.clock.now();
        let state = self.lock();
        let mut nodes = state
            .nodes
            .iter()
            .filter(|(_, node)| {
                node.pending_since
                    .is_some_and(|since| add_duration(since, timeout) <= now)
            })
            .map(|(node_id, _)| node_id.clone())
            .collect::<Vec<_>>();
        nodes.sort_unstable();
        nodes
    }

    /// Lag for one node, if it is connected.
    pub fn node_lag(&self, node_id: &str) -> Option<NodeLag> {
        self.lag().into_iter().find(|lag| lag.node_id == node_id)
    }

    /// Registers a newly connected stream and reconciles its version.
    ///
    /// Returns the registration's generation; pass it to [`Self::unregister`]
    /// so a stale stream cannot remove a newer registration.
    ///
    /// - master newer (or the node has none) → push the current snapshot;
    /// - equal → nothing;
    /// - sub-node newer → the master is authoritative and pushes its snapshot
    ///   (master-wins).
    pub(crate) fn register(
        &self,
        node_id: &str,
        last_applied_version: Option<i64>,
        capabilities: Vec<String>,
        tx: mpsc::Sender<StreamRecord>,
    ) -> u64 {
        let now = self.clock.now();
        let mut state = self.lock();
        let applied = last_applied_version.unwrap_or(0);
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        let mut node = NodeSync {
            generation,
            tx,
            capabilities,
            pushed_version: applied,
            acked_version: applied,
            pending: None,
            pending_since: None,
            next_attempt: None,
            backoff: DEFAULT_RECONNECT_BACKOFF,
        };
        if let Some(push) = state.current.clone()
            && last_applied_version != Some(push.config_version)
        {
            node.pushed_version = push.config_version;
            node.pending = Some(Arc::clone(&push));
            node.pending_since = Some(now);
            node.next_attempt = Some(add_duration(now, node.backoff));
            let _ = node.tx.try_send(StreamRecord::ConfigPush((*push).clone()));
        }
        state.nodes.insert(node_id.to_owned(), node);
        drop(state);
        self.wake.notify_one();
        generation
    }

    /// Removes a disconnected stream; retries for it stop.
    ///
    /// A reconnecting node can register a new stream before the old one notices
    /// the disconnect. The old stream must not then delete the new
    /// registration, so the entry is removed only when its generation matches.
    pub(crate) fn unregister(&self, node_id: &str, generation: u64) {
        let mut state = self.lock();
        if state
            .nodes
            .get(node_id)
            .is_some_and(|node| node.generation == generation)
        {
            state.nodes.remove(node_id);
        }
    }

    /// Forcibly removes a node's stream regardless of which registration it is.
    ///
    /// Used by the admin revoke path, which must terminate the node even if a
    /// reconnect raced the revocation.
    pub(crate) fn remove(&self, node_id: &str) {
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

    /// Sends one record to a single connected node (best-effort, no retry).
    pub(crate) fn send_to(&self, node_id: &str, record: StreamRecord) {
        if let Some(node) = self.lock().nodes.get(node_id) {
            let _ = node.tx.try_send(record);
        }
    }

    /// Sends the Cloudflare token (or a clear) to `node_id` if it advertised
    /// [`CAP_CLOUDFLARE_TOKEN`]. A clear only goes to nodes that were sent a
    /// token before. Returns whether a record was queued.
    pub(crate) fn send_cloudflare_token(&self, node_id: &str, token: Option<&str>) -> bool {
        let mut state = self.lock();
        let Some(node) = state.nodes.get(node_id) else {
            return false;
        };
        if !node.capabilities.iter().any(|c| c == CAP_CLOUDFLARE_TOKEN) {
            return false;
        }
        if token.is_none() && !state.cloudflare_sent.contains(node_id) {
            return false;
        }
        let record = StreamRecord::CloudflareTokenPush(CloudflareTokenPush {
            protocol: crate::PROTOCOL_VERSION,
            token: token.map(str::to_owned),
        });
        let queued = node.tx.try_send(record).is_ok();
        if queued {
            if token.is_some() {
                state.cloudflare_sent.insert(node_id.to_owned());
            } else {
                state.cloudflare_sent.remove(node_id);
            }
        }
        queued
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
            capabilities: Vec::new(),
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
    fn auth_snapshot_debug_never_leaks_material() {
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
    fn secret_push_debug_redacts_api_key_and_round_trips() {
        let record = StreamRecord::SecretPush(SecretPush {
            protocol: crate::PROTOCOL_VERSION,
            profile_id: "home".to_owned(),
            api_key: Some("super-secret-key".to_owned()),
        });
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("super-secret-key"));
        assert!(rendered.contains("<redacted>"));
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.starts_with(r#"{"type":"secret_push""#));
        assert_eq!(serde_json::from_str::<StreamRecord>(&line).unwrap(), record);

        let directory = StreamRecord::ClientsDirectoryPush(ClientsDirectoryPush {
            protocol: crate::PROTOCOL_VERSION,
            profile_id: "home".to_owned(),
            generation: 3,
            observations: json!([]),
            networks: json!([]),
        });
        let line = serde_json::to_string(&directory).unwrap();
        assert!(line.starts_with(r#"{"type":"clients_directory_push""#));
        assert_eq!(
            serde_json::from_str::<StreamRecord>(&line).unwrap(),
            directory
        );
    }

    #[test]
    fn tls_renewed_round_trips_without_key_material() {
        let record = StreamRecord::TlsRenewed(TlsRenewed {
            protocol: crate::PROTOCOL_VERSION,
            names: vec!["example.net".to_owned(), "*.example.net".to_owned()],
        });
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.starts_with(r#"{"type":"tls_renewed""#));
        assert!(!line.contains("PRIVATE KEY"));
        let decoded: StreamRecord = serde_json::from_str(&line).unwrap();
        assert_eq!(decoded, record);

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

    #[tokio::test]
    async fn a_stale_stream_unregister_keeps_the_newer_registration() {
        let sync = ConfigSync {
            clock: Arc::new(dnscraft_common::clock::ManualClock::new(
                std::time::SystemTime::UNIX_EPOCH,
            )),
            state: Mutex::new(SyncState::default()),
            wake: Notify::new(),
        };
        let (old_tx, _old_rx) = mpsc::channel(8);
        let (new_tx, mut new_rx) = mpsc::channel(8);
        let old_generation = sync.register("node-b", Some(0), Vec::new(), old_tx);
        sync.register("node-b", Some(0), Vec::new(), new_tx);

        // The old stream notices its disconnect after the reconnect registered.
        sync.unregister("node-b", old_generation);
        sync.publish(1, &json!({ "a": 1 })).unwrap();

        assert!(
            matches!(new_rx.try_recv(), Ok(StreamRecord::ConfigPush(_))),
            "the live stream must keep receiving pushes"
        );
    }
    #[tokio::test]
    async fn a_node_without_an_ack_is_degraded_after_the_apply_timeout() {
        let clock = Arc::new(dnscraft_common::clock::ManualClock::new(
            std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let sync = ConfigSync {
            clock: clock.clone(),
            state: Mutex::new(SyncState::default()),
            wake: Notify::new(),
        };
        let (tx, _rx) = mpsc::channel(8);
        sync.register("node-a", Some(0), Vec::new(), tx);
        sync.publish(1, &json!({ "a": 1 })).unwrap();
        let timeout = Duration::from_secs(30);

        clock.advance(Duration::from_secs(29));
        assert!(sync.degraded_nodes(timeout).is_empty());

        // A later push does not restart the clock: the oldest unacked push counts.
        sync.publish(2, &json!({ "a": 2 })).unwrap();
        clock.advance(Duration::from_secs(1));
        assert_eq!(sync.degraded_nodes(timeout), vec!["node-a".to_owned()]);

        // A full ack clears the degradation.
        sync.ack("node-a", 2);
        assert!(sync.degraded_nodes(timeout).is_empty());
    }
    #[test]
    fn cloudflare_token_push_debug_redacts_and_round_trips() {
        let record = StreamRecord::CloudflareTokenPush(CloudflareTokenPush {
            protocol: crate::PROTOCOL_VERSION,
            token: Some("cf-secret-token".to_owned()),
        });
        let rendered = format!("{record:?}");
        assert!(!rendered.contains("cf-secret-token"));
        assert!(rendered.contains("<redacted>"));
        let line = serde_json::to_string(&record).unwrap();
        assert!(line.starts_with(r#"{"type":"cloudflare_token_push""#));
        assert_eq!(serde_json::from_str::<StreamRecord>(&line).unwrap(), record);
    }

    #[test]
    fn old_hello_without_capabilities_parses_and_new_one_omits_empty() {
        let old = r#"{"type":"hello","protocol":1,"node_id":"n"}"#;
        match serde_json::from_str::<StreamRecord>(old).unwrap() {
            StreamRecord::Hello(hello) => assert!(hello.capabilities.is_empty()),
            other => panic!("unexpected {other:?}"),
        }
        let hello = StreamRecord::Hello(Hello {
            protocol: 1,
            node_id: "n".to_owned(),
            last_applied_version: None,
            last_acked_log_seq: None,
            capabilities: Vec::new(),
        });
        assert!(
            !serde_json::to_string(&hello)
                .unwrap()
                .contains("capabilities")
        );
    }

    #[tokio::test]
    async fn cloudflare_token_goes_only_to_capable_nodes_and_clear_only_after_a_send() {
        let clock = Arc::new(dnscraft_common::clock::ManualClock::new(
            SystemTime::UNIX_EPOCH,
        ));
        let (_shutdown, rx) = watch::channel(false);
        let sync = ConfigSync::start(clock, rx);
        let (old_tx, mut old_rx) = mpsc::channel(8);
        let (new_tx, mut new_rx) = mpsc::channel(8);
        sync.register("old", None, Vec::new(), old_tx);
        sync.register("new", None, vec![CAP_CLOUDFLARE_TOKEN.to_owned()], new_tx);

        // An old node (no capability) must never get the unknown record.
        assert!(!sync.send_cloudflare_token("old", Some("t")));
        assert!(old_rx.try_recv().is_err());

        // A clear before any send is a no-op.
        assert!(!sync.send_cloudflare_token("new", None));
        assert!(new_rx.try_recv().is_err());

        assert!(sync.send_cloudflare_token("new", Some("t")));
        assert!(matches!(
            new_rx.try_recv(),
            Ok(StreamRecord::CloudflareTokenPush(CloudflareTokenPush {
                token: Some(_),
                ..
            }))
        ));
        assert!(sync.send_cloudflare_token("new", None));
        assert!(matches!(
            new_rx.try_recv(),
            Ok(StreamRecord::CloudflareTokenPush(CloudflareTokenPush {
                token: None,
                ..
            }))
        ));
        assert!(!sync.send_cloudflare_token("new", None));
    }
}
