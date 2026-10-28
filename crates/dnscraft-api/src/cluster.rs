//! Cluster runtime wiring: the `dnscraft-cluster` hook implementations and the
//! master/sub-node startup entry point.
//!
//! The cluster crate owns the transport, snapshot digests, ack/lag tracking and
//! the offline queue. This module supplies the control-api side of each trait:
//!
//! - [`SyncedConfigApplier`] — applies a pushed snapshot through
//!   [`ConfigService::apply_synced_config`](crate::ConfigService::apply_synced_config),
//!   filtering node-scoped policy views first.
//! - [`TlsCertInstaller`] — installs a node's own certificate (requested with
//!   a node-local key) through the TLS hot-reload resolver and store.
//! - [`StateAuthApplier`] — replaces local auth state with a pushed
//!   [`AuthSnapshot`](crate::AuthSnapshot).
//! - [`StateRuntimeApplier`] — applies a volatile runtime command to the local
//!   filter engine.
//! - [`ConfigWriteExecutor`] — re-checks RBAC and executes a relayed config
//!   write on the master, with `Idempotency-Key` deduplication.
//! - [`QueryLogOutbox`] / [`QueryLogIngest`] — the sub-node log cursor and the
//!   master's deduplicating ingest.
//!
//! [`ClusterRuntime::start`] switches on [`Role`] and starts the mTLS listener
//! (master) or the reconnect/apply loop plus log-streamer and offline-replay
//! tasks (sub-node). It never opens a connection from the master to a sub-node.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use axum::http::Method;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::sync::{Notify, watch};
use tokio::task::JoinHandle;

use dnscraft_cluster::{
    ActorValidator, AuthSnapshotApplier, AuthSnapshotSource, Backfill, CertInstaller,
    ClusterBroadcast, ClusterCa, ClusterClient, ClusterConfig, ClusterError, ClusterServer,
    ClusterServerConfig, ClusterStore, ConfigApplier, ConfigSync, LogIngest, LogOutbox, LogRecord,
    LogStreamer, NodeIdentity, OfflineWriteQueue, PendingNodeIdentity, RelayResponse, RelayedActor,
    Role, RuntimeCommandApplier, StreamRecord, TlsCsrSigner, TlsPaths, WriteExecutor, WriteRelay,
};
use dnscraft_common::clock::{Clock, add_duration, wait_until};
use dnscraft_common::secret::Secret;
use dnscraft_tls::{CertResolver, CertStore, TlsEngine};

use crate::api::auth::{AuthSnapshot, AuthState, Scope, authorize, requirement};
use crate::api::clients_routes::{ManualEntryBody, name as manual_name, reject_conflict};
use crate::api::config_routes::{
    ProfileBody, ViewBody, array_mut, module_error, remove_by_id, stored_snapshot, upsert_by_id,
};
use crate::api::filter_routes::{FilterListBody, FilterSetBody};
use crate::api::listener_routes::ListenerBody;
use crate::api::policy_routes::{
    ClientIdBody, RecordBody, RecordKey, delete_policy_record, register_client_id,
    revoke_client_id, upsert_policy_record,
};
use crate::api::tls_routes::validate_tls;
use crate::cluster_status::{ClusterStatus, ClusterStatusHandle};
use crate::config_apply::{ConfigActor, ConfigService};
use crate::error::ControlApiError;
use crate::query_log::QueryLog;
use crate::server::AppState;

/// How long a relayed write's response is kept for `Idempotency-Key` replay.
const IDEMPOTENCY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// Delay between log-streamer retries after a transport failure.
const LOG_RETRY_DELAY: Duration = Duration::from_secs(1);
/// How long a reconnect waits for the master's first auth snapshot before
/// replaying buffered writes anyway.
const AUTH_REPLAY_GRACE: Duration = Duration::from_secs(5);

/// Sub-node applier: node-scoped views → `apply_synced_config`.
pub struct SyncedConfigApplier {
    service: Arc<ConfigService>,
    node_id: String,
    status: Option<Arc<ClusterStatusHandle>>,
    clock: Option<Arc<dyn Clock>>,
}

impl SyncedConfigApplier {
    /// Applies pushed snapshots for `node_id`.
    pub fn new(service: Arc<ConfigService>, node_id: impl Into<String>) -> Self {
        Self {
            service,
            node_id: node_id.into(),
            status: None,
            clock: None,
        }
    }

    /// Publishes `cluster.applied_version` as soon as the snapshot is stored.
    ///
    /// [`ClusterClient::apply_push`] posts the config ack over HTTP after apply;
    /// without an early status update, `GET /api/v1/status` can briefly (or, on
    /// a slow master, for a long time) report a stale `applied_version` while
    /// module state already reflects the new snapshot.
    pub fn with_cluster_status(
        mut self,
        status: Arc<ClusterStatusHandle>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        self.status = Some(status);
        self.clock = Some(clock);
        self
    }
}

#[async_trait]
impl ConfigApplier for SyncedConfigApplier {
    async fn apply(&self, version: i64, snapshot: &Value) -> Result<i64, ClusterError> {
        let snapshot = node_scoped_views(snapshot, &self.node_id)?;
        let applied = self
            .service
            .apply_synced_config(snapshot, version)
            .await
            .map_err(|error| ClusterError::ConfigApply {
                message: format!("{}: {error}", error.code()),
            })?;
        if let (Some(status), Some(clock)) = (&self.status, &self.clock) {
            status.update(|cluster| {
                cluster.applied_version = Some(applied);
                cluster.lag = (version - applied).max(0);
                cluster.last_sync = Some(clock.now());
            });
        }
        Ok(applied)
    }
}

/// Filters `policy.views` to those valid on `node_id`.
///
/// A view is valid when its `nodes` list is absent, `null` or empty, or
/// contains `node_id`. A node that would lose its default view is rejected
/// (`policy.config.invalid`) so every node keeps a reachable default. The rest
/// of the snapshot is untouched.
///
/// The policy crate's typed `ViewConfig` has no `nodes` field yet, so this is
/// enforced on the JSON snapshot before apply; the unknown field is otherwise
/// ignored (and silently applied to every node) by the policy engine.
pub fn node_scoped_views(snapshot: &Value, node_id: &str) -> Result<Value, ClusterError> {
    let mut snapshot = snapshot.clone();
    let Some(views) = snapshot
        .get_mut("policy")
        .and_then(|policy| policy.get_mut("views"))
        .and_then(Value::as_array_mut)
    else {
        return Ok(snapshot);
    };
    let mut default_removed = false;
    views.retain(|view| {
        let valid = match view.get("nodes") {
            None | Some(Value::Null) => true,
            Some(Value::Array(nodes)) => {
                nodes.is_empty() || nodes.iter().any(|node| node.as_str() == Some(node_id))
            }
            Some(_) => false,
        };
        if !valid && view.get("is_default").and_then(Value::as_bool) == Some(true) {
            default_removed = true;
        }
        valid
    });
    if default_removed {
        return Err(ClusterError::ConfigApply {
            message: format!("policy.config.invalid: default view is not valid on node {node_id}"),
        });
    }
    Ok(snapshot)
}

/// Sub-node applier: installs a pushed certificate through the hot-reload path.
pub struct TlsCertInstaller {
    resolver: Arc<CertResolver>,
    store: CertStore,
}

impl TlsCertInstaller {
    /// Wraps the live resolver and its on-disk store.
    pub fn new(resolver: Arc<CertResolver>, store: CertStore) -> Self {
        Self { resolver, store }
    }
}

#[async_trait]
impl CertInstaller for TlsCertInstaller {
    async fn install(&self, chain_pem: &str, private_key: &Secret) -> Result<(), ClusterError> {
        self.resolver
            .import(
                &self.store,
                chain_pem.as_bytes(),
                private_key.expose().as_bytes(),
            )
            .map_err(|error| ClusterError::CertPushFailed {
                message: error.to_string(),
            })
    }
}

/// Master signer: finalizes a sub-node's CSR through the TLS engine's ACME
/// account. The node's key stays on the node.
pub struct TlsEngineCsrSigner {
    engine: Arc<TlsEngine>,
}

impl TlsEngineCsrSigner {
    /// Wraps the master's TLS engine.
    pub fn new(engine: Arc<TlsEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl TlsCsrSigner for TlsEngineCsrSigner {
    async fn sign(&self, _node_id: &str, csr_pem: &str) -> Result<String, ClusterError> {
        self.engine
            .sign_csr(csr_pem)
            .await
            .map_err(|error| ClusterError::Internal {
                message: format!("TLS certificate request failed ({})", error.code()),
            })
    }
}

/// Sub-node applier: replaces local auth state with a pushed snapshot.
pub struct StateAuthApplier {
    auth: Arc<AuthState>,
}

impl StateAuthApplier {
    /// Wraps the node's auth state.
    pub fn new(auth: Arc<AuthState>) -> Self {
        Self { auth }
    }
}

#[async_trait]
impl AuthSnapshotApplier for StateAuthApplier {
    async fn apply(&self, snapshot: &Value) -> Result<(), ClusterError> {
        let snapshot: AuthSnapshot =
            serde_json::from_value(snapshot.clone()).map_err(|error| ClusterError::Internal {
                message: format!("invalid auth snapshot: {error}"),
            })?;
        self.auth
            .apply_auth_snapshot(&snapshot)
            .await
            .map_err(|error| ClusterError::Internal {
                message: format!("{}: {error}", error.code()),
            })
    }
}

/// Sub-node applier: applies a volatile runtime command locally.
pub struct StateRuntimeApplier {
    state: AppState,
}

impl StateRuntimeApplier {
    /// Wraps the node's shared state.
    pub fn new(state: AppState) -> Self {
        Self { state }
    }
}

#[async_trait]
impl RuntimeCommandApplier for StateRuntimeApplier {
    async fn apply_runtime_command(&self, kind: &str, payload: &Value) -> Result<(), ClusterError> {
        self.state
            .apply_runtime_command(kind, payload)
            .await
            .map_err(|error| ClusterError::RuntimeCommandFailed {
                message: format!("{}: {error}", error.code()),
            })
    }
}

/// Sub-node hook: rejects a queued write whose actor is no longer valid.
///
/// A token revoked on the master disappears from the replicated snapshot, so a
/// write queued under it must not replay after reconnect.
pub struct StateActorValidator {
    auth: Arc<AuthState>,
}

impl StateActorValidator {
    /// Wraps the sub-node's replicated auth state.
    pub fn new(auth: Arc<AuthState>) -> Self {
        Self { auth }
    }
}

#[async_trait]
impl ActorValidator for StateActorValidator {
    async fn is_valid(&self, actor: &RelayedActor) -> Result<bool, ClusterError> {
        self.auth
            .relayed_actor_is_current(&actor.actor_type, &actor.actor_id, &actor.scope)
            .await
            .map_err(internal)
    }
}

/// Master hook: serializes the current auth state for a connecting node.
pub struct StateAuthSnapshotSource {
    auth: Arc<AuthState>,
}

impl StateAuthSnapshotSource {
    /// Wraps the master's authoritative auth state.
    pub fn new(auth: Arc<AuthState>) -> Self {
        Self { auth }
    }
}

#[async_trait]
impl AuthSnapshotSource for StateAuthSnapshotSource {
    async fn snapshot(&self) -> Result<Value, ClusterError> {
        let snapshot = self.auth.auth_snapshot().await.map_err(internal)?;
        serde_json::to_value(snapshot).map_err(|error| ClusterError::Internal {
            message: format!("encode auth snapshot: {error}"),
        })
    }
}

/// Master hook: RBAC re-check + canonical config handler for a relayed write.
///
/// The actor is *claimed* by the sub-node and never re-authenticated here: the
/// master sees no credential, only the actor id/type/scope. A compromised
/// sub-node can assert any actor for its own relayed writes; this is accepted
/// by SPEC-cluster § Security considerations and contained by revocation. The
/// executor still enforces the claimed scope and audits the write with the
/// originating `node_id`.
pub struct ConfigWriteExecutor {
    service: Arc<ConfigService>,
    clock: Arc<dyn Clock>,
    /// Durable answers (`relay_responses`), so a retry that spans a master
    /// restart returns the stored answer instead of applying again.
    store: Option<ClusterStore>,
    // In-memory fallback when no store is given (tests and standalone helpers).
    idempotency: Mutex<HashMap<String, (RelayResponse, SystemTime)>>,
}

impl ConfigWriteExecutor {
    /// Wraps the master's config service with an in-memory answer cache.
    pub fn new(service: Arc<ConfigService>, clock: Arc<dyn Clock>) -> Self {
        Self {
            service,
            clock,
            store: None,
            idempotency: Mutex::new(HashMap::new()),
        }
    }

    /// Wraps the master's config service and keeps answers in `store`, so
    /// they survive a master restart for [`IDEMPOTENCY_TTL`].
    pub fn with_store(
        service: Arc<ConfigService>,
        clock: Arc<dyn Clock>,
        store: ClusterStore,
    ) -> Self {
        Self {
            store: Some(store),
            ..Self::new(service, clock)
        }
    }

    async fn cached(&self, key: &str) -> Result<Option<RelayResponse>, ClusterError> {
        if let Some(store) = &self.store {
            return Ok(store
                .recall_relay_response(key, IDEMPOTENCY_TTL)
                .await?
                .map(|(status, body)| RelayResponse { status, body }));
        }
        let now = self.clock.now();
        let mut cache = self
            .idempotency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cache.retain(|_, (_, at)| {
            now.duration_since(*at)
                .map_or(true, |age| age < IDEMPOTENCY_TTL)
        });
        Ok(cache.get(key).map(|(response, _)| response.clone()))
    }

    async fn remember(&self, key: &str, response: &RelayResponse) {
        if let Some(store) = &self.store {
            // The write has already been applied, so a storage failure here
            // cannot change the answer; it is logged, not returned.
            if let Err(error) = store
                .remember_relay_response(key, response.status, &response.body, IDEMPOTENCY_TTL)
                .await
            {
                tracing::warn!(error = %error, "relay answer not stored for idempotent retry");
            }
            return;
        }
        self.idempotency
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_owned(), (response.clone(), self.clock.now()));
    }

    async fn run(
        &self,
        node_id: &str,
        actor: RelayedActor,
        method: &str,
        path: &str,
        body: Value,
        if_match: Option<&str>,
    ) -> RelayResponse {
        // The actor type is copied into the audit row, so only the two known
        // credential kinds are accepted; an arbitrary claim must not persist.
        if !actor.has_known_type() {
            return error_response(ControlApiError::AuthInvalidScope);
        }
        let Some(scope) = Scope::parse(&actor.scope) else {
            return error_response(ControlApiError::AuthInvalidScope);
        };
        let Ok(http_method) = Method::from_bytes(method.as_bytes()) else {
            return RelayResponse {
                status: 405,
                body: json!({
                    "error": {
                        "code": "control_api.method_not_allowed",
                        "params": { "method": method, "path": path },
                    }
                }),
            };
        };
        let path = path.trim_end_matches('/');
        if let Err(error) = authorize(requirement(&http_method, path), scope) {
            return error_response(error);
        }

        let config_actor = ConfigActor::new(actor.actor_id, actor.actor_type).on_node(node_id);
        let result = match (http_method.as_str(), path) {
            ("PUT", "/api/v1/config") => self
                .service
                .replace(body, &config_actor, if_match)
                .await
                .map(|version| json!({ "data": { "version": version } })),
            ("POST", _) if rollback_version(path).is_some() => {
                let target = rollback_version(path).unwrap_or(0);
                self.service
                    .rollback(target, &config_actor, if_match)
                    .await
                    .map(|outcome| {
                        json!({
                            "data": {
                                "version": outcome.version,
                                "restored_from": outcome.restored_from,
                            }
                        })
                    })
            }
            _ => {
                self.module_write(http_method.as_str(), path, body, &config_actor, if_match)
                    .await
            }
        };
        match result {
            Ok(body) => RelayResponse { status: 200, body },
            Err(error) => error_response(error),
        }
    }

    /// Dispatches a config-family write other than the full replace/rollback.
    ///
    /// Mirrors the canonical route handler: load the stored snapshot, apply the
    /// same validated mutation, then run the shared atomic replace path
    /// (validate → apply → store → audit). Routes that are not config writes
    /// (auth, TLS engine actions, runtime commands, reads) remain unmapped and
    /// return `control_api.not_found`.
    async fn module_write(
        &self,
        method: &str,
        path: &str,
        body: Value,
        actor: &ConfigActor,
        if_match: Option<&str>,
    ) -> Result<Value, ControlApiError> {
        if path == "/api/v1/filter-sets" {
            return match method {
                "POST" | "PUT" => {
                    let set = parse_body::<FilterSetBody>(body, "filtering.config.invalid")?
                        .into_json()?;
                    let id = required_str(&set, "id", "filtering.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let replaced = upsert_by_id(
                        array_mut(&mut snapshot, "filtering", "sets")?,
                        &id,
                        set.clone(),
                    );
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": {
                            "version": version,
                            "filter_set": set,
                            "created": !replaced,
                        }
                    }))
                }
                "DELETE" => {
                    let id = required_str(&body, "id", "filtering.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    remove_by_id(array_mut(&mut snapshot, "filtering", "sets")?, &id).ok_or_else(
                        || ControlApiError::NotFound {
                            what: format!("filter set {id}"),
                        },
                    )?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/filter-lists" {
            return match method {
                "POST" | "PUT" => {
                    let list = parse_body::<FilterListBody>(body, "filtering.config.invalid")?
                        .into_json()?;
                    let id = required_str(&list, "id", "filtering.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let replaced = upsert_by_id(
                        array_mut(&mut snapshot, "filtering", "lists")?,
                        &id,
                        list.clone(),
                    );
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": {
                            "version": version,
                            "filter_list": list,
                            "created": !replaced,
                        }
                    }))
                }
                "DELETE" => {
                    let id = required_str(&body, "id", "filtering.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    remove_by_id(array_mut(&mut snapshot, "filtering", "lists")?, &id).ok_or_else(
                        || ControlApiError::NotFound {
                            what: format!("filter list {id}"),
                        },
                    )?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/listeners" {
            return match method {
                "POST" | "PUT" => {
                    let listener = parse_body::<ListenerBody>(body, "listeners.config.invalid")?
                        .into_json()?;
                    let id = required_str(&listener, "id", "listeners.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let replaced = upsert_by_id(
                        array_mut(&mut snapshot, "listeners", "listeners")?,
                        &id,
                        listener.clone(),
                    );
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": {
                            "version": version,
                            "listener": listener,
                            "created": !replaced,
                        }
                    }))
                }
                "DELETE" => {
                    let id = required_str(&body, "id", "listeners.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    remove_by_id(array_mut(&mut snapshot, "listeners", "listeners")?, &id)
                        .ok_or_else(|| ControlApiError::NotFound {
                            what: format!("listener {id}"),
                        })?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/tls" {
            return match method {
                "POST" | "PUT" => {
                    let tls = body;
                    validate_tls(&tls)?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let section = snapshot
                        .get_mut("tls")
                        .and_then(Value::as_object_mut)
                        .ok_or_else(malformed_snapshot)?;
                    *section = tls.as_object().cloned().unwrap_or_default();
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "tls": tls } }))
                }
                "DELETE" => {
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let section = snapshot
                        .get_mut("tls")
                        .and_then(Value::as_object_mut)
                        .ok_or_else(malformed_snapshot)?;
                    let removed = !section.is_empty();
                    section.clear();
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "deleted": removed } }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/clients/manual" {
            return match method {
                "POST" => {
                    let entry = parse_body::<ManualEntryBody>(body, "clients.config.invalid")?
                        .into_json()?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let entries = array_mut(&mut snapshot, "clients", "manual")?;
                    let entry_name = manual_name(&entry).unwrap_or_default();
                    if entries
                        .iter()
                        .any(|existing| manual_name(existing) == Some(entry_name))
                    {
                        return Err(module_error(
                            "clients.name.collision",
                            "a manual entry with that name already exists",
                        ));
                    }
                    reject_conflict(entries, &entry, None)?;
                    entries.push(entry.clone());
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "entry": entry } }))
                }
                "PUT" => {
                    let entry = parse_body::<ManualEntryBody>(body, "clients.config.invalid")?
                        .into_json()?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let entries = array_mut(&mut snapshot, "clients", "manual")?;
                    let entry_name = manual_name(&entry).unwrap_or_default();
                    reject_conflict(entries, &entry, Some(entry_name))?;
                    let replaced = if let Some(existing) = entries
                        .iter_mut()
                        .find(|existing| manual_name(existing) == Some(entry_name))
                    {
                        *existing = entry.clone();
                        true
                    } else {
                        entries.push(entry.clone());
                        false
                    };
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": {
                            "version": version,
                            "entry": entry,
                            "created": !replaced,
                        }
                    }))
                }
                "DELETE" => {
                    let name = required_str(&body, "name", "clients.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let entries = array_mut(&mut snapshot, "clients", "manual")?;
                    let index = entries
                        .iter()
                        .position(|entry| manual_name(entry) == Some(name.as_str()))
                        .ok_or_else(|| ControlApiError::NotFound {
                            what: format!("manual entry {name}"),
                        })?;
                    entries.remove(index);
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "name": name }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if let Some(id) = sub_path(path, "/api/v1/policy/views/") {
            return match method {
                "POST" | "PUT" => {
                    let view =
                        parse_body::<ViewBody>(body, "policy.config.invalid")?.into_json(&id)?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    upsert_by_id(
                        array_mut(&mut snapshot, "policy", "views")?,
                        &id,
                        view.clone(),
                    );
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "view": view } }))
                }
                "DELETE" => {
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    remove_by_id(array_mut(&mut snapshot, "policy", "views")?, &id).ok_or_else(
                        || ControlApiError::NotFound {
                            what: format!("view {id}"),
                        },
                    )?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if let Some(id) = sub_path(path, "/api/v1/policy/profiles/") {
            return match method {
                "POST" | "PUT" => {
                    let profile =
                        parse_body::<ProfileBody>(body, "policy.config.invalid")?.into_json(&id)?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    upsert_by_id(
                        array_mut(&mut snapshot, "policy", "profiles")?,
                        &id,
                        profile.clone(),
                    );
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "profile": profile } }))
                }
                "DELETE" => {
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    remove_by_id(array_mut(&mut snapshot, "policy", "profiles")?, &id).ok_or_else(
                        || ControlApiError::NotFound {
                            what: format!("profile {id}"),
                        },
                    )?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/policy/records" {
            return match method {
                "POST" | "PUT" => {
                    let body = parse_body::<RecordBody>(body, "policy.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let record = upsert_policy_record(&mut snapshot, body)?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "record": record } }))
                }
                "DELETE" => {
                    let key = parse_body::<RecordKey>(body, "policy.config.invalid")?;
                    let name = key.name.clone();
                    let rtype = key.rtype.clone();
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    delete_policy_record(&mut snapshot, key)?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": {
                            "version": version,
                            "deleted": true,
                            "name": name,
                            "type": rtype,
                        }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/policy/client-ids" {
            return match method {
                "POST" => {
                    let body = parse_body::<ClientIdBody>(body, "policy.config.invalid")?;
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    register_client_id(&mut snapshot, body.id.clone())?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "client_id": body.id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if let Some(id) = sub_path(path, "/api/v1/policy/client-ids/") {
            return match method {
                "DELETE" => {
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    revoke_client_id(&mut snapshot, &id)?;
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({
                        "data": { "version": version, "deleted": true, "id": id }
                    }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        if path == "/api/v1/policy/pause" {
            return match method {
                "POST" | "PUT" => {
                    let pause = body;
                    if !pause.is_object() {
                        return Err(module_error(
                            "policy.config.invalid",
                            "pause state must be a JSON object",
                        ));
                    }
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    snapshot
                        .get_mut("policy")
                        .and_then(Value::as_object_mut)
                        .ok_or_else(malformed_snapshot)?
                        .insert("pause".to_owned(), pause.clone());
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "pause": pause } }))
                }
                "DELETE" => {
                    let mut snapshot = stored_snapshot(&self.service).await?;
                    let removed = snapshot
                        .get_mut("policy")
                        .and_then(Value::as_object_mut)
                        .ok_or_else(malformed_snapshot)?
                        .remove("pause")
                        .is_some();
                    let version = self.service.replace(snapshot, actor, if_match).await?;
                    Ok(json!({ "data": { "version": version, "deleted": removed } }))
                }
                _ => Err(method_not_allowed(method, path)),
            };
        }
        Err(ControlApiError::NotFound {
            what: path.to_owned(),
        })
    }
}

/// Parses a relayed JSON body as the canonical handler's typed body.
fn parse_body<T: DeserializeOwned>(body: Value, code: &'static str) -> Result<T, ControlApiError> {
    serde_json::from_value(body).map_err(|error| module_error(code, &error.to_string()))
}

/// Reads a required string field from a small JSON body.
fn required_str(body: &Value, field: &str, code: &'static str) -> Result<String, ControlApiError> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| module_error(code, &format!("`{field}` is required")))
}

/// The single path segment following `prefix`, if it is exactly one segment.
fn sub_path(path: &str, prefix: &str) -> Option<String> {
    let id = path.strip_prefix(prefix)?;
    (!id.is_empty() && !id.contains('/')).then(|| id.to_owned())
}

fn method_not_allowed(method: &str, path: &str) -> ControlApiError {
    ControlApiError::MethodNotAllowed {
        method: method.to_owned(),
        path: path.to_owned(),
    }
}

fn malformed_snapshot() -> ControlApiError {
    ControlApiError::Internal {
        message: "stored config snapshot is malformed".to_owned(),
    }
}

#[async_trait]
impl WriteExecutor for ConfigWriteExecutor {
    async fn execute(
        &self,
        node_id: &str,
        request_id: &str,
        actor: RelayedActor,
        method: String,
        path: String,
        body: Value,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        // `request_id` is always present and stable across retries (including
        // keyless ones), so it is the primary dedupe key; the optional
        // `Idempotency-Key` is kept for callers that reuse it across requests.
        if let Some(response) = self.cached(request_id).await? {
            return Ok(response);
        }
        if let Some(key) = idempotency_key.as_deref()
            && let Some(response) = self.cached(key).await?
        {
            return Ok(response);
        }
        let response = self
            .run(node_id, actor, &method, &path, body, if_match.as_deref())
            .await;
        self.remember(request_id, &response).await;
        if let Some(key) = idempotency_key {
            self.remember(&key, &response).await;
        }
        Ok(response)
    }
}

/// Parses `/api/v1/config/versions/{version}/rollback`.
fn rollback_version(path: &str) -> Option<u64> {
    let rest = path
        .strip_prefix("/api/v1/config/versions/")?
        .strip_suffix("/rollback")?;
    rest.parse().ok()
}

fn error_response(error: ControlApiError) -> RelayResponse {
    let mut body = json!({ "error": { "code": error.code() } });
    if let Some(params) = error.params() {
        body["error"]["params"] = params;
    }
    RelayResponse {
        status: error.status().as_u16(),
        body,
    }
}

/// Resumes the query-log outbox after a (re)connect and reports a gap.
///
/// The master's highest contiguous sequence is the resume point. When the
/// local buffer already dropped rows below it, [`Backfill::gap`] carries
/// `cluster.log_gap` (also logged here) and streaming resumes from the oldest
/// buffered row.
pub async fn backfill_logs(
    streamer: &LogStreamer,
    master_highest: u64,
) -> Result<Backfill, ClusterError> {
    let backfill = streamer.backfill(master_highest).await?;
    if let Some(gap) = backfill.gap() {
        tracing::warn!(
            code = %gap.code(),
            missing = backfill.missing,
            "cluster log backfill gap"
        );
    }
    Ok(backfill)
}

/// Sub-node hook: the local query-log outbox cursor.
pub struct QueryLogOutbox {
    log: Arc<QueryLog>,
}

impl QueryLogOutbox {
    /// Wraps the node's query log.
    pub fn new(log: Arc<QueryLog>) -> Self {
        Self { log }
    }
}

#[async_trait]
impl LogOutbox for QueryLogOutbox {
    async fn next_unacked_seq(&self) -> Result<u64, ClusterError> {
        self.log
            .next_seq()
            .await
            .map(|seq| u64::try_from(seq.max(1)).unwrap_or(1))
            .map_err(internal)
    }

    async fn fetch_batch(
        &self,
        from_seq: u64,
        max_records: usize,
    ) -> Result<Vec<LogRecord>, ClusterError> {
        let from_seq = i64::try_from(from_seq).map_err(|_| ClusterError::LogStreamInvalid {
            reason: "log sequence number out of range".to_owned(),
        })?;
        self.log
            .outbox_rows(from_seq, max_records)
            .await
            .map(|rows| {
                rows.into_iter()
                    .map(|(_, id, record)| LogRecord { id, record })
                    .collect()
            })
            .map_err(internal)
    }

    async fn ack(&self, seq: u64) -> Result<(), ClusterError> {
        let seq = i64::try_from(seq).map_err(|_| ClusterError::LogStreamInvalid {
            reason: "log sequence number out of range".to_owned(),
        })?;
        self.log.ack(seq).await.map(|_| ()).map_err(internal)
    }

    async fn prune(&self, cutoff: SystemTime) -> Result<u64, ClusterError> {
        let cutoff_us = cutoff
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |age| i64::try_from(age.as_micros()).unwrap_or(i64::MAX));
        self.log
            .prune_outbox_before(cutoff_us)
            .await
            .map_err(internal)
    }
}

/// Master hook: deduplicating query-log ingest.
pub struct QueryLogIngest {
    log: Arc<QueryLog>,
}

impl QueryLogIngest {
    /// Wraps the master's query log.
    pub fn new(log: Arc<QueryLog>) -> Self {
        Self { log }
    }
}

#[async_trait]
impl LogIngest for QueryLogIngest {
    async fn ingest(
        &self,
        node_id: &str,
        first_seq: u64,
        last_seq: u64,
        records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        let records = records
            .iter()
            .map(|record| record.record.clone())
            .collect::<Vec<_>>();
        self.log
            .ingest_remote(node_id, first_seq, last_seq, &records)
            .await
            .map_err(|error| match error {
                ControlApiError::QueryLogInvalid { reason } => {
                    ClusterError::LogStreamInvalid { reason }
                }
                other => internal(other),
            })
    }

    async fn highest_seq(&self, node_id: &str) -> Result<u64, ClusterError> {
        self.log.highest_remote_seq(node_id).await.map_err(internal)
    }
}

/// Fallback ingest when the node has no query log configured.
struct UnavailableLogIngest;

#[async_trait]
impl LogIngest for UnavailableLogIngest {
    async fn ingest(
        &self,
        _node_id: &str,
        _first_seq: u64,
        _last_seq: u64,
        _records: &[LogRecord],
    ) -> Result<u64, ClusterError> {
        Err(ClusterError::Internal {
            message: "query log is not configured".to_owned(),
        })
    }

    async fn highest_seq(&self, _node_id: &str) -> Result<u64, ClusterError> {
        Ok(0)
    }
}

/// Sub-node hook: relays buffered writes through the mTLS client.
struct ClientWriteExecutor {
    client: Arc<ClusterClient>,
}

impl ClientWriteExecutor {
    fn new(client: Arc<ClusterClient>) -> Self {
        Self { client }
    }
}

static RELAY_COUNTER: AtomicU64 = AtomicU64::new(1);

#[async_trait]
impl WriteExecutor for ClientWriteExecutor {
    async fn execute(
        &self,
        _node_id: &str,
        request_id: &str,
        actor: RelayedActor,
        method: String,
        path: String,
        body: Value,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError> {
        // The offline queue supplies its persisted request_id, which is the
        // master's dedupe key across replay attempts.
        let request_id = if request_id.is_empty() {
            idempotency_key.clone().unwrap_or_else(|| {
                format!("relay-{}", RELAY_COUNTER.fetch_add(1, Ordering::Relaxed))
            })
        } else {
            request_id.to_owned()
        };
        self.client
            .relay_write(WriteRelay {
                request_id,
                idempotency_key,
                if_match,
                method,
                path,
                body,
                actor,
            })
            .await
    }
}

/// Options for [`ClusterRuntime::start`].
pub struct ClusterRuntimeOptions {
    /// Node data directory (cluster CA, registry, offline queue, TLS store).
    pub data_dir: PathBuf,
    /// Clock used by the cluster transport and retry loops.
    pub clock: Arc<dyn Clock>,
    /// Status handle shared with [`AppState`]. Attach it before starting.
    pub status: Arc<ClusterStatusHandle>,
    /// Master certificate SAN; defaults to the configured bind address.
    pub server_name: Option<String>,
    /// One-time join token used only when the sub-node has no identity yet.
    pub join_token: Option<Secret>,
    /// Pinned master certificate (PEM) used only for first enrollment.
    pub master_cert_pem: Option<String>,
    /// Live TLS resolver a pushed certificate is installed into.
    pub tls_resolver: Option<Arc<CertResolver>>,
}

impl ClusterRuntimeOptions {
    /// Options with a fresh status handle and no enrollment material.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            clock: Arc::new(dnscraft_common::clock::SystemClock),
            status: Arc::new(ClusterStatusHandle::new()),
            server_name: None,
            join_token: None,
            master_cert_pem: None,
            tls_resolver: None,
        }
    }
}

/// A running cluster role.
pub struct ClusterRuntime {
    role: Role,
    status: Arc<ClusterStatusHandle>,
    store: Option<ClusterStore>,
    config_sync: Option<Arc<ConfigSync>>,
    shutdown: watch::Sender<bool>,
    notify: Arc<Notify>,
    tasks: Vec<JoinHandle<()>>,
    server: Option<ClusterServer>,
}

impl ClusterRuntime {
    /// Starts the cluster role configured in `config`.
    ///
    /// `standalone` returns an idle runtime that starts nothing. `master` opens
    /// the mTLS listener, publishes the current snapshot, and republishes on
    /// every config change. `sub_node` loads (or enrolls) its identity and
    /// starts the reconnect/apply loop plus the log-streamer and offline-write
    /// replay tasks.
    ///
    /// `state` is borrowed so the caller keeps ownership; after a master start,
    /// attach [`Self::cluster_store`] with
    /// [`AppState::with_cluster_store`](crate::AppState::with_cluster_store)
    /// before serving the admin API.
    pub async fn start(
        config: ClusterConfig,
        state: &AppState,
        options: ClusterRuntimeOptions,
    ) -> Result<Self, ControlApiError> {
        let (shutdown, _) = watch::channel(false);
        let notify = Arc::new(Notify::new());
        let clock = Arc::clone(&options.clock);
        // Expose the role to the router (token/account creation is master-only).
        state.attach_cluster_role(config.role);
        match config.role {
            Role::Standalone => Ok(Self {
                role: config.role,
                status: options.status,
                store: None,
                config_sync: None,
                shutdown,
                notify,
                tasks: Vec::new(),
                server: None,
            }),
            Role::Master => {
                let mut runtime = Self {
                    role: config.role,
                    status: Arc::clone(&options.status),
                    store: None,
                    config_sync: None,
                    shutdown,
                    notify,
                    tasks: Vec::new(),
                    server: None,
                };
                runtime
                    .start_master(&config, state, &options, clock)
                    .await?;
                Ok(runtime)
            }
            Role::SubNode => {
                let mut runtime = Self {
                    role: config.role,
                    status: Arc::clone(&options.status),
                    store: None,
                    config_sync: None,
                    shutdown,
                    notify,
                    tasks: Vec::new(),
                    server: None,
                };
                runtime
                    .start_sub_node(&config, state, &options, clock)
                    .await?;
                Ok(runtime)
            }
        }
    }

    /// The role this runtime started.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The shared status handle.
    pub fn status_handle(&self) -> Arc<ClusterStatusHandle> {
        Arc::clone(&self.status)
    }

    /// The master's node registry (the same store the admin API uses).
    pub fn cluster_store(&self) -> Option<ClusterStore> {
        self.store.clone()
    }

    /// The master's config broadcast registry.
    pub fn config_sync(&self) -> Option<Arc<ConfigSync>> {
        self.config_sync.clone()
    }

    /// The master listener's bound address (useful when the port was `0`).
    pub fn listen_addr(&self) -> Option<std::net::SocketAddr> {
        self.server.as_ref().map(ClusterServer::addr)
    }

    /// The master's own server certificate (PEM), for bootstrap pinning.
    pub fn server_cert_pem(&self) -> Option<&str> {
        self.server.as_ref().map(ClusterServer::server_cert_pem)
    }

    /// The master's volatile broadcast handle, when this runtime is the master.
    pub fn broadcast_handle(&self) -> Option<ClusterBroadcast> {
        self.server.as_ref().map(ClusterServer::broadcast_handle)
    }

    /// Attaches the master's TLS certificate signer, backed by `engine`, so a
    /// node's CSR is finalized through ACME. No-op unless this is the master.
    pub fn attach_tls_engine(&self, engine: Arc<TlsEngine>) {
        if let Some(server) = &self.server {
            server.attach_tls_signer(Arc::new(TlsEngineCsrSigner::new(engine)));
        }
    }

    /// Stops the listener and background tasks.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        self.notify.notify_waiters();
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        if let Some(server) = self.server.take() {
            server.shutdown().await;
        }
    }

    async fn start_master(
        &mut self,
        config: &ClusterConfig,
        state: &AppState,
        options: &ClusterRuntimeOptions,
        clock: Arc<dyn Clock>,
    ) -> Result<(), ControlApiError> {
        let service = state
            .config_service_arc()
            .ok_or_else(|| ControlApiError::Internal {
                message: "cluster master requires a config service".to_owned(),
            })?;
        let listen = config.listen.clone().ok_or_else(|| {
            ControlApiError::from(ClusterError::RoleInvalid {
                reason: "master requires cluster.listen".to_owned(),
            })
        })?;
        let ca = ClusterCa::load_or_generate(&config.tls.ca_cert)?;
        let store = ClusterStore::open(
            &options.data_dir.join("cluster.db"),
            clock.clone(),
            config.join.token_ttl,
        )
        .await?;

        let write_executor: Arc<dyn WriteExecutor> = Arc::new(ConfigWriteExecutor::with_store(
            Arc::clone(&service),
            clock.clone(),
            store.clone(),
        ));
        let log_ingest: Arc<dyn LogIngest> = match state.query_log_arc() {
            Some(log) => Arc::new(QueryLogIngest::new(log)),
            None => Arc::new(UnavailableLogIngest),
        };
        // Every (re)connecting node receives the current auth snapshot, so a
        // revocation that happened while it was offline is applied before it
        // replays buffered writes.
        let auth_snapshot: Option<Arc<dyn AuthSnapshotSource>> =
            state.auth_state_arc().map(|auth| {
                Arc::new(StateAuthSnapshotSource::new(auth)) as Arc<dyn AuthSnapshotSource>
            });
        let server = ClusterServer::start(
            ClusterServerConfig {
                listen,
                server_name: options.server_name.clone().unwrap_or_else(|| {
                    config
                        .listen
                        .as_ref()
                        .map_or_else(|| config.node_id.clone(), |listen| listen.bind.to_string())
                }),
                node_cert_ttl: config.join.node_cert_ttl,
                quota: config.quota.clone(),
                timing: config.timing.clone(),
            },
            ca,
            store.clone(),
            clock.clone(),
            write_executor,
            log_ingest,
            auth_snapshot,
        )
        .await?;

        // Let the master's runtime-command endpoints push to connected nodes.
        state.attach_cluster_broadcast(server.broadcast_handle());

        let (version, snapshot) = service.current().await?;
        self.status.set(ClusterStatus {
            role: "master".to_owned(),
            master_reachable: true,
            applied_version: version,
            lag: 0,
            queue_depth: 0,
            last_sync: None,
            degraded_nodes: 0,
        });
        if let (Some(version), Some(snapshot)) = (version, snapshot) {
            server.config_sync().publish(version, &snapshot)?;
            self.status.update(|status| {
                status.last_sync = Some(clock.now());
            });
        }

        // Publish every later apply/rollback to the connected sub-nodes.
        let sync = server.config_sync_handle();
        let status = Arc::clone(&self.status);
        let change_clock = clock.clone();
        let mut shutdown = self.shutdown.subscribe();
        let change_service = Arc::clone(&service);
        // Subscribe before spawning: a send that races the task start would
        // otherwise be folded into the receiver's initial value and missed.
        let mut changes = change_service.subscribe();
        self.tasks.push(tokio::spawn(async move {
            loop {
                tokio::select! {
                    changed = changes.changed() => {
                        if changed.is_err() {
                            return;
                        }
                        let Ok((Some(version), Some(snapshot))) = change_service.current().await else {
                            continue;
                        };
                        if sync.publish(version, &snapshot).is_ok() {
                            let lag = sync.lag().iter().map(|node| node.lag).max().unwrap_or(0);
                            status.update(|status| {
                                status.applied_version = Some(version);
                                status.lag = lag;
                                status.last_sync = Some(change_clock.now());
                            });
                        }
                    }
                    _ = shutdown.changed() => return,
                }
            }
        }));

        // Report nodes that have not acknowledged a push within
        // `config_apply_timeout` as degraded, refreshed every heartbeat interval.
        let degraded_sync = server.config_sync_handle();
        let degraded_status = Arc::clone(&self.status);
        let degraded_clock = clock.clone();
        let apply_timeout = config.timing.config_apply_timeout;
        let interval = config.timing.heartbeat_interval;
        let mut degraded_shutdown = self.shutdown.subscribe();
        self.tasks.push(tokio::spawn(async move {
            let wake = Notify::new();
            loop {
                let degraded = degraded_sync.degraded_nodes(apply_timeout).len();
                let degraded = u32::try_from(degraded).unwrap_or(u32::MAX);
                degraded_status.update(|status| status.degraded_nodes = degraded);
                let deadline = add_duration(degraded_clock.now(), interval);
                tokio::select! {
                    () = wait_until(degraded_clock.as_ref(), deadline, &wake) => {}
                    _ = degraded_shutdown.changed() => return,
                }
            }
        }));

        // Push a fresh auth snapshot to sub-nodes whenever the master's token
        // or local-account state changes. The notification is event-driven (a
        // watch channel), never a poll loop.
        if let Some(auth) = state.auth_state_arc() {
            let broadcast = server.broadcast_handle();
            let mut changes = auth.subscribe_changes();
            let mut auth_shutdown = self.shutdown.subscribe();
            self.tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        changed = changes.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            let Ok(snapshot) = auth.auth_snapshot().await else {
                                continue;
                            };
                            let Ok(value) = serde_json::to_value(&snapshot) else {
                                continue;
                            };
                            broadcast.push_auth_snapshot(&value);
                        }
                        _ = auth_shutdown.changed() => return,
                    }
                }
            }));
        }

        self.store = Some(store);
        self.config_sync = Some(server.config_sync_handle());
        self.server = Some(server);
        Ok(())
    }

    async fn start_sub_node(
        &mut self,
        config: &ClusterConfig,
        state: &AppState,
        options: &ClusterRuntimeOptions,
        clock: Arc<dyn Clock>,
    ) -> Result<(), ControlApiError> {
        let service = state
            .config_service_arc()
            .ok_or_else(|| ControlApiError::Internal {
                message: "cluster sub-node requires a config service".to_owned(),
            })?;
        let master_url = config.master_url.clone().ok_or_else(|| {
            ControlApiError::from(ClusterError::RoleInvalid {
                reason: "sub_node requires master_url".to_owned(),
            })
        })?;
        let identity = match NodeIdentity::load(&config.tls) {
            Ok(identity) => identity,
            Err(_) => enroll_identity(config, options).await?,
        };
        let client = Arc::new(ClusterClient::new_with_timing(
            &master_url,
            &identity,
            clock.clone(),
            config.timing.clone(),
        )?);

        let applier = Arc::new(
            SyncedConfigApplier::new(Arc::clone(&service), config.node_id.clone())
                .with_cluster_status(Arc::clone(&self.status), Arc::clone(&clock)),
        );
        let auth_state = state.auth_state_arc();
        let auth_applier: Option<Arc<dyn AuthSnapshotApplier>> = auth_state
            .clone()
            .map(|auth| Arc::new(StateAuthApplier::new(auth)) as Arc<dyn AuthSnapshotApplier>);
        let cert_installer: Option<Arc<dyn CertInstaller>> = match (
            options.tls_resolver.clone(),
            CertStore::open(&options.data_dir),
        ) {
            (Some(resolver), Ok(store)) => Some(Arc::new(TlsCertInstaller::new(resolver, store))),
            _ => None,
        };
        let runtime_applier = Arc::new(StateRuntimeApplier::new(state.clone()));

        let (version, _) = service.current().await?;
        let queue_depth = match state.offline_write_queue_arc() {
            Some(queue) => queue
                .status()
                .await
                .map(|status| status.pending)
                .unwrap_or(0),
            None => 0,
        };
        self.status.set(ClusterStatus {
            role: "sub_node".to_owned(),
            master_reachable: false,
            applied_version: version,
            lag: 0,
            queue_depth,
            last_sync: None,
            degraded_nodes: 0,
        });

        let status = Arc::clone(&self.status);
        let mut shutdown = self.shutdown.subscribe();
        let notify = Arc::clone(&self.notify);
        let connection_clock = clock.clone();
        let connection_state = state.clone();
        let queue = state.offline_write_queue_arc().map(|queue| {
            let queue = (*queue).clone().with_backoff(
                config.timing.reconnect_backoff,
                config.timing.reconnect_backoff_max,
            );
            match &auth_state {
                Some(auth) => Arc::new(
                    queue
                        .with_actor_validator(Arc::new(StateActorValidator::new(Arc::clone(auth)))),
                ),
                None => Arc::new(queue),
            }
        });
        let replay_executor = Arc::new(ClientWriteExecutor::new(Arc::clone(&client)));
        state.attach_cluster_write_relay(
            Arc::clone(&replay_executor) as Arc<dyn WriteExecutor>,
            config.node_id.clone(),
        );
        let replay_lock = Arc::new(tokio::sync::Mutex::new(()));
        let log_streamer = state.query_log_arc().map(|log| {
            Arc::new(LogStreamer::new(
                Arc::new(QueryLogOutbox::new(log)),
                Arc::clone(&client),
                config.log.clone(),
                clock.clone(),
            ))
        });
        // Maintenance: heartbeats and certificate renewal, one pass per
        // heartbeat interval. The renewal check reads the identity from disk.
        let maintenance_client = Arc::clone(&client);
        let maintenance_paths = config.tls.clone();
        let maintenance_clock = clock.clone();
        let maintenance_service = Arc::clone(&service);
        let maintenance_queue = queue.clone();
        let maintenance_streamer = log_streamer.clone();
        let interval = config.timing.heartbeat_interval;
        let mut maintenance_shutdown = self.shutdown.subscribe();
        self.tasks.push(tokio::spawn(async move {
            let wake = Notify::new();
            let mut reported_drops = 0_u64;
            loop {
                maintenance_pass(
                    &maintenance_client,
                    &maintenance_paths,
                    maintenance_clock.as_ref(),
                    &maintenance_service,
                    maintenance_queue.as_deref(),
                )
                .await;
                if let Some(streamer) = &maintenance_streamer {
                    let dropped = streamer.dropped_rows();
                    if dropped > reported_drops {
                        let code = ClusterError::LogBufferDropped { count: dropped }.code();
                        tracing::warn!(code, dropped, "cluster log buffer dropped rows");
                        reported_drops = dropped;
                    }
                }
                let deadline = add_duration(maintenance_clock.now(), interval);
                tokio::select! {
                    () = wait_until(maintenance_clock.as_ref(), deadline, &wake) => {}
                    _ = maintenance_shutdown.changed() => return,
                }
            }
        }));

        let connection_streamer = log_streamer.clone();
        let connection_client = Arc::clone(&client);
        self.tasks.push(tokio::spawn(async move {
            run_sub_node_loop(
                connection_client,
                applier,
                auth_applier,
                cert_installer,
                runtime_applier,
                connection_streamer,
                status,
                connection_clock,
                connection_state,
                queue,
                replay_executor,
                replay_lock,
                notify,
                &mut shutdown,
            )
            .await;
        }));

        if let Some(streamer) = log_streamer {
            let mut shutdown = self.shutdown.subscribe();
            let notify = Arc::clone(&self.notify);
            let stream_clock = clock.clone();
            self.tasks.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown.changed() => return,
                        result = streamer.run(&notify) => {
                            if *shutdown.borrow() {
                                return;
                            }
                            if result.is_ok() {
                                continue;
                            }
                            let deadline =
                                add_duration(stream_clock.now(), LOG_RETRY_DELAY);
                            tokio::select! {
                                () = wait_until(stream_clock.as_ref(), deadline, &notify) => {}
                                _ = shutdown.changed() => return,
                            }
                        }
                    }
                }
            }));
        }

        Ok(())
    }
}

impl Drop for ClusterRuntime {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.notify.notify_waiters();
    }
}

/// Loads a persisted identity or enrolls a new one with the join token.
async fn enroll_identity(
    config: &ClusterConfig,
    options: &ClusterRuntimeOptions,
) -> Result<NodeIdentity, ControlApiError> {
    let (Some(token), Some(master_cert), Some(master_url)) = (
        options.join_token.clone(),
        options.master_cert_pem.clone(),
        config.master_url.as_deref(),
    ) else {
        return Err(ControlApiError::from(ClusterError::RoleInvalid {
            reason: "sub_node has no identity; provide join_token and master_cert_pem to enroll"
                .to_owned(),
        }));
    };
    let pending = PendingNodeIdentity::generate(&config.node_id)?;
    let response = ClusterClient::enroll(master_url, &master_cert, pending.request(token)).await?;
    Ok(pending.persist(&response, &config.tls)?)
}

/// One sub-node maintenance pass: renews the certificate when two thirds of
/// its lifetime have passed, then sends a heartbeat. Failures are logged and
/// retried on the next pass; neither blocks DNS answering.
async fn maintenance_pass(
    client: &ClusterClient,
    paths: &TlsPaths,
    clock: &dyn Clock,
    service: &ConfigService,
    queue: Option<&OfflineWriteQueue>,
) {
    if let Err(error) = client.renew_if_due(paths, clock.now()).await {
        tracing::warn!(error = %error, "cluster certificate renewal failed");
    }
    let applied_version = match service.current().await {
        Ok((version, _)) => version,
        Err(error) => {
            tracing::debug!(error = %error, "cluster heartbeat skipped: no config state");
            return;
        }
    };
    let queue_depth = match queue {
        Some(queue) => queue
            .status()
            .await
            .map(|status| status.pending)
            .unwrap_or(0),
        None => 0,
    };
    match client.heartbeat(applied_version, queue_depth).await {
        Ok(response) => {
            for warning in response.warnings {
                tracing::warn!(code = %warning.code, "cluster heartbeat warning");
            }
        }
        Err(error) => tracing::debug!(error = %error, "cluster heartbeat failed"),
    }
}

/// The sub-node reconnect/apply loop.
#[allow(clippy::too_many_arguments)]
async fn run_sub_node_loop(
    client: Arc<ClusterClient>,
    applier: Arc<SyncedConfigApplier>,
    auth_applier: Option<Arc<dyn AuthSnapshotApplier>>,
    cert_installer: Option<Arc<dyn CertInstaller>>,
    runtime_applier: Arc<StateRuntimeApplier>,
    log_streamer: Option<Arc<LogStreamer>>,
    status: Arc<ClusterStatusHandle>,
    clock: Arc<dyn Clock>,
    state: AppState,
    queue: Option<Arc<OfflineWriteQueue>>,
    replay_executor: Arc<ClientWriteExecutor>,
    replay_lock: Arc<tokio::sync::Mutex<()>>,
    notify: Arc<Notify>,
    shutdown: &mut watch::Receiver<bool>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let last_applied = match state.config_service_arc() {
            Some(service) => service
                .current()
                .await
                .ok()
                .and_then(|(version, _)| version),
            None => None,
        };
        let last_acked = match state.query_log_arc() {
            Some(log) => log
                .next_seq()
                .await
                .ok()
                .map(|seq| u64::try_from(seq.saturating_sub(1)).unwrap_or(0)),
            None => None,
        };
        let mut stream = tokio::select! {
            stream = client.connect_with(last_applied, last_acked, &notify) => match stream {
                Ok(stream) => stream,
                Err(_) if *shutdown.borrow() => return,
                Err(error) => {
                    tracing::warn!(error = %error, "cluster sub-node could not connect");
                    status.update(|status| status.master_reachable = false);
                    return;
                }
            },
            _ = shutdown.changed() => return,
        };
        status.update(|status| status.master_reachable = true);

        // Resume the query-log outbox from the master's cursor. A master
        // sequence ahead of the local buffer means rows were dropped; the
        // backfill reports the gap instead of silently skipping it.
        if let (Some(streamer), Some(master_highest)) =
            (log_streamer.as_deref(), stream.master_highest_log_seq())
            && let Err(error) = backfill_logs(streamer, master_highest).await
        {
            tracing::warn!(error = %error, "cluster log backfill failed");
        }

        // When auth is replicated, wait for the reconnect's first auth
        // snapshot before replaying: a token revoked while the node was
        // offline must be gone before a queued write is re-submitted. A
        // ConfigPush (always queued after the snapshot) is the liveness
        // fallback when the master has no auth state.
        let mut replay_pending = if queue.is_some() {
            replay_lock.clone().try_lock_owned().ok()
        } else {
            None
        };
        if auth_applier.is_none() {
            spawn_replay(&mut replay_pending, &queue, &replay_executor);
        }
        // Liveness fallback: if no snapshot or config push arrives (for
        // example a master with no auth state), replay anyway after a grace
        // period driven by the injected clock.
        let replay_wake = Notify::new();
        let replay_deadline = add_duration(clock.now(), AUTH_REPLAY_GRACE);

        loop {
            tokio::select! {
                _ = shutdown.changed() => return,
                () = wait_until(clock.as_ref(), replay_deadline, &replay_wake), if replay_pending.is_some() => {
                    spawn_replay(&mut replay_pending, &queue, &replay_executor);
                }
                record = stream.next_record() => match record {
                    Ok(StreamRecord::ConfigPush(push)) => {
                        spawn_replay(&mut replay_pending, &queue, &replay_executor);
                        match client.apply_push(&push, applier.as_ref()).await {
                            Ok(applied) => status.update(|status| {
                                status.applied_version = Some(applied);
                                status.lag = (push.config_version - applied).max(0);
                                status.last_sync = Some(clock.now());
                            }),
                            Err(error) => {
                                tracing::warn!(error = %error, "cluster config apply failed");
                                status.update(|status| {
                                    status.master_reachable = false;
                                    status.lag = (push.config_version
                                        - status.applied_version.unwrap_or(0))
                                    .max(0);
                                });
                                break;
                            }
                        }
                    }
                    Ok(StreamRecord::TlsRenewed(notice)) => match &cert_installer {
                        Some(installer) => {
                            // A node requests its own certificate: the key is made
                            // here and never leaves the node. Run it in the
                            // background, since the master's signing may take a
                            // while and must not stall config pushes.
                            let client = Arc::clone(&client);
                            let installer = Arc::clone(installer);
                            tokio::spawn(async move {
                                if let Err(error) = client
                                    .request_tls_certificate(&notice.names, installer.as_ref())
                                    .await
                                {
                                    tracing::warn!(error = %error, "cluster TLS certificate request failed");
                                }
                            });
                        }
                        None => tracing::warn!("cluster TLS renewal notice ignored: no TLS resolver wired"),
                    },
                    Ok(StreamRecord::AuthSnapshotPush(push)) => {
                        match &auth_applier {
                            Some(applier) => {
                                if let Err(error) =
                                    client.apply_auth_snapshot(&push, applier.as_ref()).await
                                {
                                    tracing::warn!(error = %error, "cluster auth snapshot failed");
                                    status.update(|status| status.master_reachable = false);
                                    break;
                                }
                            }
                            None => {
                                tracing::warn!("cluster auth snapshot ignored: no auth state wired")
                            }
                        }
                        spawn_replay(&mut replay_pending, &queue, &replay_executor);
                    }
                    Ok(StreamRecord::RuntimeCommand(command)) => {
                        if let Err(error) =
                            client.apply_runtime_command(&command, runtime_applier.as_ref()).await
                        {
                            tracing::warn!(error = %error, "cluster runtime command failed");
                        }
                    }
                    Ok(StreamRecord::Error { error }) => {
                        tracing::warn!(code = %error.code, "cluster stream error");
                        status.update(|status| status.master_reachable = false);
                        break;
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::debug!(error = %error, "cluster stream disconnected");
                        status.update(|status| status.master_reachable = false);
                        break;
                    }
                }
            }
        }
    }
}

/// Spawns one offline-write replay pass if one is still pending.
fn spawn_replay(
    pending: &mut Option<tokio::sync::OwnedMutexGuard<()>>,
    queue: &Option<Arc<OfflineWriteQueue>>,
    executor: &Arc<ClientWriteExecutor>,
) {
    let (Some(guard), Some(queue)) = (pending.take(), queue.clone()) else {
        return;
    };
    let executor = Arc::clone(executor);
    tokio::spawn(async move {
        let _guard = guard;
        if let Err(error) = queue.replay_all(executor.as_ref()).await {
            tracing::warn!(error = %error, "offline write replay failed");
        }
    });
}

fn internal(error: ControlApiError) -> ClusterError {
    ClusterError::Internal {
        message: format!("{}: {error}", error.code()),
    }
}
