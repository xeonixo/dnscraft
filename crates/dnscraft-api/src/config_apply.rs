//! Atomic config replace and rollback.
//!
//! Every write validates the whole snapshot first, applies the module sections
//! in the fixed order `filtering → clients → policy → listeners → tls`, and
//! only stores a new `config_versions` row after every apply succeeded. A
//! failure re-applies the previously active snapshot for the modules that were
//! already touched, then returns the failing module's stable code unchanged.
//!
//! Persisting after apply (rather than persisting first and marking the row
//! failed) means a version that failed to apply can never become the current
//! version: the schema has no failed-status column, and `MAX(version)` is the
//! current pointer. The previous version simply remains current.
//!
//! [`mcp_rules`](merge_mcp_rules) are the one merge exception: omitting the
//! field carries the stored rules of the same filter set over; an explicit
//! empty array deletes them; any unknown field is rejected instead of being
//! silently dropped.

use std::collections::{BTreeSet, HashSet};

use serde_json::{Map, Value, json};

use crate::audit::{Audit, ConfigChangeRecord};
use crate::error::ControlApiError;
use crate::modules::ModuleAppliers;
use crate::storage::ConfigStore;

/// The fixed leaf-first apply order.
const APPLY_ORDER: [&str; 5] = ["filtering", "clients", "policy", "listeners", "tls"];

/// Top-level sections a snapshot may contain. `resolver` is carried for
/// cross-module validation only (forward-zone ids); it is not applied here.
const TOP_LEVEL_KEYS: [&str; 7] = [
    "filtering",
    "clients",
    "policy",
    "listeners",
    "tls",
    "resolver",
    // Runtime settings owned by the control API (update check, backups).
    "control_api_settings",
];

/// Sections every config replace must provide.
const REQUIRED_SECTIONS: [&str; 5] = ["filtering", "clients", "policy", "listeners", "tls"];

/// Fields accepted inside one `filtering.sets[]` entry.
/// A set's pause is runtime state (SPEC-mcp § pauses), never a config field.
const FILTER_SET_KEYS: [&str; 7] = [
    "id",
    "name",
    "lists",
    "custom_rules",
    "services",
    "block_mode",
    "mcp_rules",
];

/// Fields accepted inside one `mcp_rules[]` entry.
const MCP_RULE_KEYS: [&str; 6] = [
    "id",
    "domain",
    "include_subdomains",
    "created_at",
    "expires_at",
    "token_id",
];

/// Sub-blocks of the `tls` section reported separately by the field diff
/// (control-api Q6). Top-level TLS fields (`public_domain`, `key_type`, …) are
/// reported as `tls`.
const TLS_SUB_BLOCKS: [&str; 5] = ["acme", "dyndns", "dns_provider", "notifications", "manual"];

/// The actor performing a config change (from the authenticated principal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigActor {
    /// User or token identifier.
    pub actor_id: String,
    /// `user` or `token`.
    pub actor_type: String,
    /// Originating cluster node, when the write was relayed by a sub-node.
    ///
    /// `None` means the local node performed the action.
    node_id: Option<String>,
}

impl ConfigActor {
    /// Builds an actor from raw fields.
    pub fn new(actor_id: impl Into<String>, actor_type: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            actor_type: actor_type.into(),
            node_id: None,
        }
    }

    /// Attributes the change to the cluster node that originated it.
    pub fn on_node(mut self, node_id: impl Into<String>) -> Self {
        self.node_id = Some(node_id.into());
        self
    }

    /// The originating node override, if any.
    fn audit_node_id<'a>(&'a self, local: &'a str) -> &'a str {
        self.node_id.as_deref().unwrap_or(local)
    }

    /// The actor used when the API is embedded without authentication.
    pub fn local() -> Self {
        Self::new("local", "user")
    }
}

/// Audit content captured by an audited config mutation.
///
/// The service fills `config_version` and commits the record with the config
/// version; the closure supplies the redaction-ready `before`/`after` shapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MutationAudit {
    /// Pre-change state.
    pub before: Option<Value>,
    /// Post-change state; `config_version` is filled by the service.
    pub after: Value,
}

/// Result of a rollback: the newly created version and the restored source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// Newly stored version (rollback always creates a new row).
    pub version: i64,
    /// Version whose snapshot was restored.
    pub restored_from: i64,
}

/// Result of a dry run ([`ConfigService::validate`]).
pub(crate) struct Validation {
    /// The stored version the check ran against.
    pub(crate) config_version: Option<i64>,
    /// Every rejection the real write would hit; empty when it would pass.
    pub(crate) errors: Vec<ControlApiError>,
    /// Section and sub-key diff of the merged snapshot against the stored one.
    pub(crate) diff: Value,
}

/// The atomic config service shared by every config route.
pub struct ConfigService {
    store: ConfigStore,
    audit: Audit,
    modules: ModuleAppliers,
    node_id: String,
    apply_lock: tokio::sync::Mutex<()>,
    changes: tokio::sync::watch::Sender<Option<i64>>,
}

impl ConfigService {
    /// Builds the service around a store, audit log and module appliers.
    pub fn new(
        store: ConfigStore,
        audit: Audit,
        modules: ModuleAppliers,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            store,
            audit,
            modules,
            node_id: node_id.into(),
            apply_lock: tokio::sync::Mutex::new(()),
            changes: tokio::sync::watch::channel(None).0,
        }
    }

    /// Subscribes to successful config-version changes.
    ///
    /// The cluster master runtime uses this to publish the new snapshot to
    /// [`dnscraft_cluster::ConfigSync`] after every apply or rollback. Every
    /// successful [`Self::replace`], [`Self::mutate`],
    /// [`Self::mutate_audited`], [`Self::apply_synced_config`] and
    /// [`Self::rollback`] sends the new version.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<Option<i64>> {
        self.changes.subscribe()
    }

    fn notify_change(&self, version: i64) {
        let _ = self.changes.send(Some(version));
    }

    /// The current version and its stored (already redacted) snapshot.
    pub async fn current(&self) -> Result<(Option<i64>, Option<Value>), ControlApiError> {
        let version = self.store.current().await?;
        let snapshot = match version {
            Some(version) => self.store.load(version).await?,
            None => None,
        };
        Ok((version, snapshot))
    }

    /// Holds the config apply lock across a volatile mutation that reads the
    /// current snapshot and then mutates engine state (protected-domain check +
    /// temporary allow), so a concurrent config replace cannot interleave.
    pub(crate) async fn apply_guard(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.apply_lock.lock().await
    }

    /// Records a runtime action (temporary allow, pause, resume) in the audit
    /// log without creating a config version.
    ///
    /// The current version is recorded for context. An audit failure is logged
    /// and never masks the outcome of the action itself.
    pub(crate) async fn record_action(
        &self,
        actor: &ConfigActor,
        action: &str,
        before: Option<&Value>,
        after: Option<&Value>,
        error_code: Option<&str>,
    ) {
        let version = self.store.current().await.ok().flatten();
        let result = if error_code.is_some() { "error" } else { "ok" };
        self.record(actor, action, version, before, after, result, error_code)
            .await;
    }

    /// Lists stored versions newest first.
    pub async fn versions(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<(i64, i64)>, ControlApiError> {
        self.store.versions(limit, offset).await
    }

    /// Stores `snapshot` as the first version when SQLite holds no config yet
    /// (bootstrap seed, GA28). Returns the new version, or `None` when a config
    /// already exists and the bootstrap values are ignored.
    ///
    /// Called once at startup, before the listeners serve, so the check and the
    /// first write need no lock against a concurrent writer.
    pub async fn seed_if_empty(&self, snapshot: Value) -> Result<Option<i64>, ControlApiError> {
        if self.store.current().await?.is_some() {
            return Ok(None);
        }
        self.replace(snapshot, &ConfigActor::local(), None)
            .await
            .map(Some)
    }

    /// Validates, applies and stores a full config replace.
    ///
    /// Returns the new version. `if_match` is the raw `If-Match` header value.
    pub async fn replace(
        &self,
        body: Value,
        actor: &ConfigActor,
        if_match: Option<&str>,
    ) -> Result<i64, ControlApiError> {
        let _guard = self.apply_lock.lock().await;
        let previous_version = self.store.current().await?;
        check_if_match(if_match, previous_version)?;
        let previous = match previous_version {
            Some(version) => self.store.load(version).await?,
            None => None,
        };

        let snapshot = match merge_mcp_rules(body, previous.as_ref()) {
            Ok(snapshot) => snapshot,
            Err(err) => {
                self.record(
                    actor,
                    "config.write",
                    previous_version,
                    previous.as_ref(),
                    None,
                    "error",
                    Some(err.code()),
                )
                .await;
                return Err(err);
            }
        };
        self.commit(
            actor,
            "config.write",
            previous_version,
            previous.as_ref(),
            &snapshot,
            None,
        )
        .await
    }

    /// Applies a full snapshot pushed by the cluster master and adopts its
    /// `config_version` verbatim (no local bump).
    ///
    /// Takes the same validate → apply → store path as [`Self::replace`] under
    /// the same serial apply lock, including re-applying the previous snapshot
    /// on a module failure. The `mcp_rules` merge is deliberately not applied:
    /// the pushed snapshot is complete and is adopted as-is.
    pub async fn apply_synced_config(
        &self,
        snapshot: Value,
        version: i64,
    ) -> Result<i64, ControlApiError> {
        let _guard = self.apply_lock.lock().await;
        let previous_version = self.store.current().await?;
        // A lost ack makes the master redeliver the same version after the
        // sub-node has already stored it. Re-inserting would hit the
        // `config_versions` primary key; the snapshot is already applied, so
        // the redelivery is a successful no-op.
        if previous_version == Some(version) {
            return Ok(version);
        }
        let previous = match previous_version {
            Some(previous) => self.store.load(previous).await?,
            None => None,
        };
        self.commit(
            &ConfigActor::local(),
            "cluster.config.apply",
            previous_version,
            previous.as_ref(),
            &snapshot,
            Some(version),
        )
        .await
    }

    /// Applies an in-place mutation of the current snapshot under the config
    /// apply lock.
    ///
    /// `mutate` must return `Ok(false)` when it made no change; that stores no
    /// version and writes no audit entry. `Ok(true)` takes the same validate →
    /// apply → store → audit path as [`Self::replace`].
    pub async fn mutate<F>(
        &self,
        actor: &ConfigActor,
        action: &str,
        mutate: F,
    ) -> Result<Option<i64>, ControlApiError>
    where
        F: FnOnce(&mut Value) -> Result<bool, ControlApiError>,
    {
        let _guard = self.apply_lock.lock().await;
        let current_version = self.store.current().await?;
        let previous = match current_version {
            Some(version) => self.store.load(version).await?,
            None => None,
        };
        let mut snapshot = previous.clone().unwrap_or_else(empty_snapshot);
        match mutate(&mut snapshot) {
            Ok(true) => {}
            Ok(false) => return Ok(None),
            Err(err) => {
                self.record(
                    actor,
                    action,
                    current_version,
                    previous.as_ref(),
                    None,
                    "error",
                    Some(err.code()),
                )
                .await;
                return Err(err);
            }
        }
        self.commit(
            actor,
            action,
            current_version,
            previous.as_ref(),
            &snapshot,
            None,
        )
        .await
        .map(Some)
    }

    /// Runs a config mutation whose audit row is committed with the new
    /// config version in one SQLite transaction.
    ///
    /// The apply lock is held across read, mutation, validation, apply, store
    /// and audit, so a committed mutation always has exactly one audit row and
    /// a failed audit write rolls the config version back. `mutate` returns
    /// `Ok(None)` when it made no change (no version, no audit of its own
    /// content); then `fallback_after` is audited best-effort as a successful
    /// no-op. An error from `mutate` or from validate/apply is audited
    /// best-effort only, because nothing was committed.
    pub(crate) async fn mutate_audited<F>(
        &self,
        actor: &ConfigActor,
        action: &str,
        fallback_after: Option<Value>,
        mutate: F,
    ) -> Result<Option<i64>, ControlApiError>
    where
        F: FnOnce(&mut Value) -> Result<Option<MutationAudit>, ControlApiError>,
    {
        let _guard = self.apply_lock.lock().await;
        let current_version = self.store.current().await?;
        let previous = match current_version {
            Some(version) => self.store.load(version).await?,
            None => None,
        };
        let mut snapshot = previous.clone().unwrap_or_else(empty_snapshot);
        let audit = match mutate(&mut snapshot) {
            Ok(Some(audit)) => audit,
            Ok(None) => {
                self.record(
                    actor,
                    action,
                    current_version,
                    None,
                    fallback_after.as_ref(),
                    "ok",
                    None,
                )
                .await;
                return Ok(None);
            }
            Err(err) => {
                self.record(
                    actor,
                    action,
                    current_version,
                    None,
                    fallback_after.as_ref(),
                    "error",
                    Some(err.code()),
                )
                .await;
                return Err(err);
            }
        };
        let change = ConfigChangeRecord {
            node_id: actor.audit_node_id(&self.node_id).to_owned(),
            actor_id: actor.actor_id.clone(),
            actor_type: actor.actor_type.clone(),
            action: action.to_owned(),
            config_version: None,
            before: audit.before.clone(),
            after: Some(audit.after.clone()),
            result: "ok".to_owned(),
            error_code: None,
        };
        match self.validate_and_apply(&snapshot, previous.as_ref()).await {
            Ok(()) => match self.store.store_with_audit(&snapshot, change.clone()).await {
                Ok(version) => {
                    self.notify_change(version);
                    Ok(Some(version))
                }
                Err(err) => {
                    self.record(
                        actor,
                        action,
                        current_version,
                        change.before.as_ref(),
                        change.after.as_ref(),
                        "error",
                        Some(err.code()),
                    )
                    .await;
                    Err(err)
                }
            },
            Err(err) => {
                self.record(
                    actor,
                    action,
                    current_version,
                    change.before.as_ref(),
                    change.after.as_ref(),
                    "error",
                    Some(err.code()),
                )
                .await;
                Err(err)
            }
        }
    }

    /// Shared validate → apply → store → audit path used by [`Self::replace`],
    /// [`Self::mutate`] and [`Self::apply_synced_config`].
    ///
    /// `version` is `Some` only for a cluster sync, which stores under the
    /// master's explicit version; `None` auto-increments.
    async fn commit(
        &self,
        actor: &ConfigActor,
        action: &str,
        previous_version: Option<i64>,
        previous: Option<&Value>,
        snapshot: &Value,
        version: Option<i64>,
    ) -> Result<i64, ControlApiError> {
        match self.validate_apply_store(snapshot, previous, version).await {
            Ok(version) => {
                self.record(
                    actor,
                    action,
                    Some(version),
                    previous,
                    Some(snapshot),
                    "ok",
                    None,
                )
                .await;
                Ok(version)
            }
            Err(err) => {
                self.record(
                    actor,
                    action,
                    previous_version,
                    previous,
                    Some(snapshot),
                    "error",
                    Some(err.code()),
                )
                .await;
                Err(err)
            }
        }
    }

    /// Validates and applies `snapshot`, then stores it as a new version.
    ///
    /// Apply failures replay `previous` for the modules already touched; the
    /// failing module's error is returned unchanged. An explicit `version`
    /// stores under that version instead of auto-incrementing.
    async fn validate_apply_store(
        &self,
        snapshot: &Value,
        previous: Option<&Value>,
        version: Option<i64>,
    ) -> Result<i64, ControlApiError> {
        self.validate_and_apply(snapshot, previous).await?;
        let version = match version {
            Some(version) => self.store.store_at(snapshot, version).await?,
            None => self.store.store(snapshot).await?,
        };
        self.notify_change(version);
        Ok(version)
    }

    /// Validates `snapshot` and applies it to every configured module.
    ///
    /// Nothing is persisted; this is the pre-commit half of
    /// [`Self::validate_apply_store`], also used before the transactional
    /// store-and-audit path.
    async fn validate_and_apply(
        &self,
        snapshot: &Value,
        previous: Option<&Value>,
    ) -> Result<(), ControlApiError> {
        self.check_snapshot(snapshot)?;
        self.apply_with_replay(snapshot, previous).await
    }

    /// The side-effect-free checks shared by apply and the dry run: cross-module
    /// references first, then each module's own section validation.
    fn check_snapshot(&self, snapshot: &Value) -> Result<(), ControlApiError> {
        validate_cross_module(snapshot)?;
        self.validate_modules(snapshot)
    }

    /// Dry run of [`Self::replace`]: the same merge and checks, but nothing is
    /// applied, stored or audited, and `config_version` does not move.
    ///
    /// Rejections are returned as data in [`Validation::errors`]; only store
    /// read failures are `Err`.
    pub(crate) async fn validate(
        &self,
        body: Value,
        if_match: Option<&str>,
    ) -> Result<Validation, ControlApiError> {
        let current = self.store.current().await?;
        let previous = match current {
            Some(version) => self.store.load(version).await?,
            None => None,
        };
        let mut errors = Vec::new();
        if let Err(err) = check_if_match(if_match, current) {
            errors.push(err);
        }
        let mut diff = diff_snapshots(None, None);
        match merge_mcp_rules(body, previous.as_ref()) {
            Ok(snapshot) => {
                if let Err(err) = self.check_snapshot(&snapshot) {
                    errors.push(err);
                }
                diff = diff_snapshots(previous.as_ref(), Some(&snapshot));
            }
            Err(err) => errors.push(err),
        }
        Ok(Validation {
            config_version: current,
            errors,
            diff,
        })
    }

    /// Restores a stored version through the same atomic apply path.
    ///
    /// The restored snapshot is stored as a **new** version, so history stays
    /// append-only. `if_match` is the raw `If-Match` header value.
    pub async fn rollback(
        &self,
        target: u64,
        actor: &ConfigActor,
        if_match: Option<&str>,
    ) -> Result<RollbackOutcome, ControlApiError> {
        let _guard = self.apply_lock.lock().await;
        let current_version = self.store.current().await?;
        check_if_match(if_match, current_version)?;
        let previous = match current_version {
            Some(version) => self.store.load(version).await?,
            None => None,
        };

        let Some(target_version) = i64::try_from(target).ok().filter(|v| *v > 0) else {
            return Err(ControlApiError::ConfigUnknownVersion { version: target });
        };
        let Some(snapshot) = self.store.load(target_version).await? else {
            return Err(ControlApiError::ConfigUnknownVersion { version: target });
        };

        if let Err(err) = validate_cross_module(&snapshot) {
            self.record(
                actor,
                "config.rollback",
                current_version,
                previous.as_ref(),
                Some(&snapshot),
                "error",
                Some(err.code()),
            )
            .await;
            return Err(err);
        }
        if let Err(err) = self.validate_modules(&snapshot) {
            self.record(
                actor,
                "config.rollback",
                current_version,
                previous.as_ref(),
                Some(&snapshot),
                "error",
                Some(err.code()),
            )
            .await;
            return Err(err);
        }
        if let Err(err) = self.apply_with_replay(&snapshot, previous.as_ref()).await {
            self.record(
                actor,
                "config.rollback",
                current_version,
                previous.as_ref(),
                Some(&snapshot),
                "error",
                Some(err.code()),
            )
            .await;
            return Err(err);
        }

        let version = self.store.store(&snapshot).await?;
        self.notify_change(version);
        self.record(
            actor,
            "config.rollback",
            Some(version),
            previous.as_ref(),
            Some(&snapshot),
            "ok",
            None,
        )
        .await;
        Ok(RollbackOutcome {
            version,
            restored_from: target_version,
        })
    }

    /// Runs each configured module's section validation, in apply order.
    fn validate_modules(&self, snapshot: &Value) -> Result<(), ControlApiError> {
        if let (Some(module), Some(config)) = (&self.modules.filtering, snapshot.get("filtering")) {
            module.validate(config)?;
        }
        if let (Some(module), Some(config)) = (&self.modules.clients, snapshot.get("clients")) {
            module.validate(config)?;
        }
        if let (Some(module), Some(config)) = (&self.modules.policy, snapshot.get("policy")) {
            module.validate(config)?;
        }
        if let (Some(module), Some(config)) = (&self.modules.listeners, snapshot.get("listeners")) {
            module.validate(config)?;
        }
        if let (Some(module), Some(config)) = (&self.modules.tls, snapshot.get("tls")) {
            module.validate(config)?;
        }
        Ok(())
    }

    /// Applies the snapshot; on failure replays `previous` up to the failed
    /// module and returns the original (failing module's) error.
    ///
    /// A TLS failure additionally reports which TLS sub-blocks changed
    /// (`acme`, `dyndns`, …) under `changed_sub_blocks`, while keeping the
    /// module's stable error code unchanged (control-api Q6).
    async fn apply_with_replay(
        &self,
        snapshot: &Value,
        previous: Option<&Value>,
    ) -> Result<(), ControlApiError> {
        let tls_diff = tls_changed_sub_blocks(previous, snapshot);
        if !tls_diff.is_empty() {
            tracing::debug!(changed = ?tls_diff, "tls sub-blocks changed");
        }
        let (failed, mut error) = match self.apply_all(snapshot, usize::MAX).await {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
        if APPLY_ORDER[failed] == "tls" {
            error = annotate_tls_failure(error, &tls_diff);
        }
        // A module error without its own stable code is reported as the
        // generic apply failure (GA22), so the client sees `config.apply`.
        if !matches!(error, ControlApiError::Module { .. }) {
            error = ControlApiError::ConfigApply {
                message: format!("module `{}` failed: {}", APPLY_ORDER[failed], error.code()),
            };
        }
        if let Some(previous) = previous
            && let Err((_, replay)) = self.apply_all(previous, failed).await
        {
            tracing::error!(
                error = %replay,
                "re-applying the previous config snapshot failed"
            );
        }
        Err(error)
    }

    /// Applies modules `0..=last` in the fixed order.
    ///
    /// Returns the failing module's index and error; unconfigured modules are
    /// skipped.
    async fn apply_all(
        &self,
        snapshot: &Value,
        last: usize,
    ) -> Result<(), (usize, ControlApiError)> {
        for (index, name) in APPLY_ORDER.iter().enumerate() {
            if index > last {
                break;
            }
            let Some(config) = snapshot.get(*name) else {
                continue;
            };
            let result = match *name {
                "filtering" => match &self.modules.filtering {
                    Some(module) => module.apply(config).await,
                    None => Ok(()),
                },
                "clients" => match &self.modules.clients {
                    Some(module) => module.apply(config).await,
                    None => Ok(()),
                },
                "policy" => match &self.modules.policy {
                    Some(module) => module.apply(config).await,
                    None => Ok(()),
                },
                "listeners" => match &self.modules.listeners {
                    Some(module) => module.apply(config).await,
                    None => Ok(()),
                },
                _ => match &self.modules.tls {
                    Some(module) => module.apply(config).await,
                    None => Ok(()),
                },
            };
            if let Err(err) = result {
                return Err((index, err));
            }
        }
        Ok(())
    }

    /// Appends an audit record; a failure to audit never masks the result of
    /// the operation itself (it is logged instead).
    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        actor: &ConfigActor,
        action: &str,
        config_version: Option<i64>,
        before: Option<&Value>,
        after: Option<&Value>,
        result: &str,
        error_code: Option<&str>,
    ) {
        let change = ConfigChangeRecord {
            node_id: actor.audit_node_id(&self.node_id).to_owned(),
            actor_id: actor.actor_id.clone(),
            actor_type: actor.actor_type.clone(),
            action: action.to_owned(),
            config_version,
            before: before.cloned(),
            after: after.cloned(),
            result: result.to_owned(),
            error_code: error_code.map(str::to_owned),
        };
        if let Err(err) = self.audit.record_config_change(change).await {
            tracing::error!(error = %err, "failed to write config audit record");
        }
    }
}

/// Cross-module validation performed before any module apply.
///
/// Checks list references, duplicate ids, view → profile references,
/// profile → filter-set references and profile → forward-zone references. A
/// missing `resolver` section disables the forward-zone check (nothing to
/// compare against); set/profile references are always checked.
fn validate_cross_module(snapshot: &Value) -> Result<(), ControlApiError> {
    let filtering = snapshot.get("filtering");
    let lists = filtering
        .and_then(|value| value.get("lists"))
        .and_then(Value::as_array);
    let sets = filtering
        .and_then(|value| value.get("sets"))
        .and_then(Value::as_array);

    let mut list_ids = HashSet::new();
    if let Some(lists) = lists {
        for list in lists {
            let Some(id) = list.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !list_ids.insert(id) {
                return Err(module_error(
                    "filter_set.duplicate_list",
                    json!({ "id": id }),
                ));
            }
        }
    }

    let mut set_ids = HashSet::new();
    if let Some(sets) = sets {
        for set in sets {
            let Some(id) = set.get("id").and_then(Value::as_str) else {
                continue;
            };
            if !set_ids.insert(id) {
                return Err(module_error(
                    "filter_set.duplicate_set",
                    json!({ "id": id }),
                ));
            }
            if let Some(references) = set.get("lists").and_then(Value::as_array) {
                for reference in references.iter().filter_map(Value::as_str) {
                    if !list_ids.contains(reference) {
                        return Err(module_error(
                            "filter_set.unknown_list",
                            json!({ "set": id, "list": reference }),
                        ));
                    }
                }
            }
        }
    }

    let policy = snapshot.get("policy");
    let profiles = policy
        .and_then(|value| value.get("profiles"))
        .and_then(Value::as_array);
    let mut profile_ids = HashSet::new();
    if let Some(profiles) = profiles {
        for profile in profiles {
            if let Some(id) = profile.get("id").and_then(Value::as_str)
                && !profile_ids.insert(id)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "duplicate profile id", "id": id }),
                ));
            }
        }
    }

    if let Some(views) = policy
        .and_then(|value| value.get("views"))
        .and_then(Value::as_array)
    {
        let mut view_ids = HashSet::new();
        for view in views {
            if let Some(id) = view.get("id").and_then(Value::as_str)
                && !view_ids.insert(id)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "duplicate view id", "id": id }),
                ));
            }
            if let Some(profile) = view.get("profile").and_then(Value::as_str)
                && !profile_ids.contains(profile)
            {
                return Err(module_error(
                    "policy.config.invalid",
                    json!({ "reason": "view references unknown profile", "profile": profile }),
                ));
            }
        }
    }

    let resolver_zone_ids = snapshot
        .get("resolver")
        .and_then(|value| value.get("forward_zones"))
        .and_then(Value::as_array)
        .map(|zones| {
            zones
                .iter()
                .filter_map(|zone| {
                    zone.as_str()
                        .or_else(|| zone.get("id").and_then(Value::as_str))
                })
                .collect::<HashSet<_>>()
        });

    if let Some(profiles) = profiles {
        for profile in profiles {
            let id = profile.get("id").and_then(Value::as_str).unwrap_or("-");
            if let Some(filter_set) = profile.get("filter_set").and_then(Value::as_str)
                && !set_ids.contains(filter_set)
            {
                return Err(module_error(
                    "policy.config.unknown_filter_set",
                    json!({ "id": filter_set }),
                ));
            }
            if let Some(zone_ids) = &resolver_zone_ids
                && let Some(zone) = profile
                    .get("forward_zones")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .find(|zone| !zone_ids.contains(zone))
            {
                return Err(module_error(
                    "policy.config.unknown_forward_zone",
                    json!({ "id": zone, "profile": id }),
                ));
            }
        }
    }
    Ok(())
}

/// Builds a forwarded module error with non-secret `params`.
/// The five required sections, empty. Used when a mutation starts on a fresh
/// install; closures then reject references to missing sets like any replace.
fn empty_snapshot() -> Value {
    json!({
        "filtering": {},
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

fn module_error(code: &'static str, params: Value) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}

/// Section and sub-key diff (`section` or `section.key`) of `next` against
/// `previous`. Only key names are returned, never values, so secrets cannot
/// leak through a dry run.
fn diff_snapshots(previous: Option<&Value>, next: Option<&Value>) -> Value {
    let none = Map::new();
    let old = previous.and_then(Value::as_object).unwrap_or(&none);
    let new = next.and_then(Value::as_object).unwrap_or(&none);
    let mut changed_sections = Vec::new();
    let (mut added, mut removed, mut changed) = (Vec::new(), Vec::new(), Vec::new());
    let names: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
    for name in names {
        let (before, after) = (old.get(name), new.get(name));
        if before == after {
            continue;
        }
        changed_sections.push(name.clone());
        match (before, after) {
            (None, _) => added.push(name.clone()),
            (_, None) => removed.push(name.clone()),
            (Some(Value::Object(b)), Some(Value::Object(a))) => {
                for key in b.keys().chain(a.keys()).collect::<BTreeSet<_>>() {
                    let path = format!("{name}.{key}");
                    match (b.get(key.as_str()), a.get(key.as_str())) {
                        (None, Some(_)) => added.push(path),
                        (Some(_), None) => removed.push(path),
                        (Some(x), Some(y)) if x != y => changed.push(path),
                        _ => {}
                    }
                }
            }
            _ => changed.push(name.clone()),
        }
    }
    json!({
        "changed_sections": changed_sections,
        "added": added,
        "removed": removed,
        "changed": changed,
    })
}

/// Checks the raw `If-Match` value against the current version.
///
/// Accepts `*`, `"5"`, `5`, and the weak form `W/"5"`. A missing header means
/// "no precondition". A malformed header or a mismatch is
/// `control_api.config.version`.
fn check_if_match(raw: Option<&str>, current: Option<i64>) -> Result<(), ControlApiError> {
    let Some(raw) = raw else {
        return Ok(());
    };
    let raw = raw.trim();
    if raw == "*" {
        return match current {
            Some(_) => Ok(()),
            None => Err(ControlApiError::ConfigVersion {
                message: "If-Match: * but no config version exists".to_owned(),
            }),
        };
    }
    let value = raw.strip_prefix("W/").unwrap_or(raw).trim();
    let value = value.trim_matches('"');
    let Ok(version) = value.parse::<i64>() else {
        return Err(ControlApiError::ConfigVersion {
            message: format!("invalid If-Match value `{raw}`"),
        });
    };
    if Some(version) == current {
        Ok(())
    } else {
        Err(ControlApiError::ConfigVersion {
            message: format!("If-Match version {version} is not the current version"),
        })
    }
}

/// Validates the non-secret runtime keys of `control_api_settings` (GA15).
///
/// Accepted: `update_check` (bool), `backups` (`enabled`, `retention_count`),
/// `query_log.retention_days` (1..=3650) and `oidc` (`admin_group`,
/// `groups_claim`, `token_skew_seconds` 5..=300). Secrets, accounts and bind
/// settings are not accepted here; they stay in the bootstrap TOML, the
/// environment or the local-account store.
fn validate_control_api_settings(settings: &Value) -> Result<(), ControlApiError> {
    let Some(map) = settings.as_object() else {
        return Err(config_invalid("control_api_settings must be an object"));
    };
    for (key, value) in map {
        match key.as_str() {
            "update_check" => {
                if !value.is_boolean() {
                    return Err(config_invalid(
                        "control_api_settings.update_check must be a boolean",
                    ));
                }
            }
            "backups" => {
                let backups: crate::system::BackupSettings = serde_json::from_value(value.clone())
                    .map_err(|error| {
                        config_invalid(format!("control_api_settings.backups: {error}"))
                    })?;
                if backups.retention_count == 0
                    || backups.retention_count > crate::system::BACKUP_RETENTION_MAX
                {
                    return Err(config_invalid(
                        "control_api_settings.backups.retention_count is out of range",
                    ));
                }
            }
            "query_log" => {
                let days = value.get("retention_days").and_then(Value::as_u64);
                if value.as_object().is_none_or(|o| o.len() != 1)
                    || !days.is_some_and(|d| (1..=3650).contains(&d))
                {
                    return Err(config_invalid(
                        "control_api_settings.query_log.retention_days must be 1..=3650",
                    ));
                }
            }
            "oidc" => {
                let object = value
                    .as_object()
                    .ok_or_else(|| config_invalid("control_api_settings.oidc must be an object"))?;
                for (field, field_value) in object {
                    match field.as_str() {
                        "admin_group" | "groups_claim" => {
                            if !field_value.is_string() {
                                return Err(config_invalid(format!(
                                    "control_api_settings.oidc.{field} must be a string"
                                )));
                            }
                        }
                        "token_skew_seconds" => {
                            if !field_value.as_u64().is_some_and(|s| (5..=300).contains(&s)) {
                                return Err(config_invalid(
                                    "control_api_settings.oidc.token_skew_seconds must be 5..=300",
                                ));
                            }
                        }
                        other => {
                            return Err(config_invalid(format!(
                                "unknown field `control_api_settings.oidc.{other}`"
                            )));
                        }
                    }
                }
            }
            other => {
                return Err(config_invalid(format!(
                    "unknown field `control_api_settings.{other}`"
                )));
            }
        }
    }
    Ok(())
}

/// Rejects unknown top-level fields, requires the five applied sections, and
/// applies the `mcp_rules` merge to every filter set.
fn merge_mcp_rules(body: Value, stored: Option<&Value>) -> Result<Value, ControlApiError> {
    let Value::Object(mut snapshot) = body else {
        return Err(config_invalid("config body must be a JSON object"));
    };
    for key in snapshot.keys() {
        if !TOP_LEVEL_KEYS.contains(&key.as_str()) {
            return Err(config_invalid(format!("unknown field `{key}`")));
        }
    }
    if let Some(settings) = snapshot.get(crate::system::SETTINGS_SECTION) {
        validate_control_api_settings(settings)?;
    }
    for section in REQUIRED_SECTIONS {
        match snapshot.get(section) {
            Some(Value::Object(_)) => {}
            Some(_) => {
                return Err(config_invalid(format!("`{section}` must be a JSON object")));
            }
            None => {
                return Err(config_invalid(format!(
                    "missing required field `{section}`"
                )));
            }
        }
    }
    if let Some(resolver) = snapshot.get("resolver")
        && !resolver.is_object()
    {
        return Err(config_invalid("`resolver` must be a JSON object"));
    }

    let stored_sets = stored
        .and_then(|value| value.get("filtering"))
        .and_then(|value| value.get("sets"))
        .and_then(Value::as_array);
    if let Some(Value::Object(filtering)) = snapshot.get_mut("filtering")
        && let Some(sets) = filtering.get_mut("sets")
    {
        let Value::Array(sets) = sets else {
            return Err(config_invalid("`filtering.sets` must be an array"));
        };
        for set in sets.iter_mut() {
            let Value::Object(set) = set else {
                return Err(config_invalid(
                    "each `filtering.sets` entry must be an object",
                ));
            };
            for key in set.keys() {
                if !FILTER_SET_KEYS.contains(&key.as_str()) {
                    return Err(config_invalid(format!(
                        "unknown field `{key}` in `filtering.sets`"
                    )));
                }
            }
            merge_set_rules(set, stored_sets)?;
        }
    }

    // A full snapshot may carry local filter-list sources directly. Apply the
    // same traversal/SSRF guards as `PUT /api/v1/filter-lists`; otherwise the
    // raw config path would be a bypass.
    if let Some(Value::Object(filtering)) = snapshot.get("filtering")
        && let Some(Value::Array(lists)) = filtering.get("lists")
    {
        for list in lists {
            let Some(source) = list.get("source").and_then(Value::as_object) else {
                continue;
            };
            if let Some(file) = source.get("file").and_then(Value::as_str)
                && !list_source_path_is_safe(file)
            {
                return Err(config_invalid(
                    "filter list `source.file` must be a relative path without `..` components",
                ));
            }
            if let Some(url) = source.get("url").and_then(Value::as_str)
                && !list_source_url_is_safe(url)
            {
                return Err(config_invalid(
                    "filter list `source.url` must be an https:// URL whose host is not loopback/private",
                ));
            }
        }
    }
    Ok(Value::Object(snapshot))
}

/// Whether a client-supplied local filter-list source path is a safe relative
/// path: non-empty, with no `..`, root, or prefix components. An absolute path
/// (`/etc/passwd`) would let a raw snapshot read arbitrary files from the data
/// directory, so it is rejected too.
///
/// `file` sources are an admin-only filtering feature. Rejecting absolute and
/// parent components here covers both the per-list route and a raw
/// `PUT /config` snapshot, so the two validation paths cannot drift. The data
/// directory itself is a server-side bootstrap value and is never accepted
/// from a request.
pub(crate) fn list_source_path_is_safe(path: &str) -> bool {
    let path = std::path::Path::new(path);
    !path.as_os_str().is_empty()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
}

/// Whether a client-supplied filter-list source URL is an `https://` URL whose
/// host is not an internal IP literal. A literal loopback/private/link-local/
/// ULA/CGNAT host is rejected to block SSRF against the node's own services
/// (e.g. `169.254.169.254` cloud metadata); a hostname passes because it is
/// expected to resolve to a public address (a hostname that resolves privately
/// is a fetch-time concern, not config validation).
pub(crate) fn list_source_url_is_safe(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    if parsed.scheme() != "https" {
        return false;
    }
    match parsed.host() {
        Some(url::Host::Ipv4(ip)) => !crate::config::is_internal_bind(std::net::IpAddr::V4(ip)),
        Some(url::Host::Ipv6(ip)) => !crate::config::is_internal_bind(std::net::IpAddr::V6(ip)),
        Some(url::Host::Domain(_)) => true,
        None => false,
    }
}

/// Applies the per-set `mcp_rules` merge rule to one filter-set object.
fn merge_set_rules(
    set: &mut Map<String, Value>,
    stored_sets: Option<&Vec<Value>>,
) -> Result<(), ControlApiError> {
    match set.get("mcp_rules") {
        None => {
            let id = set.get("id").and_then(Value::as_str);
            let carried = stored_sets
                .and_then(|sets| {
                    sets.iter()
                        .find(|stored| stored.get("id").and_then(Value::as_str) == id)
                })
                .and_then(|stored| stored.get("mcp_rules"))
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new()));
            set.insert("mcp_rules".to_owned(), carried);
        }
        Some(Value::Array(rules)) => {
            for rule in rules {
                let Value::Object(rule) = rule else {
                    return Err(config_invalid("each `mcp_rules` entry must be an object"));
                };
                for key in rule.keys() {
                    if !MCP_RULE_KEYS.contains(&key.as_str()) {
                        return Err(config_invalid(format!(
                            "unknown field `{key}` in `mcp_rules`"
                        )));
                    }
                }
            }
        }
        Some(_) => {
            return Err(config_invalid("`mcp_rules` must be an array"));
        }
    }
    Ok(())
}

/// Builds `control_api.config.invalid`.
fn config_invalid(reason: impl Into<String>) -> ControlApiError {
    ControlApiError::ConfigInvalid {
        reason: reason.into(),
    }
}

/// Names of the TLS sub-blocks that changed between two snapshots.
///
/// Returns `"tls"` for a top-level TLS field change (for example
/// `public_domain` or `key_type`) and one entry per changed sub-block
/// (`acme`, `dyndns`, `dns_provider`, `notifications`, `manual`). An unchanged
/// TLS section returns an empty list.
fn tls_changed_sub_blocks(previous: Option<&Value>, next: &Value) -> Vec<&'static str> {
    let before = previous.and_then(|snapshot| snapshot.get("tls"));
    let after = next.get("tls");
    if before == after {
        return Vec::new();
    }
    let before = before.and_then(Value::as_object);
    let after = after.and_then(Value::as_object);

    // Top-level TLS fields, excluding the sub-blocks reported separately.
    let top_level = |map: Option<&Map<String, Value>>| {
        map.map(|map| {
            map.iter()
                .filter(|(key, _)| !TLS_SUB_BLOCKS.contains(&key.as_str()))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect::<Map<_, _>>()
        })
        .unwrap_or_default()
    };

    let mut changed = Vec::new();
    if top_level(before) != top_level(after) {
        changed.push("tls");
    }
    for block in TLS_SUB_BLOCKS {
        if before.and_then(|map| map.get(block)) != after.and_then(|map| map.get(block)) {
            changed.push(block);
        }
    }
    changed
}

/// Adds the changed TLS sub-blocks to a failed module error without changing
/// its stable code, so a partial-failure report stays machine-readable.
fn annotate_tls_failure(error: ControlApiError, changed: &[&'static str]) -> ControlApiError {
    match error {
        ControlApiError::Module { code, params } => {
            let mut map = params
                .as_ref()
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            map.insert("changed_sub_blocks".to_owned(), json!(changed));
            ControlApiError::Module {
                code,
                params: Some(Value::Object(map)),
            }
        }
        other => other,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::modules::{ApplyFiltering, ModuleFuture};
    use crate::storage::Db;
    use dnscraft_common::clock::ManualClock;

    #[tokio::test]
    async fn audited_mutation_rolls_back_when_the_audit_insert_fails() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        db.with_conn(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER reject_ok_audit BEFORE INSERT ON audit_log
                 WHEN NEW.result = 'ok'
                 BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
            )
            .map_err(crate::storage::db_err)
        })
        .await
        .unwrap();
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers::default(),
            "node-a",
        );
        let actor = ConfigActor::new("tok", "token");

        let err = service
            .mutate_audited(
                &actor,
                "mcp.add_rule",
                Some(json!({ "domain": "x.example.com" })),
                |snapshot| {
                    snapshot["filtering"]["marker"] = json!(true);
                    Ok(Some(MutationAudit {
                        before: None,
                        after: json!({
                            "domain": "x.example.com",
                            "config_version": Value::Null,
                        }),
                    }))
                },
            )
            .await
            .expect_err("the audit insert fails");

        assert_eq!(err.code(), "control_api.internal");
        assert_eq!(
            service.current().await.unwrap(),
            (None, None),
            "a failed audit insert rolls the config version back"
        );
        let rows = db.audit_list(10, 0).await.unwrap();
        assert_eq!(rows.len(), 1, "only the best-effort failure audit lands");
        assert_eq!(rows[0].action, "mcp.add_rule");
        assert_eq!(rows[0].result, "error");
        assert_eq!(rows[0].config_version, None);
    }

    #[tokio::test]
    async fn audited_mutation_commits_one_audit_row_with_the_version() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers::default(),
            "node-a",
        );
        let actor = ConfigActor::new("tok", "token");

        let version = service
            .mutate_audited(&actor, "mcp.add_rule", None, |snapshot| {
                snapshot["filtering"]["marker"] = json!(true);
                Ok(Some(MutationAudit {
                    before: None,
                    after: json!({
                        "domain": "x.example.com",
                        "config_version": Value::Null,
                    }),
                }))
            })
            .await
            .unwrap()
            .expect("a version");

        let rows = db.audit_list(10, 0).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].action, "mcp.add_rule");
        assert_eq!(rows[0].result, "ok");
        assert_eq!(rows[0].config_version, Some(version));
        let after: Value = serde_json::from_str(rows[0].after.as_deref().unwrap()).unwrap();
        assert_eq!(after["config_version"], version);
    }

    #[test]
    fn tls_diff_names_the_changed_sub_blocks() {
        let before = json!({"tls": {
            "public_domain": "a.example",
            "acme": {"enabled": true},
            "dyndns": {"enabled": false},
        }});
        let after = json!({"tls": {
            "public_domain": "b.example",
            "acme": {"enabled": true},
            "dyndns": {"enabled": true},
        }});
        assert_eq!(
            tls_changed_sub_blocks(Some(&before), &after),
            vec!["tls", "dyndns"]
        );
    }

    #[test]
    fn tls_diff_is_empty_for_an_unchanged_section() {
        let snapshot = json!({"tls": {"public_domain": "a.example", "acme": {}}});
        assert!(tls_changed_sub_blocks(Some(&snapshot), &snapshot).is_empty());
        assert!(tls_changed_sub_blocks(None, &json!({"tls": {}})).is_empty());
    }

    #[test]
    fn tls_failure_keeps_the_module_code_and_reports_blocks() {
        let error = annotate_tls_failure(
            ControlApiError::Module {
                code: "tls.acme.order",
                params: Some(json!({ "reason": "bad order" })),
            },
            &["acme"],
        );
        assert_eq!(error.code(), "tls.acme.order");
        assert_eq!(
            error,
            ControlApiError::Module {
                code: "tls.acme.order",
                params: Some(json!({
                    "reason": "bad order",
                    "changed_sub_blocks": ["acme"],
                })),
            }
        );
    }

    /// A valid full snapshot carrying a marker the fake applier inspects.
    fn synced_snapshot(marker: &str, fail: bool) -> Value {
        json!({
            "filtering": { "lists": [], "sets": [], "marker": marker, "fail": fail },
            "clients": {},
            "policy": {},
            "listeners": {},
            "tls": {},
        })
    }

    /// Filtering applier that records every applied section and fails when the
    /// section carries `"fail": true`.
    struct RecordingFiltering {
        applied: Arc<Mutex<Vec<Value>>>,
    }

    impl ApplyFiltering for RecordingFiltering {
        fn apply<'a>(&'a self, config: &'a Value) -> ModuleFuture<'a> {
            Box::pin(async move {
                self.applied.lock().unwrap().push(config.clone());
                if config.get("fail").and_then(Value::as_bool) == Some(true) {
                    return Err(module_error(
                        "filtering.config.invalid",
                        json!({ "reason": "injected" }),
                    ));
                }
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn apply_synced_config_adopts_the_explicit_version() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers::default(),
            "node-b",
        );

        assert_eq!(
            service
                .apply_synced_config(synced_snapshot("v7", false), 7)
                .await
                .unwrap(),
            7
        );
        assert_eq!(service.current().await.unwrap().0, Some(7));

        // The next push continues from the master's version, not a local bump.
        assert_eq!(
            service
                .apply_synced_config(synced_snapshot("v8", false), 8)
                .await
                .unwrap(),
            8
        );
        assert_eq!(
            service.current().await.unwrap(),
            (Some(8), Some(synced_snapshot("v8", false)))
        );

        let rows = db.audit_list(10, 0).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].action, "cluster.config.apply");
        assert_eq!(rows[0].node_id, "node-b");
        assert_eq!(rows[0].config_version, Some(8));
        assert_eq!(rows[0].result, "ok");
    }

    #[tokio::test]
    async fn apply_synced_config_is_idempotent_for_an_already_stored_version() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers::default(),
            "node-b",
        );
        let snapshot = synced_snapshot("v7", false);

        assert_eq!(
            service
                .apply_synced_config(snapshot.clone(), 7)
                .await
                .unwrap(),
            7
        );
        // The master redelivers the same version after a lost ack: no PK
        // conflict, no second audit row, same current snapshot.
        assert_eq!(
            service
                .apply_synced_config(snapshot.clone(), 7)
                .await
                .unwrap(),
            7
        );
        assert_eq!(service.current().await.unwrap(), (Some(7), Some(snapshot)));
        assert_eq!(db.audit_list(10, 0).await.unwrap().len(), 1);
    }

    /// Filtering applier that fails without a module-specific code.
    struct UncodedFiltering;

    impl ApplyFiltering for UncodedFiltering {
        fn apply<'a>(&'a self, _config: &'a Value) -> ModuleFuture<'a> {
            Box::pin(async {
                Err(ControlApiError::Internal {
                    message: "disk full".to_owned(),
                })
            })
        }
    }

    #[tokio::test]
    async fn unmapped_module_failure_is_reported_as_config_apply() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers {
                filtering: Some(Arc::new(UncodedFiltering)),
                ..ModuleAppliers::default()
            },
            "node-b",
        );

        let err = service
            .apply_synced_config(synced_snapshot("new", false), 3)
            .await
            .expect_err("the injected module apply fails");
        assert_eq!(err.code(), "control_api.config.apply");
    }

    #[tokio::test]
    async fn apply_synced_config_rolls_back_to_the_previous_version_on_failure() {
        let clock = Arc::new(ManualClock::new(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        let applied = Arc::new(Mutex::new(Vec::new()));
        let service = ConfigService::new(
            ConfigStore::new(db.clone()),
            Audit::new(db.clone()),
            ModuleAppliers {
                filtering: Some(Arc::new(RecordingFiltering {
                    applied: Arc::clone(&applied),
                })),
                ..ModuleAppliers::default()
            },
            "node-b",
        );

        service
            .apply_synced_config(synced_snapshot("old", false), 5)
            .await
            .unwrap();
        applied.lock().unwrap().clear();

        let err = service
            .apply_synced_config(synced_snapshot("new", true), 6)
            .await
            .expect_err("the injected module apply fails");
        assert_eq!(err.code(), "filtering.config.invalid");

        // The sub-node stays on the previous version and snapshot.
        let (version, snapshot) = service.current().await.unwrap();
        assert_eq!(version, Some(5));
        assert_eq!(snapshot.unwrap()["filtering"]["marker"], "old");
        assert!(
            service.store.load(6).await.unwrap().is_none(),
            "the rejected version is never stored"
        );

        // The new snapshot was attempted, then the previous one was re-applied.
        {
            let applied = applied.lock().unwrap();
            assert_eq!(applied.len(), 2);
            assert_eq!(applied[0]["marker"], "new");
            assert_eq!(applied[1]["marker"], "old");
        }

        let rows = db.audit_list(10, 0).await.unwrap();
        assert_eq!(rows[0].action, "cluster.config.apply");
        assert_eq!(rows[0].result, "error");
        assert_eq!(
            rows[0].error_code.as_deref(),
            Some("filtering.config.invalid")
        );
        assert_eq!(rows[0].config_version, Some(5));
    }
}
