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

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::audit::{Audit, ConfigChangeRecord};
use crate::error::ControlApiError;
use crate::modules::ModuleAppliers;
use crate::storage::ConfigStore;

/// The fixed leaf-first apply order.
const APPLY_ORDER: [&str; 5] = ["filtering", "clients", "policy", "listeners", "tls"];

/// Top-level sections a snapshot may contain. `resolver` is carried for
/// cross-module validation only (forward-zone ids); it is not applied here.
const TOP_LEVEL_KEYS: [&str; 6] = [
    "filtering",
    "clients",
    "policy",
    "listeners",
    "tls",
    "resolver",
];

/// Sections every config replace must provide.
const REQUIRED_SECTIONS: [&str; 5] = ["filtering", "clients", "policy", "listeners", "tls"];

/// Fields accepted inside one `filtering.sets[]` entry.
const FILTER_SET_KEYS: [&str; 8] = [
    "id",
    "name",
    "lists",
    "custom_rules",
    "services",
    "block_mode",
    "paused_until",
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

/// The actor performing a config change (from the authenticated principal).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigActor {
    /// User or token identifier.
    pub actor_id: String,
    /// `user` or `token`.
    pub actor_type: String,
}

impl ConfigActor {
    /// Builds an actor from raw fields.
    pub fn new(actor_id: impl Into<String>, actor_type: impl Into<String>) -> Self {
        Self {
            actor_id: actor_id.into(),
            actor_type: actor_type.into(),
        }
    }

    /// The actor used when the API is embedded without authentication.
    pub fn local() -> Self {
        Self::new("local", "user")
    }
}

/// Result of a rollback: the newly created version and the restored source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RollbackOutcome {
    /// Newly stored version (rollback always creates a new row).
    pub version: i64,
    /// Version whose snapshot was restored.
    pub restored_from: i64,
}

/// The atomic config service shared by every config route.
pub struct ConfigService {
    store: ConfigStore,
    audit: Audit,
    modules: ModuleAppliers,
    node_id: String,
    apply_lock: tokio::sync::Mutex<()>,
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
        }
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

    /// Lists stored versions newest first.
    pub async fn versions(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<(i64, i64)>, ControlApiError> {
        self.store.versions(limit, offset).await
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
        self.commit(actor, action, current_version, previous.as_ref(), &snapshot)
            .await
            .map(Some)
    }

    /// Shared validate → apply → store → audit path used by [`Self::replace`]
    /// and [`Self::mutate`].
    async fn commit(
        &self,
        actor: &ConfigActor,
        action: &str,
        previous_version: Option<i64>,
        previous: Option<&Value>,
        snapshot: &Value,
    ) -> Result<i64, ControlApiError> {
        if let Err(err) = validate_cross_module(snapshot) {
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
            return Err(err);
        }
        if let Err(err) = self.validate_modules(snapshot) {
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
            return Err(err);
        }
        if let Err(err) = self.apply_with_replay(snapshot, previous).await {
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
            return Err(err);
        }

        let version = self.store.store(snapshot).await?;
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
    async fn apply_with_replay(
        &self,
        snapshot: &Value,
        previous: Option<&Value>,
    ) -> Result<(), ControlApiError> {
        let (failed, error) = match self.apply_all(snapshot, usize::MAX).await {
            Ok(()) => return Ok(()),
            Err(failure) => failure,
        };
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
            node_id: self.node_id.clone(),
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

/// Convenience alias so callers can build the service from an `Arc`.
pub type SharedConfigService = Arc<ConfigService>;
