//! `/api/v1/config` routes plus the policy views/profiles/pause resources.
//!
//! All handlers delegate to [`crate::ConfigService`]; they only translate HTTP
//! concerns (auth extension, `If-Match`, pagination, envelope) into service
//! calls. RBAC already restricts non-GET requests to `admin`.
//!
//! Per-module handlers mutate one section of the versioned snapshot and call
//! the same atomic replace path, so cross-module validation and apply ordering
//! are identical to a full `PUT /config`.

use std::net::IpAddr;

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::http::header::IF_MATCH;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::pagination::{Pagination, RawPagination};
use crate::api::response::{success, unix_rfc3339};
use crate::cluster_write_relay::relay_config_write_if_sub_node;
use crate::config_apply::ConfigActor;
use crate::config_apply::ConfigService;
use crate::error::ControlApiError;
use crate::server::AppState;

/// The actor for this request; falls back to the embedded `local` actor when the
/// API runs without authentication configured.
pub(crate) fn actor(auth: Option<Extension<Authenticated>>) -> ConfigActor {
    match auth {
        Some(Extension(auth)) => ConfigActor::new(auth.actor_id(), auth.actor_type().as_str()),
        None => ConfigActor::local(),
    }
}

/// The configured service, or an internal error if the route was mounted
/// without one (the router only mounts these routes when a service exists).
pub(crate) fn service(state: &AppState) -> Result<&ConfigService, ControlApiError> {
    state
        .config_service()
        .ok_or_else(|| ControlApiError::Internal {
            message: "config service is not configured".to_owned(),
        })
}

/// Parses an `If-Match` header value, if present and representable as UTF-8.
pub(crate) fn if_match(headers: &HeaderMap) -> Option<&str> {
    headers.get(IF_MATCH).and_then(|value| value.to_str().ok())
}

/// Forwards a versioned config-family write to the cluster master on sub-nodes.
///
/// Returns `Some(response)` when the request was relayed or queued; `None` on
/// master/standalone so the handler can apply locally.
pub(crate) async fn relay_config_family_write(
    state: &AppState,
    method: &str,
    path: &str,
    body: Value,
    auth: Option<Extension<Authenticated>>,
    headers: &HeaderMap,
) -> Result<Option<Response>, ControlApiError> {
    relay_config_write_if_sub_node(
        state,
        method,
        path,
        body,
        &actor(auth.clone()),
        auth.as_ref().map(|Extension(auth)| auth),
        headers,
    )
    .await
}

/// Body carrying a single resource id (`{ "id": "..." }`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdBody {
    pub(crate) id: String,
}

/// The snapshot mutations start from: the stored one, or five empty sections.
pub(crate) fn default_snapshot() -> Value {
    json!({
        "filtering": {},
        "clients": {},
        "policy": {},
        "listeners": {},
        "tls": {},
    })
}

/// Loads the current stored snapshot, or the empty default on a fresh install.
pub(crate) async fn stored_snapshot(service: &ConfigService) -> Result<Value, ControlApiError> {
    Ok(service.current().await?.1.unwrap_or_else(default_snapshot))
}

/// A per-module error with the module's own stable code.
pub(crate) fn module_error(code: &'static str, reason: &str) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(json!({ "reason": reason })),
    }
}

/// Parses a JSON body, mapping malformed input to a module's stable code.
pub(crate) fn json_body<T: DeserializeOwned>(
    body: Result<Json<T>, JsonRejection>,
    code: &'static str,
) -> Result<T, ControlApiError> {
    body.map(|Json(value)| value)
        .map_err(|rejection| module_error(code, &rejection.body_text()))
}

/// Mutable section array, creating it when absent.
pub(crate) fn array_mut<'a>(
    snapshot: &'a mut Value,
    section: &str,
    key: &str,
) -> Result<&'a mut Vec<Value>, ControlApiError> {
    let section = snapshot
        .get_mut(section)
        .and_then(Value::as_object_mut)
        .ok_or_else(malformed_snapshot)?;
    let entry = section
        .entry(key.to_owned())
        .or_insert_with(|| Value::Array(Vec::new()));
    entry.as_array_mut().ok_or_else(malformed_snapshot)
}

/// Copies a section array (empty when absent).
pub(crate) fn array(snapshot: &Value, section: &str, key: &str) -> Vec<Value> {
    snapshot
        .get(section)
        .and_then(|section| section.get(key))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Inserts or replaces an entry by its `id`; returns whether it replaced one.
pub(crate) fn upsert_by_id(items: &mut Vec<Value>, id: &str, value: Value) -> bool {
    if let Some(existing) = items
        .iter_mut()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(id))
    {
        *existing = value;
        true
    } else {
        items.push(value);
        false
    }
}

/// Removes and returns the entry with `id`, if present.
pub(crate) fn remove_by_id(items: &mut Vec<Value>, id: &str) -> Option<Value> {
    let index = items
        .iter()
        .position(|item| item.get("id").and_then(Value::as_str) == Some(id))?;
    Some(items.remove(index))
}

/// Whether `id` matches the module id charset `[a-z0-9-]{1,64}`.
pub(crate) fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Whether `value` is a syntactically valid IPv4/IPv6 address or CIDR.
pub(crate) fn valid_ip_or_cidr(value: &str) -> bool {
    if value.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((address, prefix)) = value.split_once('/') else {
        return false;
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    prefix <= if address.is_ipv4() { 32 } else { 128 }
}

/// A stored snapshot that cannot be interpreted (never created by this code).
fn malformed_snapshot() -> ControlApiError {
    ControlApiError::Internal {
        message: "stored config snapshot is malformed".to_owned(),
    }
}

/// `GET /api/v1/config` — current version plus the stored snapshot.
///
/// Snapshots are redacted when stored, so secrets are never returned.
pub(crate) async fn get_config(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let (version, config) = service(&state)?.current().await.map_err(read_error)?;
    Ok(success(json!({
        "version": version,
        "config": config,
    })))
}

/// `PUT /api/v1/config` — validate, apply atomically, store a new version.
pub(crate) async fn put_config(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) = body.map_err(|rejection| ControlApiError::ConfigInvalid {
        reason: rejection.body_text(),
    })?;
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/config",
        body.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let version = service(&state)?
        .replace(body, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version })).into_response())
}

/// `POST /api/v1/config/validate` — dry run of `PUT /api/v1/config`.
///
/// Rejections come back as data with HTTP 200; nothing is stored, applied or
/// audited. Only a malformed JSON body is a 400.
pub(crate) async fn validate_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) = body.map_err(|rejection| ControlApiError::ConfigInvalid {
        reason: rejection.body_text(),
    })?;
    let outcome = service(&state)?.validate(body, if_match(&headers)).await?;
    let errors: Vec<Value> = outcome.errors.iter().map(error_entry).collect();
    Ok(success(json!({
        "valid": errors.is_empty(),
        "config_version": outcome.config_version,
        "errors": errors,
        "warnings": [],
        "diff": outcome.diff,
    })))
}

/// One `{ code, path, params }` entry; `path` is taken from the error's params
/// when the module supplies one.
fn error_entry(err: &ControlApiError) -> Value {
    let params = err.params();
    let path = params
        .as_ref()
        .and_then(|params| params.get("path"))
        .cloned()
        .unwrap_or(Value::Null);
    json!({ "code": err.code(), "path": path, "params": params })
}

/// `GET /api/v1/config/versions` — newest first, paginated.
pub(crate) async fn list_versions(
    State(state): State<AppState>,
    query: Query<RawPagination>,
) -> Result<impl IntoResponse, ControlApiError> {
    let page = Pagination::from_query(query)?;
    let service = service(&state)?;
    let current_version = service.current().await.map_err(read_error)?.0;
    // Fetch one extra row to expose `has_more` without a second query.
    let mut rows = service
        .versions(page.limit + 1, page.offset)
        .await
        .map_err(read_error)?;
    let fetched = rows.len();
    let has_more = page.has_more(fetched);
    let next_offset = page.next_offset(fetched);
    rows.truncate(page.limit as usize);
    let versions: Vec<Value> = rows
        .into_iter()
        .map(|(version, created_at)| {
            json!({ "version": version, "created_at": unix_rfc3339(created_at) })
        })
        .collect();
    Ok(success(json!({
        "current_version": current_version,
        "versions": versions,
        "has_more": has_more,
        "next_offset": next_offset,
    })))
}

/// `POST /api/v1/config/versions/{version}/rollback` — restore a stored version.
pub(crate) async fn rollback(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(version): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let target = version
        .parse::<u64>()
        .map_err(|_| ControlApiError::ConfigUnknownVersion { version: 0 })?;
    if let Some(response) = relay_config_family_write(
        &state,
        "POST",
        &format!("/api/v1/config/versions/{target}/rollback"),
        json!({}),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let outcome = service(&state)?
        .rollback(target, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": outcome.version,
        "restored_from": outcome.restored_from,
    }))
    .into_response())
}

/// Maps a read failure to the documented `control_api.config.read` code.
fn read_error(err: ControlApiError) -> ControlApiError {
    ControlApiError::ConfigRead {
        message: err.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Policy views
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ViewBody {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    is_default: bool,
    #[serde(default)]
    subnets: Vec<String>,
    /// Nodes the view exists on; empty means every node.
    #[serde(default)]
    nodes: Vec<String>,
    profile: String,
}

impl ViewBody {
    pub(crate) fn into_json(self, path_id: &str) -> Result<Value, ControlApiError> {
        if let Some(body_id) = &self.id
            && body_id != path_id
        {
            return Err(module_error(
                "policy.config.invalid",
                "body id does not match the path id",
            ));
        }
        if !valid_id(path_id) {
            return Err(module_error(
                "policy.config.invalid",
                "view id must match [a-z0-9-]{1,64}",
            ));
        }
        if self.profile.is_empty() {
            return Err(module_error(
                "policy.config.invalid",
                "view profile must not be empty",
            ));
        }
        if let Some(subnet) = self.subnets.iter().find(|s| !valid_ip_or_cidr(s)) {
            return Err(module_error(
                "policy.config.invalid",
                &format!("invalid view subnet `{subnet}`"),
            ));
        }
        if let Some(node) = self.nodes.iter().find(|n| !valid_id(n)) {
            return Err(module_error(
                "policy.config.invalid",
                &format!("invalid view node `{node}`"),
            ));
        }
        if self.is_default && !self.nodes.is_empty() {
            return Err(module_error(
                "policy.config.invalid",
                "the default view must not restrict nodes",
            ));
        }
        Ok(json!({
            "id": path_id,
            "is_default": self.is_default,
            "subnets": self.subnets,
            "nodes": self.nodes,
            "profile": self.profile,
        }))
    }
}

/// `GET /api/v1/policy/views`.
pub(crate) async fn list_views(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(
        json!({ "views": array(&snapshot, "policy", "views") }),
    ))
}

/// `GET /api/v1/policy/views/{id}`.
pub(crate) async fn get_view(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let view = find_by_id(&array(&snapshot, "policy", "views"), &id)?;
    Ok(success(json!({ "view": view })))
}

/// `POST|PUT /api/v1/policy/views/{id}` — create or replace a view.
pub(crate) async fn put_view(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<ViewBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let view = json_body(body, "policy.config.invalid")?.into_json(&id)?;
    let path = format!("/api/v1/policy/views/{id}");
    if let Some(response) =
        relay_config_family_write(&state, "PUT", &path, view.clone(), auth.clone(), &headers)
            .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    upsert_by_id(
        array_mut(&mut snapshot, "policy", "views")?,
        &id,
        view.clone(),
    );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "view": view })).into_response())
}

/// `DELETE /api/v1/policy/views/{id}`.
pub(crate) async fn delete_view(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let path = format!("/api/v1/policy/views/{id}");
    if let Some(response) =
        relay_config_family_write(&state, "DELETE", &path, json!({}), auth.clone(), &headers)
            .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    remove_by_id(array_mut(&mut snapshot, "policy", "views")?, &id).ok_or_else(|| {
        ControlApiError::NotFound {
            what: format!("view {id}"),
        }
    })?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": id })).into_response())
}

// ---------------------------------------------------------------------------
// Policy profiles
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProfileBody {
    #[serde(default)]
    id: Option<String>,
    filter_set: String,
    #[serde(default)]
    suppress_aaaa: bool,
    #[serde(default)]
    firefox_canary: bool,
    #[serde(default)]
    icloud_private_relay: bool,
    #[serde(default)]
    rebind: Option<bool>,
    #[serde(default)]
    rebind_exceptions: Vec<String>,
    #[serde(default)]
    forward_zones: Option<Vec<String>>,
    #[serde(default)]
    safesearch: Option<Value>,
    #[serde(default)]
    schedules: Vec<Value>,
}

impl ProfileBody {
    pub(crate) fn into_json(self, path_id: &str) -> Result<Value, ControlApiError> {
        if let Some(body_id) = &self.id
            && body_id != path_id
        {
            return Err(module_error(
                "policy.config.invalid",
                "body id does not match the path id",
            ));
        }
        if !valid_id(path_id) {
            return Err(module_error(
                "policy.config.invalid",
                "profile id must match [a-z0-9-]{1,64}",
            ));
        }
        if !valid_id(&self.filter_set) {
            return Err(module_error(
                "policy.config.invalid",
                "filter_set must match [a-z0-9-]{1,64}",
            ));
        }
        if let Some(zone) = self
            .forward_zones
            .as_ref()
            .and_then(|zones| zones.iter().find(|zone| !valid_id(zone)))
        {
            return Err(module_error(
                "policy.config.invalid",
                &format!("invalid forward zone id `{zone}`"),
            ));
        }
        if let Some(pattern) = self
            .rebind_exceptions
            .iter()
            .find(|pattern| pattern.is_empty())
        {
            return Err(module_error(
                "policy.config.invalid",
                &format!("invalid rebind exception `{pattern}`"),
            ));
        }
        Ok(json!({
            "id": path_id,
            "filter_set": self.filter_set,
            "suppress_aaaa": self.suppress_aaaa,
            "firefox_canary": self.firefox_canary,
            "icloud_private_relay": self.icloud_private_relay,
            "rebind": self.rebind,
            "rebind_exceptions": self.rebind_exceptions,
            "forward_zones": self.forward_zones,
            "safesearch": self.safesearch,
            "schedules": self.schedules,
        }))
    }
}

/// `GET /api/v1/policy/profiles/{id}`.
pub(crate) async fn get_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let profile = find_by_id(&array(&snapshot, "policy", "profiles"), &id)?;
    Ok(success(json!({ "profile": profile })))
}

/// `POST|PUT /api/v1/policy/profiles/{id}` — create or replace a profile.
pub(crate) async fn put_profile(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<ProfileBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let profile = json_body(body, "policy.config.invalid")?.into_json(&id)?;
    let path = format!("/api/v1/policy/profiles/{id}");
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        &path,
        profile.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    upsert_by_id(
        array_mut(&mut snapshot, "policy", "profiles")?,
        &id,
        profile.clone(),
    );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "profile": profile })).into_response())
}

/// `DELETE /api/v1/policy/profiles/{id}`.
pub(crate) async fn delete_profile(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let path = format!("/api/v1/policy/profiles/{id}");
    if let Some(response) =
        relay_config_family_write(&state, "DELETE", &path, json!({}), auth.clone(), &headers)
            .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    remove_by_id(array_mut(&mut snapshot, "policy", "profiles")?, &id).ok_or_else(|| {
        ControlApiError::NotFound {
            what: format!("profile {id}"),
        }
    })?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": id })).into_response())
}

// ---------------------------------------------------------------------------
// Policy pause (singleton)
// ---------------------------------------------------------------------------

/// `GET /api/v1/policy/pause`.
pub(crate) async fn get_pause(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let pause = snapshot
        .get("policy")
        .and_then(|policy| policy.get("pause"))
        .cloned();
    Ok(success(json!({ "pause": pause })))
}

/// `POST|PUT /api/v1/policy/pause` — store the pause state object.
pub(crate) async fn put_pause(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let pause = json_body(body, "policy.config.invalid")?;
    if !pause.is_object() {
        return Err(module_error(
            "policy.config.invalid",
            "pause state must be a JSON object",
        ));
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let policy = snapshot
        .get_mut("policy")
        .and_then(Value::as_object_mut)
        .ok_or_else(malformed_snapshot)?;
    policy.insert("pause".to_owned(), pause.clone());
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "pause": pause })))
}

/// `DELETE /api/v1/policy/pause`.
pub(crate) async fn delete_pause(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ControlApiError> {
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let policy = snapshot
        .get_mut("policy")
        .and_then(Value::as_object_mut)
        .ok_or_else(malformed_snapshot)?;
    let removed = policy.remove("pause").is_some();
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": removed })))
}

/// Finds an entry by `id`, returning `404` when absent.
fn find_by_id(items: &[Value], id: &str) -> Result<Value, ControlApiError> {
    items
        .iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(id))
        .cloned()
        .ok_or_else(|| ControlApiError::NotFound {
            what: id.to_owned(),
        })
}
