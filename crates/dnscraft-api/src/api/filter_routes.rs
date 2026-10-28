//! `/api/v1/filter-sets` and `/api/v1/filter-lists` CRUD.
//!
//! Filter sets and lists are ordinary versioned config: every mutation stores a
//! new `config_version`, applies the filtering section and is audited through
//! [`crate::ConfigService`]. Set/list id uniqueness and list references are
//! validated by the service's cross-module pass before any module apply.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use dnscraft_filtering::{ListStatus, ServiceCatalog};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    IdBody, actor, array, array_mut, if_match, json_body, module_error, relay_config_family_write,
    remove_by_id, service, stored_snapshot, upsert_by_id, valid_id,
};
use crate::api::response::{success, unix_rfc3339};
use crate::config_apply::{list_source_path_is_safe, list_source_url_is_safe};
use crate::error::ControlApiError;
use crate::mcp_backend::rfc3339;
use crate::server::AppState;

// ---------------------------------------------------------------------------
// Filter sets
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterSetBody {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    lists: Vec<String>,
    #[serde(default)]
    custom_rules: String,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    block_mode: Option<Value>,
    /// Omitted means "carry the stored rules over"; `[]` deletes them.
    #[serde(default)]
    mcp_rules: Option<Vec<Value>>,
}

impl FilterSetBody {
    pub(crate) fn into_json(self) -> Result<Value, ControlApiError> {
        if !valid_id(&self.id) {
            return Err(module_error(
                "filter_id.invalid_char",
                "filter set id must match [a-z0-9-]{1,64}",
            ));
        }
        if let Some(list) = self.lists.iter().find(|list| !valid_id(list)) {
            return Err(module_error(
                "filter_id.invalid_char",
                &format!("invalid list id `{list}`"),
            ));
        }
        if let Some(mode) = &self.block_mode
            && !valid_block_mode(mode)
        {
            return Err(module_error(
                "filtering.config.invalid",
                "block_mode must be refused, nxdomain, null_ip or a custom_ip object",
            ));
        }
        let mut value = json!({
            "id": self.id,
            "name": self.name,
            "lists": self.lists,
            "custom_rules": self.custom_rules,
            "services": self.services,
            "block_mode": self.block_mode.unwrap_or_else(|| json!("refused")),
        });
        // Omission must survive as an absent key so the mcp_rules merge treats
        // it as "carry over"; an explicit list is stored verbatim.
        if let Some(rules) = self.mcp_rules {
            value["mcp_rules"] = Value::Array(rules);
        }
        Ok(value)
    }
}

fn valid_block_mode(mode: &Value) -> bool {
    match mode {
        Value::String(mode) => matches!(mode.as_str(), "refused" | "nxdomain" | "null_ip"),
        Value::Object(map) => {
            map.contains_key("custom_ip")
                && map.keys().all(|key| key == "custom_ip" || key == "kind")
        }
        _ => false,
    }
}

/// `GET /api/v1/filter-sets`.
pub(crate) async fn list_filter_sets(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    Ok(success(json!({
        "filter_sets": array(&snapshot, "filtering", "sets"),
    })))
}

/// `POST|PUT /api/v1/filter-sets` — create or replace a set by id.
pub(crate) async fn put_filter_set(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<FilterSetBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let set = json_body(body, "filtering.config.invalid")?.into_json()?;
    let id = set["id"].as_str().unwrap_or_default().to_owned();
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/filter-sets",
        set.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let replaced = upsert_by_id(
        array_mut(&mut snapshot, "filtering", "sets")?,
        &id,
        set.clone(),
    );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "filter_set": set,
        "created": !replaced,
    }))
    .into_response())
}

/// `DELETE /api/v1/filter-sets` — body `{ "id": "..." }`.
pub(crate) async fn delete_filter_set(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "filtering.config.invalid")?;
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        "/api/v1/filter-sets",
        json!({ "id": body.id }),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    remove_by_id(array_mut(&mut snapshot, "filtering", "sets")?, &body.id).ok_or_else(|| {
        ControlApiError::NotFound {
            what: format!("filter set {}", body.id),
        }
    })?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": body.id })).into_response())
}

// ---------------------------------------------------------------------------
// Filter lists
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FilterListBody {
    id: String,
    #[serde(default)]
    name: String,
    source: Value,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

impl FilterListBody {
    pub(crate) fn into_json(self) -> Result<Value, ControlApiError> {
        if !valid_id(&self.id) {
            return Err(module_error(
                "filter_id.invalid_char",
                "filter list id must match [a-z0-9-]{1,64}",
            ));
        }
        validate_list_source(&self.source)?;
        Ok(json!({
            "id": self.id,
            "name": self.name,
            "source": self.source,
            "enabled": self.enabled,
        }))
    }
}

/// Validates `{ "url": "https://…" }` or `{ "file": "/path" }` (exactly one).
fn validate_list_source(source: &Value) -> Result<(), ControlApiError> {
    let Some(map) = source.as_object() else {
        return Err(module_error(
            "filter_store.invalid_source",
            "source must be an object",
        ));
    };
    if map.len() != 1 {
        return Err(module_error(
            "filter_store.invalid_source",
            "source must contain exactly one of `url` or `file`",
        ));
    }
    match map.get_key_value("url") {
        Some((_, Value::String(url))) if list_source_url_is_safe(url) => Ok(()),
        Some(_) => Err(module_error(
            "filter_store.invalid_source",
            "url must be an https:// URL whose host is not loopback/private",
        )),
        None => match map.get_key_value("file") {
            Some((_, Value::String(path))) if list_source_path_is_safe(path) => Ok(()),
            Some(_) => Err(module_error(
                "filter_store.invalid_source",
                "file must be a relative path without `..` components",
            )),
            None => Err(module_error(
                "filter_store.invalid_source",
                "source must contain `url` or `file`",
            )),
        },
    }
}

/// `GET /api/v1/filter-lists`.
pub(crate) async fn list_filter_lists(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let mut lists = array(&snapshot, "filtering", "lists");
    if let Some(engine) = state.filter_engine() {
        merge_list_status(&mut lists, &engine.list_status());
    }
    Ok(success(json!({ "filter_lists": lists })))
}

/// Adds a `status` object to each stored list that has engine status for its
/// id. Lists without status (disabled, never fetched) are left unchanged.
fn merge_list_status(lists: &mut [Value], statuses: &[ListStatus]) {
    for list in lists.iter_mut() {
        let Some(id) = list["id"].as_str() else {
            continue;
        };
        let Some(status) = statuses.iter().find(|s| s.id.as_str() == id) else {
            continue;
        };
        list["status"] = json!({
            "rules_parsed": status.rules_parsed,
            "rules_skipped": status.rules_skipped,
            "unique_contribution": status.unique_contribution,
            "last_success": status.last_success.map(rfc3339),
            "last_attempt": status.last_attempt.map(rfc3339),
            "error_code": status.error_code,
            "http_status": status.http_status,
        });
    }
}

/// `POST|PUT /api/v1/filter-lists` — create or replace a list by id.
pub(crate) async fn put_filter_list(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<FilterListBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let list = json_body(body, "filtering.config.invalid")?.into_json()?;
    let id = list["id"].as_str().unwrap_or_default().to_owned();
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/filter-lists",
        list.clone(),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let replaced = upsert_by_id(
        array_mut(&mut snapshot, "filtering", "lists")?,
        &id,
        list.clone(),
    );
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "filter_list": list,
        "created": !replaced,
    }))
    .into_response())
}

/// `DELETE /api/v1/filter-lists` — body `{ "id": "..." }`.
pub(crate) async fn delete_filter_list(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "filtering.config.invalid")?;
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        "/api/v1/filter-lists",
        json!({ "id": body.id }),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    remove_by_id(array_mut(&mut snapshot, "filtering", "lists")?, &body.id).ok_or_else(|| {
        ControlApiError::NotFound {
            what: format!("filter list {}", body.id),
        }
    })?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": body.id })).into_response())
}

// ---------------------------------------------------------------------------
// Blocked services (WP5)
// ---------------------------------------------------------------------------

/// Supplies the runtime blocked-services catalog to the control API (WP5).
///
/// The binary implements it over `dnscraft-filtering`. Without an
/// implementation, `GET /api/v1/filtering/services` reports `available: false`
/// and the toggle answers `filtering.catalog.unavailable`.
pub trait ServiceCatalogProvider: Send + Sync {
    /// The loaded catalog, if one is cached.
    fn catalog(&self) -> Option<Arc<ServiceCatalog>>;
    /// Unix seconds of the last successful catalog download.
    fn updated_at(&self) -> Option<u64>;
}

/// Query of `GET /api/v1/filtering/services`.
#[derive(Deserialize)]
pub(crate) struct ServicesQuery {
    locale: Option<String>,
}

/// `GET /api/v1/filtering/services?locale=de` — catalog with per-set state (viewer).
///
/// Icons are not returned: they are third-party SVG and no sanitizer exists yet.
pub(crate) async fn list_services(
    State(state): State<AppState>,
    Query(query): Query<ServicesQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    let locale = query
        .locale
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "en".to_owned());
    if locale.len() > 16
        || !locale
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(service_error(
            "filtering.service.invalid",
            "locale is malformed",
        ));
    }
    let Some(provider) = state.service_catalog() else {
        return Ok(success(unavailable(&locale, None)));
    };
    let Some(catalog) = provider.catalog() else {
        return Ok(success(unavailable(&locale, None)));
    };
    let snapshot = stored_snapshot(service(&state)?).await?;
    let sets = array(&snapshot, "filtering", "sets");
    let items: Vec<Value> = catalog
        .services()
        .iter()
        .map(|info| {
            let enabled: serde_json::Map<String, Value> = sets
                .iter()
                .filter_map(|set| {
                    let id = set.get("id")?.as_str()?;
                    let on = set
                        .get("services")
                        .and_then(Value::as_array)
                        .is_some_and(|list| list.iter().any(|s| s.as_str() == Some(&*info.id)));
                    Some((id.to_owned(), Value::Bool(on)))
                })
                .collect();
            json!({
                "id": &*info.id,
                "name": catalog.translated_name(&info.id, &locale).unwrap_or(&info.name),
                "group": catalog.translated_group(&info.group, &locale),
                "group_id": info.group,
                "enabled": enabled,
            })
        })
        .collect();
    Ok(success(json!({
        "available": true,
        "catalog_updated_at": provider.updated_at().map(|t| unix_rfc3339(i64::try_from(t).unwrap_or(i64::MAX))),
        "locale": locale,
        "items": items,
    })))
}

/// Body of `PUT /api/v1/filtering/services/{service_id}`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ServiceToggleBody {
    filter_set_id: String,
    enabled: bool,
}

/// `PUT /api/v1/filtering/services/{service_id}` — block or allow a service in one
/// filter set (admin). The toggle is versioned config like any set edit.
pub(crate) async fn put_service(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(service_id): Path<String>,
    body: Result<Json<ServiceToggleBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "filtering.service.invalid")?;
    if !valid_id(&service_id) || !valid_id(&body.filter_set_id) {
        return Err(service_error(
            "filtering.service.invalid",
            "id is malformed",
        ));
    }
    let catalog = state
        .service_catalog()
        .and_then(|provider| provider.catalog())
        .ok_or_else(|| service_error("filtering.catalog.unavailable", "no services catalog"))?;
    if catalog.get(&service_id).is_none() {
        return Err(service_error(
            "filtering.service.unknown",
            "unknown service id",
        ));
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let set = array_mut(&mut snapshot, "filtering", "sets")?
        .iter_mut()
        .find(|set| set.get("id").and_then(Value::as_str) == Some(body.filter_set_id.as_str()))
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("filter set {}", body.filter_set_id),
        })?;
    let list = set
        .as_object_mut()
        .ok_or_else(|| service_error("filtering.config.invalid", "filter set is not an object"))?
        .entry("services")
        .or_insert_with(|| json!([]));
    let list = list
        .as_array_mut()
        .ok_or_else(|| service_error("filtering.config.invalid", "services is not a list"))?;
    list.retain(|id| id.as_str() != Some(service_id.as_str()));
    if body.enabled {
        list.push(json!(service_id));
    }
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "service_id": service_id,
        "filter_set_id": body.filter_set_id,
        "enabled": body.enabled,
    })))
}

/// The `available: false` answer, with the configured locale echoed back.
fn unavailable(locale: &str, updated: Option<u64>) -> Value {
    json!({
        "available": false,
        "catalog_updated_at": updated.map(|t| unix_rfc3339(i64::try_from(t).unwrap_or(i64::MAX))),
        "locale": locale,
        "items": [],
    })
}

/// A module-coded error (HTTP 400) for the blocked-services routes.
fn service_error(code: &'static str, reason: &str) -> ControlApiError {
    module_error(code, reason)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::{Duration, SystemTime};

    use dnscraft_filtering::{ListId, ListStatus, SkipCounts};
    use serde_json::json;

    use super::merge_list_status;

    #[test]
    fn merge_adds_status_only_to_lists_with_engine_status() {
        let mut lists = vec![
            json!({ "id": "ads", "name": "Ads", "enabled": true }),
            json!({ "id": "never", "name": "Never", "enabled": false }),
        ];
        let statuses = vec![ListStatus {
            id: ListId::new("ads").unwrap(),
            last_attempt: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_100)),
            last_success: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
            error_code: Some("filter_list.fetch_failed".to_owned()),
            http_status: Some(503),
            rules_parsed: 41_230,
            rules_skipped: 7,
            skipped_by_reason: SkipCounts::default(),
            unique_contribution: 1_200,
        }];

        merge_list_status(&mut lists, &statuses);

        assert_eq!(lists[0]["name"], "Ads");
        assert_eq!(lists[0]["status"]["rules_parsed"], 41_230);
        assert_eq!(lists[0]["status"]["rules_skipped"], 7);
        assert_eq!(lists[0]["status"]["unique_contribution"], 1_200);
        assert_eq!(lists[0]["status"]["last_success"], "2023-11-14T22:13:20Z");
        assert_eq!(lists[0]["status"]["last_attempt"], "2023-11-14T22:15:00Z");
        assert_eq!(lists[0]["status"]["error_code"], "filter_list.fetch_failed");
        assert_eq!(lists[0]["status"]["http_status"], 503);
        assert!(lists[1].get("status").is_none());
    }
}
