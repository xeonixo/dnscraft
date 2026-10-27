//! `/api/v1/filter-sets` and `/api/v1/filter-lists` CRUD.
//!
//! Filter sets and lists are ordinary versioned config: every mutation stores a
//! new `config_version`, applies the filtering section and is audited through
//! [`crate::ConfigService`]. Set/list id uniqueness and list references are
//! validated by the service's cross-module pass before any module apply.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::extract::rejection::JsonRejection;
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    IdBody, actor, array, array_mut, if_match, json_body, module_error, remove_by_id, service,
    stored_snapshot, upsert_by_id, valid_id,
};
use crate::api::response::success;
use crate::config_apply::{list_source_path_is_safe, list_source_url_is_safe};
use crate::error::ControlApiError;
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
    #[serde(default)]
    paused_until: Option<String>,
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
            "paused_until": self.paused_until,
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
    })))
}

/// `DELETE /api/v1/filter-sets` — body `{ "id": "..." }`.
pub(crate) async fn delete_filter_set(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "filtering.config.invalid")?;
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
    Ok(success(
        json!({ "version": version, "deleted": true, "id": body.id }),
    ))
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
    Ok(success(json!({
        "filter_lists": array(&snapshot, "filtering", "lists"),
    })))
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
    })))
}

/// `DELETE /api/v1/filter-lists` — body `{ "id": "..." }`.
pub(crate) async fn delete_filter_list(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<IdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "filtering.config.invalid")?;
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
    Ok(success(
        json!({ "version": version, "deleted": true, "id": body.id }),
    ))
}
