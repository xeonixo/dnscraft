//! `/api/v1/policy/records` (global local-record name space) and
//! `/api/v1/policy/client-ids` (Client-ID registry), both admin-only.
//!
//! Records are keyed by owner name and type: one entry per pair through this
//! API. Values use presentation text (`192.0.2.10`, `10 mail.example.com.`,
//! `1 5 5060 sip.example.com.`, a TXT string). Stored entries use the policy
//! crate's serde form. Client IDs are an admission registry, never a selection
//! key. Every write goes through the same config-apply path as `PUT /config`.

use std::collections::BTreeMap;

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use dnscraft_policy::{
    ClientId, DEFAULT_RECORD_TTL, ViewId, ViewRecordConfig, check_client_device,
    check_client_label, format_rdata, parse_record_type, record_type_text,
};
use dnscraft_proto::{Name, RData, RecordType};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    actor, array, array_mut, if_match, json_body, malformed_snapshot, module_error,
    relay_config_family_write, service, stored_snapshot, valid_id,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

/// Body of `POST|PUT /api/v1/policy/records`: one record (name + type).
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordBody {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
    #[serde(default)]
    ttl: Option<u32>,
    rdata: String,
    /// Per-view replacement values, keyed by view id.
    #[serde(default)]
    overrides: BTreeMap<String, String>,
}

/// Body of `DELETE /api/v1/policy/records`: the record key.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordKey {
    pub(crate) name: String,
    #[serde(rename = "type")]
    pub(crate) rtype: String,
}

/// Body of `POST /api/v1/policy/client-ids`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientIdBody {
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) label: Option<String>,
    #[serde(default)]
    pub(crate) device: Option<String>,
    /// Pinned view (an existing view id), selected for this Client ID when no
    /// subnet matches the source IP.
    #[serde(default)]
    pub(crate) view: Option<String>,
}

/// Requested change of `PUT /api/v1/policy/client-ids/{id}`. `None` leaves a
/// field as it is, `Some(None)` clears it.
#[derive(Default)]
pub(crate) struct ClientIdPatch {
    label: Option<Option<String>>,
    device: Option<Option<String>>,
    view: Option<Option<String>>,
}

/// `GET /api/v1/policy/records`.
pub(crate) async fn list_records(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let records: Vec<Value> = stored_records(&snapshot).iter().map(record_json).collect();
    Ok(success(json!({ "records": records })))
}

/// `POST|PUT /api/v1/policy/records` — create or replace the record `(name, type)`.
pub(crate) async fn put_record(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<RecordBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "policy.config.invalid")?;
    let relay_body = serde_json::to_value(&body).map_err(|err| invalid(&err.to_string()))?;
    if let Some(response) = relay_config_family_write(
        &state,
        "PUT",
        "/api/v1/policy/records",
        relay_body,
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let record = upsert_policy_record(&mut snapshot, body)?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "record": record })).into_response())
}

/// `DELETE /api/v1/policy/records` — remove the record `(name, type)`.
pub(crate) async fn delete_record(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<RecordKey>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(key) = body.map_err(|rejection| invalid(&rejection.body_text()))?;
    let relay_body = serde_json::to_value(&key).map_err(|err| invalid(&err.to_string()))?;
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        "/api/v1/policy/records",
        relay_body,
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let name = key.name.clone();
    let rtype = key.rtype.clone();
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    delete_policy_record(&mut snapshot, key)?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "deleted": true,
        "name": name,
        "type": rtype,
    }))
    .into_response())
}

/// `GET /api/v1/policy/client-ids` — the registry, in stored order. Bare-string
/// entries are shown as objects with `label` and `device` set to `null`.
pub(crate) async fn list_client_ids(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let ids: Vec<Value> = array(&snapshot, "policy", "client_ids")
        .iter()
        .filter_map(client_id_json)
        .collect();
    Ok(success(json!({ "client_ids": ids })))
}

/// `POST /api/v1/policy/client-ids` — register a Client ID.
pub(crate) async fn create_client_id(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ClientIdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "policy.config.invalid")?;
    let relay_body = serde_json::to_value(&body).map_err(|err| invalid(&err.to_string()))?;
    if let Some(response) = relay_config_family_write(
        &state,
        "POST",
        "/api/v1/policy/client-ids",
        relay_body,
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let id = body.id.clone();
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    register_client_id(&mut snapshot, body)?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "client_id": id })).into_response())
}

/// `PUT /api/v1/policy/client-ids/{id}` — change the label and/or device of a
/// registered Client ID. The id itself never changes.
pub(crate) async fn put_client_id(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Result<Json<Value>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(body) = body.map_err(|rejection| invalid(&rejection.body_text()))?;
    let patch = parse_client_patch(&body)?;
    let path = format!("/api/v1/policy/client-ids/{id}");
    if let Some(response) =
        relay_config_family_write(&state, "PUT", &path, body, auth.clone(), &headers).await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let client_id = update_client_id(&mut snapshot, &id, patch)?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "client_id": client_id })).into_response())
}

/// `DELETE /api/v1/policy/client-ids/{id}` — revoke a Client ID.
pub(crate) async fn delete_client_id(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let path = format!("/api/v1/policy/client-ids/{id}");
    if let Some(response) =
        relay_config_family_write(&state, "DELETE", &path, json!({}), auth.clone(), &headers)
            .await?
    {
        return Ok(response.into_response());
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    revoke_client_id(&mut snapshot, &id)?;
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "deleted": true, "id": id })).into_response())
}

/// A `policy.config.invalid` error with `reason`.
fn invalid(reason: &str) -> ControlApiError {
    module_error("policy.config.invalid", reason)
}

/// Inserts or replaces one local record in `snapshot`.
pub(crate) fn upsert_policy_record(
    snapshot: &mut Value,
    body: RecordBody,
) -> Result<Value, ControlApiError> {
    let record = build_record(body)?;
    let stored = serde_json::to_value(&record).map_err(|err| invalid(&err.to_string()))?;
    let items = array_mut(snapshot, "policy", "records")?;
    match items.iter().position(|item| same_key(item, &record)) {
        Some(index) => items[index] = stored,
        None => items.push(stored),
    }
    Ok(record_json(&record))
}

/// Removes one local record from `snapshot`.
pub(crate) fn delete_policy_record(
    snapshot: &mut Value,
    key: RecordKey,
) -> Result<(), ControlApiError> {
    let name = owner_name(&key.name)?;
    let rtype = parse_rtype(&key.rtype)?;
    let items = array_mut(snapshot, "policy", "records")?;
    let index = items
        .iter()
        .position(|item| {
            serde_json::from_value::<ViewRecordConfig>(item.clone())
                .is_ok_and(|rec| rec.name == name && rec.rtype() == rtype)
        })
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("record {} {}", key.name, key.rtype),
        })?;
    items.remove(index);
    Ok(())
}

/// Parts of one stored registry entry: a bare string or `{id, label?, device?}`.
fn entry_parts(item: &Value) -> Option<(&str, Option<&str>, Option<&str>)> {
    match item {
        Value::String(id) => Some((id, None, None)),
        Value::Object(object) => Some((
            object.get("id")?.as_str()?,
            object.get("label").and_then(Value::as_str),
            object.get("device").and_then(Value::as_str),
        )),
        _ => None,
    }
}

/// The pinned view of one stored entry, if it has one.
fn entry_view(item: &Value) -> Option<&str> {
    item.as_object()?.get("view")?.as_str()
}

/// API view of one stored entry: `{id, label, device, view}` with nulls for absent fields.
fn client_id_json(item: &Value) -> Option<Value> {
    let (id, label, device) = entry_parts(item)?;
    Some(json!({
        "id": id,
        "label": label,
        "device": device,
        "view": entry_view(item),
    }))
}

/// Stored form of an entry: a bare string when it has no metadata (so older
/// snapshots stay byte-identical), otherwise the object form without null keys.
fn stored_entry(id: &str, label: Option<&str>, device: Option<&str>, view: Option<&str>) -> Value {
    if label.is_none() && device.is_none() && view.is_none() {
        return Value::String(id.to_owned());
    }
    let mut object = json!({ "id": id });
    if let Some(label) = label {
        object["label"] = json!(label);
    }
    if let Some(device) = device {
        object["device"] = json!(device);
    }
    if let Some(view) = view {
        object["view"] = json!(view);
    }
    object
}

/// Whether `snapshot` defines a view with this id.
fn view_exists(snapshot: &Value, view: &str) -> bool {
    snapshot
        .get("policy")
        .and_then(|policy| policy.get("views"))
        .and_then(Value::as_array)
        .is_some_and(|views| {
            views
                .iter()
                .any(|item| item.get("id").and_then(Value::as_str) == Some(view))
        })
}

/// Trims an optional pinned-view id: blank becomes `None`; otherwise the view
/// must exist in `snapshot`.
fn clean_view(snapshot: &Value, text: Option<String>) -> Result<Option<String>, ControlApiError> {
    let Some(view) = text
        .map(|text| text.trim().to_owned())
        .filter(|v| !v.is_empty())
    else {
        return Ok(None);
    };
    if !view_exists(snapshot, &view) {
        return Err(invalid_field("view", "is not a defined view"));
    }
    Ok(Some(view))
}

/// Rejects deleting view `view` while Client IDs are pinned to it. The error
/// names the pinned Client IDs.
pub(crate) fn check_view_unpinned(snapshot: &Value, view: &str) -> Result<(), ControlApiError> {
    let client_ids: Vec<String> = array(snapshot, "policy", "client_ids")
        .iter()
        .filter(|item| entry_view(item) == Some(view))
        .filter_map(|item| entry_parts(item).map(|(id, _, _)| id.to_owned()))
        .collect();
    if client_ids.is_empty() {
        return Ok(());
    }
    Err(ControlApiError::Module {
        code: "policy.config.invalid",
        params: Some(json!({
            "reason": "view_in_use",
            "view": view,
            "client_ids": client_ids,
        })),
    })
}

/// A `policy.config.invalid` error whose `params` name the rejected field.
fn invalid_field(field: &str, reason: &str) -> ControlApiError {
    ControlApiError::Module {
        code: "policy.config.invalid",
        params: Some(json!({ "reason": format!("{field} {reason}"), "field": field })),
    }
}

/// Trims an optional text field: blank becomes `None`, otherwise `check` runs.
fn clean_meta(
    text: Option<String>,
    field: &str,
    check: fn(&str) -> Result<(), &'static str>,
) -> Result<Option<String>, ControlApiError> {
    let Some(text) = text else {
        return Ok(None);
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    check(trimmed).map_err(|reason| invalid_field(field, reason))?;
    Ok(Some(trimmed.to_owned()))
}

/// Rejects `label` if another registered Client ID already uses it
/// (case-insensitive).
fn check_unique_label(items: &[Value], own_id: &str, label: &str) -> Result<(), ControlApiError> {
    let wanted = label.to_lowercase();
    let taken = items.iter().any(|item| {
        entry_parts(item).is_some_and(|(id, other, _)| {
            id != own_id && other.is_some_and(|other| other.to_lowercase() == wanted)
        })
    });
    if taken {
        return Err(invalid_field(
            "label",
            "is already used by another client id",
        ));
    }
    Ok(())
}

/// Parses the `PUT` body: only `label`, `device` and `view` are accepted; each
/// is a string or `null`, and an absent key means "leave unchanged".
pub(crate) fn parse_client_patch(body: &Value) -> Result<ClientIdPatch, ControlApiError> {
    let object = body
        .as_object()
        .ok_or_else(|| invalid("client id update must be a JSON object"))?;
    if let Some(key) = object
        .keys()
        .find(|key| !matches!(key.as_str(), "label" | "device" | "view"))
    {
        return Err(invalid(&format!("unknown field {key}")));
    }
    let field = |name: &str| match object.get(name) {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(None)),
        Some(Value::String(text)) => Ok(Some(Some(text.clone()))),
        Some(_) => Err(invalid(&format!("{name} must be a string or null"))),
    };
    Ok(ClientIdPatch {
        label: field("label")?,
        device: field("device")?,
        view: field("view")?,
    })
}

/// Registers a Client ID (with optional label, device and pinned view) in `snapshot`.
pub(crate) fn register_client_id(
    snapshot: &mut Value,
    body: ClientIdBody,
) -> Result<(), ControlApiError> {
    if ClientId::new(&body.id).is_err() {
        return Err(invalid("client id must match [a-z0-9-]{1,63}"));
    }
    let label = clean_meta(body.label, "label", check_client_label)?;
    let device = clean_meta(body.device, "device", check_client_device)?;
    let view = clean_view(snapshot, body.view)?;
    let ids = array_mut(snapshot, "policy", "client_ids")?;
    if ids
        .iter()
        .any(|item| entry_parts(item).is_some_and(|(id, _, _)| id == body.id))
    {
        return Err(invalid("client id is already registered"));
    }
    if let Some(label) = &label {
        check_unique_label(ids, &body.id, label)?;
    }
    ids.push(stored_entry(
        &body.id,
        label.as_deref(),
        device.as_deref(),
        view.as_deref(),
    ));
    Ok(())
}

/// Changes the label, device and/or pinned view of registered Client ID `id`;
/// returns its API view.
pub(crate) fn update_client_id(
    snapshot: &mut Value,
    id: &str,
    patch: ClientIdPatch,
) -> Result<Value, ControlApiError> {
    let new_view = match patch.view {
        Some(value) => Some(clean_view(snapshot, value)?),
        None => None,
    };
    let ids = array_mut(snapshot, "policy", "client_ids")?;
    let index = ids
        .iter()
        .position(|item| entry_parts(item).is_some_and(|(entry, _, _)| entry == id))
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("client id {id}"),
        })?;
    let (_, current_label, current_device) =
        entry_parts(&ids[index]).ok_or_else(malformed_snapshot)?;
    let (current_label, current_device) = (
        current_label.map(str::to_owned),
        current_device.map(str::to_owned),
    );
    let label = match patch.label {
        Some(value) => clean_meta(value, "label", check_client_label)?,
        None => current_label,
    };
    let device = match patch.device {
        Some(value) => clean_meta(value, "device", check_client_device)?,
        None => current_device,
    };
    let view = match new_view {
        Some(view) => view,
        None => entry_view(&ids[index]).map(str::to_owned),
    };
    if let Some(label) = &label {
        check_unique_label(ids, id, label)?;
    }
    ids[index] = stored_entry(id, label.as_deref(), device.as_deref(), view.as_deref());
    client_id_json(&ids[index]).ok_or_else(malformed_snapshot)
}

/// Revokes a Client ID from `snapshot`.
pub(crate) fn revoke_client_id(snapshot: &mut Value, id: &str) -> Result<(), ControlApiError> {
    let ids = array_mut(snapshot, "policy", "client_ids")?;
    let index = ids
        .iter()
        .position(|item| entry_parts(item).is_some_and(|(entry, _, _)| entry == id))
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("client id {id}"),
        })?;
    ids.remove(index);
    Ok(())
}

/// Validates a record body and converts it to the policy model.
fn build_record(body: RecordBody) -> Result<ViewRecordConfig, ControlApiError> {
    let name = owner_name(&body.name)?;
    let rtype = parse_rtype(&body.rtype)?;
    let rdata = parse_rdata(rtype, &body.rdata)?;
    let mut overrides = BTreeMap::new();
    for (view, text) in &body.overrides {
        if !valid_id(view) {
            return Err(invalid(&format!("invalid override view id `{view}`")));
        }
        let view_id = ViewId::new(view).map_err(|_| invalid("invalid override view id"))?;
        overrides.insert(view_id, parse_rdata(rtype, text)?);
    }
    Ok(ViewRecordConfig {
        name,
        ttl: body.ttl.unwrap_or(DEFAULT_RECORD_TTL),
        rdata,
        overrides,
    })
}

/// Parses an owner name (letters, digits, `-`, `_` and `.` only). Wildcards
/// pass this check and are rejected by the policy build.
fn owner_name(text: &str) -> Result<Name, ControlApiError> {
    let allowed = text
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'*'));
    if !allowed {
        return Err(invalid("owner name has characters outside [a-z0-9_.-]"));
    }
    Name::from_ascii(&text.to_ascii_lowercase()).map_err(|err| invalid(&format!("{err}")))
}

/// The record types accepted for local records (SPEC-policy.md).
fn parse_rtype(text: &str) -> Result<RecordType, ControlApiError> {
    parse_record_type(text).ok_or_else(|| invalid("unsupported record type"))
}

/// Presentation text of the record type.
fn rtype_text(rtype: RecordType) -> &'static str {
    record_type_text(rtype)
}

/// Parses presentation text into record data of type `rtype`.
fn parse_rdata(rtype: RecordType, text: &str) -> Result<RData, ControlApiError> {
    dnscraft_policy::parse_rdata(rtype, text).map_err(|reason| invalid(&reason))
}

/// Presentation text of record data (inverse of [`parse_rdata`]).
fn rdata_text(rdata: &RData) -> String {
    format_rdata(rdata)
}

/// Stored records that decode as policy records (malformed entries are skipped).
fn stored_records(snapshot: &Value) -> Vec<ViewRecordConfig> {
    array(snapshot, "policy", "records")
        .into_iter()
        .filter_map(|item| serde_json::from_value(item).ok())
        .collect()
}

/// Whether a stored entry has the same owner name and type as `record`.
fn same_key(item: &Value, record: &ViewRecordConfig) -> bool {
    serde_json::from_value::<ViewRecordConfig>(item.clone())
        .is_ok_and(|stored| stored.name == record.name && stored.rtype() == record.rtype())
}

/// API view of one record: presentation text for the default and overrides.
fn record_json(record: &ViewRecordConfig) -> Value {
    let overrides: BTreeMap<String, String> = record
        .overrides
        .iter()
        .map(|(view, rdata)| (view.to_string(), rdata_text(rdata)))
        .collect();
    json!({
        "name": record.name.to_string(),
        "type": rtype_text(record.rtype()),
        "ttl": record.ttl,
        "rdata": rdata_text(&record.rdata),
        "overrides": overrides,
    })
}
