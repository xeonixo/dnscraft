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
    ClientId, DEFAULT_RECORD_TTL, ViewId, ViewRecordConfig, format_rdata, parse_record_type,
    record_type_text,
};
use dnscraft_proto::{Name, RData, RecordType};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{
    actor, array, array_mut, if_match, json_body, module_error, service, stored_snapshot, valid_id,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

/// Body of `POST|PUT /api/v1/policy/records`: one record (name + type).
#[derive(Deserialize)]
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecordKey {
    name: String,
    #[serde(rename = "type")]
    rtype: String,
}

/// Body of `POST /api/v1/policy/client-ids`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientIdBody {
    id: String,
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
    let record = build_record(json_body(body, "policy.config.invalid")?)?;
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let stored = serde_json::to_value(&record).map_err(|err| invalid(&err.to_string()))?;
    let items = array_mut(&mut snapshot, "policy", "records")?;
    match items.iter().position(|item| same_key(item, &record)) {
        Some(index) => items[index] = stored,
        None => items.push(stored),
    }
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(
        json!({ "version": version, "record": record_json(&record) }),
    ))
}

/// `DELETE /api/v1/policy/records` — remove the record `(name, type)`.
pub(crate) async fn delete_record(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<RecordKey>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let Json(key) = body.map_err(|rejection| invalid(&rejection.body_text()))?;
    let name = owner_name(&key.name)?;
    let rtype = parse_rtype(&key.rtype)?;
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let items = array_mut(&mut snapshot, "policy", "records")?;
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
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({
        "version": version,
        "deleted": true,
        "name": key.name,
        "type": key.rtype,
    })))
}

/// `GET /api/v1/policy/client-ids` — the registry, in stored order.
pub(crate) async fn list_client_ids(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let snapshot = stored_snapshot(service(&state)?).await?;
    let ids = array(&snapshot, "policy", "client_ids");
    Ok(success(json!({ "client_ids": ids })))
}

/// `POST /api/v1/policy/client-ids` — register a Client ID.
pub(crate) async fn create_client_id(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<ClientIdBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let id = json_body(body, "policy.config.invalid")?.id;
    if ClientId::new(&id).is_err() {
        return Err(invalid("client id must match [a-z0-9-]{1,63}"));
    }
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let ids = array_mut(&mut snapshot, "policy", "client_ids")?;
    if ids.iter().any(|item| item.as_str() == Some(id.as_str())) {
        return Err(invalid("client id is already registered"));
    }
    ids.push(Value::String(id.clone()));
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(json!({ "version": version, "client_id": id })))
}

/// `DELETE /api/v1/policy/client-ids/{id}` — revoke a Client ID.
pub(crate) async fn delete_client_id(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let service = service(&state)?;
    let mut snapshot = stored_snapshot(service).await?;
    let ids = array_mut(&mut snapshot, "policy", "client_ids")?;
    let index = ids
        .iter()
        .position(|item| item.as_str() == Some(id.as_str()))
        .ok_or_else(|| ControlApiError::NotFound {
            what: format!("client id {id}"),
        })?;
    ids.remove(index);
    let version = service
        .replace(snapshot, &actor(auth), if_match(&headers))
        .await?;
    Ok(success(
        json!({ "version": version, "deleted": true, "id": id }),
    ))
}

/// A `policy.config.invalid` error with `reason`.
fn invalid(reason: &str) -> ControlApiError {
    module_error("policy.config.invalid", reason)
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
