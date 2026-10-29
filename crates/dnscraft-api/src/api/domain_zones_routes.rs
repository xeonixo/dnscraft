//! `/api/v1/domain-zones` — Split-DNS Namen Cloudflare inventory + write path.
//!
//! Viewer-readable GETs surface attached Domain-Zonen and paginated DNS records
//! through the TLS engine's Cloudflare client. Missing token →
//! `tls.secret.missing` so the UI can offer a CTA to `PUT /tls/cloudflare-token`.
//! Discover (`?discover=1`) is admin-only.
//!
//! Admin writes: create/update/delete records on an attached zone (all hold
//! `CloudflareClient::write_guard`), and attach/detach apexes in
//! `dns_provider.zones`. Detach never deletes the Cloudflare zone.

use std::sync::Arc;

use axum::Extension;
use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::{Authenticated, Scope};
use crate::api::config_routes::{
    actor, if_match, json_body, relay_config_family_write, service, stored_snapshot,
};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::tls::TlsAdmin;

const DEFAULT_PAGE: u32 = 1;
const DEFAULT_PER_PAGE: u32 = 50;
const MAX_PER_PAGE: u32 = 100;

/// Query for `GET /api/v1/domain-zones`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListDomainZonesQuery {
    /// When truthy (`1` / `true`), include the token's discoverable zone list.
    /// Admin-only; requires a Cloudflare token.
    #[serde(default)]
    discover: Option<String>,
}

/// Query for `GET /api/v1/domain-zones/{zone_id}/records`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct ListDomainZoneRecordsQuery {
    page: Option<u32>,
    per_page: Option<u32>,
    name_substr: Option<String>,
}

/// Body of `POST /api/v1/domain-zones/attach`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachDomainZoneBody {
    /// Zone apex (e.g. `example.org`).
    name: String,
    /// Optional Cloudflare zone id; resolved by name when omitted.
    #[serde(default)]
    zone_id: Option<String>,
}

/// Body of `POST /api/v1/domain-zones/{zone_id}/records`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreateDomainZoneRecordBody {
    name: String,
    #[serde(alias = "record_type")]
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    proxied: Option<bool>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
}

/// Body of `PUT /api/v1/domain-zones/{zone_id}/records`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateDomainZoneRecordBody {
    /// Cloudflare record id to update.
    id: String,
    name: String,
    #[serde(alias = "record_type")]
    #[serde(rename = "type")]
    record_type: String,
    content: String,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    proxied: Option<bool>,
    #[serde(default)]
    priority: Option<u16>,
    #[serde(default)]
    weight: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
}

/// Body of `DELETE /api/v1/domain-zones/{zone_id}/records`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeleteDomainZoneRecordBody {
    /// Cloudflare record id to delete.
    id: String,
}

/// `GET /api/v1/domain-zones`.
pub(crate) async fn list_domain_zones(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    Query(query): Query<ListDomainZonesQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    let admin = tls_admin(&state)?;
    let has_cloudflare_token = has_cloudflare_token(&state, admin.as_ref()).await?;
    let attached = admin.attached_domain_zones().await?;
    let zones = attached.get("zones").cloned().unwrap_or_else(|| json!([]));

    let discoverable = if discover_requested(query.discover.as_deref()) {
        ensure_admin(auth.as_ref())?;
        if !has_cloudflare_token {
            return Err(ControlApiError::Module {
                code: "tls.secret.missing",
                params: Some(json!({ "name": "DNSCRAFT_CLOUDFLARE_API_TOKEN" })),
            });
        }
        let discovered = admin.discover_domain_zones().await?;
        Some(
            discovered
                .get("zones")
                .cloned()
                .unwrap_or_else(|| json!([])),
        )
    } else {
        None
    };

    Ok(success(match discoverable {
        Some(discoverable) => json!({
            "zones": zones,
            "has_cloudflare_token": has_cloudflare_token,
            "discoverable": discoverable,
        }),
        None => json!({
            "zones": zones,
            "has_cloudflare_token": has_cloudflare_token,
        }),
    }))
}

/// `GET /api/v1/domain-zones/{zone_id}/records`.
pub(crate) async fn list_domain_zone_records(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    Query(query): Query<ListDomainZoneRecordsQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    let admin = tls_admin(&state)?;
    if !has_cloudflare_token(&state, admin.as_ref()).await? {
        return Err(ControlApiError::Module {
            code: "tls.secret.missing",
            params: Some(json!({ "name": "DNSCRAFT_CLOUDFLARE_API_TOKEN" })),
        });
    }
    let page = query.page.unwrap_or(DEFAULT_PAGE).max(1);
    let per_page = query
        .per_page
        .unwrap_or(DEFAULT_PER_PAGE)
        .clamp(1, MAX_PER_PAGE);
    let name_substr = query
        .name_substr
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let records = admin
        .domain_zone_records(&zone_id, page, per_page, name_substr)
        .await?;
    Ok(success(records))
}

/// `POST /api/v1/domain-zones/{zone_id}/records`.
pub(crate) async fn create_domain_zone_record(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    body: Result<Json<CreateDomainZoneRecordBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "tls.config.invalid")?;
    let admin = tls_admin(&state)?;
    require_cloudflare_token(&state, admin.as_ref()).await?;
    let record = admin
        .create_domain_zone_record(&zone_id, record_value_from_create(&body))
        .await?;
    Ok(success(record))
}

/// `PUT /api/v1/domain-zones/{zone_id}/records`.
pub(crate) async fn update_domain_zone_record(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    body: Result<Json<UpdateDomainZoneRecordBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "tls.config.invalid")?;
    let record_id = body.id.trim();
    if record_id.is_empty() {
        return Err(ControlApiError::config("id is required"));
    }
    let admin = tls_admin(&state)?;
    require_cloudflare_token(&state, admin.as_ref()).await?;
    let record = admin
        .update_domain_zone_record(&zone_id, record_id, record_value_from_update(&body))
        .await?;
    Ok(success(record))
}

/// `DELETE /api/v1/domain-zones/{zone_id}/records`.
pub(crate) async fn delete_domain_zone_record(
    State(state): State<AppState>,
    Path(zone_id): Path<String>,
    body: Result<Json<DeleteDomainZoneRecordBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "tls.config.invalid")?;
    let record_id = body.id.trim();
    if record_id.is_empty() {
        return Err(ControlApiError::config("id is required"));
    }
    let admin = tls_admin(&state)?;
    require_cloudflare_token(&state, admin.as_ref()).await?;
    admin.delete_domain_zone_record(&zone_id, record_id).await?;
    Ok(success(json!({ "deleted": true, "id": record_id })))
}

/// `POST /api/v1/domain-zones/attach`.
pub(crate) async fn attach_domain_zone(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    body: Result<Json<AttachDomainZoneBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "tls.config.invalid")?;
    let name = body.name.trim();
    if name.is_empty() {
        return Err(ControlApiError::config("name is required"));
    }
    let zone_id = body
        .zone_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned);
    let relay_body = json!({
        "name": name,
        "zone_id": zone_id,
    });
    if let Some(response) = relay_config_family_write(
        &state,
        "POST",
        "/api/v1/domain-zones/attach",
        relay_body,
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let admin = tls_admin(&state)?;
    if zone_id.is_none() {
        require_cloudflare_token(&state, admin.as_ref()).await?;
    }
    let zone = admin.attach_domain_zone(name, zone_id).await?;
    persist_dns_provider_zones(&state, admin.as_ref(), auth, &headers).await?;
    Ok(success(zone).into_response())
}

/// `DELETE /api/v1/domain-zones/attach/{apex}`.
pub(crate) async fn detach_domain_zone(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    headers: HeaderMap,
    Path(apex): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let apex = apex.trim();
    if apex.is_empty() {
        return Err(ControlApiError::config("apex is required"));
    }
    if let Some(response) = relay_config_family_write(
        &state,
        "DELETE",
        &format!("/api/v1/domain-zones/attach/{apex}"),
        json!({}),
        auth.clone(),
        &headers,
    )
    .await?
    {
        return Ok(response.into_response());
    }
    let admin = tls_admin(&state)?;
    admin.detach_domain_zone(apex).await?;
    persist_dns_provider_zones(&state, admin.as_ref(), auth, &headers).await?;
    Ok(success(json!({ "detached": true, "name": apex })).into_response())
}

async fn persist_dns_provider_zones(
    state: &AppState,
    admin: &dyn TlsAdmin,
    auth: Option<Extension<Authenticated>>,
    headers: &HeaderMap,
) -> Result<(), ControlApiError> {
    let zones_value = admin.domain_zone_configs().await?;
    let zones = zones_value
        .get("zones")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let public_domain = admin
        .public_domain()
        .await?
        .get("public_domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();

    let Ok(svc) = service(state) else {
        // Engine-only embeddings (no config service) still mutate live zones.
        return Ok(());
    };
    let mut snapshot = stored_snapshot(svc).await?;
    let tls = snapshot
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored config snapshot is malformed".to_owned(),
        })?
        .entry("tls")
        .or_insert_with(|| json!({}));
    let tls_obj = tls
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored tls section is malformed".to_owned(),
        })?;
    if tls_obj
        .get("public_domain")
        .and_then(Value::as_str)
        .unwrap_or("")
        .is_empty()
        && !public_domain.is_empty()
    {
        tls_obj.insert("public_domain".into(), json!(public_domain));
    }
    let dns_provider = tls_obj.entry("dns_provider").or_insert_with(|| json!({}));
    let dns_obj = dns_provider
        .as_object_mut()
        .ok_or_else(|| ControlApiError::Internal {
            message: "stored dns_provider section is malformed".to_owned(),
        })?;
    if !dns_obj.contains_key("kind") {
        dns_obj.insert("kind".into(), json!("cloudflare"));
    }
    dns_obj.insert("zones".into(), zones);
    let _version = svc
        .replace(snapshot, &actor(auth), if_match(headers))
        .await?;
    Ok(())
}

fn record_value_from_create(body: &CreateDomainZoneRecordBody) -> Value {
    let mut obj = json!({
        "name": body.name,
        "type": body.record_type,
        "content": body.content,
    });
    if let Some(ttl) = body.ttl {
        obj["ttl"] = json!(ttl);
    }
    if let Some(proxied) = body.proxied {
        obj["proxied"] = json!(proxied);
    }
    if let Some(priority) = body.priority {
        obj["priority"] = json!(priority);
    }
    if let Some(weight) = body.weight {
        obj["weight"] = json!(weight);
    }
    if let Some(port) = body.port {
        obj["port"] = json!(port);
    }
    obj
}

fn record_value_from_update(body: &UpdateDomainZoneRecordBody) -> Value {
    let mut obj = json!({
        "name": body.name,
        "type": body.record_type,
        "content": body.content,
    });
    if let Some(ttl) = body.ttl {
        obj["ttl"] = json!(ttl);
    }
    if let Some(proxied) = body.proxied {
        obj["proxied"] = json!(proxied);
    }
    if let Some(priority) = body.priority {
        obj["priority"] = json!(priority);
    }
    if let Some(weight) = body.weight {
        obj["weight"] = json!(weight);
    }
    if let Some(port) = body.port {
        obj["port"] = json!(port);
    }
    obj
}

fn tls_admin(state: &AppState) -> Result<&Arc<dyn TlsAdmin>, ControlApiError> {
    state.tls_admin().ok_or_else(|| ControlApiError::NotReady {
        module: "tls".to_owned(),
    })
}

async fn has_cloudflare_token(
    state: &AppState,
    admin: &dyn TlsAdmin,
) -> Result<bool, ControlApiError> {
    if let Some(db) = state.db()
        && crate::cloudflare_secrets::has_api_token(db).await?
    {
        return Ok(true);
    }
    let live = admin.has_cloudflare_token().await?;
    Ok(live
        .get("has_cloudflare_token")
        .and_then(Value::as_bool)
        .unwrap_or(false))
}

async fn require_cloudflare_token(
    state: &AppState,
    admin: &dyn TlsAdmin,
) -> Result<(), ControlApiError> {
    if has_cloudflare_token(state, admin).await? {
        return Ok(());
    }
    Err(ControlApiError::Module {
        code: "tls.secret.missing",
        params: Some(json!({ "name": "DNSCRAFT_CLOUDFLARE_API_TOKEN" })),
    })
}

fn discover_requested(raw: Option<&str>) -> bool {
    matches!(raw.map(str::trim), Some("1" | "true" | "yes" | "on"))
}

fn ensure_admin(auth: Option<&Extension<Authenticated>>) -> Result<(), ControlApiError> {
    match auth {
        None => Ok(()),
        Some(Extension(principal)) if principal.scope() == Scope::Admin => Ok(()),
        Some(_) => Err(ControlApiError::AuthInsufficientScope {
            required: "admin".to_owned(),
        }),
    }
}
