//! `/api/v1/domain-zones` — Split-DNS Namen read path (Cloudflare inventory).
//!
//! Viewer-readable GETs that surface attached Domain-Zonen and paginated DNS
//! records through the TLS engine's Cloudflare client. Missing token →
//! `tls.secret.missing` so the UI can offer a CTA to `PUT /tls/cloudflare-token`.
//! Discover (`?discover=1`) is admin-only.

use std::sync::Arc;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::{Authenticated, Scope};
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
