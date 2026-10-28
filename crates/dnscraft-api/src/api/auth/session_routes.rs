//! `GET /api/v1/auth/sessions` and `DELETE /api/v1/auth/sessions/{id}` (WX8).
//!
//! Viewers see and revoke their own sessions; admins see and revoke any
//! session. The public id is the SHA-256 of the cookie value, so the list never
//! carries a usable session secret. The current session is revoked with logout,
//! not here.

use std::net::IpAddr;

use axum::Extension;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use serde_json::json;

use super::sessions::{SessionMeta, SessionRow, session_id_for_cookie};
use super::{Authenticated, session_cookie_value};
use crate::api::pagination::Pagination;
use crate::api::response::{success, unix_rfc3339};
use crate::config::IpTruncate;
use crate::error::ControlApiError;
use crate::server::AppState;

/// `GET /api/v1/auth/sessions?scope=own|all&limit&offset`.
///
/// `scope=all` is admin-only. Without `scope`, a viewer gets `own` and an
/// admin gets `all`.
pub(crate) async fn list_sessions(
    State(state): State<AppState>,
    Extension(caller): Extension<Authenticated>,
    headers: HeaderMap,
    Query(query): Query<SessionQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    let admin = caller.scope().is_admin();
    let scope = query
        .scope
        .as_deref()
        .unwrap_or(if admin { "all" } else { "own" });
    let all = match scope {
        "all" if admin => true,
        "all" => {
            return Err(ControlApiError::AuthInsufficientScope {
                required: "admin".to_owned(),
            });
        }
        "own" => false,
        _ => {
            return Err(ControlApiError::PaginationInvalid {
                reason: "scope must be `own` or `all`".to_owned(),
            });
        }
    };
    let page = Pagination::parse(query.limit.as_deref(), query.offset.as_deref())?;
    let auth = state.auth_state().ok_or_else(not_configured)?;
    let actor = (!all).then(|| caller.actor_id().to_owned());
    let rows = auth
        .sessions()
        .list(actor.as_deref(), page.limit + 1, page.offset)
        .await?;
    let fetched = rows.len();
    let has_more = page.has_more(fetched);
    let next_offset = page.next_offset(fetched);
    let current = session_cookie_value(&headers).map(|cookie| session_id_for_cookie(&cookie));
    let items: Vec<_> = rows
        .iter()
        .take(page.limit as usize)
        .map(|row| session_json(row, current.as_deref()))
        .collect();
    Ok(success(json!({
        "items": items,
        "has_more": has_more,
        "next_offset": next_offset,
    })))
}

/// `DELETE /api/v1/auth/sessions/{id}`: revoke another session.
///
/// A foreign session is `404 unknown_session` for a viewer (so ids of other
/// actors are not confirmed), the current session is `409 session_current`.
pub(crate) async fn revoke_session(
    State(state): State<AppState>,
    Extension(caller): Extension<Authenticated>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let auth = state.auth_state().ok_or_else(not_configured)?;
    let row = auth
        .sessions()
        .find(&id)
        .await?
        .ok_or(ControlApiError::AuthUnknownSession)?;
    if row.actor_id != caller.actor_id() && !caller.scope().is_admin() {
        return Err(ControlApiError::AuthUnknownSession);
    }
    let current = session_cookie_value(&headers).map(|cookie| session_id_for_cookie(&cookie));
    if current.as_deref() == Some(id.as_str()) {
        return Err(ControlApiError::AuthSessionCurrent);
    }
    auth.sessions().revoke(&id).await?;
    crate::audit::record_auth_event(
        state.db(),
        caller.actor_id(),
        caller.actor_type().as_str(),
        "auth.session.revoke",
        &id,
        "ok",
        None,
    )
    .await;
    Ok(success(json!({ "id": id, "revoked": true })))
}

/// Query parameters of the session list.
#[derive(serde::Deserialize)]
pub(crate) struct SessionQuery {
    scope: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
}

fn session_json(row: &SessionRow, current: Option<&str>) -> serde_json::Value {
    json!({
        "id": row.id,
        "actor_id": row.actor_id,
        "actor_type": "user",
        "role": row.role.as_str(),
        "client_label": row.meta.client_label,
        "ip": row.meta.ip,
        "created_at": unix_rfc3339(row.created_at),
        "last_seen": unix_rfc3339(row.last_active),
        "expires_at": unix_rfc3339(row.expires_at),
        "current": current == Some(row.id.as_str()),
    })
}

fn not_configured() -> ControlApiError {
    ControlApiError::Internal {
        message: "session authentication is not configured".to_owned(),
    }
}

/// Builds the list metadata captured at login: the client IP truncated with
/// `ip_truncate` and a browser/OS label parsed from the user agent. The raw
/// user agent is discarded.
pub(crate) fn session_meta(peer: IpAddr, headers: &HeaderMap, truncate: IpTruncate) -> SessionMeta {
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    SessionMeta {
        ip: Some(truncate.truncate(peer)),
        client_label: Some(client_label(user_agent)),
    }
}

/// A short "Browser on OS" label. Unknown parts are dropped; an empty user
/// agent yields `Unknown client`.
pub(crate) fn client_label(user_agent: &str) -> String {
    let ua = user_agent;
    // Order matters: Edge and Opera and Chrome all also contain "Safari/".
    let browser = [
        ("Edg/", "Edge"),
        ("OPR/", "Opera"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
        ("curl/", "curl"),
    ]
    .iter()
    .find(|(token, _)| ua.contains(token))
    .map(|(_, name)| *name);
    let os = [
        ("Windows", "Windows"),
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iOS"),
        ("Macintosh", "macOS"),
        ("Linux", "Linux"),
    ]
    .iter()
    .find(|(token, _)| ua.contains(token))
    .map(|(_, name)| *name);
    match (browser, os) {
        (Some(b), Some(o)) => format!("{b} on {o}"),
        (Some(b), None) => b.to_owned(),
        (None, Some(o)) => format!("Browser on {o}"),
        (None, None) if ua.trim().is_empty() => "Unknown client".to_owned(),
        (None, None) => "Browser".to_owned(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn labels_name_the_browser_and_os_without_the_raw_agent() {
        assert_eq!(
            client_label(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15"
            ),
            "Safari on macOS"
        );
        assert_eq!(
            client_label(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36 Edg/120.0"
            ),
            "Edge on Windows"
        );
        assert_eq!(client_label(""), "Unknown client");
        assert_eq!(client_label("weird-client"), "Browser");
    }
}
