//! Cookie-session authentication and CSRF for the internal API.
//!
//! Cookie sessions authorize `/api/v1` only. The [`auth_middleware`] validates
//! the session cookie against the [`SessionStore`] (idle + absolute expiry on
//! the injected clock), requires a synchronizer CSRF token on mutating methods,
//! and inserts the authenticated [`Principal`] into request extensions for
//! downstream role checks. Bearer-token requests (A7) are exempt from CSRF and
//! from cookie sessions; requests with no credentials pass through untouched so
//! A7 owns the final `401`/role decisions.

mod csrf;
mod sessions;

pub use sessions::{
    CreatedSession, Principal, Role, SessionStore, secure_cookie, session_set_cookie,
};

use axum::extract::{Request, State};
use axum::http::HeaderMap;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::error::ControlApiError;

/// Name of the session cookie.
pub(crate) const SESSION_COOKIE: &str = "dnscraft_session";

/// Request header carrying the CSRF token.
pub(crate) const CSRF_HEADER: &str = "x-csrf-token";

/// Lowercase hex encoding (used for session ids and their SHA-256 hashes).
pub(crate) fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Session/CSRF middleware state.
#[derive(Clone)]
pub struct Auth {
    store: SessionStore,
}

impl Auth {
    /// Wraps a [`SessionStore`] for use with [`auth_middleware`].
    pub fn new(store: SessionStore) -> Self {
        Self { store }
    }

    /// The session store backing this middleware.
    pub fn store(&self) -> &SessionStore {
        &self.store
    }
}

/// Middleware enforcing cookie-session authentication and CSRF on `/api/v1`.
///
/// Mount with `axum::middleware::from_fn_with_state(auth, auth_middleware)`.
/// On `/api/v1` a valid session cookie authenticates the request (inserting a
/// [`Principal`]) and mutating methods additionally require a matching CSRF
/// token. Cookie sessions never authenticate any other path family (for
/// example `/mcp/v1`), and bearer-token requests are passed through untouched.
pub async fn auth_middleware(State(auth): State<Auth>, mut req: Request, next: Next) -> Response {
    let path = req.uri().path().to_owned();
    if !is_api_path(&path) {
        // Cookie sessions never authorize other path families (e.g. /mcp/v1).
        return next.run(req).await;
    }
    // Bearer-token requests are exempt from CSRF and from cookie sessions.
    if has_bearer(req.headers()) {
        return next.run(req).await;
    }
    let Some(cookie) = session_cookie_value(req.headers()) else {
        // No credentials: A7 owns the 401 decision.
        return next.run(req).await;
    };
    let principal = match auth.store.validate(&cookie).await {
        Ok(principal) => principal,
        Err(err) => return err.into_response(),
    };
    if csrf::is_mutating(req.method()) {
        let submitted = req
            .headers()
            .get(CSRF_HEADER)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        if !csrf::csrf_matches(&cookie, submitted) {
            return ControlApiError::AuthCsrf.into_response();
        }
    }
    req.extensions_mut().insert(principal);
    next.run(req).await
}

/// Whether `path` belongs to the cookie-session family (`/api/v1`).
fn is_api_path(path: &str) -> bool {
    path == "/api/v1" || path.starts_with("/api/v1/")
}

/// Whether the request authenticates with a bearer token (CSRF exempt).
fn has_bearer(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("Bearer "))
}

/// Extracts the session cookie value from the `Cookie` header, if present.
fn session_cookie_value(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == SESSION_COOKIE
        {
            return Some(value.trim().to_owned());
        }
    }
    None
}
