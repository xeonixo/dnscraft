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
pub(crate) mod roles;
mod sessions;
pub(crate) mod tokens;

pub use roles::{Authenticated, EndpointFamily, Scope, rbac_middleware};
pub use sessions::{
    CreatedSession, Principal, Role, SessionStore, secure_cookie, session_set_cookie,
};
pub use tokens::{CreatedToken, TokenPrincipal, TokenStore};

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

/// Session + token stores backing the authentication middleware.
///
/// Build once at startup from the shared [`Db`](crate::Db) and attach to
/// [`AppState`](crate::AppState) with
/// [`AppState::with_auth`](crate::AppState::with_auth).
#[derive(Clone)]
pub struct AuthState {
    sessions: Auth,
    tokens: TokenStore,
}

impl AuthState {
    /// Bundles the cookie-session and bearer-token stores.
    pub fn new(sessions: Auth, tokens: TokenStore) -> Self {
        Self { sessions, tokens }
    }

    /// The cookie-session middleware state.
    pub fn sessions(&self) -> &Auth {
        &self.sessions
    }

    /// The bearer-token store.
    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }
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

/// Splits an `Authorization` header into a non-empty bearer token.
///
/// The scheme is matched case-insensitively (RFC 7235). Shared by A6's CSRF
/// exemption and A7's bearer authentication so both agree on what counts as a
/// bearer request.
pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let token = token.trim();
    (!token.is_empty()).then_some(token)
}

/// Whether the request carries a bearer `Authorization` scheme (CSRF exempt).
///
/// Unlike [`bearer_token`] this is true even for an empty/malformed token, so
/// the request is never subjected to CSRF checks; A7 then returns the
/// documented `401 control_api.auth.unauthenticated`.
fn has_bearer(headers: &HeaderMap) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("Bearer"))
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
