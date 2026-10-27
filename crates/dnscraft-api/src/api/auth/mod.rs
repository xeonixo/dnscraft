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
pub(crate) mod local;
pub(crate) mod oidc;
pub(crate) mod roles;
mod sessions;
pub(crate) mod tokens;

pub use local::{LocalAccountSnapshot, LocalAccountStore};
pub use oidc::{OidcSettings, OidcState};
pub use roles::{
    ActorType, Authenticated, EndpointFamily, Requirement, Scope, authorize, rbac_middleware,
    requirement,
};
pub use sessions::{
    CreatedSession, Principal, Role, SessionStore, secure_cookie, session_set_cookie,
};
pub use tokens::{CreatedToken, TokenPrincipal, TokenSnapshot, TokenStore};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::error::ControlApiError;
use crate::server::AppState;

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

/// The auth state a sub-node needs to authenticate bearer tokens offline.
///
/// This is the payload of the cluster stream's `auth_snapshot` record. It
/// carries only persisted credential material (hashes, never plaintext token,
/// password or OIDC client secret); the transport is the already-encrypted
/// mTLS channel, so encryption-at-rest is a separate, later concern.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthSnapshot {
    /// Issued token hashes and their non-secret metadata.
    pub tokens: Vec<TokenSnapshot>,
    /// Local break-glass accounts (Argon2id PHC hashes and roles).
    pub local_accounts: Vec<LocalAccountSnapshot>,
    /// Non-secret OIDC settings, or `None` when OIDC is not configured.
    pub oidc: Option<OidcSettings>,
    /// Monotonic epoch incremented whenever auth state is invalidated
    /// (token revocation, account change, explicit session invalidation).
    pub session_epoch: u64,
}

/// Session + token stores backing the authentication middleware.
///
/// Build once at startup from the shared [`Db`](crate::Db) and attach to
/// [`AppState`](crate::AppState) with
/// [`AppState::with_auth`](crate::AppState::with_auth). Local accounts and OIDC
/// settings are optional handles used only to build an [`AuthSnapshot`].
#[derive(Clone)]
pub struct AuthState {
    sessions: Auth,
    tokens: TokenStore,
    local_accounts: Option<LocalAccountStore>,
    oidc: Arc<RwLock<Option<OidcSettings>>>,
    epoch: Arc<AtomicU64>,
}

impl AuthState {
    /// Bundles the cookie-session and bearer-token stores.
    pub fn new(sessions: Auth, mut tokens: TokenStore) -> Self {
        let epoch = Arc::new(AtomicU64::new(0));
        tokens.set_epoch(epoch.clone());
        Self {
            sessions,
            tokens,
            local_accounts: None,
            oidc: Arc::new(RwLock::new(None)),
            epoch,
        }
    }

    /// Attaches the local-account store so [`AuthState::auth_snapshot`]
    /// includes its hashes.
    pub fn with_local_accounts(mut self, mut store: LocalAccountStore) -> Self {
        store.set_epoch(self.epoch.clone());
        self.local_accounts = Some(store);
        self
    }

    /// Attaches the OIDC settings so [`AuthState::auth_snapshot`] includes its
    /// non-secret fields.
    pub fn with_oidc(self, oidc: &OidcState) -> Self {
        *self
            .oidc
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(oidc.settings());
        self
    }

    /// The cookie-session middleware state.
    pub fn sessions(&self) -> &Auth {
        &self.sessions
    }

    /// The bearer-token store.
    pub fn tokens(&self) -> &TokenStore {
        &self.tokens
    }

    /// Gathers the auth state a sub-node needs to authenticate bearer tokens
    /// offline.
    ///
    /// Token revocations, local-account changes and explicit
    /// [`invalidate_sessions`](Self::invalidate_sessions) calls bump the
    /// `session_epoch`; the mTLS transport and encryption at rest are handled
    /// by the cluster layer.
    pub async fn auth_snapshot(&self) -> Result<AuthSnapshot, ControlApiError> {
        let local_accounts = match &self.local_accounts {
            Some(store) => store.snapshot_entries().await?,
            None => Vec::new(),
        };
        Ok(AuthSnapshot {
            tokens: self.tokens.snapshot_entries().await?,
            local_accounts,
            oidc: self
                .oidc
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            session_epoch: self.epoch.load(Ordering::Relaxed),
        })
    }

    /// Replaces the local auth state with a snapshot pushed by the master.
    ///
    /// Token and local-account rows are swapped in one transaction each;
    /// OIDC settings and the session-invalidation epoch are adopted verbatim.
    /// Only hashes and non-secret OIDC fields are ever carried, so no
    /// plaintext credential is written here.
    pub async fn apply_auth_snapshot(
        &self,
        snapshot: &AuthSnapshot,
    ) -> Result<(), ControlApiError> {
        self.tokens.replace_all(&snapshot.tokens).await?;
        if let Some(local) = &self.local_accounts {
            local.replace_all(&snapshot.local_accounts).await?;
        } else if !snapshot.local_accounts.is_empty() {
            return Err(ControlApiError::Internal {
                message: "local-account store is not configured; cannot apply auth snapshot"
                    .to_owned(),
            });
        }
        *self
            .oidc
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot.oidc.clone();
        self.epoch.store(snapshot.session_epoch, Ordering::Relaxed);
        Ok(())
    }

    /// Invalidates every session derived from this auth state by advancing the
    /// monotonic epoch (for example after a global sign-out).
    pub fn invalidate_sessions(&self) {
        self.epoch.fetch_add(1, Ordering::Relaxed);
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
pub(crate) fn session_cookie_value(headers: &HeaderMap) -> Option<String> {
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

/// Rejects a cross-site `Origin` on the public cookie-setting endpoints (login
/// CSRF). `SameSite=Lax` stops the browser from *sending* the session cookie
/// cross-site, but not from *accepting* a `Set-Cookie` in a cross-site
/// response, so an attacker's page could log the victim into the attacker's
/// account. A same-origin request and a non-browser client both pass (matching
/// authority, or no `Origin` header at all).
pub(crate) fn ensure_same_origin(headers: &HeaderMap) -> Result<(), ControlApiError> {
    let Some(origin) = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let authority = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .unwrap_or(origin)
        .trim_end_matches('/');
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if !authority.is_empty() && authority.eq_ignore_ascii_case(host) {
        Ok(())
    } else {
        Err(ControlApiError::AuthInvalidOrigin)
    }
}

/// `POST /api/v1/auth/logout`: revokes the cookie session server-side and
/// clears the browser cookie. A missing or already-invalid cookie is a no-op,
/// so logout stays idempotent even after the session has expired.
pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ControlApiError> {
    if let Some(auth) = state.auth_state()
        && let Some(cookie) = session_cookie_value(&headers)
    {
        auth.sessions().store().logout(&cookie).await?;
        // A logout invalidates auth state, so sub-nodes see a new epoch.
        auth.invalidate_sessions();
    }

    let mut response = crate::api::response::success(json!({})).into_response();
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0"
    )) {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use super::*;
    use crate::clock::ManualClock;
    use crate::config::AuthConfig;
    use crate::secret::Secret;
    use crate::storage::Db;

    async fn auth_state() -> (AuthState, CreatedToken, OidcState) {
        let clock: Arc<ManualClock> = Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH));
        let db = Db::open_in_memory(clock.clone()).await.unwrap();
        let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
        let created = tokens
            .create("alice".into(), "ci".into(), Scope::Admin, None)
            .await
            .unwrap();

        let local = LocalAccountStore::new(db.clone(), 5, Duration::from_secs(15 * 60));
        local
            .upsert("break-glass", "hunter2", Role::Admin)
            .await
            .unwrap();

        let config = AuthConfig {
            oidc_enabled: true,
            oidc_issuer: "https://id.example.com".into(),
            oidc_client_id: "dnscraft".into(),
            oidc_client_secret: Secret::new("super-secret-client"),
            ..AuthConfig::default()
        };
        let oidc = OidcState::from_config_with_clock(&config, clock)
            .unwrap()
            .unwrap();

        let auth = AuthState::new(
            Auth::new(SessionStore::new(
                db,
                Duration::from_secs(3600),
                Duration::from_secs(12 * 3600),
            )),
            tokens,
        )
        .with_local_accounts(local)
        .with_oidc(&oidc);
        (auth, created, oidc)
    }

    #[tokio::test]
    async fn auth_snapshot_carries_hashes_never_plaintext() {
        let (auth, created, oidc) = auth_state().await;
        let snapshot = auth.auth_snapshot().await.unwrap();

        assert_eq!(snapshot.tokens.len(), 1);
        assert_eq!(snapshot.tokens[0].id_hash, created.id());
        assert_eq!(snapshot.tokens[0].scope, "admin");
        assert_eq!(snapshot.tokens[0].actor_id, "alice");

        assert_eq!(snapshot.local_accounts.len(), 1);
        assert_eq!(snapshot.local_accounts[0].username, "break-glass");
        assert_eq!(snapshot.local_accounts[0].role, "admin");
        assert!(
            snapshot.local_accounts[0]
                .password_hash
                .starts_with("$argon2id$")
        );

        let settings = snapshot.oidc.as_ref().unwrap();
        assert!(settings.issuer.starts_with("https://id.example.com"));
        assert_eq!(settings.client_id, "dnscraft");
        assert_eq!(settings.admin_group, oidc.settings().admin_group);
        assert_eq!(snapshot.session_epoch, 0);

        // No plaintext token, password or OIDC client secret in the wire form.
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains(created.plaintext().expose()));
        assert!(!serialized.contains("hunter2"));
        assert!(!serialized.contains("super-secret-client"));
        assert!(!format!("{snapshot:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn revocation_bumps_the_session_epoch() {
        let (auth, created, _) = auth_state().await;
        auth.tokens().revoke(created.id()).await.unwrap();

        let snapshot = auth.auth_snapshot().await.unwrap();
        assert!(snapshot.tokens.is_empty());
        assert_eq!(snapshot.session_epoch, 1);

        auth.invalidate_sessions();
        assert_eq!(auth.auth_snapshot().await.unwrap().session_epoch, 2);
    }
}
