//! Minimal OAuth 2.1 authorization server for the MCP endpoint.
//!
//! Lets an MCP client (Claude's custom connector) sign in through the owner's
//! existing browser session (OIDC or break-glass) instead of a pasted token.
//! The result is an ordinary `mcp:write` bearer token, so `/mcp/v1` validation,
//! revocation and the token list are unchanged.
//!
//! - Public clients only, PKCE `S256` mandatory, no client secrets.
//! - Dynamic client registration is stateless: a registration only checks the
//!   redirect URIs; `client_id` is not stored or verified later. The redirect
//!   allow-list plus PKCE plus the admin consent carry the security.
//! - Authorization codes live in memory for 60 s and are single-use.
//! - No refresh tokens: the access token lives 30 days, then the client signs
//!   in again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{Value, json};

use super::auth::{Role, Scope, csrf_matches, csrf_token_for, session_cookie_value};
use crate::server::AppState;

const CODE_TTL: Duration = Duration::from_secs(60);
const TOKEN_TTL: Duration = Duration::from_secs(30 * 24 * 3600);
const ALLOWED_REDIRECTS: [&str; 2] = [
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
];

/// One issued, not yet redeemed authorization code.
pub(crate) struct PendingCode {
    challenge: String,
    redirect_uri: String,
    actor_id: String,
    expires: Instant,
}

/// In-memory code store shared by the authorize and token endpoints.
pub(crate) type OAuthCodes = Arc<Mutex<HashMap<String, PendingCode>>>;

/// The public base URL: the first configured MCP origin, else the request's
/// `Host` (and trusted `X-Forwarded-Proto`).
fn public_base(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(origin) = state.mcp_config().allowed_origins.first() {
        return origin.trim_end_matches('/').to_owned();
    }
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost");
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http");
    format!("{proto}://{host}")
}

fn redirect_allowed(uri: &str) -> bool {
    if ALLOWED_REDIRECTS.contains(&uri) {
        return true;
    }
    // Native clients (Claude Code) use a loopback redirect on any port.
    url::Url::parse(uri).is_ok_and(|u| {
        u.scheme() == "http"
            && matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            && u.fragment().is_none()
    })
}

fn random_hex(len: usize) -> Option<String> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    let mut res = (status, Json(json!({ "error": error }))).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Every OAuth route, with `state` applied.
pub(crate) fn routes(state: AppState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp/v1",
            get(protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(server_metadata),
        )
        .route("/oauth/register", post(register))
        .route(
            "/oauth/authorize",
            get(authorize_page).post(authorize_decision),
        )
        .route("/oauth/token", post(token))
        .with_state(state)
}

/// `GET /.well-known/oauth-protected-resource[/mcp/v1]`.
pub(crate) async fn protected_resource(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let base = public_base(&state, &headers);
    Json(json!({
        "resource": format!("{base}/mcp/v1"),
        "authorization_servers": [base],
        "scopes_supported": ["mcp:write"],
        "bearer_methods_supported": ["header"],
    }))
}

/// `GET /.well-known/oauth-authorization-server`.
pub(crate) async fn server_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Json<Value> {
    let base = public_base(&state, &headers);
    Json(json!({
        "issuer": base,
        "authorization_endpoint": format!("{base}/oauth/authorize"),
        "token_endpoint": format!("{base}/oauth/token"),
        "registration_endpoint": format!("{base}/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "scopes_supported": ["mcp:write"],
    }))
}

/// `POST /oauth/register`: stateless dynamic client registration.
pub(crate) async fn register(Json(body): Json<Value>) -> Response {
    let uris: Vec<&str> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if uris.is_empty() || !uris.iter().all(|u| redirect_allowed(u)) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_redirect_uri");
    }
    let Some(client_id) = random_hex(16) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    (
        StatusCode::CREATED,
        Json(json!({
            "client_id": client_id,
            "redirect_uris": uris,
            "client_name": body.get("client_name").and_then(Value::as_str).unwrap_or("MCP client"),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        })),
    )
        .into_response()
}

#[derive(Deserialize)]
pub(crate) struct AuthorizeParams {
    #[serde(default)]
    response_type: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: String,
}

impl AuthorizeParams {
    fn valid(&self) -> bool {
        self.response_type == "code"
            && redirect_allowed(&self.redirect_uri)
            && self.code_challenge_method == "S256"
            && !self.code_challenge.is_empty()
    }
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn page(status: StatusCode, body: &str) -> Response {
    let html = format!(
        "<!doctype html><html lang=\"de\"><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>DNScraft</title>\
         <body style=\"font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem\">{body}</body></html>"
    );
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        ),
    );
    res
}

/// The admin session behind the request, as its cookie and actor id.
async fn admin_session(state: &AppState, headers: &HeaderMap) -> Option<(String, String)> {
    let cookie = session_cookie_value(headers)?;
    let principal = state
        .auth_state()?
        .sessions()
        .validate(&cookie)
        .await
        .ok()?;
    (principal.role == Role::Admin).then_some((cookie, principal.actor_id))
}

/// `GET /oauth/authorize`: the consent page.
pub(crate) async fn authorize_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(p): Query<AuthorizeParams>,
) -> Response {
    if !p.valid() {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    }
    let Some((cookie, _)) = admin_session(&state, &headers).await else {
        return page(
            StatusCode::UNAUTHORIZED,
            "<h1>Anmeldung nötig</h1><p>Melde dich zuerst als Administrator im \
             <a href=\"/\" target=\"_blank\">DNScraft-Web-UI</a> an (auch per SSO) \
             und lade diese Seite danach neu.</p>",
        );
    };
    let csrf = csrf_token_for(&cookie);
    let hidden = |name: &str, value: &str| {
        format!(
            "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
            escape(value)
        )
    };
    page(
        StatusCode::OK,
        &format!(
            "<h1>Zugriff erlauben?</h1>\
             <p>Eine Anwendung (z. B. Claude) möchte über MCP auf diesen DNScraft-Knoten \
             zugreifen: Abfragen lesen sowie – sofern aktiviert – Regeln ändern. \
             Der Zugriff gilt 30 Tage und lässt sich in den API-Tokens widerrufen.</p>\
             <p>Weiterleitung an: <code>{}</code></p>\
             <form method=\"post\" action=\"/oauth/authorize\">{}{}{}{}{}\
             <button name=\"decision\" value=\"allow\">Erlauben</button> \
             <button name=\"decision\" value=\"deny\">Ablehnen</button></form>",
            escape(&p.redirect_uri),
            hidden("csrf", csrf.expose()),
            hidden("redirect_uri", &p.redirect_uri),
            hidden("state", &p.state),
            hidden("code_challenge", &p.code_challenge),
            hidden("code_challenge_method", &p.code_challenge_method),
        ),
    )
}

fn form(body: &Bytes) -> HashMap<String, String> {
    url::form_urlencoded::parse(body).into_owned().collect()
}

fn redirect(base: &str, params: &[(&str, &str)]) -> Response {
    let Ok(mut url) = url::Url::parse(base) else {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    };
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params.iter().filter(|(_, v)| !v.is_empty()) {
            q.append_pair(k, v);
        }
    }
    let mut res = StatusCode::SEE_OTHER.into_response();
    if let Ok(v) = HeaderValue::from_str(url.as_str()) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// `POST /oauth/authorize`: the owner's decision.
pub(crate) async fn authorize_decision(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let f = form(&body);
    let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
    let params = AuthorizeParams {
        response_type: "code".to_owned(),
        redirect_uri: get("redirect_uri").to_owned(),
        state: get("state").to_owned(),
        code_challenge: get("code_challenge").to_owned(),
        code_challenge_method: get("code_challenge_method").to_owned(),
    };
    let Some((cookie, actor_id)) = admin_session(&state, &headers).await else {
        return page(StatusCode::UNAUTHORIZED, "<h1>Anmeldung nötig</h1>");
    };
    if !params.valid() || !csrf_matches(&cookie, get("csrf")) {
        return page(StatusCode::BAD_REQUEST, "<h1>Ungültige Anfrage</h1>");
    }
    let result = if get("decision") == "allow" {
        "ok"
    } else {
        "denied"
    };
    crate::audit::record_auth_event(
        state.db(),
        &actor_id,
        "user",
        "oauth.authorize",
        "mcp",
        result,
        None,
    )
    .await;
    if result == "denied" {
        return redirect(
            &params.redirect_uri,
            &[("error", "access_denied"), ("state", &params.state)],
        );
    }
    let Some(code) = random_hex(32) else {
        return page(StatusCode::INTERNAL_SERVER_ERROR, "<h1>Fehler</h1>");
    };
    {
        let mut codes = state
            .oauth_codes()
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let now = Instant::now();
        codes.retain(|_, c| c.expires > now);
        codes.insert(
            code.clone(),
            PendingCode {
                challenge: params.code_challenge.clone(),
                redirect_uri: params.redirect_uri.clone(),
                actor_id,
                expires: now + CODE_TTL,
            },
        );
    }
    redirect(
        &params.redirect_uri,
        &[("code", &code), ("state", &params.state)],
    )
}

/// `POST /oauth/token`: `authorization_code` grant with PKCE.
pub(crate) async fn token(State(state): State<AppState>, body: Bytes) -> Response {
    let f = form(&body);
    let get = |k: &str| f.get(k).map(String::as_str).unwrap_or_default();
    if get("grant_type") != "authorization_code" {
        return oauth_error(StatusCode::BAD_REQUEST, "unsupported_grant_type");
    }
    let pending = state
        .oauth_codes()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .remove(get("code"));
    let challenge = URL_SAFE_NO_PAD.encode(digest(&SHA256, get("code_verifier").as_bytes()));
    let Some(pending) = pending.filter(|c| {
        c.expires > Instant::now()
            && c.redirect_uri == get("redirect_uri")
            && c.challenge == challenge
    }) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let Some(tokens) = state.auth_state().map(|a| a.tokens()) else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let Ok(created) = tokens
        .create(
            pending.actor_id,
            "OAuth (MCP)".to_owned(),
            Scope::McpWrite,
            Some(TOKEN_TTL),
        )
        .await
    else {
        return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error");
    };
    let mut res = Json(json!({
        "access_token": created.plaintext().expose(),
        "token_type": "Bearer",
        "expires_in": TOKEN_TTL.as_secs(),
        "scope": "mcp:write",
    }))
    .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

/// Points a 401 from `/mcp/v1` at the OAuth metadata so clients can sign in.
pub(crate) async fn www_authenticate(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let is_mcp = req.uri().path().starts_with("/mcp/v1");
    let base = public_base(&state, req.headers());
    let mut res = next.run(req).await;
    if is_mcp && res.status() == StatusCode::UNAUTHORIZED {
        let value =
            format!("Bearer resource_metadata=\"{base}/.well-known/oauth-protected-resource\"");
        if let Ok(v) = HeaderValue::from_str(&value) {
            res.headers_mut().insert(header::WWW_AUTHENTICATE, v);
        }
    }
    res
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::time::SystemTime;

    use axum::body::Body;
    use axum::http::Request;
    use dnscraft_common::clock::ManualClock;
    use tower::ServiceExt as _;

    use super::*;
    use crate::api::auth::{AuthState, SessionStore, TokenStore};
    use crate::storage::Db;

    const REDIRECT: &str = "https://claude.ai/api/mcp/auth_callback";
    const VERIFIER: &str = "verifier-verifier-verifier-verifier-verifier";

    async fn app() -> (Router, String) {
        let db = Db::open_in_memory(Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH)))
            .await
            .unwrap();
        let sessions = SessionStore::new(
            db.clone(),
            Duration::from_secs(3600),
            Duration::from_secs(43200),
        );
        let tokens = TokenStore::new(db.clone(), Duration::from_secs(365 * 24 * 3600));
        let admin = sessions
            .create("owner".to_owned(), Role::Admin)
            .await
            .unwrap();
        let cookie = admin.cookie().expose().to_owned();
        let state = AppState::new()
            .with_db(db)
            .with_auth(AuthState::new(sessions, tokens));
        (routes(state), cookie)
    }

    fn challenge() -> String {
        URL_SAFE_NO_PAD.encode(digest(&SHA256, VERIFIER.as_bytes()))
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let res = app.clone().oneshot(req).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn post_form(path: &str, cookie: Option<&str>, body: String) -> Request<Body> {
        let mut req =
            Request::post(path).header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, format!("dnscraft_session={c}"));
        }
        req.body(Body::from(body)).unwrap()
    }

    fn consent_form(cookie: &str, decision: &str) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf", csrf_token_for(cookie).expose())
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("state", "xyz")
            .append_pair("code_challenge", &challenge())
            .append_pair("code_challenge_method", "S256")
            .append_pair("decision", decision)
            .finish()
    }

    fn token_form(code: &str) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", REDIRECT)
            .append_pair("code_verifier", VERIFIER)
            .finish()
    }

    fn code_from(headers: &HeaderMap) -> String {
        let location = headers.get(header::LOCATION).unwrap().to_str().unwrap();
        let url = url::Url::parse(location).unwrap();
        assert!(location.starts_with(REDIRECT));
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned()
    }

    #[tokio::test]
    async fn full_flow_issues_a_single_use_mcp_token() {
        let (app, cookie) = app().await;
        let (status, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, "allow"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        let code = code_from(&headers);

        let (status, _, body) =
            send(&app, post_form("/oauth/token", None, token_form(&code))).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let json: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["scope"], "mcp:write");
        assert_eq!(json["access_token"].as_str().unwrap().len(), 64);

        let (status, _, _) = send(&app, post_form("/oauth/token", None, token_form(&code))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "code is single-use");
    }

    #[tokio::test]
    async fn wrong_verifier_csrf_and_anonymous_are_refused() {
        let (app, cookie) = app().await;
        let (_, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, "allow"),
            ),
        )
        .await;
        let code = code_from(&headers);
        let bad = token_form(&code).replace("verifier-", "other-");
        let (status, _, _) = send(&app, post_form("/oauth/token", None, bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let forged =
            consent_form(&cookie, "allow").replace(csrf_token_for(&cookie).expose(), "nope");
        let (status, _, _) = send(&app, post_form("/oauth/authorize", Some(&cookie), forged)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, _, _) = send(
            &app,
            post_form("/oauth/authorize", None, consent_form(&cookie, "allow")),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn deny_redirects_with_access_denied_and_register_checks_redirects() {
        let (app, cookie) = app().await;
        let (status, headers, _) = send(
            &app,
            post_form(
                "/oauth/authorize",
                Some(&cookie),
                consent_form(&cookie, "deny"),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::SEE_OTHER);
        assert!(
            headers
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .contains("error=access_denied")
        );

        let register = |uri: &str| {
            Request::post("/oauth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({ "redirect_uris": [uri] }).to_string()))
                .unwrap()
        };
        assert_eq!(send(&app, register(REDIRECT)).await.0, StatusCode::CREATED);
        assert_eq!(
            send(&app, register("https://evil.example/cb")).await.0,
            StatusCode::BAD_REQUEST
        );
    }
}
