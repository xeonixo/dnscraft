//! A9 integration tests: OIDC Authorization Code + PKCE + nonce against an
//! in-process mock provider.
//!
//! The mock provider speaks real discovery/JWKS/authorization/token HTTP on
//! `127.0.0.1:0`; no external network is used. Cryptographic negative cases
//! (bad signature, `alg=none`, HS256 confusion, `at_hash`) are produced by the
//! mock through a forced-token switch. Tests were written before the
//! implementation (red first) and cover the A9 acceptance criteria.
//!
//! All server-side time checks run on a `ManualClock` fixed at [`BASE`], so
//! expiry and skew are exact without sleeps (ADR-0005).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom as _, SystemRandom};
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Auth, AuthConfig, AuthState, ControlApiError, Db, ManualClock, OidcState, Role,
    Secret, SessionStore, TokenStore,
};

/// Fixed wall-clock instant used by the injected clock and the mock ID tokens.
const BASE: i64 = 1_700_000_000;
const CLIENT_ID: &str = "dnscraft-control-api";
const CLIENT_SECRET: &str = "oidc-client-secret-value";
const ADMIN_GROUP: &str = "dnscraft-admin";
const HOST: &str = "node1.example.net";
const CALLBACK_PATH: &str = "/api/v1/auth/oidc/callback";
const KEY_ID: &str = "mock-key";

const IDLE: Duration = Duration::from_secs(60 * 60);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);

fn test_addr() -> std::net::SocketAddr {
    std::net::SocketAddr::from(([127, 0, 0, 1], 40_000))
}

fn test_clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(BASE as u64),
    ))
}

// --- in-process mock OIDC provider -----------------------------------------

#[derive(Clone)]
struct MockProvider {
    issuer: String,
    state: MockState,
}

#[derive(Clone)]
struct MockState {
    issuer: String,
    client_id: String,
    client_secret: String,
    key: Arc<EcdsaKeyPair>,
    wrong_key: Arc<EcdsaKeyPair>,
    public: Vec<u8>,
    codes: Arc<Mutex<HashMap<String, PendingCode>>>,
    forced_token: Arc<Mutex<Option<String>>>,
    groups: Arc<Mutex<Vec<String>>>,
}

struct PendingCode {
    nonce: String,
    challenge: String,
    redirect_uri: String,
}

#[derive(Clone, Copy)]
enum Signature {
    Valid,
    WrongKey,
    None,
    HmacSha256,
}

struct TokenSpec {
    sign: Signature,
    issuer: Option<String>,
    audience: Option<String>,
    nonce: Option<String>,
    exp: i64,
    iat: i64,
    at_hash: Option<String>,
    groups: Option<Vec<String>>,
}

impl MockProvider {
    async fn start() -> Self {
        let rng = SystemRandom::new();
        let key = new_key(&rng);
        let wrong_key = new_key(&rng);
        let public = key.public_key().as_ref().to_vec();

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let issuer = format!("http://{addr}");
        let state = MockState {
            issuer: issuer.clone(),
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
            key: Arc::new(key),
            wrong_key: Arc::new(wrong_key),
            public,
            codes: Arc::new(Mutex::new(HashMap::new())),
            forced_token: Arc::new(Mutex::new(None)),
            groups: Arc::new(Mutex::new(Vec::new())),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/authorize", get(authorize))
            .route("/token", post(token))
            .with_state(state.clone());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { issuer, state }
    }

    fn set_groups(&self, groups: &[&str]) {
        *self.state.groups.lock().unwrap() = groups.iter().map(|g| (*g).to_owned()).collect();
    }

    fn force_token(&self, spec: TokenSpec) {
        let token = self.state.sign(&spec);
        *self.state.forced_token.lock().unwrap() = Some(token);
    }
}

impl MockState {
    fn sign(&self, spec: &TokenSpec) -> String {
        let alg = match spec.sign {
            Signature::HmacSha256 => "HS256",
            Signature::None => "none",
            Signature::Valid | Signature::WrongKey => "ES256",
        };
        let header = json!({ "alg": alg, "typ": "JWT", "kid": KEY_ID });
        let mut payload = json!({
            "iss": spec.issuer.clone().unwrap_or_else(|| self.issuer.clone()),
            "aud": spec.audience.clone().unwrap_or_else(|| self.client_id.clone()),
            "sub": "user-1",
            "exp": spec.exp,
            "iat": spec.iat,
        });
        let object = payload.as_object_mut().unwrap();
        if let Some(nonce) = &spec.nonce {
            object.insert("nonce".to_owned(), json!(nonce));
        }
        if let Some(at_hash) = &spec.at_hash {
            object.insert("at_hash".to_owned(), json!(at_hash));
        }
        if let Some(groups) = &spec.groups {
            object.insert("groups".to_owned(), json!(groups));
        }

        let signing_input = format!("{}.{}", b64_json(&header), b64_json(&payload));
        let signature = match spec.sign {
            Signature::Valid => b64_bytes(
                self.key
                    .sign(&SystemRandom::new(), signing_input.as_bytes())
                    .unwrap()
                    .as_ref(),
            ),
            Signature::WrongKey => b64_bytes(
                self.wrong_key
                    .sign(&SystemRandom::new(), signing_input.as_bytes())
                    .unwrap()
                    .as_ref(),
            ),
            Signature::None => String::new(),
            // The realistic alg-confusion attack: HMAC keyed with a value the
            // verifier knows. openidconnect's confidential-client verifier
            // would accept this if HS256 were not explicitly disallowed.
            Signature::HmacSha256 => {
                let key =
                    ring::hmac::Key::new(ring::hmac::HMAC_SHA256, self.client_secret.as_bytes());
                let tag = ring::hmac::sign(&key, signing_input.as_bytes());
                b64_bytes(tag.as_ref())
            }
        };
        format!("{signing_input}.{signature}")
    }
}

fn new_key(rng: &SystemRandom) -> EcdsaKeyPair {
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), rng).unwrap()
}

async fn discovery(State(state): State<MockState>) -> axum::Json<Value> {
    axum::Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}/authorize", state.issuer),
        "token_endpoint": format!("{}/token", state.issuer),
        "jwks_uri": format!("{}/jwks", state.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "scopes_supported": ["openid"],
    }))
}

async fn jwks(State(state): State<MockState>) -> axum::Json<Value> {
    let (x, y) = split_coordinates(&state.public);
    axum::Json(json!({
        "keys": [{
            "kty": "EC",
            "crv": "P-256",
            "use": "sig",
            "alg": "ES256",
            "kid": KEY_ID,
            "x": b64_bytes(x),
            "y": b64_bytes(y),
        }]
    }))
}

async fn authorize(
    State(state): State<MockState>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let client_ok = query.get("client_id").map(String::as_str) == Some(CLIENT_ID);
    let response_type_ok = query.get("response_type").map(String::as_str) == Some("code");
    let pkce_ok = query.get("code_challenge_method").map(String::as_str) == Some("S256")
        && query.contains_key("code_challenge");
    if !client_ok || !response_type_ok || !pkce_ok {
        return (StatusCode::BAD_REQUEST, "bad authorization request").into_response();
    }
    let (Some(challenge), Some(redirect_uri), Some(csrf), Some(nonce)) = (
        query.get("code_challenge"),
        query.get("redirect_uri"),
        query.get("state"),
        query.get("nonce"),
    ) else {
        return (StatusCode::BAD_REQUEST, "missing authorization parameter").into_response();
    };
    let code = random_hex();
    state.codes.lock().unwrap().insert(
        code.clone(),
        PendingCode {
            nonce: nonce.clone(),
            challenge: challenge.clone(),
            redirect_uri: redirect_uri.clone(),
        },
    );
    let location = format!("{redirect_uri}?code={code}&state={csrf}");
    let location = header::HeaderValue::from_str(&location).unwrap();
    (StatusCode::FOUND, [(header::LOCATION, location)]).into_response()
}

async fn token(State(state): State<MockState>, headers: HeaderMap, body: Bytes) -> Response {
    if !client_authenticated(&state, &headers) {
        return oauth_error(StatusCode::UNAUTHORIZED, "invalid_client");
    }
    let access_token = "mock-access-token";
    if let Some(id_token) = state.forced_token.lock().unwrap().clone() {
        return token_success(access_token, &id_token);
    }

    let form = form_decode(&body);
    let Some(pending) = take_authorized_code(&state, &form) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    };
    let groups = state.groups.lock().unwrap().clone();
    let spec = TokenSpec {
        sign: Signature::Valid,
        issuer: None,
        audience: None,
        nonce: Some(pending.nonce),
        exp: BASE + 300,
        iat: BASE,
        at_hash: Some(at_hash(access_token)),
        groups: Some(groups),
    };
    token_success(access_token, &state.sign(&spec))
}

/// Removes and validates a one-time authorization code, including the PKCE
/// S256 verifier and the redirect URI.
fn take_authorized_code(state: &MockState, form: &HashMap<String, String>) -> Option<PendingCode> {
    let pending = {
        let mut codes = state.codes.lock().unwrap();
        codes.remove(form.get("code")?)?
    };
    let verifier = form.get("code_verifier")?;
    let challenge = URL_SAFE_NO_PAD
        .encode(ring::digest::digest(&ring::digest::SHA256, verifier.as_bytes()).as_ref());
    if challenge != pending.challenge {
        return None;
    }
    if form.get("redirect_uri") != Some(&pending.redirect_uri) {
        return None;
    }
    Some(pending)
}

fn client_authenticated(state: &MockState, headers: &HeaderMap) -> bool {
    let Some(value) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let Some(encoded) = value.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = STANDARD.decode(encoded) else {
        return false;
    };
    decoded == format!("{}:{}", state.client_id, state.client_secret).as_bytes()
}

fn token_success(access_token: &str, id_token: &str) -> Response {
    axum::Json(json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    }))
    .into_response()
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    (status, axum::Json(json!({ "error": error }))).into_response()
}

fn form_decode(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    None => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn split_coordinates(public: &[u8]) -> (&[u8], &[u8]) {
    assert_eq!(public.len(), 65, "uncompressed P-256 point");
    assert_eq!(public[0], 4, "uncompressed P-256 point");
    (&public[1..33], &public[33..65])
}

fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).unwrap();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn b64_json(value: &Value) -> String {
    b64_bytes(&serde_json::to_vec(value).unwrap())
}

fn b64_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn at_hash(access_token: &str) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, access_token.as_bytes());
    let bytes = digest.as_ref();
    b64_bytes(&bytes[..bytes.len() / 2])
}

/// A reqwest client for the test's own HTTP calls to the mock. It is built on
/// the ring provider like production; the mock is plain HTTP.
fn test_http() -> reqwest::Client {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

// --- harness ---------------------------------------------------------------

struct Harness {
    provider: MockProvider,
    router: Router,
    sessions: SessionStore,
    clock: Arc<ManualClock>,
}

async fn harness() -> Harness {
    let clock = test_clock();
    let provider = MockProvider::start().await;
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let sessions = SessionStore::new(db.clone(), IDLE, ABSOLUTE);
    let auth = AuthState::new(
        Auth::new(sessions.clone()),
        TokenStore::new(db.clone(), MAX_TTL),
    );
    let config = AuthConfig {
        oidc_enabled: true,
        oidc_issuer: provider.issuer.clone(),
        oidc_client_id: CLIENT_ID.to_owned(),
        oidc_client_secret: Secret::new(CLIENT_SECRET),
        oidc_admin_group: ADMIN_GROUP.to_owned(),
        oidc_token_skew: Duration::from_secs(30),
        ..AuthConfig::default()
    };
    let oidc = OidcState::from_config_with_clock(&config, clock.clone())
        .unwrap()
        .expect("OIDC is configured");
    let app = AppState::new().with_auth(auth).with_oidc(Arc::new(oidc));
    let router = app.router().layer(MockConnectInfo(test_addr()));
    Harness {
        provider,
        router,
        sessions,
        clock,
    }
}

async fn send(router: Router, req: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, headers, body)
}

async fn authorize_url(router: &Router) -> (String, String) {
    let req = Request::builder()
        .method("GET")
        .uri("/api/v1/auth/oidc/authorize-url")
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let url = body["data"]["authorization_url"]
        .as_str()
        .expect("authorization_url")
        .to_owned();
    let state = body["data"]["state"].as_str().expect("state").to_owned();
    (url, state)
}

/// Drives the mock provider's authorization endpoint and returns the code it
/// redirected back with.
async fn fetch_authorize_code(url: &str) -> String {
    let response = test_http().get(url).send().await.unwrap();
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("redirect location")
        .to_str()
        .unwrap()
        .to_owned();
    query_value(&location, "code").expect("code in redirect")
}

async fn callback(router: &Router, code: &str, state: &str) -> (StatusCode, HeaderMap, Value) {
    let uri = format!("{CALLBACK_PATH}?code={code}&state={state}");
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    send(router.clone(), req).await
}

async fn login(harness: &Harness) -> (StatusCode, HeaderMap, Value) {
    let (url, state) = authorize_url(&harness.router).await;
    let code = fetch_authorize_code(&url).await;
    callback(&harness.router, &code, &state).await
}

/// Starts a login (creating a one-time `state`) and returns the nonce the
/// client expects plus the state value.
async fn pending_login(harness: &Harness) -> (String, String) {
    let (url, state) = authorize_url(&harness.router).await;
    let nonce = query_value(&url, "nonce").expect("nonce in authorization URL");
    (nonce, state)
}

fn query_value(url: &str, key: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()?
        .query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn session_cookie(headers: &HeaderMap) -> String {
    let raw = headers
        .get(header::SET_COOKIE)
        .expect("login must set a session cookie")
        .to_str()
        .unwrap();
    raw.split(';')
        .next()
        .unwrap()
        .trim()
        .strip_prefix("dnscraft_session=")
        .expect("session cookie name")
        .to_owned()
}

fn base_spec(nonce: &str) -> TokenSpec {
    TokenSpec {
        sign: Signature::Valid,
        issuer: None,
        audience: None,
        nonce: Some(nonce.to_owned()),
        exp: BASE + 300,
        iat: BASE,
        at_hash: Some(at_hash("mock-access-token")),
        groups: None,
    }
}

async fn forced_login(
    harness: &Harness,
    mutate: impl FnOnce(&mut TokenSpec),
) -> (StatusCode, HeaderMap, Value) {
    let (nonce, state) = pending_login(harness).await;
    let mut spec = base_spec(&nonce);
    mutate(&mut spec);
    harness.provider.force_token(spec);
    callback(&harness.router, "forced-code", &state).await
}

fn assert_oidc_rejection(status: StatusCode, headers: &HeaderMap, body: &Value) {
    assert_eq!(status, StatusCode::BAD_GATEWAY, "{body}");
    assert_eq!(body["error"]["code"], "control_api.auth.oidc");
    assert!(
        headers.get(header::SET_COOKIE).is_none(),
        "a rejected OIDC login must not mint a session"
    );
}

// --- acceptance: happy path, role mapping, PKCE/nonce ----------------------

#[tokio::test]
async fn admin_group_claim_maps_to_admin_and_mints_a_cookie_session() {
    let harness = harness().await;
    harness.provider.set_groups(&[ADMIN_GROUP, "other-group"]);

    let (status, headers, body) = login(&harness).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["actor_id"], "user-1");
    assert_eq!(body["data"]["role"], "admin");
    let csrf = body["data"]["csrf_token"].as_str().unwrap();
    assert!(!csrf.is_empty());

    let cookie = session_cookie(&headers);
    let principal = harness.sessions.validate(&cookie).await.unwrap();
    assert_eq!(principal.actor_id, "user-1");
    assert_eq!(principal.role, Role::Admin);

    assert!(!body.to_string().contains(CLIENT_SECRET));
}

#[tokio::test]
async fn missing_admin_group_claim_maps_to_viewer() {
    let harness = harness().await;
    harness.provider.set_groups(&["some-other-group"]);

    let (status, headers, body) = login(&harness).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["actor_id"], "user-1");
    assert_eq!(body["data"]["role"], "viewer");

    let cookie = session_cookie(&headers);
    let principal = harness.sessions.validate(&cookie).await.unwrap();
    assert_eq!(principal.role, Role::Viewer);
}

#[tokio::test]
async fn authorize_url_uses_discovery_pkce_s256_nonce_and_state() {
    let harness = harness().await;
    let (url, state) = authorize_url(&harness.router).await;

    assert!(
        url.starts_with(&format!("{}/authorize?", harness.provider.issuer)),
        "authorization endpoint must come from discovery: {url}"
    );
    assert_eq!(query_value(&url, "response_type").as_deref(), Some("code"));
    assert_eq!(query_value(&url, "client_id").as_deref(), Some(CLIENT_ID));
    assert_eq!(
        query_value(&url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert_eq!(
        query_value(&url, "code_challenge").map(|c| c.len()),
        Some(43),
        "S256 challenge is base64url of a SHA-256 digest"
    );
    assert_eq!(
        query_value(&url, "redirect_uri").as_deref(),
        Some(format!("http://{HOST}{CALLBACK_PATH}").as_str())
    );
    let nonce = query_value(&url, "nonce").expect("nonce");
    assert!(!nonce.is_empty());
    assert_eq!(query_value(&url, "state").as_deref(), Some(state.as_str()));

    // Every login gets a fresh state and nonce.
    let (second_url, second_state) = authorize_url(&harness.router).await;
    assert_ne!(second_state, state);
    assert_ne!(query_value(&second_url, "nonce"), Some(nonce));
}

// --- acceptance: ID-token validation --------------------------------------

#[tokio::test]
async fn invalid_signature_is_rejected_with_auth_oidc() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.sign = Signature::WrongKey;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn expired_token_is_rejected_with_auth_oidc() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.exp = BASE - 60;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn token_expired_just_inside_the_configured_skew_is_accepted() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.exp = BASE - 10;
    })
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(headers.get(header::SET_COOKIE).is_some());
}

#[tokio::test]
async fn future_issued_token_outside_the_skew_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.iat = BASE + 31;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn wrong_audience_is_rejected_with_auth_oidc() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.audience = Some("another-client".to_owned());
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn wrong_issuer_is_rejected_with_auth_oidc() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.issuer = Some("https://evil.example".to_owned());
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn missing_nonce_claim_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.nonce = None;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn mismatched_nonce_claim_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.nonce = Some("a-different-nonce".to_owned());
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn mismatched_at_hash_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.at_hash = Some(at_hash("some-other-access-token"));
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

// --- threat model: alg=none and HS256 alg confusion ------------------------

#[tokio::test]
async fn alg_none_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        spec.sign = Signature::None;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn hs256_alg_confusion_is_rejected() {
    let harness = harness().await;
    let (status, headers, body) = forced_login(&harness, |spec| {
        // The HMAC is keyed with the real client secret, so this token is
        // valid under the crate's confidential-client verifier; only the
        // explicit asymmetric-algorithm allow-list rejects it. No `at_hash`,
        // so the rejection cannot come from the optional hash check.
        spec.sign = Signature::HmacSha256;
        spec.at_hash = None;
    })
    .await;
    assert_oidc_rejection(status, &headers, &body);
}

// --- threat model: state is validated and one-time -------------------------

#[tokio::test]
async fn unknown_state_is_rejected() {
    let harness = harness().await;
    // Use a code the provider really issued, so only the wrong state can make
    // this fail.
    let (url, _state) = authorize_url(&harness.router).await;
    let code = fetch_authorize_code(&url).await;
    let req = Request::builder()
        .method("GET")
        .uri(format!("{CALLBACK_PATH}?code={code}&state=never-issued"))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = send(harness.router.clone(), req).await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn expired_pending_login_is_rejected() {
    let harness = harness().await;
    let (url, state) = authorize_url(&harness.router).await;
    let code = fetch_authorize_code(&url).await;
    // A forced token that would still be valid at the advanced clock, so only
    // the ten-minute pending-login expiry can reject the callback.
    let nonce = query_value(&url, "nonce").expect("nonce");
    let mut spec = base_spec(&nonce);
    spec.exp = BASE + 1000;
    harness.provider.force_token(spec);

    harness.clock.advance(Duration::from_secs(601));
    let (status, headers, body) = callback(&harness.router, &code, &state).await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn state_and_code_are_single_use() {
    let harness = harness().await;

    let (url, state) = authorize_url(&harness.router).await;
    let code = fetch_authorize_code(&url).await;
    let (status, _, body) = callback(&harness.router, &code, &state).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Replaying the same state (and code) must fail: the pending entry was
    // removed before the token exchange.
    let (status, headers, body) = callback(&harness.router, &code, &state).await;
    assert_oidc_rejection(status, &headers, &body);

    // A fresh provider code for the same (already consumed) state must also
    // fail, so only the one-time state, not provider code reuse, rejects it.
    let fresh_code = fetch_authorize_code(&url).await;
    let (status, headers, body) = callback(&harness.router, &fresh_code, &state).await;
    assert_oidc_rejection(status, &headers, &body);

    // And with a different code but the same state.
    let (status, headers, body) = callback(&harness.router, "other-code", &state).await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn authorization_code_is_single_use_at_the_provider() {
    let harness = harness().await;
    let (url, state) = authorize_url(&harness.router).await;
    let code = fetch_authorize_code(&url).await;

    let (status, _, body) = callback(&harness.router, &code, &state).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Reuse the consumed code with a fresh state: the mock token endpoint
    // rejects it, so login fails.
    let (_url, fresh_state) = authorize_url(&harness.router).await;
    let (status, headers, body) = callback(&harness.router, &code, &fresh_state).await;
    assert_oidc_rejection(status, &headers, &body);
}

#[tokio::test]
async fn provider_error_response_is_reported_as_auth_oidc() {
    let harness = harness().await;
    let req = Request::builder()
        .method("GET")
        .uri(format!(
            "{CALLBACK_PATH}?error=access_denied&state=anything"
        ))
        .header(header::HOST, HOST)
        .body(Body::empty())
        .unwrap();
    let (status, headers, body) = send(harness.router.clone(), req).await;
    assert_oidc_rejection(status, &headers, &body);
}

// --- configuration and secret handling -------------------------------------

#[tokio::test]
async fn disabled_or_unconfigured_oidc_yields_no_state() {
    let clock: Arc<dyn dnscraft_api::Clock> = test_clock();
    let disabled = AuthConfig {
        oidc_enabled: false,
        oidc_issuer: "https://idp.example".to_owned(),
        oidc_client_id: CLIENT_ID.to_owned(),
        ..AuthConfig::default()
    };
    assert!(
        OidcState::from_config_with_clock(&disabled, clock.clone())
            .unwrap()
            .is_none()
    );

    let unconfigured = AuthConfig::default();
    assert!(
        OidcState::from_config_with_clock(&unconfigured, clock)
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn client_secret_is_redacted_in_debug_and_serialized_config() {
    let clock: Arc<dyn dnscraft_api::Clock> = test_clock();
    let config = AuthConfig {
        oidc_enabled: true,
        oidc_issuer: "https://idp.example".to_owned(),
        oidc_client_id: CLIENT_ID.to_owned(),
        oidc_client_secret: Secret::new(CLIENT_SECRET),
        ..AuthConfig::default()
    };
    let oidc = OidcState::from_config_with_clock(&config, clock)
        .unwrap()
        .expect("configured");
    assert!(!format!("{oidc:?}").contains(CLIENT_SECRET));
    assert!(!format!("{config:?}").contains(CLIENT_SECRET));
    assert!(
        !serde_json::to_string(&config)
            .unwrap()
            .contains(CLIENT_SECRET)
    );
}

#[test]
fn existing_error_code_and_status_still_hold() {
    assert_eq!(
        ControlApiError::AuthOidc {
            message: "x".into()
        }
        .code(),
        "control_api.auth.oidc"
    );
}
