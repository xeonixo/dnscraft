//! `GET /api/v1/domain-zones` and `…/{zone_id}/records` against a loopback
//! Cloudflare mock + real [`EngineTlsAdmin`].

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "../../dnscraft-tls/tests/support/mock_cloudflare.rs"]
mod mock_cloudflare;

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, AuthState, ConfigService, ConfigStore, Db, EngineTlsAdmin, ManualClock, Scope,
    SessionStore, TokenStore,
};
use dnscraft_tls::{
    AcmeConfig, AcmeDirectoryKind, DnsProvider, DnsProviderKind, EchoClient, EngineDeps,
    FakeAcmeDirectory, KeyType, Secret, TlsConfig, TlsEngine, ZoneConfig,
};
use mock_cloudflare::{MockCloudflare, MockRecord, MockZone};

const TOKEN: &str = "domain-zones-test-token";
const DOMAIN: &str = "example.com";
const ZONE_ID: &str = "zone-example-com";
const EXTRA_ZONE_ID: &str = "zone-extra-org";
const MAX_TTL: Duration = Duration::from_secs(365 * 24 * 3600);
const IDLE: Duration = Duration::from_secs(3600);
const ABSOLUTE: Duration = Duration::from_secs(12 * 3600);

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn temp_dir(label: &str) -> PathBuf {
    let n = TEMP_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-api-domain-zones-{label}-{}-{n}",
        std::process::id(),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn clock() -> Arc<ManualClock> {
    Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ))
}

fn zone_fixture() -> MockZone {
    MockZone {
        id: ZONE_ID.into(),
        name: DOMAIN.into(),
        status: "active".into(),
        name_servers: vec![
            "ada.ns.cloudflare.com".into(),
            "bob.ns.cloudflare.com".into(),
        ],
    }
}

fn tls_cfg() -> TlsConfig {
    TlsConfig {
        public_domain: DOMAIN.into(),
        key_type: KeyType::EcdsaP256,
        renew_before: Duration::from_secs(30 * 24 * 3600),
        acme: AcmeConfig {
            enabled: false,
            directory: AcmeDirectoryKind::Staging,
            email: "admin@example.com".into(),
            account: dnscraft_tls::AcmeAccountConfig {
                tos_agreed: true,
                ..Default::default()
            },
            ..Default::default()
        },
        dns_provider: DnsProvider {
            kind: DnsProviderKind::Cloudflare,
            zones: vec![ZoneConfig {
                name: "extra.org".into(),
                zone_id: Some(EXTRA_ZONE_ID.into()),
            }],
            ..Default::default()
        },
        ..TlsConfig::default()
    }
}

struct Harness {
    router: Router,
    tokens: TokenStore,
    #[allow(dead_code)]
    mock: MockCloudflare,
    #[allow(dead_code)]
    data_dir: PathBuf,
}

async fn harness(with_token: bool) -> Harness {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    mock.add_zone(MockZone {
        id: EXTRA_ZONE_ID.into(),
        name: "extra.org".into(),
        status: "active".into(),
        name_servers: vec!["ns1.cloudflare.com".into()],
    })
    .await;
    mock.add_zone(MockZone {
        id: "zone-unattached".into(),
        name: "unattached.test".into(),
        status: "active".into(),
        name_servers: vec!["ns1.cloudflare.com".into()],
    })
    .await;
    mock.insert_record(MockRecord {
        id: "rec-1".into(),
        zone_id: ZONE_ID.into(),
        name: "www.example.com".into(),
        record_type: "A".into(),
        content: "203.0.113.10".into(),
        ttl: 300,
        proxied: false,
    })
    .await;
    mock.insert_record(MockRecord {
        id: "rec-2".into(),
        zone_id: ZONE_ID.into(),
        name: "mail.example.com".into(),
        record_type: "A".into(),
        content: "203.0.113.20".into(),
        ttl: 300,
        proxied: false,
    })
    .await;

    let data_dir = temp_dir("engine");
    let clock = clock();
    let token = if with_token {
        Secret::new(TOKEN)
    } else {
        Secret::new("")
    };
    let engine = TlsEngine::open_with(
        tls_cfg(),
        &data_dir,
        clock.clone(),
        EngineDeps {
            acme: Arc::new(FakeAcmeDirectory::new()),
            cloudflare_base_url: Some(mock.base_url()),
            echo: EchoClient::unbound().unwrap(),
            token,
            allow_http_for_tests: true,
        },
    )
    .unwrap();
    let engine = Arc::new(engine);

    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    if with_token {
        // Mirrors PUT /tls/cloudflare-token for `has_cloudflare_token`.
        db.kv_set("tls.cloudflare.api_token", TOKEN).await.unwrap();
    }
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        dnscraft_api::ModuleAppliers::default(),
        "node-a",
    ));
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        tokens.clone(),
    );

    let router = AppState::new()
        .with_db(db)
        .with_config_service(service)
        .with_auth(auth)
        .with_tls_admin(Arc::new(EngineTlsAdmin::new(engine)))
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));

    Harness {
        router,
        tokens,
        mock,
        data_dir,
    }
}

async fn request(
    router: &Router,
    method: Method,
    uri: &str,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(token) = bearer {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    let response = router
        .clone()
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

async fn mint(tokens: &TokenStore, scope: Scope) -> String {
    tokens
        .create("tester".into(), scope.as_str().into(), scope, None)
        .await
        .unwrap()
        .plaintext()
        .expose()
        .to_owned()
}

#[tokio::test]
async fn list_attached_zones_without_token_returns_cta_flag() {
    let harness = harness(false).await;
    let viewer = mint(&harness.tokens, Scope::Viewer).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones",
        Some(&viewer),
    )
    .await;

    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["data"]["has_cloudflare_token"], false);
    let zones = body["data"]["zones"].as_array().unwrap();
    assert_eq!(zones.len(), 2);
    assert_eq!(zones[0]["name"], DOMAIN);
    assert_eq!(zones[0]["source"], "public_domain");
    assert_eq!(zones[1]["name"], "extra.org");
    assert_eq!(zones[1]["source"], "dns_provider");
    assert_eq!(zones[1]["id"], EXTRA_ZONE_ID);
    assert!(body["data"].get("discoverable").is_none());
}

#[tokio::test]
async fn list_with_token_enriches_attached_and_discover_is_admin_only() {
    let harness = harness(true).await;
    let viewer = mint(&harness.tokens, Scope::Viewer).await;
    let admin = mint(&harness.tokens, Scope::Admin).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones",
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["data"]["has_cloudflare_token"], true);
    let zones = body["data"]["zones"].as_array().unwrap();
    assert_eq!(zones[0]["id"], ZONE_ID);
    assert_eq!(zones[0]["status"], "active");
    assert!(
        zones[0]["name_servers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|ns| ns == "ada.ns.cloudflare.com")
    );

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones?discover=1",
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::FORBIDDEN);
    assert_eq!(body["error"]["code"], "control_api.auth.insufficient_scope");

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones?discover=1",
        Some(&admin),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    let discoverable = body["data"]["discoverable"].as_array().unwrap();
    assert!(discoverable.iter().any(|z| z["id"] == "zone-unattached"));
    assert!(discoverable.iter().any(|z| z["id"] == ZONE_ID));
}

#[tokio::test]
async fn discover_without_token_returns_stable_secret_missing() {
    let harness = harness(false).await;
    let admin = mint(&harness.tokens, Scope::Admin).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones?discover=1",
        Some(&admin),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "tls.secret.missing");
}

#[tokio::test]
async fn records_paginated_and_filtered_for_attached_zone() {
    let harness = harness(true).await;
    let viewer = mint(&harness.tokens, Scope::Viewer).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        &format!("/api/v1/domain-zones/{ZONE_ID}/records?page=1&per_page=1"),
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["page"], 1);
    assert_eq!(body["data"]["per_page"], 1);
    assert_eq!(body["data"]["total_count"], 2);
    assert_eq!(body["data"]["total_pages"], 2);
    assert_eq!(body["data"]["records"].as_array().unwrap().len(), 1);

    let (code, body) = request(
        &harness.router,
        Method::GET,
        &format!("/api/v1/domain-zones/{ZONE_ID}/records?name_substr=mail"),
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::OK, "{body}");
    let records = body["data"]["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["name"], "mail.example.com");
    assert_eq!(records[0]["record_type"], "A");
    assert_eq!(records[0]["content"], "203.0.113.20");
    assert_eq!(records[0]["proxied"], false);
}

#[tokio::test]
async fn records_unknown_or_unattached_zone_is_not_found() {
    let harness = harness(true).await;
    let viewer = mint(&harness.tokens, Scope::Viewer).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones/zone-unattached/records",
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");

    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/domain-zones/does-not-exist/records",
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::NOT_FOUND);
    assert_eq!(body["error"]["code"], "control_api.not_found");
}

#[tokio::test]
async fn records_without_token_returns_stable_secret_missing() {
    let harness = harness(false).await;
    let viewer = mint(&harness.tokens, Scope::Viewer).await;

    let (code, body) = request(
        &harness.router,
        Method::GET,
        &format!("/api/v1/domain-zones/{EXTRA_ZONE_ID}/records"),
        Some(&viewer),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "tls.secret.missing");
}

#[tokio::test]
async fn list_without_tls_admin_is_not_ready() {
    let clock = clock();
    let db = Db::open_in_memory(clock.clone()).await.unwrap();
    let tokens = TokenStore::new(db.clone(), MAX_TTL);
    let auth = AuthState::new(
        SessionStore::new(db.clone(), IDLE, ABSOLUTE),
        tokens.clone(),
    );
    let router = AppState::new()
        .with_auth(auth)
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let viewer = mint(&tokens, Scope::Viewer).await;

    let (code, body) = request(&router, Method::GET, "/api/v1/domain-zones", Some(&viewer)).await;
    assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"]["code"], "control_api.not_ready");
}
