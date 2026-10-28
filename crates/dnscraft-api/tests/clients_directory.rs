//! GA6: `GET /api/v1/clients` and `POST /api/v1/clients/sync` over a
//! `ClientDirectory` adapter (the binary wraps the real `ClientEngine`).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, ClientDirectory, ConfigService, ConfigStore, ControlApiError, Db,
    DirectoryClient, ManualClock, ModuleAppliers, SyncSummary,
};

/// A directory with fixed entries; `fail` makes the sync report a backoff.
struct FakeDirectory {
    fail: bool,
}

#[async_trait::async_trait]
impl ClientDirectory for FakeDirectory {
    fn clients(&self) -> Vec<DirectoryClient> {
        vec![
            DirectoryClient {
                id: "unifi-1".into(),
                name: "Laptop".into(),
                dns_label: "laptop".into(),
                local_domain: "home.example.net".into(),
                source: "unifi",
                ips: vec!["192.0.2.20".parse::<IpAddr>().unwrap()],
                macs: vec!["aa:bb:cc:dd:ee:ff".into()],
                vlan: Some(20),
                online: true,
                last_seen: None,
            },
            DirectoryClient {
                id: "manual-1".into(),
                name: "Printer".into(),
                dns_label: "printer".into(),
                local_domain: "home.example.net".into(),
                source: "manual",
                ips: Vec::new(),
                macs: Vec::new(),
                vlan: None,
                online: false,
                last_seen: Some("2026-10-28T08:00:00Z".into()),
            },
        ]
    }

    async fn sync(&self) -> Result<SyncSummary, ControlApiError> {
        if self.fail {
            return Err(ControlApiError::Module {
                code: "clients.sync.backoff",
                params: None,
            });
        }
        Ok(SyncSummary {
            generation: 7,
            rebuilt: true,
            client_count: 2,
            ip_conflicts: 0,
        })
    }
}

async fn state(directory: Option<FakeDirectory>) -> AppState {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db),
        ModuleAppliers::default(),
        "node-a",
    ));
    let state = AppState::new().with_config_service(service);
    match directory {
        Some(dir) => state.with_clients(Arc::new(dir)),
        None => state,
    }
}

async fn call(state: &AppState, method: &str, uri: &str) -> (StatusCode, Value) {
    let router = state
        .clone()
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn directory_entries_are_listed_in_the_public_shape() {
    let state = state(Some(FakeDirectory { fail: false })).await;
    let (status, body) = call(&state, "GET", "/api/v1/clients").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let clients = body["data"]["clients"].as_array().unwrap();
    assert_eq!(clients.len(), 2);
    assert_eq!(clients[0]["name"], "Laptop");
    assert_eq!(clients[0]["source"], "unifi");
    assert_eq!(clients[0]["ips"], json!(["192.0.2.20"]));
    assert_eq!(clients[0]["vlan"], json!(20));
    assert_eq!(clients[1]["source"], "manual");
    assert_eq!(clients[1]["last_seen"], "2026-10-28T08:00:00Z");
}

#[tokio::test]
async fn sync_returns_the_report_from_the_directory() {
    let state = state(Some(FakeDirectory { fail: false })).await;
    let (status, body) = call(&state, "POST", "/api/v1/clients/sync").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["generation"], 7);
    assert_eq!(body["data"]["rebuilt"], true);
    assert_eq!(body["data"]["client_count"], 2);
}

#[tokio::test]
async fn sync_errors_keep_the_clients_code() {
    let state = state(Some(FakeDirectory { fail: true })).await;
    let (_, body) = call(&state, "POST", "/api/v1/clients/sync").await;
    assert_eq!(body["error"]["code"], "clients.sync.backoff");
}

#[tokio::test]
async fn without_a_directory_sync_is_not_configured_and_list_is_empty() {
    let state = state(None).await;
    let (status, body) = call(&state, "POST", "/api/v1/clients/sync").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "clients.sync.not_configured");
    let (_, body) = call(&state, "GET", "/api/v1/clients").await;
    assert!(body["data"]["clients"].as_array().unwrap().is_empty());
}
