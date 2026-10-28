//! WP1: `GET /api/v1/alerts` assembles active alerts from the TLS status and
//! the filter-list status.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Request, StatusCode, header};
use serde_json::Value;
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, AuthState, Db, ManualClock, Scope, SessionStore, TlsMode, TlsStatus,
    TlsStatusProvider, TokenStore,
};

/// A TLS provider reporting a fixed status.
struct FixedTls(TlsStatus);

impl TlsStatusProvider for FixedTls {
    fn status(&self) -> TlsStatus {
        self.0.clone()
    }
}

async fn get_alerts(state: AppState, bearer: &str) -> (StatusCode, Value) {
    let router = state
        .router()
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    let req = Request::builder()
        .uri("/api/v1/alerts")
        .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap();
    let res = router.oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn viewer_state(tls: Option<TlsStatus>) -> (AppState, String) {
    let clock = Arc::new(ManualClock::new(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
    ));
    let db = Db::open_in_memory(clock).await.unwrap();
    let tokens = TokenStore::new(db.clone(), Duration::from_secs(3600));
    let viewer = tokens
        .create("ops".into(), "dash".into(), Scope::Viewer, None)
        .await
        .unwrap();
    let auth = AuthState::new(
        SessionStore::new(
            db.clone(),
            Duration::from_secs(3600),
            Duration::from_secs(7200),
        ),
        tokens,
    );
    let mut state = AppState::new().with_db(db).with_auth(auth);
    if let Some(status) = tls {
        state = state.with_tls(Arc::new(FixedTls(status)));
    }
    (state, viewer.plaintext().expose().to_owned())
}

#[tokio::test]
async fn no_alerts_gives_an_empty_list_for_a_viewer() {
    let (state, viewer) = viewer_state(None).await;
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["active_count"], 0);
    assert!(body["data"]["items"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn a_certificate_inside_the_renewal_window_is_one_warning() {
    let mut tls = TlsStatus::new(TlsMode::Acme, "00".repeat(32));
    tls.cert_expiring = true;
    tls.days_to_expiry = Some(12);
    let (state, viewer) = viewer_state(Some(tls)).await;
    let (status, body) = get_alerts(state, &viewer).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["data"]["active_count"], 1);
    let item = &body["data"]["items"][0];
    assert_eq!(item["id"], "tls.cert.expiring");
    assert_eq!(item["severity"], "warning");
    assert_eq!(item["module"], "tls");
    assert_eq!(item["params"]["days_to_expiry"], 12);
    assert_eq!(item["target_route"], "/tls");
}
