//! `/api/v1/tls/*` admin endpoints against a fake engine.
//!
//! The fake [`TlsAdmin`] records each action and can fail with a stable
//! `tls.*` code, so the tests exercise the HTTP contract, the audit path and
//! secret hygiene without a real ACME/Cloudflare network.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use dnscraft_api::{
    AppState, Audit, CertSource, ConfigService, ConfigStore, ControlApiError, Db, ManualClock,
    ModuleAppliers, Secret, TlsActionFuture, TlsAdmin, TlsMode, TlsStatus, TlsStatusProvider,
    TlsValueFuture,
};

const NOW: u64 = 1_700_000_000;
const DAY: u64 = 24 * 3600;

fn at(seconds: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(seconds)
}

fn rfc3339(seconds: u64) -> String {
    chrono::DateTime::from_timestamp(seconds as i64, 0)
        .unwrap()
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A fixed status provider.
struct StaticStatus(TlsStatus);

impl TlsStatusProvider for StaticStatus {
    fn status(&self) -> TlsStatus {
        self.0.clone()
    }
}

/// A recording fake engine.
struct FakeAdmin {
    calls: Arc<Mutex<Vec<String>>>,
    fail: Option<&'static str>,
}

impl FakeAdmin {
    fn record(&self, call: impl Into<String>) {
        self.calls.lock().unwrap().push(call.into());
    }

    fn action(&self, name: &str) -> TlsActionFuture<'_> {
        self.record(name);
        let fail = self.fail;
        Box::pin(async move {
            match fail {
                Some(code) => Err(ControlApiError::Module { code, params: None }),
                None => Ok(()),
            }
        })
    }

    fn value(&self, name: &str, value: Value) -> TlsValueFuture<'_> {
        self.record(name);
        let fail = self.fail;
        Box::pin(async move {
            match fail {
                Some(code) => Err(ControlApiError::Module { code, params: None }),
                None => Ok(value),
            }
        })
    }
}

impl TlsAdmin for FakeAdmin {
    fn upload_manual_cert(
        &self,
        cert_pem: &str,
        key_pem: &Secret,
        chain_pem: Option<&str>,
    ) -> TlsActionFuture<'_> {
        // Record only whether the key looks like a key; the secret itself must
        // never be retained by the fake.
        self.record(format!(
            "upload:cert={}:key={}:chain={}",
            cert_pem.contains("BEGIN CERTIFICATE"),
            key_pem.expose().contains("PRIVATE KEY"),
            chain_pem.is_some(),
        ));
        let fail = self.fail;
        Box::pin(async move {
            match fail {
                Some(code) => Err(ControlApiError::Module { code, params: None }),
                None => Ok(()),
            }
        })
    }

    fn revoke(&self, reason: &str) -> TlsActionFuture<'_> {
        self.record(format!("revoke:{reason}"));
        let fail = self.fail;
        Box::pin(async move {
            match fail {
                Some(code) => Err(ControlApiError::Module { code, params: None }),
                None => Ok(()),
            }
        })
    }

    fn rotate_key(&self) -> TlsActionFuture<'_> {
        self.action("rotate")
    }

    fn renew_now(&self) -> TlsActionFuture<'_> {
        self.action("renew")
    }

    fn dyndns_now(&self) -> TlsValueFuture<'_> {
        self.value("dyndns", json!({ "changed": true }))
    }

    fn preflight(&self) -> TlsValueFuture<'_> {
        self.value("preflight", json!({ "ok": true, "checks": [] }))
    }

    fn export_cert(&self) -> Result<String, ControlApiError> {
        self.record("export");
        Ok("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_owned())
    }

    fn account_status(&self) -> TlsValueFuture<'_> {
        self.value(
            "account",
            json!({ "account_url": "https://acme.example/acct/1" }),
        )
    }

    fn order_status(&self) -> Result<Value, ControlApiError> {
        self.record("order");
        Ok(json!({ "status": "valid" }))
    }

    fn record_inventory(&self) -> TlsValueFuture<'_> {
        self.value("records", json!({ "records": [] }))
    }

    fn dyndns_audit(&self) -> TlsValueFuture<'_> {
        self.value("audit", json!({ "entries": [] }))
    }
}

struct Harness {
    router: Router,
    db: Db,
    calls: Arc<Mutex<Vec<String>>>,
}

async fn harness_with(status: TlsStatus, fail: Option<&'static str>) -> Harness {
    let clock = Arc::new(ManualClock::new(at(NOW)));
    let db = Db::open_in_memory(clock).await.unwrap();
    let service = Arc::new(ConfigService::new(
        ConfigStore::new(db.clone()),
        Audit::new(db.clone()),
        ModuleAppliers::default(),
        "node-a",
    ));
    let calls: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let router = AppState::new()
        .with_config_service(service)
        .with_tls(Arc::new(StaticStatus(status)))
        .with_tls_admin(Arc::new(FakeAdmin {
            calls: Arc::clone(&calls),
            fail,
        }))
        .router()
        // The rate-limiter middleware extracts the peer address; without a
        // ConnectInfo the request would fail before reaching the handler.
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40_000))));
    Harness { router, db, calls }
}

async fn harness() -> Harness {
    harness_with(TlsStatus::new(TlsMode::SelfSigned, "fp"), None).await
}

async fn request(
    router: &Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let body = body.map_or_else(Body::empty, |value| Body::from(value.to_string()));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body)
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn calls(harness: &Harness) -> Vec<String> {
    harness.calls.lock().unwrap().clone()
}

#[tokio::test]
async fn status_returns_the_typed_dto_with_rfc3339_times() {
    let mut status = TlsStatus::new(TlsMode::Manual, "leaf-fp");
    status.source = CertSource::Manual;
    status.not_after = Some(at(NOW + DAY));
    status.chain = vec!["-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".into()];
    status.key_usage = vec!["digitalSignature".into()];
    let harness = harness_with(status, None).await;

    let (code, body) = request(&harness.router, Method::GET, "/api/v1/tls/status", None).await;

    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["data"]["mode"], "manual");
    assert_eq!(body["data"]["source"], "manual");
    assert_eq!(body["data"]["fingerprint"], "leaf-fp");
    assert_eq!(body["data"]["not_after"], rfc3339(NOW + DAY));
    assert_eq!(body["data"]["key_usage"][0], "digitalSignature");
    assert!(
        body["data"]["chain"][0]
            .as_str()
            .unwrap()
            .contains("CERTIFICATE")
    );
    assert!(!body.to_string().contains("PRIVATE KEY"));
}

#[tokio::test]
async fn manual_certificate_upload_switches_to_manual_and_audits_without_echoing_the_key() {
    let harness = harness().await;
    let (code, body) = request(
        &harness.router,
        Method::PUT,
        "/api/v1/tls/certificate",
        Some(json!({
            "cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "key_pem": "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n",
        })),
    )
    .await;

    assert_eq!(code, StatusCode::OK);
    assert_eq!(body["data"]["mode"], "manual");
    let text = body.to_string();
    assert!(!text.contains("PRIVATE KEY") && !text.contains("MIIEvQ"));

    assert_eq!(
        calls(&harness),
        vec!["upload:cert=true:key=true:chain=false"]
    );
    let records = harness.db.audit_list(10, 0).await.unwrap();
    assert!(
        records
            .iter()
            .any(|record| record.action == "tls.certificate.upload" && record.result == "ok")
    );
}

#[tokio::test]
async fn manual_certificate_upload_rejects_non_pem_material() {
    let harness = harness().await;
    let (code, body) = request(
        &harness.router,
        Method::PUT,
        "/api/v1/tls/certificate",
        Some(json!({ "cert_pem": "not a cert", "key_pem": "not a key" })),
    )
    .await;

    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "tls.cert.manual.invalid");
    assert!(calls(&harness).is_empty());
}

#[tokio::test]
async fn certificate_export_returns_a_fullchain_pem_envelope() {
    let harness = harness().await;
    let (code, body) = request(
        &harness.router,
        Method::GET,
        "/api/v1/tls/certificate",
        None,
    )
    .await;

    assert_eq!(code, StatusCode::OK);
    assert!(
        body["data"]["fullchain_pem"]
            .as_str()
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    assert!(!body.to_string().contains("PRIVATE KEY"));
}

#[tokio::test]
async fn renew_rotate_preflight_and_dyndns_delegate_and_audit_mutations() {
    let harness = harness().await;

    for (method, path, action) in [
        (Method::POST, "/api/v1/tls/renew", "tls.cert.renew"),
        (Method::POST, "/api/v1/tls/rotate", "tls.cert.rotate"),
        (Method::POST, "/api/v1/tls/dyndns", "tls.dyndns.update"),
    ] {
        let (code, _) = request(&harness.router, method, path, None).await;
        assert_eq!(code, StatusCode::OK, "{path}");
        let records = harness.db.audit_list(20, 0).await.unwrap();
        assert!(
            records.iter().any(|record| record.action == action),
            "missing audit action {action}"
        );
    }

    let (code, body) = request(&harness.router, Method::POST, "/api/v1/tls/preflight", None).await;
    assert_eq!(code, StatusCode::OK);
    assert!(body["data"]["ok"].as_bool().unwrap());
}

#[tokio::test]
async fn revoke_requires_a_reason_and_records_it() {
    let harness = harness().await;

    let (code, body) = request(
        &harness.router,
        Method::POST,
        "/api/v1/tls/revoke",
        Some(json!({ "reason": "key compromise" })),
    )
    .await;
    assert_eq!(code, StatusCode::OK);
    assert!(body["data"]["revoked"].as_bool().unwrap());
    assert_eq!(calls(&harness), vec!["revoke:key compromise"]);

    let (code, body) = request(
        &harness.router,
        Method::POST,
        "/api/v1/tls/revoke",
        Some(json!({ "reason": "  " })),
    )
    .await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "tls.config.invalid");
}

#[tokio::test]
async fn read_reports_are_mounted_and_return_the_engine_payload() {
    let harness = harness().await;

    for (path, key) in [
        ("/api/v1/tls/records", "records"),
        ("/api/v1/tls/account", "account_url"),
        ("/api/v1/tls/order", "status"),
        ("/api/v1/tls/audit", "entries"),
    ] {
        let (code, body) = request(&harness.router, Method::GET, path, None).await;
        assert_eq!(code, StatusCode::OK, "{path}");
        assert!(body["data"].get(key).is_some(), "{path} missing {key}");
    }
}

#[tokio::test]
async fn engine_tls_errors_are_forwarded_unchanged_and_audited_as_failures() {
    let harness = harness_with(
        TlsStatus::new(TlsMode::SelfSigned, "fp"),
        Some("tls.acme.order_pending"),
    )
    .await;

    let (code, body) = request(&harness.router, Method::POST, "/api/v1/tls/renew", None).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"]["code"], "tls.acme.order_pending");

    let records = harness.db.audit_list(10, 0).await.unwrap();
    assert!(records.iter().any(|record| {
        record.action == "tls.cert.renew"
            && record.result == "error"
            && record.error_code.as_deref() == Some("tls.acme.order_pending")
    }));
}
