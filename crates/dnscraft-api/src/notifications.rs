//! TLS webhook notifications (control-api Q26).
//!
//! One JSON `POST` to the configured `tls.notifications.webhook_url` on
//! certificate expiry and DynDNS failure. SMTP is deliberately out of scope;
//! the webhook can fan out to any alerting system. The client reuses the
//! workspace `reqwest` build with the rustls ring provider (no native-tls,
//! aws-lc or OpenSSL).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};

/// `tls.cert.expiring` event name.
pub(crate) const EVENT_CERT_EXPIRING: &str = "tls.cert.expiring";
/// `tls.dyndns.failure` event name.
pub(crate) const EVENT_DYNDNS_FAILURE: &str = "tls.dyndns.failure";

/// A webhook destination parsed from the stored `tls.notifications` object.
pub(crate) struct TlsWebhook {
    client: reqwest::Client,
    url: String,
    on_expiry: bool,
    on_dyndns_failure: bool,
}

impl TlsWebhook {
    /// Builds a webhook from a `tls` config section, or `None` when no
    /// webhook is configured.
    pub(crate) fn from_tls_section(tls: &Value) -> Option<Self> {
        let notifications = tls.get("notifications")?;
        let url = notifications
            .get("webhook_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|url| !url.is_empty())?;
        let parsed = url::Url::parse(url).ok()?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return None;
        }
        Some(Self {
            client: ring_client()?,
            url: url.to_owned(),
            on_expiry: notifications
                .get("on_expiry")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            on_dyndns_failure: notifications
                .get("on_dyndns_failure")
                .and_then(Value::as_bool)
                .unwrap_or(true),
        })
    }

    /// Whether certificate-expiry events are enabled.
    pub(crate) fn on_expiry(&self) -> bool {
        self.on_expiry
    }

    /// Whether DynDNS-failure events are enabled.
    pub(crate) fn on_dyndns_failure(&self) -> bool {
        self.on_dyndns_failure
    }

    /// Sends one event. Failures are logged, never surfaced to the caller: a
    /// broken webhook must not turn a successful TLS action into an error.
    pub(crate) async fn send(&self, event: &str, code: &str, message: &str, time: &str) {
        let body = json!({
            "event": event,
            "code": code,
            "message": message,
            "time": time,
        });
        let response = self
            .client
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await;
        match response {
            Ok(response) if !response.status().is_success() => {
                tracing::warn!(
                    %event,
                    status = %response.status(),
                    "TLS webhook returned a non-success status"
                );
            }
            Ok(_) => {}
            Err(error) => {
                tracing::warn!(%event, error = %error, "TLS webhook delivery failed");
            }
        }
    }
}

/// Ring-backed, redirect-free HTTP client for the webhook.
fn ring_client() -> Option<reqwest::Client> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .ok()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .build()
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::Json;
    use axum::Router;
    use axum::extract::State;
    use axum::routing::post;
    use tokio::net::TcpListener;

    use super::*;

    #[test]
    fn no_webhook_without_a_url_or_with_a_non_http_scheme() {
        assert!(TlsWebhook::from_tls_section(&json!({})).is_none());
        assert!(TlsWebhook::from_tls_section(&json!({"notifications": {}})).is_none());
        assert!(
            TlsWebhook::from_tls_section(
                &json!({"notifications": {"webhook_url": "file:///etc/passwd"}})
            )
            .is_none()
        );
    }

    #[test]
    fn flags_default_to_enabled() {
        let webhook = TlsWebhook::from_tls_section(
            &json!({"notifications": {"webhook_url": "http://127.0.0.1:1/hook"}}),
        )
        .expect("webhook");
        assert!(webhook.on_expiry());
        assert!(webhook.on_dyndns_failure());
    }

    /// Starts a loopback receiver and returns its URL plus the captured bodies.
    async fn receiver() -> (String, Arc<Mutex<Vec<Value>>>) {
        async fn capture(State(received): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>) {
            received.lock().unwrap().push(body);
        }

        let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/hook", post(capture))
            .with_state(received.clone());
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind receiver");
        let address = listener.local_addr().expect("receiver address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{address}/hook"), received)
    }

    #[tokio::test]
    async fn sends_one_json_post_for_an_expiry_event() {
        let (url, received) = receiver().await;
        let webhook = TlsWebhook::from_tls_section(&json!({
            "notifications": { "webhook_url": url }
        }))
        .expect("webhook");

        webhook
            .send(
                EVENT_CERT_EXPIRING,
                "tls.cert.expiring",
                "certificate expires in 3 days",
                "2026-10-27T00:00:00Z",
            )
            .await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(body) = received.lock().unwrap().first().cloned() {
                assert_eq!(body["event"], EVENT_CERT_EXPIRING);
                assert_eq!(body["code"], "tls.cert.expiring");
                assert_eq!(body["time"], "2026-10-27T00:00:00Z");
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "webhook POST never arrived"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(received.lock().unwrap().len(), 1, "exactly one POST");
    }
}
