//! Transport conformance layer around the rmcp service.
//!
//! rmcp performs the protocol work (stateless routing, SEP-2243 headers,
//! version negotiation, body streaming) but reports its own rejections as
//! plain text. This layer:
//!
//! - rejects non-POST methods, oversized declared bodies, bad `Origin` and
//!   missing/unsupported `MCP-Protocol-Version` before rmcp runs;
//! - wraps every remaining plain-text rejection in the control-api error
//!   envelope (or, for an unsupported version, a `-32022` JSON-RPC error);
//! - applies `request_timeout` to the whole request.
//!
//! The timeout body has no dedicated SPEC-mcp.md code (the spec only says the
//! request is cancelled), so it uses `control_api.internal` with
//! `{"reason":"timeout"}` and HTTP 504.
//!
//! The caller owns the token rate limiter: 401 responses are counted there
//! (SPEC-mcp.md § Authentication), not in this crate.

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
use axum::response::{IntoResponse, Json};
use rmcp::model::ProtocolVersion;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};
use tower::Service;

use crate::auth::{self, AuthError};
use crate::backend::McpBackend;
use crate::config::McpConfig;
use crate::tools::McpServer;

const VERSION_HEADER: &str = "MCP-Protocol-Version";
const ORIGIN_HEADER: &str = "Origin";

/// The protocol/transport service returned by [`crate::service`].
#[derive(Clone)]
pub struct McpTransport {
    inner: StreamableHttpService<McpServer, LocalSessionManager>,
    backend: Arc<dyn McpBackend>,
    config: McpConfig,
    supported_versions: Vec<String>,
    in_flight: InFlight,
}

impl McpTransport {
    fn new(
        inner: StreamableHttpService<McpServer, LocalSessionManager>,
        backend: Arc<dyn McpBackend>,
        config: McpConfig,
    ) -> Self {
        let supported_versions = if config.legacy_session_mode {
            ProtocolVersion::KNOWN_VERSIONS
                .iter()
                .map(|version| version.as_str().to_owned())
                .collect()
        } else {
            vec![ProtocolVersion::V_2026_07_28.as_str().to_owned()]
        };
        Self {
            inner,
            backend,
            config,
            supported_versions,
            in_flight: InFlight::default(),
        }
    }

    fn reject_oversized(&self, headers: &HeaderMap) -> Option<Response<Body>> {
        let declared = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())?;
        (declared > self.config.max_request_body_size as u64).then(|| {
            envelope(
                StatusCode::PAYLOAD_TOO_LARGE,
                "control_api.payload_too_large",
                json!({ "limit_bytes": self.config.max_request_body_size }),
            )
        })
    }

    fn reject_origin(&self, headers: &HeaderMap) -> Option<Response<Body>> {
        let mut values = headers.get_all(ORIGIN_HEADER).iter();
        values.next()?;
        let allowed = &self.config.allowed_origins;
        let valid = headers.get_all(ORIGIN_HEADER).iter().all(|value| {
            value
                .to_str()
                .is_ok_and(|value| allowed.iter().any(|a| a == value))
        });
        (!valid).then(|| {
            envelope(
                StatusCode::FORBIDDEN,
                "control_api.auth.invalid_origin",
                json!({}),
            )
        })
    }

    fn reject_version(&self, headers: &HeaderMap) -> Option<Response<Body>> {
        let mut values = headers.get_all(VERSION_HEADER).iter();
        let Some(first) = values.next() else {
            // Legacy handshakes may omit the header; stateless requests may not.
            return (!self.config.legacy_session_mode)
                .then(|| unsupported_version(None, &self.supported_versions));
        };
        if values.next().is_some() {
            return Some(unsupported_version(
                Some("<duplicate>"),
                &self.supported_versions,
            ));
        }
        let requested = first.to_str().ok();
        let supported = requested.is_some_and(|value| {
            self.supported_versions
                .iter()
                .any(|supported| supported == value)
        });
        (!supported).then(|| unsupported_version(requested, &self.supported_versions))
    }
}

impl Service<Request<Body>> for McpTransport {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let mut inner = self.inner.clone();
        let this = self.clone();
        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            if method != Method::POST {
                return Ok(envelope(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "control_api.method_not_allowed",
                    json!({ "method": method.as_str(), "path": path }),
                ));
            }
            if let Some(response) = this.reject_oversized(request.headers()) {
                return Ok(response);
            }
            if let Some(response) = this.reject_origin(request.headers()) {
                return Ok(response);
            }
            if let Some(response) = this.reject_version(request.headers()) {
                return Ok(response);
            }

            // One deadline covers token validation and the tool call.
            let deadline = tokio::time::Instant::now() + this.config.request_timeout;
            let token = match tokio::time::timeout_at(
                deadline,
                auth::authenticate(request.headers(), &*this.backend),
            )
            .await
            {
                Ok(Ok(token)) => token,
                Ok(Err(AuthError::Unauthenticated)) => {
                    return Ok(envelope(
                        StatusCode::UNAUTHORIZED,
                        "control_api.auth.unauthenticated",
                        json!({}),
                    ));
                }
                Ok(Err(AuthError::InvalidScope)) => {
                    return Ok(envelope(
                        StatusCode::FORBIDDEN,
                        "control_api.auth.invalid_scope",
                        json!({}),
                    ));
                }
                Ok(Err(AuthError::Internal)) => {
                    return Ok(envelope(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "control_api.internal",
                        json!({ "reason": "token_validation" }),
                    ));
                }
                Err(_) => return Ok(timeout_response(&this.config)),
            };
            let _slot = match this.in_flight.try_acquire(
                &token.token_id,
                this.config.max_concurrent_requests_per_token,
            ) {
                Some(slot) => slot,
                None => {
                    return Ok(envelope(
                        StatusCode::TOO_MANY_REQUESTS,
                        "control_api.rate_limited",
                        json!({ "limit": this.config.max_concurrent_requests_per_token }),
                    ));
                }
            };
            request.extensions_mut().insert(token);

            match tokio::time::timeout_at(deadline, inner.call(request)).await {
                Ok(Ok(response)) => Ok(normalize(
                    response.map(Body::new),
                    &this.config,
                    method,
                    &path,
                )),
                Ok(Err(never)) => match never {},
                Err(_) => Ok(timeout_response(&this.config)),
            }
        })
    }
}

/// Per-token in-flight counters shared by every cloned service instance.
#[derive(Clone, Default)]
struct InFlight {
    counts: Arc<Mutex<HashMap<String, usize>>>,
}

impl InFlight {
    fn try_acquire(&self, token_id: &str, limit: u32) -> Option<InFlightSlot> {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(token_id.to_owned()).or_insert(0);
        if *count >= limit as usize {
            return None;
        }
        *count += 1;
        Some(InFlightSlot {
            counts: Arc::clone(&self.counts),
            token_id: token_id.to_owned(),
        })
    }
}

/// Releases one in-flight slot on completion, error, timeout or disconnect.
struct InFlightSlot {
    counts: Arc<Mutex<HashMap<String, usize>>>,
    token_id: String,
}

impl Drop for InFlightSlot {
    fn drop(&mut self) {
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.token_id) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&self.token_id);
            }
        }
    }
}

fn timeout_response(config: &McpConfig) -> Response<Body> {
    envelope(
        StatusCode::GATEWAY_TIMEOUT,
        "control_api.internal",
        json!({
            "reason": "timeout",
            "timeout_seconds": config.request_timeout.as_secs(),
        }),
    )
}

/// Turn rmcp's plain-text rejections into stable JSON bodies.
fn normalize(
    response: Response<Body>,
    config: &McpConfig,
    method: Method,
    path: &str,
) -> Response<Body> {
    let is_json = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.starts_with("application/json") || value.starts_with("text/event-stream")
        });
    if is_json {
        return response;
    }
    let status = response.status();
    if status == StatusCode::ACCEPTED || status == StatusCode::NO_CONTENT {
        return response;
    }
    match status {
        StatusCode::METHOD_NOT_ALLOWED => envelope(
            status,
            "control_api.method_not_allowed",
            json!({ "method": method.as_str(), "path": path }),
        ),
        StatusCode::PAYLOAD_TOO_LARGE => envelope(
            status,
            "control_api.payload_too_large",
            json!({ "limit_bytes": config.max_request_body_size }),
        ),
        StatusCode::FORBIDDEN => envelope(status, "control_api.auth.invalid_origin", json!({})),
        StatusCode::NOT_FOUND => envelope(status, "control_api.not_found", json!({ "path": path })),
        _ => envelope(
            status,
            "control_api.internal",
            json!({ "reason": format!("http_{}", status.as_u16()) }),
        ),
    }
}

fn envelope(status: StatusCode, code: &'static str, params: Value) -> Response<Body> {
    (
        status,
        Json(json!({ "error": { "code": code, "params": params } })),
    )
        .into_response()
}

fn unsupported_version(requested: Option<&str>, supported: &[String]) -> Response<Body> {
    // `supported` is rmcp's key; `supportedVersions` is the SPEC-mcp.md name.
    // Both are sent so either reader finds the list (ADR 0006 contradiction 2).
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "jsonrpc": "2.0",
            "id": null,
            "error": {
                "code": -32022,
                "message": "UnsupportedProtocolVersionError",
                "data": { "requested": requested, "supported": supported, "supportedVersions": supported },
            }
        })),
    )
        .into_response()
}

/// Build the rmcp service with the DNScraft transport limits.
pub(crate) fn build(backend: std::sync::Arc<dyn McpBackend>, config: McpConfig) -> McpTransport {
    let server_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(config.legacy_session_mode)
        .with_json_response(true)
        .with_max_request_body_bytes(config.max_request_body_size)
        .with_allowed_hosts(allowed_hosts(&config))
        .with_allowed_origins(config.allowed_origins.clone())
        .enforce_origin_validation();
    let server_config_for_server = config.clone();
    let transport_backend = backend.clone();
    let inner = StreamableHttpService::new(
        move || {
            Ok(McpServer::new(
                backend.clone(),
                server_config_for_server.clone(),
            ))
        },
        std::sync::Arc::new(LocalSessionManager::default()),
        server_config,
    );
    McpTransport::new(inner, transport_backend, config)
}

/// Host allowlist: loopback plus every origin host.
///
/// `McpConfig` has no separate hostname key; the browser origins the owner
/// already configures name the public hosts. An empty list leaves rmcp's
/// loopback defaults in place.
fn allowed_hosts(config: &McpConfig) -> Vec<String> {
    let mut hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];
    for origin in &config.allowed_origins {
        let authority = origin
            .split_once("://")
            .map_or(origin.as_str(), |(_, rest)| rest)
            .split('/')
            .next()
            .unwrap_or_default();
        let host = if let Some(rest) = authority.strip_prefix('[') {
            rest.split(']').next().unwrap_or_default()
        } else {
            authority.split(':').next().unwrap_or_default()
        };
        if !host.is_empty() && !hosts.iter().any(|existing| existing == host) {
            hosts.push(host.to_owned());
        }
    }
    hosts
}
