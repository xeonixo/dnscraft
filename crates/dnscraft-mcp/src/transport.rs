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

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Response, StatusCode, header};
use axum::response::{IntoResponse, Json};
use rmcp::model::ProtocolVersion;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use serde_json::{Value, json};
use tower::Service;

use crate::backend::McpBackend;
use crate::config::McpConfig;
use crate::tools::McpServer;

const VERSION_HEADER: &str = "MCP-Protocol-Version";
const ORIGIN_HEADER: &str = "Origin";

/// The protocol/transport service returned by [`crate::service`].
#[derive(Clone)]
pub struct McpTransport {
    inner: StreamableHttpService<McpServer, LocalSessionManager>,
    config: McpConfig,
    supported_versions: Vec<String>,
}

impl McpTransport {
    fn new(
        inner: StreamableHttpService<McpServer, LocalSessionManager>,
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
            config,
            supported_versions,
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

    fn call(&mut self, request: Request<Body>) -> Self::Future {
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

            match tokio::time::timeout(this.config.request_timeout, inner.call(request)).await {
                Ok(Ok(response)) => Ok(normalize(
                    response.map(Body::new),
                    &this.config,
                    method,
                    &path,
                )),
                Ok(Err(never)) => match never {},
                Err(_) => Ok(envelope(
                    StatusCode::GATEWAY_TIMEOUT,
                    "control_api.internal",
                    json!({
                        "reason": "timeout",
                        "timeout_seconds": this.config.request_timeout.as_secs(),
                    }),
                )),
            }
        })
    }
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
    McpTransport::new(inner, config)
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
