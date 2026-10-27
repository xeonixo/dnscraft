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

/// Limits and allow-lists applied by [`validate_mcp_request`].
#[derive(Debug, Clone, Copy)]
pub struct RequestLimits<'a> {
    /// Largest accepted request body, in bytes.
    pub max_body_bytes: usize,
    /// Origins accepted when an `Origin` header is present.
    pub allowed_origins: &'a [String],
    /// Protocol versions accepted in `MCP-Protocol-Version`.
    pub supported_versions: &'a [String],
    /// Whether a missing `MCP-Protocol-Version` is accepted (legacy mode).
    pub allow_missing_version: bool,
}

/// Why [`validate_mcp_request`] rejected a request.
///
/// The caller maps a rejection to the HTTP status and JSON body the endpoint
/// has always returned; the variant keeps only the values the body needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestRejection {
    /// The request method was not `POST`.
    MethodNotAllowed {
        /// The rejected method.
        method: String,
    },
    /// The declared or buffered body exceeds [`RequestLimits::max_body_bytes`].
    PayloadTooLarge {
        /// The configured limit, echoed in the error body.
        limit_bytes: usize,
    },
    /// `Origin` was present and not in the allow-list.
    InvalidOrigin,
    /// `MCP-Protocol-Version` was missing (stateless mode), duplicated or
    /// unsupported. `requested` echoes the header value, `None` when it was
    /// absent or not valid UTF-8.
    UnsupportedVersion {
        /// The version the client asked for, if it could be read.
        requested: Option<String>,
    },
}

/// Apply the transport pre-checks that do not need the streaming body.
///
/// Pure and synchronous: no I/O, no awaits and no copy of `headers` or the
/// body. Checks run in the transport's historical order: method, body size,
/// origin, protocol version.
///
/// `body_len` is the number of body bytes already known to the caller. The
/// tower layer passes `0` because rmcp streams the body and enforces the cap
/// while reading; the fuzz target passes the buffered length. The declared
/// `Content-Length` is always checked from `headers`, as before.
///
/// # Errors
///
/// Returns the first failing [`RequestRejection`].
pub fn validate_mcp_request(
    method: &str,
    headers: &HeaderMap,
    body_len: usize,
    limits: &RequestLimits<'_>,
) -> Result<(), RequestRejection> {
    if method != Method::POST.as_str() {
        return Err(RequestRejection::MethodNotAllowed {
            method: method.to_owned(),
        });
    }
    if body_len > limits.max_body_bytes || oversized_declared(headers, limits.max_body_bytes) {
        return Err(RequestRejection::PayloadTooLarge {
            limit_bytes: limits.max_body_bytes,
        });
    }
    if !origin_allowed(headers, limits.allowed_origins) {
        return Err(RequestRejection::InvalidOrigin);
    }
    if let Some(requested) = version_rejection(headers, limits) {
        return Err(RequestRejection::UnsupportedVersion { requested });
    }
    Ok(())
}

/// Whether `Content-Length` declares more than `max` bytes.
///
/// An unparsable or missing header is left to rmcp, matching the transport's
/// previous behaviour.
fn oversized_declared(headers: &HeaderMap, max: usize) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|declared| declared > max as u64)
}

/// Whether every `Origin` header value is allowed; an absent header is valid.
fn origin_allowed(headers: &HeaderMap, allowed: &[String]) -> bool {
    let mut values = headers.get_all(ORIGIN_HEADER).iter();
    if values.next().is_none() {
        return true;
    }
    headers.get_all(ORIGIN_HEADER).iter().all(|value| {
        value
            .to_str()
            .is_ok_and(|value| allowed.iter().any(|candidate| candidate == value))
    })
}

/// The requested version when the header is missing, duplicated or unsupported.
///
/// Returns `None` when the header passes validation, and `Some(None)` when the
/// rejection has no readable requested value.
fn version_rejection(headers: &HeaderMap, limits: &RequestLimits<'_>) -> Option<Option<String>> {
    let mut values = headers.get_all(VERSION_HEADER).iter();
    let Some(first) = values.next() else {
        // Legacy handshakes may omit the header; stateless requests may not.
        return (!limits.allow_missing_version).then_some(None);
    };
    if values.next().is_some() {
        return Some(Some("<duplicate>".to_owned()));
    }
    match first.to_str() {
        Ok(value)
            if limits
                .supported_versions
                .iter()
                .any(|supported| supported == value) =>
        {
            None
        }
        Ok(value) => Some(Some(value.to_owned())),
        Err(_) => Some(None),
    }
}

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
            let limits = RequestLimits {
                max_body_bytes: this.config.max_request_body_size,
                allowed_origins: &this.config.allowed_origins,
                supported_versions: &this.supported_versions,
                allow_missing_version: this.config.legacy_session_mode,
            };
            // The body is still streaming here; rmcp enforces the cap on the
            // bytes it reads, so only the declared length is known.
            if let Err(rejection) =
                validate_mcp_request(method.as_str(), request.headers(), 0, &limits)
            {
                return Ok(rejection_response(
                    rejection,
                    &path,
                    &this.supported_versions,
                ));
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

/// Build the response the endpoint has always returned for a rejection.
fn rejection_response(
    rejection: RequestRejection,
    path: &str,
    supported: &[String],
) -> Response<Body> {
    match rejection {
        RequestRejection::MethodNotAllowed { method } => envelope(
            StatusCode::METHOD_NOT_ALLOWED,
            "control_api.method_not_allowed",
            json!({ "method": method, "path": path }),
        ),
        RequestRejection::PayloadTooLarge { limit_bytes } => envelope(
            StatusCode::PAYLOAD_TOO_LARGE,
            "control_api.payload_too_large",
            json!({ "limit_bytes": limit_bytes }),
        ),
        RequestRejection::InvalidOrigin => envelope(
            StatusCode::FORBIDDEN,
            "control_api.auth.invalid_origin",
            json!({}),
        ),
        RequestRejection::UnsupportedVersion { requested } => {
            unsupported_version(requested.as_deref(), supported)
        }
    }
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::http::{HeaderName, HeaderValue};

    fn limits<'a>(
        allowed_origins: &'a [String],
        supported_versions: &'a [String],
        allow_missing_version: bool,
    ) -> RequestLimits<'a> {
        RequestLimits {
            max_body_bytes: 1024,
            allowed_origins,
            supported_versions,
            allow_missing_version,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    #[test]
    fn accepts_a_stateless_post() {
        let origins = ["https://ui.example.com".to_owned()];
        let versions = ["2026-07-28".to_owned()];
        let headers = headers(&[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("Origin", "https://ui.example.com"),
        ]);
        assert_eq!(
            validate_mcp_request("POST", &headers, 16, &limits(&origins, &versions, false)),
            Ok(())
        );
    }

    #[test]
    fn rejects_non_post_before_anything_else() {
        let headers = headers(&[("Content-Length", "999999")]);
        assert_eq!(
            validate_mcp_request("GET", &headers, 0, &limits(&[], &[], false)),
            Err(RequestRejection::MethodNotAllowed {
                method: "GET".to_owned()
            })
        );
    }

    #[test]
    fn rejects_declared_and_buffered_oversize_bodies() {
        let declared = headers(&[("Content-Length", "1025")]);
        assert_eq!(
            validate_mcp_request("POST", &declared, 0, &limits(&[], &[], true)),
            Err(RequestRejection::PayloadTooLarge { limit_bytes: 1024 })
        );
        assert_eq!(
            validate_mcp_request("POST", &HeaderMap::new(), 1025, &limits(&[], &[], true)),
            Err(RequestRejection::PayloadTooLarge { limit_bytes: 1024 })
        );
        // Non-numeric lengths are rmcp's problem, as before.
        let bogus = headers(&[("Content-Length", "lots")]);
        assert!(validate_mcp_request("POST", &bogus, 0, &limits(&[], &[], true)).is_ok());
    }

    #[test]
    fn rejects_disallowed_origin_but_accepts_absent_and_allowed() {
        let origins = ["https://ui.example.com".to_owned()];
        assert!(
            validate_mcp_request("POST", &HeaderMap::new(), 0, &limits(&origins, &[], true))
                .is_ok()
        );
        let allowed = headers(&[("Origin", "https://ui.example.com")]);
        assert!(validate_mcp_request("POST", &allowed, 0, &limits(&origins, &[], true)).is_ok());
        let rejected = headers(&[
            ("Origin", "https://ui.example.com"),
            ("Origin", "https://evil.example"),
        ]);
        assert_eq!(
            validate_mcp_request("POST", &rejected, 0, &limits(&origins, &[], true)),
            Err(RequestRejection::InvalidOrigin)
        );
    }

    #[test]
    fn versions_are_required_outside_legacy_mode_and_must_be_supported() {
        let versions = ["2026-07-28".to_owned()];
        assert_eq!(
            validate_mcp_request("POST", &HeaderMap::new(), 0, &limits(&[], &versions, false)),
            Err(RequestRejection::UnsupportedVersion { requested: None })
        );
        assert!(
            validate_mcp_request("POST", &HeaderMap::new(), 0, &limits(&[], &versions, true))
                .is_ok()
        );
        let unsupported = headers(&[("MCP-Protocol-Version", "2099-01-01")]);
        assert_eq!(
            validate_mcp_request("POST", &unsupported, 0, &limits(&[], &versions, true)),
            Err(RequestRejection::UnsupportedVersion {
                requested: Some("2099-01-01".to_owned())
            })
        );
        let duplicate = headers(&[
            ("MCP-Protocol-Version", "2026-07-28"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ]);
        assert_eq!(
            validate_mcp_request("POST", &duplicate, 0, &limits(&[], &versions, true)),
            Err(RequestRejection::UnsupportedVersion {
                requested: Some("<duplicate>".to_owned())
            })
        );
    }
}
