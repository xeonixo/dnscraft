//! `/api/v1/resolver/*` routes: passive upstream health (WX3) and cache flush (WX4).
//!
//! The resolver is node-local. Both routes answer `control_api.not_ready` when
//! the embedding attached no resolver. RBAC maps the GET to viewer and the
//! flush POST to admin (see `auth/roles.rs`).

use std::sync::Arc;

use axum::Extension;
use axum::body::Bytes;
use axum::extract::State;
use axum::response::IntoResponse;
use dnscraft_filtering::DomainName;
use dnscraft_proto::Name;
use dnscraft_resolver::{FlushScope, Resolver, UpstreamHealth, UpstreamState};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{actor, module_error, service};
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::mcp_backend::rfc3339;
use crate::server::AppState;

/// Passive sampling window in seconds. Mirrors the resolver's private window
/// in `dnscraft-resolver` `health.rs`; change both together.
// ponytail: duplicated constant, export it from dnscraft-resolver if it drifts.
const WINDOW_SECONDS: u64 = 300;

/// Stable code for a rejected flush request (bad domain or malformed body).
const FLUSH_INVALID_DOMAIN: &str = "control_api.resolver.flush.invalid_domain";

/// Audit action name for a cache flush.
const FLUSH_AUDIT_ACTION: &str = "resolver.cache.flush";

/// Body of `POST /api/v1/resolver/cache/flush`. An empty body means "all".
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct FlushBody {
    #[serde(default)]
    domain: Option<String>,
}

/// The attached resolver, or `control_api.not_ready` when none was wired.
fn resolver(state: &AppState) -> Result<&Arc<Resolver>, ControlApiError> {
    state.resolver().ok_or_else(|| ControlApiError::NotReady {
        module: "resolver".to_owned(),
    })
}

fn state_name(state: UpstreamState) -> &'static str {
    match state {
        UpstreamState::Up => "up",
        UpstreamState::Degraded => "degraded",
        UpstreamState::Down => "down",
        UpstreamState::Unknown => "unknown",
    }
}

/// One `items[]` entry of the upstream listing.
fn upstream_json(health: &UpstreamHealth) -> Value {
    let is_forward = health.kind == "forward_target";
    let rtt_ms = match (health.rtt_p50_ms, health.rtt_p95_ms) {
        (Some(p50), Some(p95)) => json!({ "p50": p50, "p95": p95 }),
        _ => Value::Null,
    };
    json!({
        "name": health.name,
        "kind": health.kind,
        "zone": health.zone,
        "address": is_forward.then_some(&health.name),
        "protocol": health.protocol,
        "state": state_name(health.state),
        "rtt_ms": rtt_ms,
        "success_rate": health.success_rate,
        "samples": health.samples,
        "last_error": health.last_error.map(|code| json!({ "code": code })),
        "last_checked": health.last_checked.map(rfc3339),
    })
}

/// `GET /api/v1/resolver/upstreams` — passive health of each forward target
/// and of recursion. Sends no probe.
pub(crate) async fn list_upstreams(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let items: Vec<Value> = resolver(&state)?
        .upstreams()
        .iter()
        .map(upstream_json)
        .collect();
    Ok(success(json!({
        "window_seconds": WINDOW_SECONDS,
        "items": items,
    })))
}

/// Parses the flush body: absent, blank or `{}` (or `domain: null`) means all.
fn parse_flush_body(raw: &[u8]) -> Result<Option<DomainName>, ControlApiError> {
    let body: FlushBody = if raw.iter().all(u8::is_ascii_whitespace) {
        FlushBody::default()
    } else {
        serde_json::from_slice(raw).map_err(|_| {
            module_error(
                FLUSH_INVALID_DOMAIN,
                "body must be a JSON object with an optional domain",
            )
        })?
    };
    body.domain
        .map(|name| {
            DomainName::parse(&name)
                .map_err(|_| module_error(FLUSH_INVALID_DOMAIN, "domain is not a valid DNS name"))
        })
        .transpose()
}

/// `POST /api/v1/resolver/cache/flush` — admin. Removes cached answers for one
/// domain (and everything below it) or for the whole cache. Node-local, audited.
pub(crate) async fn flush_cache(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Bytes,
) -> Result<impl IntoResponse, ControlApiError> {
    // Validate before touching the resolver or the audit path.
    let domain = parse_flush_body(&body)?;
    let scope =
        match &domain {
            None => FlushScope::All,
            Some(name) => FlushScope::Domain(Name::from_ascii(name.as_str()).map_err(|_| {
                module_error(FLUSH_INVALID_DOMAIN, "domain is not a valid DNS name")
            })?),
        };
    let resolver = resolver(&state)?;
    let config = service(&state)?;

    let report = resolver.flush(scope);
    let result = json!({
        "scope": if domain.is_some() { "domain" } else { "all" },
        "domain": domain.as_ref().map(DomainName::as_str),
        "evicted": report.evicted,
    });
    config
        .record_action(&actor(auth), FLUSH_AUDIT_ACTION, None, Some(&result), None)
        .await;
    Ok(success(result))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn flush_body_absent_blank_or_null_domain_means_all() {
        for raw in [&b""[..], b"   ", b"{}", br#"{"domain":null}"#] {
            assert!(parse_flush_body(raw).unwrap().is_none(), "{raw:?}");
        }
    }

    #[test]
    fn flush_body_domain_is_normalised() {
        let domain = parse_flush_body(br#"{"domain":"WWW.Example.COM."}"#)
            .unwrap()
            .unwrap();
        assert_eq!(domain.as_str(), "www.example.com");
    }

    #[test]
    fn flush_body_rejects_bad_domain_and_unknown_fields() {
        for raw in [
            &br#"{"domain":""}"#[..],
            br#"{"domain":"a..b"}"#,
            br#"{"domain":"*.example.com"}"#,
            br#"{"domain":"caf\u00e9.test"}"#,
            br#"{"domian":"example.com"}"#,
        ] {
            let err = parse_flush_body(raw).expect_err("rejected");
            assert_eq!(err.code(), FLUSH_INVALID_DOMAIN, "{raw:?}");
        }
    }

    #[test]
    fn state_names_match_wire_contract() {
        assert_eq!(state_name(UpstreamState::Up), "up");
        assert_eq!(state_name(UpstreamState::Degraded), "degraded");
        assert_eq!(state_name(UpstreamState::Down), "down");
        assert_eq!(state_name(UpstreamState::Unknown), "unknown");
    }
}
