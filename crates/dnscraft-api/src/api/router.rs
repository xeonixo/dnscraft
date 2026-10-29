//! Router assembly: liveness/readiness, the `/api/v1` prefix, and the HTTP
//! envelope / error-mapping boundaries.

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use serde_json::json;

use super::alerts_routes::list_alerts;
use super::audit_routes::list_audit;
use super::auth::local::local_login;
use super::auth::oidc::{oidc_authorize_url, oidc_callback, oidc_status, put_oidc_client_secret};
use super::auth::session_routes::{list_sessions, revoke_session};
use super::auth::tokens::{create_token, delete_token, list_tokens};
use super::auth::{auth_me, auth_middleware, logout, rbac_middleware};
use super::clients_routes::{
    create_manual, delete_manual, get_unifi, list_clients, list_manual, put_manual,
    put_unifi_api_key, sync_clients,
};
use super::cluster_endpoints::{get_write, list_nodes, mint_join_token, revoke_node};
use super::config_routes::{
    delete_pause, delete_profile, delete_view, get_config, get_pause, get_profile, get_view,
    list_versions, list_views, put_config, put_pause, put_profile, put_view, rollback,
    validate_config,
};
use super::domain_zones_routes::{list_domain_zone_records, list_domain_zones};
use super::filter_routes::{
    delete_filter_list, delete_filter_set, list_filter_lists, list_filter_sets, list_services,
    put_filter_list, put_filter_set, put_service,
};
use super::listener_routes::{delete_listener, list_listeners, put_listener};
use super::mcp_endpoints::{
    add_custom_rule, allow_temporarily, explain_block, list_mcp_rules, pause_filter_set,
    remove_custom_rule, resume_filter_set, test_query,
};
use super::notifications_routes::{get_notifications, post_notification_test, put_notifications};
use super::policy_routes::{
    create_client_id, delete_client_id, delete_record, list_client_ids, list_records,
    put_client_id, put_record,
};
use super::query_log_routes::{get_query_log, list_query_log, stream_query_log};
use super::rate_limit::rate_limit;
use super::resolver_routes::{flush_cache, list_upstreams};
use super::response::{BODY_LIMIT_BYTES, error_response, success};
use super::stats_routes::{
    export_csv, export_ndjson, stats_cache, stats_domain, stats_overview, stats_top_clients,
    stats_top_domains,
};
use super::system_routes::{get_backups, get_update_check, put_backup_settings};
use super::tls_routes::{
    delete_tls, get_tls, get_tls_account, get_tls_audit, get_tls_certificate, get_tls_order,
    get_tls_records, get_tls_status, put_cloudflare_token, put_tls, put_tls_certificate,
    trigger_tls_dyndns, trigger_tls_preflight, trigger_tls_renew, trigger_tls_revoke,
    trigger_tls_rotate,
};
use crate::error::ControlApiError;
use crate::mcp_backend::ControlMcpBackend;
use crate::server::AppState;
use crate::tls::TlsMode;

/// Builds the full router for `state`.
pub(crate) fn build_router(state: AppState) -> Router {
    let mut api = Router::new()
        .route("/status", get(status))
        .route("/filtering/explain-block", post(explain_block))
        .route("/filtering/mcp-rules", get(list_mcp_rules))
        .route(
            "/notifications",
            get(get_notifications).put(put_notifications),
        )
        .route("/notifications/test", post(post_notification_test))
        .route("/filtering/services", get(list_services))
        .route("/filtering/services/{service_id}", put(put_service))
        .route(
            "/filtering/custom-rules",
            post(add_custom_rule).delete(remove_custom_rule),
        )
        .route("/filtering/temporary-allows", post(allow_temporarily))
        .route("/filtering/pause", post(pause_filter_set))
        .route("/filtering/resume", post(resume_filter_set))
        .route("/policy/test-query", post(test_query))
        // Resolver admin: upstream health (viewer) and cache flush (admin).
        // Unwired resolvers answer `control_api.not_ready`, as TLS does.
        .route("/resolver/upstreams", get(list_upstreams))
        .route("/resolver/cache/flush", post(flush_cache))
        // Active alerts (WP1): viewer and admin read.
        .route("/alerts", get(list_alerts))
        // Domain-Zonen (Split-DNS Namen read path): viewer/admin GET; discover
        // is admin-only inside the handler. Without a TLS engine → not_ready.
        .route("/domain-zones", get(list_domain_zones))
        .route(
            "/domain-zones/{zone_id}/records",
            get(list_domain_zone_records),
        );
    if state.config_service().is_some() {
        api = api
            .route("/config", get(get_config).put(put_config))
            .route("/config/validate", post(validate_config))
            .route("/config/versions", get(list_versions))
            .route("/config/versions/{version}/rollback", post(rollback))
            .route("/policy/views", get(list_views))
            .route(
                "/policy/records",
                get(list_records)
                    .put(put_record)
                    .post(put_record)
                    .delete(delete_record),
            )
            .route(
                "/policy/client-ids",
                get(list_client_ids).post(create_client_id),
            )
            .route(
                "/policy/client-ids/{id}",
                delete(delete_client_id).put(put_client_id),
            )
            .route(
                "/policy/views/{id}",
                get(get_view)
                    .put(put_view)
                    .post(put_view)
                    .delete(delete_view),
            )
            .route(
                "/policy/profiles/{id}",
                get(get_profile)
                    .put(put_profile)
                    .post(put_profile)
                    .delete(delete_profile),
            )
            .route(
                "/policy/pause",
                get(get_pause)
                    .put(put_pause)
                    .post(put_pause)
                    .delete(delete_pause),
            )
            .route(
                "/clients/manual",
                get(list_manual)
                    .post(create_manual)
                    .put(put_manual)
                    .delete(delete_manual),
            )
            .route("/clients", get(list_clients))
            .route("/clients/sync", post(sync_clients))
            .route("/clients/unifi", get(get_unifi))
            .route(
                "/clients/unifi-profiles/{id}/api-key",
                axum::routing::put(put_unifi_api_key),
            )
            .route(
                "/filter-sets",
                get(list_filter_sets)
                    .post(put_filter_set)
                    .put(put_filter_set)
                    .delete(delete_filter_set),
            )
            .route(
                "/filter-lists",
                get(list_filter_lists)
                    .post(put_filter_list)
                    .put(put_filter_list)
                    .delete(delete_filter_list),
            )
            .route(
                "/listeners",
                get(list_listeners)
                    .post(put_listener)
                    .put(put_listener)
                    .delete(delete_listener),
            )
            .route(
                "/tls",
                get(get_tls).put(put_tls).post(put_tls).delete(delete_tls),
            )
            .route("/tls/status", get(get_tls_status))
            .route(
                "/tls/cloudflare-token",
                axum::routing::put(put_cloudflare_token),
            )
            .route(
                "/tls/certificate",
                get(get_tls_certificate).put(put_tls_certificate),
            )
            .route("/tls/renew", post(trigger_tls_renew))
            .route("/tls/revoke", post(trigger_tls_revoke))
            .route("/tls/rotate", post(trigger_tls_rotate))
            .route("/tls/preflight", post(trigger_tls_preflight))
            .route("/tls/dyndns", post(trigger_tls_dyndns))
            .route("/tls/records", get(get_tls_records))
            .route("/tls/account", get(get_tls_account))
            .route("/tls/order", get(get_tls_order))
            .route("/tls/audit", get(get_tls_audit));
    }
    if state.db().is_some() {
        // Admin-only reads: the audit log exposes every actor's actions and
        // redacted config snapshots (RBAC maps the path to ApiAdmin).
        api = api.route("/audit", get(list_audit));
        // Backups expose a filesystem path: admin-only (RBAC maps the path).
        api = api
            .route("/backups", get(get_backups))
            .route("/backups/settings", put(put_backup_settings));
    }
    // Viewer-readable; answers `enabled: false` without any outbound call.
    api = api.route("/update/check", get(get_update_check));
    if state.query_log().is_some() {
        // Viewer-accessible reads: the RBAC middleware maps non-config GETs
        // under `/api/v1` to `Requirement::Api`.
        api = api
            .route("/query-log", get(list_query_log))
            .route("/query-log/stream", get(stream_query_log))
            .route("/query-log/export.ndjson", get(export_ndjson))
            .route("/query-log/export.csv", get(export_csv))
            .route("/query-log/{id}", get(get_query_log))
            .route("/stats/overview", get(stats_overview))
            .route("/stats/top_clients", get(stats_top_clients))
            .route("/stats/top_domains", get(stats_top_domains))
            .route("/stats/cache", get(stats_cache))
            .route("/stats/domains/{name}", get(stats_domain));
    }
    if state.cluster_store().is_some() {
        // Master-only admin surface. A standalone node has no cluster routes
        // and falls through to 404 control_api.not_found.
        api = api
            .route("/cluster/join-tokens", post(mint_join_token))
            .route("/cluster/nodes", get(list_nodes))
            .route("/cluster/nodes/{node_id}", delete(revoke_node))
            .route("/cluster/writes/{request_id}", get(get_write));
    }
    if state.auth_state().is_some() {
        // Token minting is master-only (SPEC-cluster § No cross-node privilege
        // escalation). A sub-node authenticates the replicated tokens but
        // cannot issue credentials of its own; a standalone node is its own
        // master. Account provisioning has no HTTP route.
        if !state.is_cluster_sub_node() {
            // Token management (mint, list, revoke) is master-only for the same
            // reason: a sub-node must not manage credentials.
            api = api
                .route("/auth/tokens", get(list_tokens).post(create_token))
                .route("/auth/tokens/{id}", delete(delete_token));
        }
        // The current principal (role + actor + CSRF token) for the SPA.
        api = api.route("/auth/me", get(auth_me));
        // Logout revokes the cookie session; available whenever sessions exist.
        api = api.route("/auth/logout", post(logout));
        // Session list and revoke (WX8); the handlers enforce ownership.
        api = api
            .route("/auth/sessions", get(list_sessions))
            .route("/auth/sessions/{id}", delete(revoke_session));
        // Break-glass login is mounted only when local accounts are provisioned.
        if state.local_login_store().is_some() {
            api = api.route("/auth/local/login", post(local_login));
        }
        // OIDC routes are always mounted with auth so WebUI can enable SSO
        // without a restart; handlers no-op when the relying party is unset.
        api = api
            .route("/auth/oidc/status", get(oidc_status))
            .route("/auth/oidc/authorize-url", get(oidc_authorize_url))
            .route("/auth/oidc/callback", get(oidc_callback))
            .route("/auth/oidc/client-secret", put(put_oidc_client_secret));
    }

    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .nest("/api/v1", api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone());

    // Mount MCP when the backend is wired and MCP is enabled. When disabled the
    // not_found fallback returns 404 control_api.not_found (no MCP-specific code).
    if let Some(inner) = state.mcp_backend_inner().cloned() {
        let mcp_config = state.mcp_config().clone();
        if mcp_config.enabled {
            let backend = Arc::new(ControlMcpBackend::new(inner));
            router = router.nest_service("/mcp/v1", dnscraft_mcp::service(backend, mcp_config));
        }
    }

    if let Some(auth) = state.auth_state() {
        // Outermost first: the session middleware populates `Principal` for
        // cookie requests, then RBAC authenticates bearer tokens and enforces
        // the endpoint family / role for both families.
        router = router.layer(middleware::from_fn_with_state(
            state.clone(),
            rbac_middleware,
        ));
        router = router.layer(middleware::from_fn_with_state(
            auth.sessions().clone(),
            auth_middleware,
        ));
    }

    router
        // DefaultBodyLimit first so the 413 it produces is seen by the
        // envelope-mapping middleware wrapped on top of it.
        .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
        .layer(middleware::from_fn(map_payload_too_large))
        // Rate limiting is outermost: it runs before body-size mapping so an
        // over-limit source is rejected before any body is read. It needs the
        // state (for the limiter) so it uses `from_fn_with_state`.
        .layer(middleware::from_fn_with_state(state, rate_limit))
}

async fn healthz() -> impl IntoResponse {
    success(json!({ "ok": true }))
}

async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let not_ready = state.readiness().not_ready_modules();
    if not_ready.is_empty() {
        return success(json!({ "ready": true })).into_response();
    }
    error_response(
        "control_api.not_ready",
        Some(json!({ "modules": not_ready })),
        StatusCode::SERVICE_UNAVAILABLE,
    )
}

/// Status: build version, module readiness, TLS mode, leaf fingerprint, the
/// full typed TLS DTO, the cluster block when a role is active, and any active
/// warnings (self-signed bootstrap certificate).
///
/// When this process does not terminate TLS (reverse-proxy mode), the TLS
/// fields are omitted entirely.
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = serde_json::Map::new();
    // Build version and module readiness (GA14). Only non-secret state.
    body.insert("version".to_owned(), json!(state.version()));
    let not_ready = state.readiness().not_ready_modules();
    body.insert("ready".to_owned(), json!(not_ready.is_empty()));
    body.insert("modules_not_ready".to_owned(), json!(not_ready));
    if let Some(tls) = state.tls_status_async().await {
        body.insert("tls_mode".to_owned(), json!(tls.mode.as_str()));
        body.insert("tls_fingerprint".to_owned(), json!(tls.fingerprint.clone()));
        let warnings: Vec<&str> = match tls.mode {
            TlsMode::SelfSigned => vec!["control_api.tls.self_signed"],
            TlsMode::Acme | TlsMode::Manual => Vec::new(),
        };
        body.insert("warnings".to_owned(), json!(warnings));
        // The full typed DTO (contract § G); `tls_mode`/`tls_fingerprint` stay
        // for clients written against the earlier, flatter shape.
        body.insert("tls".to_owned(), json!(tls));
    }
    // Cluster fields are present only when a cluster role is active. A
    // standalone node omits them entirely (no `cluster` key).
    if let Some(cluster) = state
        .cluster_status()
        .and_then(|provider| provider.cluster_status())
    {
        body.insert("cluster".to_owned(), cluster.to_json());
    }
    success(serde_json::Value::Object(body))
}

async fn not_found(req: Request) -> Response {
    let path = req.uri().path();
    // Nested `/api/v1` and `/mcp/v1` misses bubble to this fallback; keep those JSON.
    // Exact `/api` and `/mcp` too — avoid serving SPA HTML for truncated/misspelled API paths.
    // DNS query paths never belong to the control plane, so they stay a JSON 404 as well.
    if path == "/api"
        || path == "/mcp"
        || path.starts_with("/api/")
        || path.starts_with("/mcp/")
        || path == "/dns-query"
        || path.starts_with("/dns-query/")
    {
        return ControlApiError::NotFound {
            what: path.to_owned(),
        }
        .into_response();
    }
    #[cfg(feature = "web-ui")]
    {
        crate::web_ui::serve(req.uri().clone(), req.method().clone()).await
    }
    #[cfg(not(feature = "web-ui"))]
    {
        ControlApiError::NotFound {
            what: path.to_owned(),
        }
        .into_response()
    }
}

async fn method_not_allowed(req: Request) -> impl IntoResponse {
    ControlApiError::MethodNotAllowed {
        method: req.method().to_string(),
        path: req.uri().path().to_owned(),
    }
}

/// Rewrites any 413 (produced by [`DefaultBodyLimit`]) into the documented
/// `control_api.payload_too_large` envelope.
async fn map_payload_too_large(req: Request, next: Next) -> Response {
    let res = next.run(req).await;
    if res.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ControlApiError::PayloadTooLarge {
            limit_bytes: BODY_LIMIT_BYTES as u64,
        }
        .into_response();
    }
    res
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use axum::Json;
    use axum::body::Body;
    use axum::http::header;
    use axum::routing::post;
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;

    fn body_limit_router() -> Router {
        async fn echo(Json(v): Json<Value>) -> Json<Value> {
            Json(v)
        }
        Router::new()
            .route("/", post(echo))
            .layer(DefaultBodyLimit::max(BODY_LIMIT_BYTES))
            .layer(middleware::from_fn(map_payload_too_large))
    }

    async fn body_text(res: Response) -> String {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn oversized_body_returns_413_envelope_with_stable_code() {
        let body = Body::from(vec![b'x'; BODY_LIMIT_BYTES + 1]);
        let res = body_limit_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let text = body_text(res).await;
        assert!(text.contains("control_api.payload_too_large"), "{text}");
        assert!(text.contains("1048576"), "limit bytes in params: {text}");
    }

    #[tokio::test]
    async fn body_at_the_limit_is_accepted() {
        let body = Body::from(r#"{"a":1}"#.to_owned());
        let res = body_limit_router()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .header(header::CONTENT_TYPE, "application/json")
                    .uri("/")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
}
