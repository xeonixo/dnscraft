//! Router assembly: liveness/readiness, the `/api/v1` prefix, and the HTTP
//! envelope / error-mapping boundaries.

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::json;

use super::auth::local::local_login;
use super::auth::oidc::{oidc_authorize_url, oidc_callback};
use super::auth::tokens::create_token;
use super::auth::{auth_middleware, rbac_middleware};
use super::rate_limit::rate_limit;
use super::response::{BODY_LIMIT_BYTES, error_response, success};
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::tls::TlsMode;

/// Builds the full router for `state`.
pub(crate) fn build_router(state: AppState) -> Router {
    let mut api = Router::new().route("/status", get(status));
    if state.auth_state().is_some() {
        // Token management exists only when persistence/auth is configured.
        api = api.route("/auth/tokens", post(create_token));
        // Break-glass login is mounted only when local accounts are provisioned.
        if state.local_login_store().is_some() {
            api = api.route("/auth/local/login", post(local_login));
        }
        // OIDC is mounted only when the relying party is configured.
        if state.oidc_state().is_some() {
            api = api
                .route("/auth/oidc/authorize-url", get(oidc_authorize_url))
                .route("/auth/oidc/callback", get(oidc_callback));
        }
    }

    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .nest("/api/v1", api)
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone());

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

/// Status: TLS mode, leaf fingerprint, and any active warnings (self-signed
/// bootstrap certificate). Expanded further by A11 (version, features).
///
/// When this process does not terminate TLS (reverse-proxy mode), the TLS
/// fields are omitted entirely.
async fn status(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = serde_json::Map::new();
    if let Some(tls) = state.tls_status() {
        body.insert("tls_mode".to_owned(), json!(tls.mode.as_str()));
        body.insert("tls_fingerprint".to_owned(), json!(tls.fingerprint));
        let warnings: Vec<&str> = match tls.mode {
            TlsMode::SelfSigned => vec!["control_api.tls.self_signed"],
            TlsMode::Acme => Vec::new(),
        };
        body.insert("warnings".to_owned(), json!(warnings));
    }
    success(serde_json::Value::Object(body))
}

async fn not_found(req: Request) -> impl IntoResponse {
    ControlApiError::NotFound {
        what: req.uri().path().to_owned(),
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
