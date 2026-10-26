//! `{data}` / `{error}` response envelopes and the HTTP mapping of errors.
//!
//! Success responses wrap a value in `{ "data": … }`; failures in
//! `{ "error": { "code", "params" } }`. [`ControlApiError`] implements
//! [`IntoResponse`] so handlers can return it directly.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::{Value, json};

use crate::error::ControlApiError;

/// Request-body limit: 1 MiB (the documented maximum for any control-api body).
pub(crate) const BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Success envelope `{ "data": T }`.
pub(crate) fn success<T: Serialize>(data: T) -> Json<Success<T>> {
    Json(Success { data })
}

/// The success envelope body.
#[derive(Serialize)]
pub(crate) struct Success<T> {
    data: T,
}

/// The error envelope body `{ "error": { "code", "params" } }`.
#[derive(Serialize)]
pub(crate) struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<Value>,
}

/// Builds an error envelope from a stable code and optional `params` object.
pub(crate) fn error_envelope(code: &'static str, params: Option<Value>) -> ErrorEnvelope {
    ErrorEnvelope {
        error: ErrorBody { code, params },
    }
}

/// Builds a full error [`Response`] from a stable code, params and status.
///
/// Used by handlers that need a specific status (e.g. `/readyz`'s 503) or that
/// aggregate several modules into one `params` object.
pub(crate) fn error_response(
    code: &'static str,
    params: Option<Value>,
    status: StatusCode,
) -> Response {
    (status, Json(error_envelope(code, params))).into_response()
}

impl ControlApiError {
    /// The HTTP status for this error.
    fn http_status(&self) -> StatusCode {
        use StatusCode as S;
        match self {
            ControlApiError::ConfigInvalid { .. } => S::BAD_REQUEST,
            ControlApiError::ConfigRead { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::ConfigApply { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::ConfigVersion { .. } => S::CONFLICT,
            ControlApiError::ConfigUnknownVersion { .. } => S::NOT_FOUND,
            ControlApiError::NotFound { .. } => S::NOT_FOUND,
            ControlApiError::Internal { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::RateLimited => S::TOO_MANY_REQUESTS,
            ControlApiError::QueryLogRead { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::QueryLogExport { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::QueryLogDropped { .. } => S::OK,
            ControlApiError::QueryLogInvalid { .. } => S::BAD_REQUEST,
            ControlApiError::AuthOidc { .. } => S::BAD_GATEWAY,
            ControlApiError::AuthLocal => S::UNAUTHORIZED,
            ControlApiError::AuthLocked => S::LOCKED,
            ControlApiError::TlsSelfSigned => S::OK,
            ControlApiError::AuthUnknownToken => S::UNAUTHORIZED,
            ControlApiError::AuthUnauthenticated => S::UNAUTHORIZED,
            ControlApiError::AuthInvalidScope => S::FORBIDDEN,
            ControlApiError::AuthInvalidOrigin => S::FORBIDDEN,
            ControlApiError::AuthInsufficientScope { .. } => S::FORBIDDEN,
            ControlApiError::AuthSessionExpired => S::UNAUTHORIZED,
            ControlApiError::AuthCsrf => S::FORBIDDEN,
            ControlApiError::AuditRead { .. } => S::INTERNAL_SERVER_ERROR,
            ControlApiError::NotReady { .. } => S::SERVICE_UNAVAILABLE,
            ControlApiError::MethodNotAllowed { .. } => S::METHOD_NOT_ALLOWED,
            ControlApiError::PayloadTooLarge { .. } => S::PAYLOAD_TOO_LARGE,
            ControlApiError::PaginationInvalid { .. } => S::BAD_REQUEST,
            ControlApiError::Module { .. } => S::BAD_REQUEST,
        }
    }

    /// The `params` object for the error envelope, when the variant carries
    /// non-secret context useful to a client.
    fn http_params(&self) -> Option<Value> {
        match self {
            ControlApiError::ConfigInvalid { reason } => Some(json!({ "reason": reason })),
            ControlApiError::NotFound { what } => Some(json!({ "what": what })),
            ControlApiError::NotReady { module } => Some(json!({ "modules": [module] })),
            ControlApiError::AuthInsufficientScope { required } => {
                Some(json!({ "required": required }))
            }
            ControlApiError::MethodNotAllowed { method, path } => {
                Some(json!({ "method": method, "path": path }))
            }
            ControlApiError::PayloadTooLarge { limit_bytes } => {
                Some(json!({ "limit_bytes": limit_bytes }))
            }
            ControlApiError::PaginationInvalid { reason } => Some(json!({ "reason": reason })),
            ControlApiError::QueryLogInvalid { reason } => Some(json!({ "reason": reason })),
            ControlApiError::Module { params, .. } => params.clone(),
            _ => None,
        }
    }
}

impl IntoResponse for ControlApiError {
    fn into_response(self) -> Response {
        // Internal errors never leak detail to a client: log the detail, return
        // a fixed envelope carrying only the stable code.
        if let ControlApiError::Internal { message } = &self {
            tracing::error!(error = %message, "control-api internal error");
        }
        let status = self.http_status();
        let envelope = error_envelope(self.code(), self.http_params());
        (status, Json(envelope)).into_response()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::response::Response;
    use tower::ServiceExt as _;

    async fn body_of(res: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn internal_error_never_leaks_the_message() {
        let secret = "attempt to open /secret/path: permission denied (sqlite: 14)";
        let res = ControlApiError::Internal {
            message: secret.to_owned(),
        }
        .into_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains(secret) && !text.contains("/secret/path"),
            "raw internal detail leaked: {text}"
        );
        assert!(
            text.contains("control_api.internal"),
            "missing code: {text}"
        );
    }

    #[tokio::test]
    async fn envelope_round_trips_through_a_handler() {
        async fn handler() -> Result<Json<Success<&'static str>>, ControlApiError> {
            Ok(success("ok"))
        }
        let router = axum::Router::new().route("/", axum::routing::get(handler));
        let res = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(body_of(res).await, json!({ "data": "ok" }));
    }
}
