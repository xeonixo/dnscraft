//! Bearer-token authentication for the MCP endpoint.
//!
//! Every POST is validated exactly once: [`authenticate`] extracts
//! `Authorization: Bearer <token>`, calls [`McpBackend::validate_token`] and
//! returns the [`TokenInfo`] that `transport` places in the request extension
//! (tools read it from `http::request::Parts`).
//!
//! The raw token is never logged, stored in an error or returned to a client.
//!
//! 401 responses are counted by the **caller's** rate limiter (the control-api
//! `auth` bucket, SPEC-control-api.md § Rate limits); this crate has no
//! limiter of its own.

use axum::http::{HeaderMap, header};

use crate::backend::{BackendError, McpBackend};
use crate::dto::TokenInfo;

/// A transport-level authentication failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthError {
    /// Missing, malformed or invalid token (HTTP 401).
    Unauthenticated,
    /// Valid token whose scope is not an MCP scope (HTTP 403).
    InvalidScope,
    /// Token validation could not be completed (HTTP 500).
    Internal,
}

/// Validate the request's bearer token with `backend`.
pub(crate) async fn authenticate(
    headers: &HeaderMap,
    backend: &dyn McpBackend,
) -> Result<TokenInfo, AuthError> {
    let token = bearer_token(headers).ok_or(AuthError::Unauthenticated)?;
    backend
        .validate_token(token)
        .await
        .map_err(|error| match error {
            BackendError::Unauthenticated => AuthError::Unauthenticated,
            BackendError::InvalidScope => AuthError::InvalidScope,
            _ => {
                // `code` is backend-controlled; the token itself is never logged.
                tracing::warn!(code = error.code(), "MCP token validation failed");
                AuthError::Internal
            }
        })
}

/// Extract exactly one `Bearer` token.
///
/// Duplicate `Authorization` headers, non-UTF-8 values, a non-`Bearer` scheme,
/// an empty token and whitespace inside the token are all rejected.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let (scheme, token) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.chars().any(char::is_whitespace)
    {
        return None;
    }
    Some(token)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        headers
    }

    #[test]
    fn accepts_a_single_bearer_token() {
        // Scheme comparison is case-insensitive.
        assert_eq!(bearer_token(&headers("Bearer abc123")), Some("abc123"));
        assert_eq!(bearer_token(&headers("bearer abc123")), Some("abc123"));
    }

    #[test]
    fn rejects_missing_malformed_and_duplicate_headers() {
        assert_eq!(bearer_token(&HeaderMap::new()), None);
        assert_eq!(bearer_token(&headers("Basic abc123")), None);
        assert_eq!(bearer_token(&headers("Bearer")), None);
        assert_eq!(bearer_token(&headers("Bearer ")), None);
        assert_eq!(bearer_token(&headers("Bearer a b")), None);

        let mut duplicate = headers("Bearer abc123");
        duplicate.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer def456"),
        );
        assert_eq!(bearer_token(&duplicate), None);
    }
}
