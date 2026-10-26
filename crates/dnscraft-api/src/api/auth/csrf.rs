//! Synchronizer-token CSRF for cookie-authenticated requests.
//!
//! The token is a domain-separated SHA-256 hash of the session id. Because the
//! session id is unguessable and unreadable by cross-site code (the cookie is
//! `HttpOnly`), an attacker cannot compute the token; the legitimate client
//! receives it exactly once at session creation and echoes it in the
//! `X-CSRF-Token` header. Comparison is constant-time.

use axum::http::Method;
use ring::digest::{Context, SHA256};

use super::hex;
use crate::secret::Secret;

/// Domain-separation prefix so the CSRF token never equals the stored session
/// hash (an attacker with read access to the hash cannot forge the token).
const CSRF_CONTEXT: &[u8] = b"dnscraft-csrf-token-v1\0";

/// The CSRF token for a session id.
pub(crate) fn csrf_token_for(session_id: &str) -> Secret {
    let mut ctx = Context::new(&SHA256);
    ctx.update(CSRF_CONTEXT);
    ctx.update(session_id.as_bytes());
    Secret::new(hex(ctx.finish().as_ref()))
}

/// Whether `submitted` matches the session's CSRF token (constant-time for
/// equal-length inputs).
pub(crate) fn csrf_matches(session_id: &str, submitted: &str) -> bool {
    let expected = csrf_token_for(session_id);
    ct_eq(expected.expose().as_bytes(), submitted.as_bytes())
}

/// Constant-time byte comparison. Differing lengths return false immediately,
/// which leaks only the (public) length of the expected token.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Whether a method may mutate state (everything but GET/HEAD/OPTIONS).
pub(crate) fn is_mutating(method: &Method) -> bool {
    !matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn auth_session_csrf_token_is_stable_and_distinct_from_the_id() {
        let token_a = csrf_token_for("session-a");
        let token_b = csrf_token_for("session-a");
        assert_eq!(token_a.expose(), token_b.expose(), "token must be stable");
        assert_ne!(token_a.expose(), "session-a", "token must not be the id");

        assert!(csrf_matches("session-a", token_a.expose()));
        assert!(!csrf_matches("session-a", "wrong"));
        assert!(!csrf_matches("session-b", token_a.expose()));
    }

    #[test]
    fn auth_session_mutating_methods_exclude_safe_methods() {
        assert!(!is_mutating(&Method::GET));
        assert!(!is_mutating(&Method::HEAD));
        assert!(!is_mutating(&Method::OPTIONS));
        assert!(is_mutating(&Method::POST));
        assert!(is_mutating(&Method::PUT));
        assert!(is_mutating(&Method::DELETE));
        assert!(is_mutating(&Method::PATCH));
    }
}
