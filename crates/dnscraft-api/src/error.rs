//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `control_api.<area>.<reason>` for
//! HTTP envelopes and i18n. Human-readable text is for logs, not for end users.
//!
//! ## `ControlApiError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ControlApiError::ConfigInvalid`] | `control_api.config.invalid` |
//! | [`ControlApiError::ConfigRead`] | `control_api.config.read` |
//! | [`ControlApiError::ConfigApply`] | `control_api.config.apply` |
//! | [`ControlApiError::ConfigVersion`] | `control_api.config.version` |
//! | [`ControlApiError::ConfigUnknownVersion`] | `control_api.config.unknown_version` |
//! | [`ControlApiError::NotFound`] | `control_api.not_found` |
//! | [`ControlApiError::Internal`] | `control_api.internal` |
//! | [`ControlApiError::RateLimited`] | `control_api.rate_limited` |
//! | [`ControlApiError::QueryLogRead`] | `control_api.query_log.read` |
//! | [`ControlApiError::QueryLogExport`] | `control_api.query_log.export` |
//! | [`ControlApiError::QueryLogDropped`] | `control_api.query_log.dropped` |
//! | [`ControlApiError::AuthOidc`] | `control_api.auth.oidc` |
//! | [`ControlApiError::AuthLocal`] | `control_api.auth.local` |
//! | [`ControlApiError::AuthLocked`] | `control_api.auth.locked` |
//! | [`ControlApiError::TlsSelfSigned`] | `control_api.tls.self_signed` |
//! | [`ControlApiError::AuthUnknownToken`] | `control_api.auth.unknown_token` |
//! | [`ControlApiError::AuthInsufficientScope`] | `control_api.auth.insufficient_scope` |
//! | [`ControlApiError::AuthSessionExpired`] | `control_api.auth.session_expired` |
//! | [`ControlApiError::AuthCsrf`] | `control_api.auth.csrf` |
//! | [`ControlApiError::AuditRead`] | `control_api.audit.read` |
//! | [`ControlApiError::NotReady`] | `control_api.not_ready` |

/// Top-level error of the control-api module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ControlApiError {
    /// Configuration values are inconsistent or out of range.
    #[error("invalid control-api config: {reason}")]
    ConfigInvalid {
        /// Why validation failed.
        reason: String,
    },
    /// Unable to read the current config snapshot.
    #[error("config read failed: {message}")]
    ConfigRead {
        /// Detail for logs.
        message: String,
    },
    /// One or more module apply operations failed.
    #[error("config apply failed: {message}")]
    ConfigApply {
        /// Detail for logs.
        message: String,
    },
    /// Version conflict or invalid `If-Match`.
    #[error("config version error: {message}")]
    ConfigVersion {
        /// Detail for logs.
        message: String,
    },
    /// Rollback target version does not exist.
    #[error("unknown config version {version}")]
    ConfigUnknownVersion {
        /// The requested, non-existent version.
        version: u64,
    },
    /// Route or identifiable object not found.
    #[error("not found: {what}")]
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// Invariant violation / unexpected panic boundary.
    #[error("internal error: {message}")]
    Internal {
        /// Detail for logs.
        message: String,
    },
    /// Request exceeded an API rate limit.
    #[error("rate limited")]
    RateLimited,
    /// Query-log read failure.
    #[error("query-log read failed: {message}")]
    QueryLogRead {
        /// Detail for logs.
        message: String,
    },
    /// Query-log export failed.
    #[error("query-log export failed: {message}")]
    QueryLogExport {
        /// Detail for logs.
        message: String,
    },
    /// Query events were dropped by a full sink (informational, not an HTTP error).
    #[error("dropped {count} query-log events")]
    QueryLogDropped {
        /// Number of events dropped.
        count: u64,
    },
    /// OIDC provider or configuration error.
    #[error("OIDC error: {message}")]
    AuthOidc {
        /// Detail for logs.
        message: String,
    },
    /// Local login credential failure.
    #[error("local login failed")]
    AuthLocal,
    /// Local account temporarily locked.
    #[error("local account locked")]
    AuthLocked,
    /// Serving the self-signed bootstrap certificate (warning, not an HTTP error).
    #[error("serving self-signed TLS certificate")]
    TlsSelfSigned,
    /// Token id not found or not owned by the actor.
    #[error("unknown or revoked API token")]
    AuthUnknownToken,
    /// Role lacks the required permission.
    #[error("insufficient scope (need {required})")]
    AuthInsufficientScope {
        /// The role that was required.
        required: String,
    },
    /// Cookie session expired.
    #[error("session expired")]
    AuthSessionExpired,
    /// Missing or invalid CSRF token.
    #[error("CSRF token missing or invalid")]
    AuthCsrf,
    /// Audit-log read failure.
    #[error("audit read failed: {message}")]
    AuditRead {
        /// Detail for logs.
        message: String,
    },
    /// One or more modules not ready.
    #[error("not ready: {module}")]
    NotReady {
        /// Module that is not ready.
        module: String,
    },
}

impl ControlApiError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::ConfigInvalid { .. } => "control_api.config.invalid",
            Self::ConfigRead { .. } => "control_api.config.read",
            Self::ConfigApply { .. } => "control_api.config.apply",
            Self::ConfigVersion { .. } => "control_api.config.version",
            Self::ConfigUnknownVersion { .. } => "control_api.config.unknown_version",
            Self::NotFound { .. } => "control_api.not_found",
            Self::Internal { .. } => "control_api.internal",
            Self::RateLimited => "control_api.rate_limited",
            Self::QueryLogRead { .. } => "control_api.query_log.read",
            Self::QueryLogExport { .. } => "control_api.query_log.export",
            Self::QueryLogDropped { .. } => "control_api.query_log.dropped",
            Self::AuthOidc { .. } => "control_api.auth.oidc",
            Self::AuthLocal => "control_api.auth.local",
            Self::AuthLocked => "control_api.auth.locked",
            Self::TlsSelfSigned => "control_api.tls.self_signed",
            Self::AuthUnknownToken => "control_api.auth.unknown_token",
            Self::AuthInsufficientScope { .. } => "control_api.auth.insufficient_scope",
            Self::AuthSessionExpired => "control_api.auth.session_expired",
            Self::AuthCsrf => "control_api.auth.csrf",
            Self::AuditRead { .. } => "control_api.audit.read",
            Self::NotReady { .. } => "control_api.not_ready",
        }
    }

    /// Convenience constructor for [`ControlApiError::ConfigInvalid`].
    pub(crate) fn config(reason: impl Into<String>) -> Self {
        Self::ConfigInvalid {
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all = [
            ControlApiError::config("x"),
            ControlApiError::ConfigRead {
                message: "x".into(),
            },
            ControlApiError::ConfigApply {
                message: "x".into(),
            },
            ControlApiError::ConfigVersion {
                message: "x".into(),
            },
            ControlApiError::ConfigUnknownVersion { version: 7 },
            ControlApiError::NotFound { what: "x".into() },
            ControlApiError::Internal {
                message: "x".into(),
            },
            ControlApiError::RateLimited,
            ControlApiError::QueryLogRead {
                message: "x".into(),
            },
            ControlApiError::QueryLogExport {
                message: "x".into(),
            },
            ControlApiError::QueryLogDropped { count: 3 },
            ControlApiError::AuthOidc {
                message: "x".into(),
            },
            ControlApiError::AuthLocal,
            ControlApiError::AuthLocked,
            ControlApiError::TlsSelfSigned,
            ControlApiError::AuthUnknownToken,
            ControlApiError::AuthInsufficientScope {
                required: "admin".into(),
            },
            ControlApiError::AuthSessionExpired,
            ControlApiError::AuthCsrf,
            ControlApiError::AuditRead {
                message: "x".into(),
            },
            ControlApiError::NotReady {
                module: "resolver".into(),
            },
        ];
        let mut codes: Vec<&str> = all.iter().map(ControlApiError::code).collect();
        for code in &codes {
            assert!(
                code.starts_with("control_api."),
                "code {code} must use control_api. prefix"
            );
            assert!(
                code.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
                "code {code} must be locale-neutral ascii"
            );
        }
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), all.len(), "duplicate error codes");
    }
}
