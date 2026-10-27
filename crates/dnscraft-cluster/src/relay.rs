//! Live write relay and volatile runtime-command broadcast.
//!
//! A sub-node never applies a write locally: it forwards the canonical request
//! as a [`WriteRelay`] and relays the master's [`RelayResponse`] verbatim. The
//! master re-checks RBAC and executes the existing control-api handler through
//! [`WriteExecutor`]; the cluster crate only transports the request.
//!
//! Pause/resume and temporary-allows are not part of the versioned snapshot.
//! The master broadcasts them as [`RuntimeCommand`] stream records to every
//! connected node, which resolves them through [`RuntimeCommandApplier`]. They
//! are volatile: never persisted and never queued while a node is offline.
//!
//! Request bodies, relayed response bodies, and runtime payloads are opaque to
//! this crate. Their `Debug` representations are redacted so a stray `{:?}`
//! cannot leak configuration content.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ClusterError;

/// Authenticated identity forwarded with a relayed write.
///
/// Raw bearer tokens and session cookies are never part of this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayedActor {
    /// Stable actor id (user id or token id).
    pub actor_id: String,
    /// Actor kind, `user` or `token`.
    pub actor_type: String,
    /// Authenticated role/scope the caller held on the sub-node.
    pub scope: String,
}

/// One write forwarded from a sub-node to the master.
///
/// `request_id` and `idempotency_key` are passed through unchanged on retries;
/// deduplication and the stored response are the executor's responsibility.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct WriteRelay {
    /// Per-call request id, stable across retries.
    pub request_id: String,
    /// Caller-supplied `Idempotency-Key`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// Caller-supplied `If-Match`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_match: Option<String>,
    /// Canonical write endpoint method.
    pub method: String,
    /// Canonical write endpoint path.
    pub path: String,
    /// Opaque JSON request body.
    pub body: Value,
    /// Authenticated caller identity.
    pub actor: RelayedActor,
}

impl fmt::Debug for WriteRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteRelay")
            .field("request_id", &self.request_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("if_match", &self.if_match)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("body", &"<opaque>")
            .field("actor", &self.actor)
            .finish()
    }
}

/// The master's response to a relayed write.
///
/// `status` and `body` are returned to the original caller verbatim.
#[derive(Clone, PartialEq)]
pub struct RelayResponse {
    /// HTTP status of the canonical handler.
    pub status: u16,
    /// Opaque JSON response body.
    pub body: Value,
}

impl fmt::Debug for RelayResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayResponse")
            .field("status", &self.status)
            .field("body", &"<opaque>")
            .finish()
    }
}

/// A volatile runtime command broadcast by the master.
///
/// Last command wins; the record is never persisted or buffered for an
/// offline node.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RuntimeCommand {
    /// Command kind (for example pause/resume).
    pub kind: String,
    /// Filter set the command applies to, when scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_set_id: Option<String>,
    /// Opaque command payload.
    pub payload: Value,
    /// Master clock time the command was issued (RFC 3339).
    pub issued_at: String,
}

impl fmt::Debug for RuntimeCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeCommand")
            .field("kind", &self.kind)
            .field("filter_set_id", &self.filter_set_id)
            .field("payload", &"<opaque>")
            .field("issued_at", &self.issued_at)
            .finish()
    }
}

/// Master hook that re-checks RBAC and runs the canonical write handler.
///
/// The implementation validates, persists, applies atomically, audits with the
/// originating `node_id`, and owns `Idempotency-Key` deduplication. The crate
/// passes the request through unchanged and never inspects the body.
#[async_trait::async_trait]
pub trait WriteExecutor: Send + Sync {
    /// Executes one relayed write and returns its status and response body.
    ///
    /// `node_id` is the authenticated identity of the node that originated the
    /// write: the master's mTLS route passes the certificate SAN so the audit
    /// row names the sub-node. A sub-node-side executor (live relay or offline
    /// replay) is transport-only and may pass an empty value; the master
    /// derives the authoritative identity from the client certificate.
    #[allow(clippy::too_many_arguments)]
    async fn execute(
        &self,
        node_id: &str,
        actor: RelayedActor,
        method: String,
        path: String,
        body: Value,
        if_match: Option<String>,
        idempotency_key: Option<String>,
    ) -> Result<RelayResponse, ClusterError>;
}

/// Sub-node hook that applies a broadcast runtime command locally.
#[async_trait::async_trait]
pub trait RuntimeCommandApplier: Send + Sync {
    /// Applies `kind`/`payload` to the local runtime state.
    async fn apply_runtime_command(&self, kind: &str, payload: &Value) -> Result<(), ClusterError>;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn debug_never_prints_bodies() {
        let relay = WriteRelay {
            request_id: "r1".to_owned(),
            idempotency_key: Some("i1".to_owned()),
            if_match: None,
            method: "PUT".to_owned(),
            path: "/api/v1/config".to_owned(),
            body: json!({ "secret": "do-not-log" }),
            actor: RelayedActor {
                actor_id: "u1".to_owned(),
                actor_type: "user".to_owned(),
                scope: "admin".to_owned(),
            },
        };
        let rendered = format!("{relay:?}");
        assert!(!rendered.contains("do-not-log"));
        assert!(rendered.contains("<opaque>"));

        let command = RuntimeCommand {
            kind: "pause".to_owned(),
            filter_set_id: Some("fs1".to_owned()),
            payload: json!({ "secret": "do-not-log" }),
            issued_at: "2020-01-01T00:00:00Z".to_owned(),
        };
        let rendered = format!("{command:?}");
        assert!(!rendered.contains("do-not-log"));
        assert!(rendered.contains("<opaque>"));
    }
}
