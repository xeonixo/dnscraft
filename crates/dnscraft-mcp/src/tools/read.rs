//! Read-only tools.
//!
//! Every string from the backend is untrusted and leaves through [`SafeText`].

use rmcp::model::CallToolResult;
use rmcp::{tool, tool_router};
use serde_json::{Value, json};

use super::McpServer;
use crate::dto::NodeStatus;
use crate::result::{tool_error, tool_ok};
use crate::sanitize::{CAP_CLIENT_NAME, CAP_DOMAIN, CAP_LIST_ID, CAP_RULE_TEXT, SafeText};

#[tool_router(vis = "pub(crate)")]
impl McpServer {
    /// Current node status.
    #[tool(
        description = "Get node status: resolver health, listener bindings, TLS certificate status, filter list update times, uptime.",
        annotations(
            title = "Get node status",
            read_only_hint = true,
            idempotent_hint = true
        )
    )]
    pub async fn get_status(&self) -> CallToolResult {
        match self.backend.get_status().await {
            Ok(status) => tool_ok(status_json(&status)),
            Err(error) => {
                tracing::warn!(code = error.code(), "get_status backend error");
                tool_error(error.code(), error.params().unwrap_or_else(|| json!({})))
            }
        }
    }
}

fn status_json(status: &NodeStatus) -> Value {
    let text = SafeText::new;
    json!({
        "node_id": text(&status.node_id, CAP_CLIENT_NAME),
        "version": text(&status.version, CAP_CLIENT_NAME),
        "uptime_seconds": status.uptime_seconds,
        "resolver": {
            "primed": status.resolver.primed,
            "cache_size": status.resolver.cache_size,
        },
        "listeners": status.listeners.iter().map(|listener| json!({
            "id": text(&listener.id, CAP_LIST_ID),
            "protocol": text(&listener.protocol, CAP_CLIENT_NAME),
            "bind": text(&listener.bind, CAP_DOMAIN),
            "status": text(&listener.status, CAP_CLIENT_NAME),
        })).collect::<Vec<_>>(),
        "tls": {
            "mode": text(&status.tls.mode, CAP_CLIENT_NAME),
            "cert_expiry": text(&status.tls.cert_expiry, CAP_RULE_TEXT),
            "fingerprint": text(&status.tls.fingerprint, CAP_RULE_TEXT),
        },
        "filtering": {
            "lists_loaded": status.filtering.lists_loaded,
            "rules_active": status.filtering.rules_active,
            "last_update": text(&status.filtering.last_update, CAP_RULE_TEXT),
        },
    })
}
