//! Write-only Cloudflare API token in SQLite kv (`tls.cloudflare.api_token`).

use crate::error::ControlApiError;
use crate::storage::Db;

const KV_KEY: &str = "tls.cloudflare.api_token";

/// Whether a non-empty Cloudflare API token is stored.
pub(crate) async fn has_api_token(db: &Db) -> Result<bool, ControlApiError> {
    Ok(db.kv_get(KV_KEY).await?.is_some_and(|v| !v.is_empty()))
}

/// Stores or clears the Cloudflare API token.
///
/// `None` clears the token; `Some("")` is rejected.
pub(crate) async fn set_api_token(db: &Db, token: Option<&str>) -> Result<(), ControlApiError> {
    match token {
        None => db.kv_delete(KV_KEY).await,
        Some("") => Err(ControlApiError::Module {
            code: "tls.config.invalid",
            params: Some(serde_json::json!({
                "reason": "api_token must not be empty; use null to clear"
            })),
        }),
        Some(value) => db.kv_set(KV_KEY, value).await,
    }
}

/// Loads the stored token, if any (engine bootstrap after restart).
pub(crate) async fn get_api_token(db: &Db) -> Result<Option<String>, ControlApiError> {
    let value = db.kv_get(KV_KEY).await?;
    Ok(value.filter(|v| !v.is_empty()))
}

// --- Cluster sync (master -> DynDNS sub-nodes) -----------------------------

use serde_json::Value;

use crate::server::AppState;

/// Whether the snapshot enables DynDNS for `node_id` (global switch on and an
/// enabled `tls.dyndns.nodes[]` profile for that node).
pub(crate) fn dyndns_enabled_for(snapshot: &Value, node_id: &str) -> bool {
    let Some(dyndns) = snapshot.get("tls").and_then(|t| t.get("dyndns")) else {
        return false;
    };
    dyndns.get("enabled").and_then(Value::as_bool) == Some(true)
        && dyndns
            .get("nodes")
            .and_then(Value::as_array)
            .is_some_and(|nodes| {
                nodes.iter().any(|n| {
                    n.get("node_id").and_then(Value::as_str) == Some(node_id)
                        && n.get("enabled").and_then(Value::as_bool).unwrap_or(true)
                })
            })
}

/// The token `node_id` is entitled to: only with an enabled DynDNS profile.
pub(crate) async fn token_for_node(state: &AppState, node_id: &str) -> Option<String> {
    let service = state.config_service()?;
    let snapshot = service.current().await.ok()?.1?;
    if !dyndns_enabled_for(&snapshot, node_id) {
        return None;
    }
    get_api_token(state.db()?).await.ok().flatten()
}

/// Re-evaluates every connected node: pushes the token to entitled nodes and
/// clears it on the others (a clear only reaches nodes that were sent one).
pub(crate) async fn sync_to_nodes(state: &AppState) {
    let Some(broadcast) = state.cluster_broadcast() else {
        return;
    };
    for node_id in broadcast.connected_node_ids() {
        let token = token_for_node(state, &node_id).await;
        broadcast.push_cloudflare_token(&node_id, token.as_deref());
    }
}

/// Connect-time hook for the master's cluster server.
pub(crate) struct StateTokenSource(pub(crate) AppState);

#[async_trait::async_trait]
impl dnscraft_cluster::CloudflareTokenSource for StateTokenSource {
    async fn token_for(&self, node_id: &str) -> Option<String> {
        token_for_node(&self.0, node_id).await
    }
}

/// Sub-node: stores a pushed token (empty/`None` clears) and hands it to the
/// running TLS engine, if any.
pub(crate) async fn apply_pushed(state: &AppState, token: Option<String>) {
    let token = token.filter(|t| !t.is_empty());
    if let Some(db) = state.db()
        && let Err(error) = set_api_token(db, token.as_deref()).await
    {
        tracing::warn!(error = %error, "cluster cloudflare token store failed");
    }
    if let Some(admin) = state.tls_admin()
        && let Err(error) = admin
            .set_cloudflare_token(token.map(crate::Secret::new))
            .await
    {
        tracing::warn!(error = %error, "cluster cloudflare token engine update failed");
    }
}

#[cfg(test)]
mod tests {
    use super::dyndns_enabled_for;
    use serde_json::json;

    #[test]
    fn only_enabled_profiles_of_an_enabled_dyndns_qualify() {
        let on = |nodes: serde_json::Value, enabled: bool| json!({ "tls": { "dyndns": { "enabled": enabled, "nodes": nodes } } });
        let nodes = json!([
            { "node_id": "n1", "enabled": true },
            { "node_id": "n2", "enabled": false },
            { "node_id": "n3" }
        ]);
        assert!(dyndns_enabled_for(&on(nodes.clone(), true), "n1"));
        assert!(dyndns_enabled_for(&on(nodes.clone(), true), "n3"));
        assert!(!dyndns_enabled_for(&on(nodes.clone(), true), "n2"));
        assert!(!dyndns_enabled_for(&on(nodes.clone(), true), "master"));
        assert!(!dyndns_enabled_for(&on(nodes, false), "n1"));
        assert!(!dyndns_enabled_for(&json!({}), "n1"));
    }
}
