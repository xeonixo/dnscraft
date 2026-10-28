//! `GET /api/v1/alerts` (WP1): the active alerts, assembled from the TLS
//! status, filter-list update status and the cluster link. Each item names its
//! module and a stable id; the web UI owns the wording.

use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use dnscraft_cluster::{ClusterNode, Role};

use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::system::unix_now;

/// A registered sub-node is offline when its last authenticated connection
/// (or its join time, if it never connected) is older than this (WP1).
const NODE_OFFLINE_AFTER_SECS: i64 = 300;

/// `GET /api/v1/alerts` — viewer and admin. An empty `items` list means no
/// active alert.
pub(crate) async fn list_alerts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let items = collect_alerts(&state).await;
    Ok(success(json!({
        "active_count": items.len(),
        "items": items,
    })))
}

/// The active alert items. Shared by the route and the webhook dispatcher (WX7).
pub(crate) async fn collect_alerts(state: &AppState) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();

    if let Some(tls) = state.tls_status_async().await {
        if tls.revoked {
            items.push(alert(
                "tls.cert.revoked",
                "critical",
                "tls",
                json!({}),
                "/tls",
            ));
        } else if tls.cert_expired {
            items.push(alert(
                "tls.cert.expired",
                "critical",
                "tls",
                json!({}),
                "/tls",
            ));
        } else if tls.cert_expiring {
            items.push(alert(
                "tls.cert.expiring",
                "warning",
                "tls",
                json!({ "days_to_expiry": tls.days_to_expiry }),
                "/tls",
            ));
        }
        if tls.dyndns_stale {
            items.push(alert(
                "tls.dyndns.stale",
                "warning",
                "tls",
                json!({}),
                "/tls",
            ));
        }
    }

    if let Some(filter) = state.filter_engine() {
        for list in filter.list_status() {
            if let Some(code) = list.error_code {
                items.push(alert(
                    "filtering.list.update_failed",
                    "warning",
                    "filtering",
                    json!({ "list_id": list.id.as_str(), "code": code }),
                    "/filter-lists",
                ));
            }
        }
    }

    if let Some(cluster) = state
        .cluster_status()
        .and_then(|provider| provider.cluster_status())
        && cluster.role == "sub_node"
        && !cluster.master_reachable
    {
        items.push(alert(
            "cluster.master.unreachable",
            "warning",
            "cluster",
            json!({}),
            "/cluster",
        ));
    }

    // Node liveness is a master-side fact; the master reads its own registry.
    if state.cluster_role() == Some(Role::Master)
        && let Some(store) = state.cluster_store()
        && let Ok(nodes) = store.list_nodes().await
    {
        items.extend(offline_node_alerts(&nodes, unix_now(state)));
    }
    items
}

/// One alert item in the documented shape.
fn alert(id: &str, severity: &str, module: &str, params: Value, target_route: &str) -> Value {
    json!({
        "id": id,
        "severity": severity,
        "module": module,
        "params": params,
        "target_route": target_route,
    })
}

/// Alerts for registered, non-revoked sub-nodes that have gone quiet (WP1).
fn offline_node_alerts(nodes: &[ClusterNode], now: i64) -> Vec<Value> {
    nodes
        .iter()
        .filter(|node| !node.revoked)
        .filter(|node| {
            let seen = node.last_seen.unwrap_or(node.joined_at);
            now.saturating_sub(seen) > NODE_OFFLINE_AFTER_SECS
        })
        .map(|node| {
            alert(
                "cluster.node.offline",
                "warning",
                "cluster",
                json!({ "node_id": node.node_id, "last_seen": node.last_seen }),
                "/cluster",
            )
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn node(id: &str, last_seen: Option<i64>, revoked: bool) -> ClusterNode {
        ClusterNode {
            node_id: id.to_owned(),
            fingerprint: "00".to_owned(),
            joined_at: 1_000,
            last_seen,
            applied_config_version: None,
            revoked,
        }
    }

    #[test]
    fn only_quiet_active_nodes_raise_an_offline_alert() {
        let now = 10_000;
        let nodes = [
            node("fresh", Some(now - 10), false),
            node("quiet", Some(now - 900), false),
            node("never-seen", None, false),
            node("revoked", Some(now - 900), true),
        ];
        let alerts = offline_node_alerts(&nodes, now);
        let ids: Vec<&str> = alerts
            .iter()
            .map(|alert| alert["params"]["node_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, ["quiet", "never-seen"]);
        assert_eq!(alerts[0]["id"], "cluster.node.offline");
        assert_eq!(alerts[0]["target_route"], "/cluster");
    }
}
