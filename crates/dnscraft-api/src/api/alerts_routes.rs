//! `GET /api/v1/alerts` (WP1): the active alerts, assembled from the TLS
//! status, filter-list update status and the cluster link. Each item names its
//! module and a stable id; the web UI owns the wording.

use axum::extract::State;
use axum::response::IntoResponse;
use serde_json::{Value, json};

use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

/// `GET /api/v1/alerts` — viewer and admin. An empty `items` list means no
/// active alert.
pub(crate) async fn list_alerts(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
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

    Ok(success(json!({
        "active_count": items.len(),
        "items": items,
    })))
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
