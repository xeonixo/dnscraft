//! `/api/v1/cluster/*` admin endpoints (master only).
//!
//! These expose the master's durable cluster registry: minting one-time join
//! tokens, listing and revoking sub-nodes, and reading the state of a buffered
//! offline write. The whole prefix is `admin`-only (see
//! [`crate::requirement`]) and the routes are mounted only when a
//! [`ClusterStore`](dnscraft_cluster::ClusterStore) is attached, so a
//! standalone node answers `404 control_api.not_found`.
//!
//! Every timestamp in [`ClusterStore`](dnscraft_cluster::ClusterStore) is Unix
//! seconds; the API renders them as RFC 3339, matching the other endpoints.

use std::sync::Arc;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Path, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use dnscraft_cluster::ClusterStore;

use crate::api::config_routes::json_body;
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::server::AppState;

/// Request body of `POST /api/v1/cluster/join-tokens`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinTokenBody {
    node_id: String,
}

fn store(state: &AppState) -> Result<&Arc<ClusterStore>, ControlApiError> {
    state
        .cluster_store()
        .ok_or_else(|| ControlApiError::NotFound {
            what: "cluster".to_owned(),
        })
}

/// Unix seconds as an RFC 3339 UTC timestamp.
fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_default()
}

/// `POST /api/v1/cluster/join-tokens` — mint a one-time token for `node_id`.
///
/// The plaintext is returned once and never stored; the registry keeps only its
/// SHA-256 hash.
pub(crate) async fn mint_join_token(
    State(state): State<AppState>,
    body: Result<Json<JoinTokenBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "cluster.role.invalid")?;
    let token = store(&state)?.mint_join_token(&body.node_id).await?;
    Ok(success(json!({
        "token": token.expose(),
        "expires_at": rfc3339(token.expires_at()),
    })))
}

/// `GET /api/v1/cluster/nodes` — every registered sub-node.
pub(crate) async fn list_nodes(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let nodes: Vec<Value> = store(&state)?
        .list_nodes()
        .await?
        .into_iter()
        .map(|node| {
            json!({
                "node_id": node.node_id,
                // Every registry entry is a sub-node; the master is this process.
                "role": "sub_node",
                "fingerprint": node.fingerprint,
                "joined_at": rfc3339(node.joined_at),
                "last_seen": node.last_seen.map(rfc3339),
                "applied_config_version": node.applied_config_version,
                "revoked": node.revoked,
            })
        })
        .collect();
    Ok(success(nodes))
}

/// `DELETE /api/v1/cluster/nodes/{node_id}` — revoke a node.
///
/// Its next connection is rejected with `cluster.node.revoked`.
pub(crate) async fn revoke_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    store(&state)?.revoke(&node_id).await?;
    Ok(success(json!({ "node_id": node_id, "revoked": true })))
}

/// `GET /api/v1/cluster/writes/{request_id}` — state of a buffered offline
/// write.
///
/// The queue only persists the lifecycle state and attempt count; the
/// enqueue-time expiry and the replay result are not stored, so those fields
/// are `null`.
pub(crate) async fn get_write(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<impl IntoResponse, ControlApiError> {
    let not_found = || ControlApiError::NotFound {
        what: format!("offline write {request_id}"),
    };
    let queue = state.offline_write_queue().ok_or_else(not_found)?;
    let entry = queue.get(&request_id).await?.ok_or_else(not_found)?;
    Ok(success(json!({
        "request_id": entry.request_id,
        "state": entry.state.as_str(),
        "queued_at": rfc3339(entry.enqueued_at),
        "expires_at": Value::Null,
        "result": Value::Null,
    })))
}
