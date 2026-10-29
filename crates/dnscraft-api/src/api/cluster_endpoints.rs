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
use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use dnscraft_cluster::ClusterStore;

use crate::api::config_routes::{json_body, module_error};
use crate::api::response::{success, unix_rfc3339 as rfc3339};
use crate::error::ControlApiError;
use crate::server::AppState;

/// Request body of `POST /api/v1/cluster/join-tokens`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JoinTokenBody {
    node_id: String,
}

/// Request body of `PUT /api/v1/cluster/nodes/{node_id}`. Both fields are
/// replaced as sent; `null` or an empty string clears one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeMetaBody {
    display_name: Option<String>,
    hostname: Option<String>,
}

/// A DNS name of lowercase labels (1–63 chars, letters/digits/hyphen), at most 253 chars.
fn valid_hostname(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            let b = label.as_bytes();
            (1..=63).contains(&b.len())
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b[0] != b'-'
                && b[b.len() - 1] != b'-'
        })
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

fn store(state: &AppState) -> Result<&Arc<ClusterStore>, ControlApiError> {
    state
        .cluster_store()
        .ok_or_else(|| ControlApiError::NotFound {
            what: "cluster".to_owned(),
        })
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

/// `GET /api/v1/cluster/nodes` — local node (master or this sub-node) plus every
/// registered peer. Pickers need the local id; revoke still only applies to peers.
pub(crate) async fn list_nodes(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ControlApiError> {
    let connected: std::collections::HashSet<String> = state
        .cluster_broadcast()
        .map(|broadcast| broadcast.connected_node_ids().into_iter().collect())
        .unwrap_or_default();
    let meta = store(&state)?.node_meta().await?;
    let meta_of = |id: &str| meta.get(id).cloned().unwrap_or_default();
    let mut nodes: Vec<Value> = Vec::new();
    if let Some(status) = state
        .cluster_status()
        .and_then(|handle| handle.cluster_status())
    {
        nodes.push(json!({
            "node_id": status.node_id,
            "role": status.role,
            "fingerprint": Value::Null,
            "joined_at": Value::Null,
            "last_seen": Value::Null,
            "applied_config_version": status.applied_version,
            "revoked": false,
            "local": true,
            "connected": true,
            "remote_addr": Value::Null,
            "transport": Value::Null,
            "display_name": meta_of(&status.node_id).0,
            "hostname": meta_of(&status.node_id).1,
        }));
    }
    let local_id = nodes
        .first()
        .and_then(|row| row.get("node_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    for node in store(&state)?.list_nodes().await? {
        if local_id.as_deref() == Some(node.node_id.as_str()) {
            continue;
        }
        let is_connected = connected.contains(&node.node_id);
        nodes.push(json!({
            "node_id": node.node_id,
            // Registry entries are peers that joined; the local row above is this process.
            "role": "sub_node",
            "fingerprint": node.fingerprint,
            "joined_at": rfc3339(node.joined_at),
            "last_seen": node.last_seen.map(rfc3339),
            "applied_config_version": node.applied_config_version,
            "revoked": node.revoked,
            "local": false,
            "connected": is_connected,
            "remote_addr": node.remote_addr,
            // Cluster peer links are always mTLS over HTTP/2.
            "transport": "mtls",
            "display_name": meta_of(&node.node_id).0,
            "hostname": meta_of(&node.node_id).1,
        }));
    }
    Ok(success(nodes))
}

/// `PUT /api/v1/cluster/nodes/{node_id}` — set the display name and host name.
///
/// The node id is the cluster identity (certificate, registry) and cannot change.
pub(crate) async fn update_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    body: Result<Json<NodeMetaBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "cluster.role.invalid")?;
    let display_name = non_empty(body.display_name);
    let hostname = non_empty(body.hostname).map(|h| h.to_ascii_lowercase());
    if display_name
        .as_ref()
        .is_some_and(|n| n.chars().count() > 64 || n.chars().any(char::is_control))
    {
        return Err(module_error(
            "cluster.role.invalid",
            "display_name must be at most 64 characters without control characters",
        ));
    }
    if hostname.as_ref().is_some_and(|h| !valid_hostname(h)) {
        return Err(module_error(
            "cluster.role.invalid",
            "hostname must be a DNS name of lowercase labels",
        ));
    }
    let store = store(&state)?;
    let known_peer = store.get_node(&node_id).await?.is_some();
    let is_local = state
        .cluster_status()
        .and_then(|handle| handle.cluster_status())
        .is_some_and(|status| status.node_id == node_id);
    if !known_peer && !is_local {
        return Err(ControlApiError::NotFound {
            what: format!("node {node_id}"),
        });
    }
    store
        .set_node_meta(&node_id, display_name.as_deref(), hostname.as_deref())
        .await?;
    Ok(success(
        json!({ "node_id": node_id, "display_name": display_name, "hostname": hostname }),
    ))
}

#[derive(Deserialize)]
pub(crate) struct RemoveQuery {
    #[serde(default)]
    remove: bool,
}

/// `DELETE /api/v1/cluster/nodes/{node_id}` — revoke a node.
///
/// Its next connection is rejected with `cluster.node.revoked`, and its
/// currently open stream is dropped so it receives no further pushes.
/// With `?remove=true` an already revoked node is deleted instead
/// (`cluster.node.not_revoked` for an active one).
pub(crate) async fn revoke_node(
    State(state): State<AppState>,
    Path(node_id): Path<String>,
    Query(query): Query<RemoveQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    if query.remove {
        store(&state)?.remove_revoked(&node_id).await?;
        return Ok(success(json!({ "node_id": node_id, "removed": true })));
    }
    store(&state)?.revoke(&node_id).await?;
    if let Some(broadcast) = state.cluster_broadcast() {
        broadcast.disconnect(&node_id);
    }
    Ok(success(json!({ "node_id": node_id, "revoked": true })))
}

/// `GET /api/v1/cluster/writes/{request_id}` — state of a buffered offline
/// write.
///
/// `expires_at` is the 202 deadline (RFC 3339) and `result` is `{status}` once
/// a replay has produced the master's answer. Both are `null` until known, and
/// for rows queued before the queue stored them.
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
        "expires_at": entry.expires_at.map(rfc3339),
        "result": entry.result_status.map(|status| json!({ "status": status })),
    })))
}
