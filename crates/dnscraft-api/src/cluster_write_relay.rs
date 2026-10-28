//! Sub-node HTTP config writes relayed to the master (SPEC-cluster § Live relay).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::http::{HeaderMap, StatusCode, header::IF_MATCH};
use axum::response::{IntoResponse, Response};
use dnscraft_cluster::{EnqueueOutcome, QueuedWrite, RelayedActor, WriteExecutor, WriteRelay};
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::response::{success, unix_rfc3339};
use crate::config_apply::ConfigActor;
use crate::error::ControlApiError;
use crate::server::AppState;

static HTTP_RELAY_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Live relay executor installed on a sub-node by [`crate::ClusterRuntime`].
#[derive(Clone)]
pub(crate) struct ClusterWriteRelay {
    executor: Arc<dyn WriteExecutor>,
    node_id: String,
}

impl ClusterWriteRelay {
    /// Wraps the mTLS client executor for this sub-node.
    pub(crate) fn new(executor: Arc<dyn WriteExecutor>, node_id: impl Into<String>) -> Self {
        Self {
            executor,
            node_id: node_id.into(),
        }
    }
}

/// Holds the sub-node write relay installed at runtime.
pub(crate) type ClusterWriteRelayHandle = Arc<Mutex<Option<ClusterWriteRelay>>>;

/// Forwards a config-family write to the master when this process is a sub-node.
///
/// Returns `Some(response)` when the request was relayed or queued; `None` when
/// the caller should apply locally (master or standalone).
pub(crate) async fn relay_config_write_if_sub_node(
    state: &AppState,
    method: &str,
    path: &str,
    body: Value,
    actor: &ConfigActor,
    auth: Option<&Authenticated>,
    headers: &HeaderMap,
) -> Result<Option<Response>, ControlApiError> {
    if !state.is_cluster_sub_node() {
        return Ok(None);
    }
    let relay = state
        .cluster_write_relay()
        .ok_or_else(|| ControlApiError::Internal {
            message: "cluster sub-node write relay is not configured".to_owned(),
        })?;
    let if_match = headers
        .get(IF_MATCH)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let idempotency_key = headers
        .get("Idempotency-Key")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let relayed_actor = relayed_actor(actor, auth)?;
    let request_id = format!(
        "http-{}",
        HTTP_RELAY_COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let write = WriteRelay {
        request_id: request_id.clone(),
        idempotency_key: idempotency_key.clone(),
        if_match: if_match.clone(),
        method: method.to_owned(),
        path: path.to_owned(),
        body,
        actor: relayed_actor,
    };

    let master_reachable = state
        .cluster_status()
        .and_then(|handle| handle.cluster_status())
        .is_some_and(|status| status.master_reachable);

    if master_reachable {
        match relay
            .executor
            .execute(
                &relay.node_id,
                &request_id,
                write.actor.clone(),
                write.method.clone(),
                write.path.clone(),
                write.body.clone(),
                write.if_match.clone(),
                write.idempotency_key.clone(),
            )
            .await
        {
            Ok(response) => return Ok(Some(relay_http_response(response))),
            Err(error) if error.code() == "cluster.write_relay_failed" => {}
            Err(error) => return Err(error.into()),
        }
    }

    let Some(queue) = state.offline_write_queue() else {
        return Err(ControlApiError::Module {
            code: "cluster.write_relay_failed",
            params: Some(json!({ "outcome": "unknown" })),
        });
    };
    match queue.enqueue(write).await.map_err(ControlApiError::from)? {
        EnqueueOutcome::Queued(queued) => Ok(Some(queued_response(queued))),
        EnqueueOutcome::Rejected => Err(ControlApiError::Module {
            code: "cluster.offline_write_requires_idempotency",
            params: None,
        }),
        EnqueueOutcome::Full => Err(ControlApiError::Module {
            code: "cluster.offline_write_queue_full",
            params: None,
        }),
        EnqueueOutcome::Disabled => Err(ControlApiError::Module {
            code: "cluster.master_unavailable",
            params: None,
        }),
    }
}

fn relayed_actor(
    actor: &ConfigActor,
    auth: Option<&Authenticated>,
) -> Result<RelayedActor, ControlApiError> {
    let scope = auth
        .map(|auth| auth.scope().as_str().to_owned())
        .unwrap_or_else(|| "admin".to_owned());
    Ok(RelayedActor {
        actor_id: actor.actor_id.clone(),
        actor_type: actor.actor_type.clone(),
        scope,
    })
}

fn relay_http_response(response: dnscraft_cluster::RelayResponse) -> Response {
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(response.body)).into_response()
}

fn queued_response(queued: QueuedWrite) -> Response {
    (
        StatusCode::ACCEPTED,
        success(json!({
            "queued": true,
            "request_id": queued.request_id,
            "state": queued.state.as_str(),
            "queued_at": unix_rfc3339(queued.queued_at),
            "expires_at": unix_rfc3339(queued.expires_at),
        })),
    )
        .into_response()
}
