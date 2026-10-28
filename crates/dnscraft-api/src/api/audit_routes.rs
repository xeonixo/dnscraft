//! `GET /api/v1/audit` — the redacted, append-only audit log.
//!
//! The route is admin-only (the centralized RBAC middleware maps
//! `/api/v1/audit` to `Requirement::ApiAdmin`). Rows are returned newest first;
//! secrets were masked before the rows were stored.

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde_json::json;

use crate::api::pagination::{Pagination, RawPagination};
use crate::api::response::{success, unix_rfc3339};
use crate::error::ControlApiError;
use crate::server::AppState;

/// `GET /api/v1/audit` — paginated audit rows, newest first.
pub(crate) async fn list_audit(
    State(state): State<AppState>,
    query: Query<RawPagination>,
) -> Result<impl IntoResponse, ControlApiError> {
    let db = state.db().ok_or_else(|| ControlApiError::NotFound {
        what: "audit log".to_owned(),
    })?;
    let page = Pagination::from_query(query)?;
    let offset = u32::try_from(page.offset).map_err(|_| ControlApiError::PaginationInvalid {
        reason: "offset is too large".to_owned(),
    })?;
    let records =
        db.audit_list(page.limit, offset)
            .await
            .map_err(|err| ControlApiError::AuditRead {
                message: err.to_string(),
            })?;
    let audit: Vec<_> = records
        .into_iter()
        .map(|record| {
            json!({
                "id": record.id,
                "time": unix_rfc3339(record.time),
                "node_id": record.node_id,
                "actor_id": record.actor_id,
                "actor_type": record.actor_type,
                "action": record.action,
                "object_type": record.object_type,
                "object_id": record.object_id,
                "config_version": record.config_version,
                "before_digest": record.before_digest,
                "after_digest": record.after_digest,
                "before": record.before,
                "after": record.after,
                "result": record.result,
                "error_code": record.error_code,
            })
        })
        .collect();
    Ok(success(json!({ "audit": audit })))
}
