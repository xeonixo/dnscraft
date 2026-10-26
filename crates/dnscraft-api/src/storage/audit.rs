//! Audit log (`audit_log` table) — append-only records over the shared connection.

use rusqlite::{Connection, params};

use super::{Db, db_err};
use crate::error::ControlApiError;

/// One append-only audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    /// Auto-assigned id (ignored on insert).
    pub id: i64,
    /// Unix seconds.
    pub time: i64,
    /// Node that performed the action.
    pub node_id: String,
    /// Actor identifier (user or token).
    pub actor_id: String,
    /// `user` or `token`.
    pub actor_type: String,
    /// Verb identifying the action.
    pub action: String,
    /// Kind of object that was changed.
    pub object_type: String,
    /// Identifier of the changed object.
    pub object_id: String,
    /// Config version at the time of the action.
    pub config_version: Option<i64>,
    /// Digest of the redacted before-snapshot.
    pub before_digest: Option<String>,
    /// Digest of the redacted after-snapshot.
    pub after_digest: Option<String>,
    /// Redacted before-snapshot (secrets masked).
    pub before: Option<String>,
    /// Redacted after-snapshot (secrets masked).
    pub after: Option<String>,
    /// `ok` or `error`.
    pub result: String,
    /// Stable error code when `result == "error"`.
    pub error_code: Option<String>,
}

fn insert(conn: &Connection, record: &AuditRecord) -> Result<i64, ControlApiError> {
    conn.execute(
        "INSERT INTO audit_log (
            time, node_id, actor_id, actor_type, action, object_type, object_id,
            config_version, before_digest, after_digest, before, after, result, error_code
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            record.time,
            record.node_id,
            record.actor_id,
            record.actor_type,
            record.action,
            record.object_type,
            record.object_id,
            record.config_version,
            record.before_digest,
            record.after_digest,
            record.before,
            record.after,
            record.result,
            record.error_code,
        ],
    )
    .map_err(db_err)?;
    Ok(conn.last_insert_rowid())
}

fn list(conn: &Connection, limit: u32, offset: u32) -> Result<Vec<AuditRecord>, ControlApiError> {
    let mut stmt = conn
        .prepare(
            "SELECT id, time, node_id, actor_id, actor_type, action, object_type, object_id,
                    config_version, before_digest, after_digest, before, after, result, error_code
             FROM audit_log
             ORDER BY time DESC, id DESC
             LIMIT ?1 OFFSET ?2",
        )
        .map_err(db_err)?;
    let rows = stmt
        .query_map(params![limit, offset], |row| {
            Ok(AuditRecord {
                id: row.get(0)?,
                time: row.get(1)?,
                node_id: row.get(2)?,
                actor_id: row.get(3)?,
                actor_type: row.get(4)?,
                action: row.get(5)?,
                object_type: row.get(6)?,
                object_id: row.get(7)?,
                config_version: row.get(8)?,
                before_digest: row.get(9)?,
                after_digest: row.get(10)?,
                before: row.get(11)?,
                after: row.get(12)?,
                result: row.get(13)?,
                error_code: row.get(14)?,
            })
        })
        .map_err(db_err)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
}

impl Db {
    /// Appends a record and returns its auto-assigned id.
    pub async fn audit_insert(&self, record: AuditRecord) -> Result<i64, ControlApiError> {
        self.with_conn(move |conn| insert(conn, &record)).await
    }

    /// Lists audit records, newest first (`time DESC, id DESC`).
    pub async fn audit_list(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditRecord>, ControlApiError> {
        self.with_conn(move |conn| list(conn, limit, offset)).await
    }
}
