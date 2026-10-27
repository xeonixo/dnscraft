//! Config snapshot/version store (`config_versions`) with secret redaction.

use serde_json::Value;

use super::{Db, audit as audit_store, db};
use crate::audit::{ConfigChangeRecord, config_change_record, redact};
use crate::error::ControlApiError;

/// Stores and retrieves versioned, redacted config snapshots.
///
/// The "current" version is not a separate pointer: it is always the highest
/// stored `config_versions.version` (`MAX(version)`). A `store` is therefore a
/// single insert — there is no second write that could leave a version inserted
/// but not yet current (no orphan version on failure).
#[derive(Clone)]
pub struct ConfigStore {
    db: Db,
}

impl ConfigStore {
    /// Wraps a database handle.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Redacts secrets, stores the snapshot, and returns its version.
    ///
    /// The new version becomes current by virtue of being the maximum; no
    /// separate pointer is written.
    pub async fn store(&self, snapshot: &Value) -> Result<i64, ControlApiError> {
        let redacted = redact(snapshot);
        let json = serde_json::to_string(&redacted).map_err(serialize_err)?;
        self.db.config_version_insert(&json).await
    }

    /// Stores `snapshot` and its audit record in one transaction.
    ///
    /// The config version and the audit row commit together or not at all, so
    /// a committed rule mutation can never be left unaudited. `change`'s
    /// `config_version` (and `after.config_version`, when `after` is an object)
    /// are set to the newly assigned version.
    pub(crate) async fn store_with_audit(
        &self,
        snapshot: &Value,
        change: ConfigChangeRecord,
    ) -> Result<i64, ControlApiError> {
        let redacted = redact(snapshot);
        let json = serde_json::to_string(&redacted).map_err(serialize_err)?;
        let created_at = self.db.now_unix();
        self.db
            .transaction(move |conn| {
                let version = db::config_version_insert(conn, &json, created_at)?;
                let mut change = change;
                change.config_version = Some(version);
                if let Some(Value::Object(after)) = change.after.as_mut() {
                    after.insert("config_version".to_owned(), Value::from(version));
                }
                let record = config_change_record(&change, created_at)?;
                audit_store::audit_insert(conn, &record)?;
                Ok(version)
            })
            .await
    }

    /// Loads the exact stored snapshot of a version (already redacted).
    pub async fn load(&self, version: i64) -> Result<Option<Value>, ControlApiError> {
        match self.db.config_version_load(version).await? {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json).map(Some).map_err(serialize_err),
        }
    }

    /// Returns the current (highest) version, if any snapshot has been stored.
    pub async fn current(&self) -> Result<Option<i64>, ControlApiError> {
        self.db.config_version_max().await
    }

    /// Lists stored versions newest first as `(version, created_at)`.
    pub async fn versions(
        &self,
        limit: u32,
        offset: u64,
    ) -> Result<Vec<(i64, i64)>, ControlApiError> {
        self.db.config_version_list(limit, offset).await
    }
}

fn serialize_err(err: serde_json::Error) -> ControlApiError {
    ControlApiError::Internal {
        message: err.to_string(),
    }
}
