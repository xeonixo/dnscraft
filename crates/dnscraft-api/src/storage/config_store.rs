//! Config snapshot/version store (kv + `config_versions`) with secret redaction.

use serde_json::Value;

use super::Db;
use crate::audit::redact;
use crate::error::ControlApiError;

/// Key in `kv` that records the current (latest) config version.
const CURRENT_VERSION_KEY: &str = "config.current_version";

/// Stores and retrieves versioned, redacted config snapshots.
#[derive(Clone)]
pub struct ConfigStore {
    db: Db,
}

impl ConfigStore {
    /// Wraps a database handle.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Redacts secrets, stores the snapshot, marks it current, and returns its version.
    pub async fn store(&self, snapshot: &Value) -> Result<i64, ControlApiError> {
        let redacted = redact(snapshot);
        let json = serde_json::to_string(&redacted).map_err(serialize_err)?;
        let version = self.db.config_version_insert(&json).await?;
        self.db
            .kv_set(CURRENT_VERSION_KEY, &version.to_string())
            .await?;
        Ok(version)
    }

    /// Loads the exact stored snapshot of a version (already redacted).
    pub async fn load(&self, version: i64) -> Result<Option<Value>, ControlApiError> {
        match self.db.config_version_load(version).await? {
            None => Ok(None),
            Some(json) => serde_json::from_str(&json).map(Some).map_err(serialize_err),
        }
    }

    /// Returns the current (latest) version, if any snapshot has been stored.
    pub async fn current(&self) -> Result<Option<i64>, ControlApiError> {
        let Some(raw) = self.db.kv_get(CURRENT_VERSION_KEY).await? else {
            return Ok(None);
        };
        match raw.parse::<i64>() {
            Ok(version) => Ok(Some(version)),
            Err(_) => Err(ControlApiError::Internal {
                message: format!("invalid current config version: {raw}"),
            }),
        }
    }
}

fn serialize_err(err: serde_json::Error) -> ControlApiError {
    ControlApiError::Internal {
        message: err.to_string(),
    }
}
