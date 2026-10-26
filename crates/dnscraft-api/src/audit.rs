//! Audit record creation with secret redaction and digesting.

use serde_json::{Map, Value};

use crate::error::ControlApiError;
use crate::storage::{AuditRecord, Db};

/// Secret-key name fragments that mark a JSON value for redaction (matched
/// case-insensitively against object keys). Over-redaction is acceptable; the
/// invariant is that no secret material is ever persisted or exported.
const SECRET_KEY_FRAGMENTS: &[&str] = &["secret", "password", "private_key", "api_key"];

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Redacts known secret fields from `value`, recursively, returning a new value.
///
/// Any object key containing a [`SECRET_KEY_FRAGMENTS`] fragment is replaced by
/// the literal `"redacted"`. Non-secret values are copied verbatim.
pub(crate) fn redact(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, val) in map {
                let redacted = if is_secret_key(key) {
                    Value::String("redacted".to_owned())
                } else {
                    redact(val)
                };
                out.insert(key.clone(), redacted);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
        other => other.clone(),
    }
}

/// SHA-256 hex digest of `bytes` (lowercase, 64 characters).
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(digest.as_ref().len() * 2);
    for &b in digest.as_ref() {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn is_secret_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SECRET_KEY_FRAGMENTS.iter().any(|frag| lower.contains(frag))
}

/// Redacts and digests one optional snapshot.
fn redact_and_digest(
    value: Option<&Value>,
) -> Result<(Option<String>, Option<String>), ControlApiError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let redacted = redact(value);
    let json = serde_json::to_string(&redacted).map_err(serialize_err)?;
    let digest = sha256_hex(json.as_bytes());
    Ok((Some(json), Some(digest)))
}

fn serialize_err(err: serde_json::Error) -> ControlApiError {
    ControlApiError::Internal {
        message: err.to_string(),
    }
}

/// Input for recording one config change in the audit log.
///
/// The audit timestamp is stamped by [`Audit::record_config_change`] from the
/// database's injected clock (ADR-0005), not supplied by the caller.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigChangeRecord {
    /// Node that performed the action.
    pub node_id: String,
    /// Actor identifier (user or token).
    pub actor_id: String,
    /// `user` or `token`.
    pub actor_type: String,
    /// Config version at the time of the action.
    pub config_version: Option<i64>,
    /// Pre-change snapshot (secrets are redacted before persist).
    pub before: Option<Value>,
    /// Post-change snapshot (secrets are redacted before persist).
    pub after: Option<Value>,
    /// `ok` or `error`.
    pub result: String,
    /// Stable error code when `result == "error"`.
    pub error_code: Option<String>,
}

/// Builds a redacted, digested [`AuditRecord`] for a config change at `time`.
pub(crate) fn config_change_record(
    change: &ConfigChangeRecord,
    time: i64,
) -> Result<AuditRecord, ControlApiError> {
    let (before, before_digest) = redact_and_digest(change.before.as_ref())?;
    let (after, after_digest) = redact_and_digest(change.after.as_ref())?;
    Ok(AuditRecord {
        id: 0,
        time,
        node_id: change.node_id.clone(),
        actor_id: change.actor_id.clone(),
        actor_type: change.actor_type.clone(),
        action: "config.write".to_owned(),
        object_type: "config".to_owned(),
        object_id: "config".to_owned(),
        config_version: change.config_version,
        before_digest,
        after_digest,
        before,
        after,
        result: change.result.clone(),
        error_code: change.error_code.clone(),
    })
}

/// Appends redacted, digested audit records for mutating actions.
pub struct Audit {
    db: Db,
}

impl Audit {
    /// Wraps a database handle.
    pub fn new(db: Db) -> Self {
        Self { db }
    }

    /// Records a config change with redacted before/after snapshots and their
    /// SHA-256 digests, returning the new record id.
    pub async fn record_config_change(
        &self,
        change: ConfigChangeRecord,
    ) -> Result<i64, ControlApiError> {
        let time = self.db.now_unix();
        let record = config_change_record(&change, time)?;
        self.db.audit_insert(record).await
    }
}
