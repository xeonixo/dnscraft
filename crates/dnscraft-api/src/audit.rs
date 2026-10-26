//! Audit record creation with secret redaction and digesting.

use serde_json::{Map, Value};

use crate::error::ControlApiError;
use crate::storage::{AuditRecord, Db};

/// Secret name tokens that mark a JSON object key for redaction. Keys are
/// split into tokens on `_`, `-` and camelCase boundaries and compared
/// case-insensitively. Over-redaction is acceptable; the invariant is that no
/// secret material is ever persisted or exported.
const SECRET_TOKENS: &[&str] = &[
    "secret",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
    "authorization",
    "bearer",
    "cookie",
    "token",
    "session",
    "pem",
    "apikey",
];

/// Name tokens that keep a key intact even when a secret token is also present
/// (e.g. `session_idle_timeout`, `api_token_max_ttl` are durations, not secrets).
const ALLOW_TOKENS: &[&str] = &[
    "ttl", "timeout", "days", "max", "limit", "attempts", "window", "enabled", "count", "interval",
    "lifetime",
];

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Redacts secret material from `value`, recursively, returning a new value.
///
/// An object key is redacted when its tokens contain a [`SECRET_TOKENS`] token
/// (or the `private`+`key` / `api`+`key` pair) and no [`ALLOW_TOKENS`] token.
/// String values are also redacted when they look like a PEM block or a
/// `Bearer` credential. Everything else is copied verbatim.
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
        Value::String(s) if looks_secret_value(s) => Value::String("redacted".to_owned()),
        other => other.clone(),
    }
}

/// Whether a string value itself carries secret material (PEM block or Bearer
/// credential), independent of its key name.
fn looks_secret_value(s: &str) -> bool {
    s.get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("Bearer "))
        || s.contains("-----BEGIN ")
}

/// Whether an object key names a secret field (token-based, see module docs).
fn is_secret_key(key: &str) -> bool {
    let tokens = tokenize_key(key);
    if tokens.is_empty() {
        return false;
    }
    // Allow-list tokens override secret tokens (durations/counts/flags stay
    // intact even when they mention `token` or `session`).
    if tokens.iter().any(|t| ALLOW_TOKENS.contains(&t.as_str())) {
        return false;
    }
    if tokens.iter().any(|t| SECRET_TOKENS.contains(&t.as_str())) {
        return true;
    }
    let has = |needle: &str| tokens.iter().any(|t| t == needle);
    (has("private") && has("key")) || (has("api") && has("key"))
}

/// Splits an object key into lowercase tokens on `_`, `-` and camelCase
/// boundaries (an acronym run before a lowercase letter also starts a token).
fn tokenize_key(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut tokens = Vec::new();
    let mut current = String::new();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
            continue;
        }
        if c.is_uppercase() {
            let prev_lower = i > 0 && chars[i - 1].is_lowercase();
            let next_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
            if !current.is_empty() && (prev_lower || next_lower) {
                tokens.push(std::mem::take(&mut current));
            }
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Whether `value` contains the literal `"redacted"` placeholder string.
///
/// Test-only helper used to assert that a snapshot has been redacted; it has
/// no non-test caller yet.
#[cfg(test)]
pub(crate) fn contains_redacted_placeholder(value: &Value) -> bool {
    match value {
        Value::String(s) => s == "redacted",
        Value::Array(items) => items.iter().any(contains_redacted_placeholder),
        Value::Object(map) => map.values().any(contains_redacted_placeholder),
        _ => false,
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

/// Redacts and digests one optional snapshot.
///
/// The digest is a SHA-256 over canonical JSON (keys sorted recursively, no
/// whitespace), so it is independent of serde_json's `preserve_order` feature.
/// Because redaction already replaces every secret with the literal
/// `"redacted"`, a change that differs only in secret values does not change
/// the digest — the digest cannot be used as an oracle to confirm a secret.
fn redact_and_digest(
    value: Option<&Value>,
) -> Result<(Option<String>, Option<String>), ControlApiError> {
    let Some(value) = value else {
        return Ok((None, None));
    };
    let redacted = redact(value);
    let json = canonical_json(&redacted)?;
    let digest = sha256_hex(json.as_bytes());
    Ok((Some(json), Some(digest)))
}

/// Serializes `value` to canonical JSON: object keys sorted recursively and no
/// whitespace, independent of serde_json's `preserve_order` feature.
fn canonical_json(value: &Value) -> Result<String, ControlApiError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), ControlApiError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => out.push_str(&serde_json::to_string(s).map_err(serialize_err)?),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            out.push('{');
            for (i, (key, val)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).map_err(serialize_err)?);
                out.push(':');
                write_canonical(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::config::ControlApiConfig;
    use crate::secret::Secret;

    #[test]
    fn canonical_json_sorts_keys_recursively_and_is_compact() {
        let value = json!({
            "z": 1,
            "a": { "y": true, "b": "x\"y" },
            "arr": [3, 1, 2]
        });
        assert_eq!(
            canonical_json(&value).unwrap(),
            r#"{"a":{"b":"x\"y","y":true},"arr":[3,1,2],"z":1}"#
        );
    }

    #[test]
    fn canonical_json_matches_compact_json_for_sorted_input() {
        // With the default (non-preserve_order) serde_json map, keys are already
        // sorted, so canonical JSON must equal serde_json's compact output.
        let value = json!({ "a": 1, "b": [true, null, "s"] });
        assert_eq!(
            canonical_json(&value).unwrap(),
            serde_json::to_string(&value).unwrap()
        );
    }

    #[test]
    fn tokenize_key_splits_snake_dash_and_camel() {
        assert_eq!(tokenize_key("client_secret"), ["client", "secret"]);
        assert_eq!(tokenize_key("client-secret"), ["client", "secret"]);
        assert_eq!(tokenize_key("clientSecret"), ["client", "secret"]);
        assert_eq!(tokenize_key("APIKey"), ["api", "key"]);
        assert_eq!(
            tokenize_key("session_idle_timeout"),
            ["session", "idle", "timeout"]
        );
    }

    #[test]
    fn redact_matches_tokens_not_substrings() {
        // "secret" token redacts, but a mere substring ("secretion") does not.
        assert_eq!(
            redact(&json!({ "secretion": "x" })),
            json!({ "secretion": "x" })
        );
        assert_eq!(
            redact(&json!({ "clientSecret": "x" })),
            json!({ "clientSecret": "redacted" })
        );
        // Pairs: private+key and api+key.
        assert_eq!(
            redact(&json!({ "private_key": "x" })),
            json!({ "private_key": "redacted" })
        );
        assert_eq!(
            redact(&json!({ "apiKey": "x" })),
            json!({ "apiKey": "redacted" })
        );
    }

    #[test]
    fn redact_keeps_allow_listed_durations() {
        let value = json!({
            "token_ttl_days": 30,
            "session_idle_timeout": 3600,
            "session_idle_timeout_seconds": 3600,
            "client_secret": "s3cret"
        });
        let out = redact(&value);
        assert_eq!(out["token_ttl_days"].as_i64(), Some(30));
        assert_eq!(out["session_idle_timeout"].as_i64(), Some(3600));
        assert_eq!(out["client_secret"], "redacted");
    }

    #[test]
    fn redact_detects_pem_and_bearer_values() {
        let value = json!({
            "tls": { "cert": "-----BEGIN CERTIFICATE-----\nABC" },
            "auth_header": "Bearer abc.def.ghi",
            "note": "just a note"
        });
        let out = redact(&value);
        assert_eq!(out["tls"]["cert"], "redacted");
        assert_eq!(out["auth_header"], "redacted");
        assert_eq!(out["note"], "just a note");
    }

    #[test]
    fn contains_redacted_placeholder_detects_nested() {
        assert!(contains_redacted_placeholder(
            &json!({ "a": { "b": "redacted" } })
        ));
        assert!(contains_redacted_placeholder(&json!(["x", "redacted"])));
        assert!(!contains_redacted_placeholder(
            &json!({ "a": { "b": "ok" } })
        ));
        assert!(!contains_redacted_placeholder(&json!(1)));
    }

    #[test]
    fn control_api_config_redacts_secret_and_keeps_durations() {
        let mut config = ControlApiConfig::default();
        config.auth.oidc_client_secret = Secret::new("supersecret");
        let value = serde_json::to_value(&config).unwrap();

        // The Secret field serializes as "redacted" before redact() even runs.
        assert_eq!(
            value["auth"]["oidc_client_secret"].as_str(),
            Some("redacted")
        );

        let out = redact(&value);
        assert_eq!(out["auth"]["oidc_client_secret"].as_str(), Some("redacted"));
        // Duration/count fields with allow-list tokens stay intact.
        assert!(out["auth"]["api_token_max_ttl"].is_object());
        assert!(out["auth"]["session_idle_timeout"].is_object());
        assert!(out["auth"]["session_absolute_timeout"].is_object());
        assert!(out["auth"]["local_login_max_attempts"].is_number());
        // Non-secret identifiers survive verbatim.
        assert_eq!(out["auth"]["oidc_client_id"].as_str(), Some(""));
        // The plaintext secret never appears anywhere.
        assert!(!serde_json::to_string(&out).unwrap().contains("supersecret"));
    }
}
