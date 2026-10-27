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
    "authorization",
    "bearer",
    "cookie",
    "token",
    "session",
    "pem",
    "apikey",
    "psk",
];

/// Name tokens that keep a key intact even when a secret token is also present
/// (e.g. `session_idle_timeout`, `api_token_max_ttl`, `oidc_token_skew` are
/// durations/limits, not secrets, and `legacy_session_mode` is a flag).
const ALLOW_TOKENS: &[&str] = &[
    "ttl", "timeout", "days", "max", "limit", "attempts", "window", "enabled", "count", "interval",
    "lifetime", "skew", "duration", "expiry", "age", "mode",
];

/// Tokens that mark a key secret when combined with `key` (or `keys`), e.g.
/// `private_key`, `api_key`, `access_key`, `signing_key`, `master_key`,
/// `auth_key`. `key` alone is not a secret indicator.
const KEY_MODIFIERS: &[&str] = &[
    "private",
    "api",
    "access",
    "signing",
    "encryption",
    "hmac",
    "shared",
    "master",
    "auth",
];

/// Exact key names that are identifiers, not secret material, even though a
/// token names them secret. `token_id` is the creating token's public id inside
/// a versioned MCP rule; redacting it would lose the rollback snapshot's
/// provenance. `session_id` is deliberately *not* listed here (it is secret).
const EXACT_ALLOW_KEYS: &[&str] = &["token_id"];

const HEX: &[u8; 16] = b"0123456789abcdef";

/// Redacts secret material from `value`, recursively, returning a new value.
///
/// An object key is redacted when its tokens contain a [`SECRET_TOKENS`] token
/// (or a `key`+modifier pair) and no [`ALLOW_TOKENS`] token. String values are
/// also redacted when they look like a PEM block, a `Bearer`/`Basic` credential,
/// an `Authorization:` header, or a URL with embedded userinfo. Everything else
/// is copied verbatim.
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

/// Whether a string value itself carries secret material, independent of its key
/// name: a PEM block, a `Bearer`/`Basic` credential, an `Authorization:` header,
/// or a URL whose authority embeds `user:pass@` userinfo.
fn looks_secret_value(s: &str) -> bool {
    starts_with_ci(s, "Bearer ")
        || starts_with_ci(s, "Basic ")
        || starts_with_ci(s, "Authorization:")
        || s.contains("-----BEGIN ")
        || looks_like_url_userinfo(s)
}

/// Case-insensitive `starts_with`, `None` when `s` is shorter than `prefix`.
fn starts_with_ci(s: &str, prefix: &str) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

/// Whether `s` looks like `scheme://user:pass@host` (URL userinfo).
fn looks_like_url_userinfo(s: &str) -> bool {
    let Some(scheme_end) = s.find("://") else {
        return false;
    };
    let authority = &s[scheme_end + 3..];
    let authority = authority.split(['/', '?', '#']).next().unwrap_or("");
    authority
        .rfind('@')
        .is_some_and(|at| authority[..at].contains(':'))
}

/// Whether an object key names a secret field (token-based, see module docs).
fn is_secret_key(key: &str) -> bool {
    if EXACT_ALLOW_KEYS.contains(&key) {
        return false;
    }
    let tokens = tokenize_key(key);
    if tokens.is_empty() {
        return false;
    }
    // Allow-list tokens override secret tokens (durations/counts/flags stay
    // intact even when they mention `token` or `session`).
    if tokens.iter().any(|t| ALLOW_TOKENS.contains(&t.as_str())) {
        return false;
    }
    if tokens.iter().any(|t| is_secret_token(t)) {
        return true;
    }
    // `key`/`keys` combined with a modifier names a secret (`auth_key`,
    // `master_key`), but `key` alone does not.
    let has_key = tokens.iter().any(|t| t == "key" || t == "keys");
    has_key && tokens.iter().any(|t| KEY_MODIFIERS.contains(&t.as_str()))
}

/// Whether a single token is a secret token, normalising a trailing plural `s`
/// so `tokens`, `secrets`, `passwords` and `cookies` match their singular.
fn is_secret_token(token: &str) -> bool {
    if SECRET_TOKENS.contains(&token) {
        return true;
    }
    token
        .strip_suffix('s')
        .is_some_and(|singular| !singular.is_empty() && SECRET_TOKENS.contains(&singular))
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
/// Used by the config-export path (A10) to assert that a serialized snapshot
/// carries no plaintext secrets: after [`redact`], a secret-bearing snapshot
/// must contain this placeholder. There is no non-test caller until A10 lands,
/// hence the dead-code allow.
#[allow(dead_code)]
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
    /// Verb identifying the action (`config.write` or `config.rollback`).
    pub action: String,
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
        action: change.action.clone(),
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
    use std::time::Duration;

    use serde_json::json;

    use dnscraft_mcp::McpConfig;

    use super::*;
    use crate::config::{
        AuthConfig, ControlApiConfig, IpTruncate, QueryLogConfig, RateLimitConfig,
    };
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
    fn redact_config_redacts_only_the_real_secret_fields() {
        for config in [ControlApiConfig::default(), non_default_config()] {
            let value = serde_json::to_value(&config).unwrap();
            let out = redact(&value);
            let mut pointers = redacted_leaf_pointers(&out);
            pointers.sort();
            assert_eq!(pointers, ["/auth/oidc_client_secret"]);
            // The plaintext secret never appears anywhere.
            assert!(
                !serde_json::to_string(&out)
                    .unwrap()
                    .contains("real-secret-value")
            );
        }
    }

    /// Keys the config model treats as secrets; used by the guard test below.
    const EXPECTED_SECRET_KEYS: &[&str] = &["oidc_client_secret"];

    #[test]
    fn serialized_keys_are_consistently_classified() {
        // If a future config field matches a secret token (or a key+modifier
        // pair) without being listed here — or is listed here but not flagged —
        // this fails, so a `*_token_*`-style field can neither silently leak nor
        // be silently over-redacted.
        for config in [ControlApiConfig::default(), non_default_config()] {
            let value = serde_json::to_value(&config).unwrap();
            let mut flagged: Vec<String> = all_object_keys(&value)
                .into_iter()
                .filter(|key| is_secret_key(key))
                .collect();
            flagged.sort();
            let mut expected: Vec<String> = EXPECTED_SECRET_KEYS
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            expected.sort();
            assert_eq!(flagged, expected);
        }
    }

    #[test]
    fn redact_normalises_plural_secret_tokens() {
        let value = json!({
            "api_tokens": "a",
            "client_secrets": "b",
            "passwords": "c",
            "cookies": "d",
            "status": "e", // trailing 's' but not a plural secret
        });
        let out = redact(&value);
        assert_eq!(out["api_tokens"], "redacted");
        assert_eq!(out["client_secrets"], "redacted");
        assert_eq!(out["passwords"], "redacted");
        assert_eq!(out["cookies"], "redacted");
        assert_eq!(out["status"], "e");
    }

    #[test]
    fn redact_key_combined_with_modifiers() {
        for key in [
            "access_key",
            "signing_key",
            "encryption_key",
            "hmac_key",
            "shared_key",
            "master_key",
        ] {
            let value = Value::Object(serde_json::Map::from_iter([(
                key.to_owned(),
                Value::String("x".into()),
            )]));
            let expected = Value::Object(serde_json::Map::from_iter([(
                key.to_owned(),
                Value::String("redacted".into()),
            )]));
            assert_eq!(redact(&value), expected, "{key}");
        }
        // `key` alone is not a secret indicator.
        assert_eq!(redact(&json!({ "key": "x" })), json!({ "key": "x" }));
    }

    #[test]
    fn redact_psk_and_auth_key_but_not_bare_auth() {
        let out = redact(&json!({
            "psk": "x",
            "auth_key": "y",
            "auth": "z",
            "auth_per_second": 10,
        }));
        assert_eq!(out["psk"], "redacted");
        assert_eq!(out["auth_key"], "redacted");
        // Bare `auth` (a config section) and `auth_per_second` (a rate limit)
        // are not secrets.
        assert_eq!(out["auth"], "z");
        assert_eq!(out["auth_per_second"].as_i64(), Some(10));
    }

    #[test]
    fn redact_value_detects_url_userinfo_and_auth_strings() {
        let out = redact(&json!({
            "dsn": "postgres://alice:secret@db.internal/dnscraft",
            "header": "Authorization: Bearer abc.def",
            "basic": "Basic dXNlcjpwYXNz",
            "plain_url": "https://example.com/path",
            "note": "nothing",
        }));
        assert_eq!(out["dsn"], "redacted");
        assert_eq!(out["header"], "redacted");
        assert_eq!(out["basic"], "redacted");
        assert_eq!(out["plain_url"], "https://example.com/path");
        assert_eq!(out["note"], "nothing");
    }

    /// A config whose every field differs from its default, so the redaction
    /// assertion covers the full value space, not just the defaults.
    fn non_default_config() -> ControlApiConfig {
        ControlApiConfig {
            bind: "10.1.2.3".parse().unwrap(),
            port: 9000,
            tls: false,
            trusted_proxies: vec!["192.0.2.10".parse().unwrap()],
            auth: AuthConfig {
                oidc_enabled: false,
                oidc_issuer: "https://issuer.example.com".into(),
                oidc_client_id: "client-123".into(),
                oidc_client_secret: Secret::new("real-secret-value"),
                oidc_admin_group: "admins".into(),
                oidc_token_skew: Duration::from_secs(60),
                local_login_enabled: false,
                local_login_max_attempts: 3,
                local_login_lock_window: Duration::from_secs(600),
                api_token_max_ttl: Duration::from_secs(30 * 24 * 3600),
                session_idle_timeout: Duration::from_secs(900),
                session_absolute_timeout: Duration::from_secs(3600),
            },
            query_log: QueryLogConfig {
                retention_days: 7,
                ip_truncate: IpTruncate::LastGroup,
                max_rows_per_request: 500,
            },
            rate_limit: RateLimitConfig {
                read_per_second: 50,
                write_per_second: 10,
                auth_per_second: 5,
                burst_factor: 3,
            },
            mcp: McpConfig::default(),
        }
    }

    /// JSON pointers of every leaf whose value is the literal `"redacted"`.
    fn redacted_leaf_pointers(value: &Value) -> Vec<String> {
        let mut out = Vec::new();
        collect_redacted(value, "", &mut out);
        out
    }

    fn collect_redacted(value: &Value, prefix: &str, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    let path = format!("{prefix}/{key}");
                    collect_redacted(val, &path, out);
                }
            }
            Value::Array(items) => {
                for (i, val) in items.iter().enumerate() {
                    let path = format!("{prefix}/{i}");
                    collect_redacted(val, &path, out);
                }
            }
            Value::String(s) if s == "redacted" => out.push(prefix.to_owned()),
            _ => {}
        }
    }

    /// Distinct object-key names at every nesting level of `value`.
    fn all_object_keys(value: &Value) -> Vec<String> {
        let mut out = Vec::new();
        collect_keys(value, &mut out);
        out.sort();
        out.dedup();
        out
    }

    fn collect_keys(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, val) in map {
                    out.push(key.clone());
                    collect_keys(val, out);
                }
            }
            Value::Array(items) => {
                for val in items {
                    collect_keys(val, out);
                }
            }
            _ => {}
        }
    }
}
