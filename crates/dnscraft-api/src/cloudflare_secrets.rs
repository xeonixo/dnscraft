//! Write-only Cloudflare API token in SQLite kv (`tls.cloudflare.api_token`).

use crate::error::ControlApiError;
use crate::storage::Db;

const KV_KEY: &str = "tls.cloudflare.api_token";

/// Whether a non-empty Cloudflare API token is stored.
pub(crate) async fn has_api_token(db: &Db) -> Result<bool, ControlApiError> {
    Ok(db.kv_get(KV_KEY).await?.is_some_and(|v| !v.is_empty()))
}

/// Stores or clears the Cloudflare API token.
///
/// `None` clears the token; `Some("")` is rejected.
pub(crate) async fn set_api_token(db: &Db, token: Option<&str>) -> Result<(), ControlApiError> {
    match token {
        None => db.kv_delete(KV_KEY).await,
        Some("") => Err(ControlApiError::Module {
            code: "tls.config.invalid",
            params: Some(serde_json::json!({
                "reason": "api_token must not be empty; use null to clear"
            })),
        }),
        Some(value) => db.kv_set(KV_KEY, value).await,
    }
}

/// Loads the stored token, if any (engine bootstrap after restart).
pub(crate) async fn get_api_token(db: &Db) -> Result<Option<String>, ControlApiError> {
    let value = db.kv_get(KV_KEY).await?;
    Ok(value.filter(|v| !v.is_empty()))
}
