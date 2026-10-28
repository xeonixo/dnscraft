//! Write-only UniFi API keys in SQLite kv (`unifi.api_key.{profile_id}`).

use crate::error::ControlApiError;
use crate::storage::Db;

/// Kv key for one UniFi profile's API key.
pub(crate) fn api_key_kv(profile_id: &str) -> String {
    format!("unifi.api_key.{profile_id}")
}

/// Whether a non-empty API key is stored for `profile_id`.
pub(crate) async fn has_api_key(db: &Db, profile_id: &str) -> Result<bool, ControlApiError> {
    Ok(db
        .kv_get(&api_key_kv(profile_id))
        .await?
        .is_some_and(|v| !v.is_empty()))
}

/// Stores or clears the API key for `profile_id`.
///
/// `None` clears the key; `Some("")` is rejected.
pub(crate) async fn set_api_key(
    db: &Db,
    profile_id: &str,
    api_key: Option<&str>,
) -> Result<(), ControlApiError> {
    let key = api_key_kv(profile_id);
    match api_key {
        None => db.kv_delete(&key).await,
        Some("") => Err(ControlApiError::Module {
            code: "clients.config.invalid",
            params: Some(serde_json::json!({
                "reason": "api_key must not be empty; use null to clear"
            })),
        }),
        Some(value) => db.kv_set(&key, value).await,
    }
}

/// Loads the stored API key, if any (cluster `SecretPush` and the clients applier).
pub async fn get_api_key(db: &Db, profile_id: &str) -> Result<Option<String>, ControlApiError> {
    let value = db.kv_get(&api_key_kv(profile_id)).await?;
    Ok(value.filter(|v| !v.is_empty()))
}
