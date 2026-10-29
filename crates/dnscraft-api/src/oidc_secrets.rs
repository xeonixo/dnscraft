//! Write-only OIDC client secret in SQLite kv (`auth.oidc.client_secret`).
//!
//! Mirrors [`crate::cloudflare_secrets`]: the secret never appears in the
//! versioned config snapshot or in GET responses.

use crate::error::ControlApiError;
use crate::storage::Db;

const KV_KEY: &str = "auth.oidc.client_secret";

/// Whether a non-empty OIDC client secret is stored in kv.
pub(crate) async fn has_client_secret(db: &Db) -> Result<bool, ControlApiError> {
    Ok(db.kv_get(KV_KEY).await?.is_some_and(|v| !v.is_empty()))
}

/// Stores or clears the OIDC client secret.
///
/// `None` clears; `Some("")` is rejected.
pub(crate) async fn set_client_secret(
    db: &Db,
    secret: Option<&str>,
) -> Result<(), ControlApiError> {
    match secret {
        None => db.kv_delete(KV_KEY).await,
        Some("") => Err(ControlApiError::Module {
            code: "control_api.auth.oidc",
            params: Some(serde_json::json!({
                "reason": "client_secret must not be empty; use null to clear"
            })),
        }),
        Some(value) => db.kv_set(KV_KEY, value).await,
    }
}

/// Loads the stored secret, if any (runtime apply / restart).
pub(crate) async fn get_client_secret(db: &Db) -> Result<Option<String>, ControlApiError> {
    let value = db.kv_get(KV_KEY).await?;
    Ok(value.filter(|v| !v.is_empty()))
}
