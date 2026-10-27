//! Bearer API tokens: generation, hashed storage, validation and revocation.
//!
//! A token is 32 random bytes (`ring::rand`) rendered as lowercase hex. The
//! plaintext is returned exactly once by [`TokenStore::create`] (wrapped in a
//! [`Secret`]) and only its SHA-256 hash is persisted; that hash doubles as the
//! token id used by token-management calls. Revocation deletes the hash, so it
//! takes effect on the next request. Expiry is optional and evaluated on the
//! injected [`Clock`](crate::Clock) held by the [`Db`].
//!
//! Token material never appears in logs, audit records or serialized config:
//! [`Secret`] redacts `Debug` and `Serialize`, and the one-time plaintext is
//! emitted only by the creation handler below.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use axum::Json;
use axum::extract::{Extension, State};
use axum::response::{IntoResponse, Response};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::Authenticated;
use super::hex;
use super::roles::Scope;
use crate::audit::sha256_hex;
use crate::error::ControlApiError;
use crate::secret::Secret;
use crate::server::AppState;
use crate::storage::{Db, db_err};
use crate::tls::TlsMode;

/// The one-time result of issuing a token.
#[derive(Debug)]
pub struct CreatedToken {
    plaintext: Secret,
    id: String,
    name: String,
    scope: Scope,
    actor_id: String,
    created_at: i64,
    expires_at: Option<i64>,
}

impl CreatedToken {
    /// The plaintext token. Returned to the caller exactly once; never stored.
    pub fn plaintext(&self) -> &Secret {
        &self.plaintext
    }

    /// The persisted SHA-256 hash, also used as the token id.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Human-readable token name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The token's fixed scope.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The actor that created the token.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// Creation time (unix seconds, from the injected clock).
    pub fn created_at(&self) -> i64 {
        self.created_at
    }

    /// Expiry time (unix seconds), or `None` for a non-expiring token.
    pub fn expires_at(&self) -> Option<i64> {
        self.expires_at
    }
}

/// An authenticated bearer token: its owner, scope and non-secret id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenPrincipal {
    actor_id: String,
    scope: Scope,
    id: String,
}

impl TokenPrincipal {
    /// The actor that owns the token.
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }

    /// The token's fixed scope.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The persisted hash (the token id used by token-management calls).
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// One token row as replicated to a sub-node.
///
/// The persisted hash is the only token form that ever leaves the database;
/// the plaintext is never stored and never part of a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSnapshot {
    /// SHA-256 hash of the plaintext token (also the token id).
    pub id_hash: String,
    /// Human-readable token name.
    pub name: String,
    /// The token's fixed scope wire name (`viewer` | `admin` | ...).
    pub scope: String,
    /// The actor that owns the token.
    pub actor_id: String,
    /// Creation time (unix seconds).
    pub created_at: i64,
    /// Expiry time (unix seconds), or `None` for a non-expiring token.
    pub expires_at: Option<i64>,
}

/// Issues and validates bearer tokens against the SQLite `tokens` table.
#[derive(Clone)]
pub struct TokenStore {
    db: Db,
    max_ttl: Duration,
    epoch: Arc<AtomicU64>,
}

impl TokenStore {
    /// Creates a store whose issued tokens may live at most `max_ttl`.
    pub fn new(db: Db, max_ttl: Duration) -> Self {
        Self {
            db,
            max_ttl,
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shares the session-invalidation epoch owned by the surrounding
    /// [`AuthState`](super::AuthState).
    pub(crate) fn set_epoch(&mut self, epoch: Arc<AtomicU64>) {
        self.epoch = epoch;
    }

    /// Issues a token for `actor_id` with `scope`.
    ///
    /// `ttl` is optional: `None` creates a non-expiring token, `Some(_)` must be
    /// within `1..=max_ttl`. Only the SHA-256 hash is persisted.
    pub async fn create(
        &self,
        actor_id: String,
        name: String,
        scope: Scope,
        ttl: Option<Duration>,
    ) -> Result<CreatedToken, ControlApiError> {
        let name = name.trim().to_owned();
        if name.is_empty() {
            return Err(ControlApiError::config("token name must not be empty"));
        }
        if let Some(ttl) = ttl
            && (ttl.is_zero() || ttl > self.max_ttl)
        {
            return Err(ControlApiError::config(format!(
                "token ttl must be within 1..={} seconds",
                self.max_ttl.as_secs()
            )));
        }

        let plaintext = random_token()?;
        // `ring` hashes are lowercase hex; the hash is the only stored form.
        let id = sha256_hex(plaintext.expose().as_bytes());
        let scope_str = scope.as_str().to_owned();
        let created_at = self.db.now_unix();
        let expires_at = ttl.map(|ttl| created_at.saturating_add(ttl.as_secs() as i64));

        let id_for_db = id.clone();
        let name_for_db = name.clone();
        let actor_for_db = actor_id.clone();
        self.db
            .with_conn(move |conn| {
                conn.execute(
                    "INSERT INTO tokens (id_hash, name, scope, actor_id, created_at, expires_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        id_for_db,
                        name_for_db,
                        scope_str,
                        actor_for_db,
                        created_at,
                        expires_at
                    ],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await?;

        Ok(CreatedToken {
            plaintext,
            id,
            name,
            scope,
            actor_id,
            created_at,
            expires_at,
        })
    }

    /// Validates a plaintext token, returning its principal.
    ///
    /// A missing hash, a revoked token and an expired token all yield
    /// [`ControlApiError::AuthUnauthenticated`]; an expired row is deleted.
    pub async fn authenticate(&self, plaintext: &str) -> Result<TokenPrincipal, ControlApiError> {
        let id = sha256_hex(plaintext.as_bytes());
        let now = self.db.now_unix();
        self.db
            .with_conn(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT actor_id, scope, expires_at FROM tokens WHERE id_hash = ?1",
                        params![id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<i64>>(2)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(db_err)?;
                let Some((actor_id, scope_str, expires_at)) = row else {
                    return Err(ControlApiError::AuthUnauthenticated);
                };
                if expires_at.is_some_and(|expires| now >= expires) {
                    conn.execute("DELETE FROM tokens WHERE id_hash = ?1", params![id])
                        .map_err(db_err)?;
                    return Err(ControlApiError::AuthUnauthenticated);
                }
                let scope = Scope::parse(&scope_str).ok_or_else(|| ControlApiError::Internal {
                    message: format!("unknown token scope in storage: {scope_str}"),
                })?;
                Ok(TokenPrincipal {
                    actor_id,
                    scope,
                    id,
                })
            })
            .await
    }

    /// Lists every stored token (hash and metadata, never plaintext) for an
    /// [`AuthSnapshot`](super::AuthSnapshot).
    pub async fn snapshot_entries(&self) -> Result<Vec<TokenSnapshot>, ControlApiError> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT id_hash, name, scope, actor_id, created_at, expires_at
                         FROM tokens ORDER BY id_hash",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(TokenSnapshot {
                            id_hash: row.get(0)?,
                            name: row.get(1)?,
                            scope: row.get(2)?,
                            actor_id: row.get(3)?,
                            created_at: row.get(4)?,
                            expires_at: row.get(5)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
    }

    /// Revokes a token by its id (the stored hash). Unknown ids yield
    /// [`ControlApiError::AuthUnknownToken`].
    ///
    /// A successful revocation bumps the session-invalidation epoch so the
    /// change is visible in the next [`AuthSnapshot`](super::AuthSnapshot).
    pub async fn revoke(&self, id: &str) -> Result<(), ControlApiError> {
        let id = id.to_owned();
        let deleted = self
            .db
            .with_conn(move |conn| {
                conn.execute("DELETE FROM tokens WHERE id_hash = ?1", params![id])
                    .map_err(db_err)
            })
            .await?;
        if deleted == 0 {
            return Err(ControlApiError::AuthUnknownToken);
        }
        self.epoch.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// `POST /api/v1/auth/tokens` request body.
#[derive(Debug, Deserialize)]
pub(crate) struct CreateTokenRequest {
    name: String,
    scope: String,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

/// `POST /api/v1/auth/tokens`: issue a bearer token.
///
/// The RBAC middleware restricts this route to `admin` principals. The response
/// carries the plaintext token exactly once and, while the bootstrap
/// self-signed certificate is served, the `control_api.tls.self_signed`
/// warning.
pub(crate) async fn create_token(
    State(state): State<AppState>,
    Extension(principal): Extension<Authenticated>,
    Json(req): Json<CreateTokenRequest>,
) -> Result<Response, ControlApiError> {
    let tokens = state
        .auth_state()
        .map(|auth| auth.tokens().clone())
        .ok_or_else(|| ControlApiError::Internal {
            message: "token authentication is not configured".to_owned(),
        })?;
    let scope = Scope::parse(&req.scope).ok_or_else(|| {
        ControlApiError::config(format!(
            "scope must be one of viewer, admin, mcp:read, mcp:write; got `{}`",
            req.scope
        ))
    })?;
    let ttl = req.ttl_seconds.map(Duration::from_secs);
    let created = tokens
        .create(principal.actor_id().to_owned(), req.name, scope, ttl)
        .await?;

    let mut warnings: Vec<&str> = Vec::new();
    if state
        .tls_status()
        .is_some_and(|status| status.mode == TlsMode::SelfSigned)
    {
        warnings.push("control_api.tls.self_signed");
    }

    Ok(crate::api::response::success(json!({
        "id": created.id(),
        "name": created.name(),
        "scope": created.scope().as_str(),
        "actor_id": created.actor_id(),
        "created_at": created.created_at(),
        "expires_at": created.expires_at(),
        "token": created.plaintext().expose(),
        "warnings": warnings,
    }))
    .into_response())
}

/// Generates a 256-bit random token as lowercase hex.
fn random_token() -> Result<Secret, ControlApiError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| ControlApiError::Internal {
            message: "failed to generate API token".to_owned(),
        })?;
    Ok(Secret::new(hex(&bytes)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::time::SystemTime;

    use super::*;
    use crate::clock::ManualClock;

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
    }

    async fn store() -> TokenStore {
        let db = Db::open_in_memory(clock()).await.unwrap();
        TokenStore::new(db, Duration::from_secs(365 * 24 * 3600))
    }

    #[tokio::test]
    async fn token_plaintext_is_hashed_and_never_persisted() {
        let store = store().await;
        let created = store
            .create("u1".into(), "ci".into(), Scope::Admin, None)
            .await
            .unwrap();
        let plaintext = created.plaintext().expose().to_owned();

        // The id is the SHA-256 hash of the plaintext, never the plaintext.
        assert_eq!(created.id(), sha256_hex(plaintext.as_bytes()));
        assert_ne!(created.id(), plaintext);
        assert_eq!(plaintext.len(), 64);

        let rows: Vec<(String, String, Option<i64>)> = store
            .db
            .with_conn(|conn| {
                let mut stmt = conn
                    .prepare("SELECT id_hash, scope, expires_at FROM tokens")
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<i64>>(2)?,
                        ))
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, created.id());
        assert_eq!(rows[0].1, "admin");
        assert_eq!(rows[0].2, None);
        assert!(!format!("{rows:?}").contains(&plaintext));
    }

    #[tokio::test]
    async fn revoked_token_fails_unauthenticated() {
        let store = store().await;
        let created = store
            .create("u1".into(), "ci".into(), Scope::Viewer, None)
            .await
            .unwrap();
        let plaintext = created.plaintext().expose().to_owned();
        assert!(store.authenticate(&plaintext).await.is_ok());

        store.revoke(created.id()).await.unwrap();
        assert_eq!(
            store.authenticate(&plaintext).await.unwrap_err().code(),
            "control_api.auth.unauthenticated"
        );
    }

    #[tokio::test]
    async fn expired_token_fails_unauthenticated_on_manual_clock() {
        let clock = clock();
        let db = Db::open_in_memory(clock.clone()).await.unwrap();
        let store = TokenStore::new(db, Duration::from_secs(3600));
        let created = store
            .create(
                "u1".into(),
                "short".into(),
                Scope::Viewer,
                Some(Duration::from_secs(60)),
            )
            .await
            .unwrap();
        let plaintext = created.plaintext().expose().to_owned();

        assert!(store.authenticate(&plaintext).await.is_ok());
        clock.advance(Duration::from_secs(61));
        assert_eq!(
            store.authenticate(&plaintext).await.unwrap_err().code(),
            "control_api.auth.unauthenticated"
        );
        // The expired row is deleted.
        assert_eq!(
            store.revoke(created.id()).await.unwrap_err().code(),
            "control_api.auth.unknown_token"
        );
    }

    #[tokio::test]
    async fn ttl_above_maximum_is_rejected() {
        let store = store().await;
        let err = store
            .create(
                "u1".into(),
                "long".into(),
                Scope::Admin,
                Some(Duration::from_secs(366 * 24 * 3600)),
            )
            .await
            .unwrap_err();
        assert_eq!(err.code(), "control_api.config.invalid");
    }
}
