//! Local break-glass login: Argon2id password verification, lockout and audit.
//!
//! Local accounts are a separate source of truth from OIDC. Passwords are
//! hashed with **Argon2id** (RFC 9106, `argon2` crate defaults) and only the
//! PHC string is persisted in the `local_accounts` table — the plaintext never
//! reaches SQLite, the audit log or a response. Failed attempts are counted per
//! account inside a sliding [`local_login_lock_window`](crate::AuthConfig) and
//! evaluated on the database's injected [`Clock`](crate::Clock) (ADR-0005), so
//! expiry is tested without sleeps.
//!
//! Every attempt — success, credential failure, unknown account and locked
//! attempt — appends one `auth.local.login` record to the A2 audit log. The
//! password is never part of that record.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use argon2::Argon2;
use argon2::password_hash::PasswordHasher as _;
use argon2::password_hash::PasswordVerifier as _;
use argon2::password_hash::phc::PasswordHash;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Response};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use super::Role;
use super::ensure_same_origin;
use super::sessions::{secure_cookie, session_set_cookie};
use crate::error::ControlApiError;
use crate::server::AppState;
use crate::storage::{AuditRecord, Db, db_err};

/// Node id recorded for in-process local-auth events until the binary supplies
/// a real node identity.
const LOCAL_NODE_ID: &str = "local";

/// Audit action for every local login attempt.
const LOGIN_ACTION: &str = "auth.local.login";

/// The result of one credential check inside the database transaction.
enum Attempt {
    /// The password matched; the account's role is returned.
    Success(Role),
    /// The attempt failed with the documented error.
    Failure(ControlApiError),
}

/// One local break-glass account as replicated to a sub-node.
///
/// Only the Argon2id PHC hash is carried; the plaintext password is never
/// stored and never part of a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAccountSnapshot {
    /// Account username.
    pub username: String,
    /// Argon2id PHC password hash.
    pub password_hash: String,
    /// Account role wire name (`viewer` | `admin`).
    pub role: String,
}

/// Persists Argon2id password hashes and per-account lockout state.
///
/// Construct one from the shared [`Db`] and the validated `AuthConfig` limits,
/// then attach it with [`AppState::with_local_login`]. The store owns no
/// plaintext: only PHC hashes and counters are written.
#[derive(Clone)]
pub struct LocalAccountStore {
    db: Db,
    max_attempts: u32,
    lock_window: Duration,
    epoch: Arc<AtomicU64>,
}

impl LocalAccountStore {
    /// Creates a store over `db` that locks an account after `max_attempts`
    /// failures within `lock_window`.
    pub fn new(db: Db, max_attempts: u32, lock_window: Duration) -> Self {
        Self {
            db,
            max_attempts,
            lock_window,
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shares the session-invalidation epoch owned by
    /// [`AuthState`](super::AuthState).
    pub(crate) fn set_epoch(&mut self, epoch: Arc<AtomicU64>) {
        self.epoch = epoch;
    }

    /// Lists every account (username, PHC hash and role) for an
    /// [`AuthSnapshot`](super::AuthSnapshot).
    pub async fn snapshot_entries(&self) -> Result<Vec<LocalAccountSnapshot>, ControlApiError> {
        self.db
            .with_conn(|conn| {
                let mut stmt = conn
                    .prepare(
                        "SELECT username, password_hash, role
                         FROM local_accounts ORDER BY username",
                    )
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok(LocalAccountSnapshot {
                            username: row.get(0)?,
                            password_hash: row.get(1)?,
                            role: row.get(2)?,
                        })
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
    }

    /// Replaces every local account with `entries` (sub-node auth replication).
    ///
    /// Each entry carries an Argon2id PHC hash, never a plaintext password;
    /// lockout counters are reset because the snapshot has none.
    pub async fn replace_all(
        &self,
        entries: &[LocalAccountSnapshot],
    ) -> Result<(), ControlApiError> {
        let entries = entries.to_vec();
        // Reject an unknown role before touching the table so a bad snapshot
        // leaves the previous accounts intact.
        for entry in &entries {
            if Role::parse(&entry.role).is_none() {
                return Err(ControlApiError::Internal {
                    message: format!("unknown local account role in snapshot: {}", entry.role),
                });
            }
        }
        self.db
            .transaction(move |conn| {
                conn.execute("DELETE FROM local_accounts", []).map_err(db_err)?;
                for entry in &entries {
                    conn.execute(
                        "INSERT INTO local_accounts
                            (username, password_hash, role, failed_attempts, window_started, locked_until)
                         VALUES (?1, ?2, ?3, 0, NULL, NULL)",
                        params![entry.username, entry.password_hash, entry.role],
                    )
                    .map_err(db_err)?;
                }
                Ok(())
            })
            .await
    }

    /// Creates or replaces a local account with `role`, storing only the
    /// Argon2id hash. Replacing an account clears its lockout state and bumps
    /// the session-invalidation epoch, so the change reaches the next
    /// [`AuthSnapshot`](super::AuthSnapshot).
    ///
    /// Account provisioning is not part of the v1 HTTP surface; the binary (or
    /// a later config endpoint) seeds accounts through this method.
    pub async fn upsert(
        &self,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<(), ControlApiError> {
        let username = username.trim();
        if username.is_empty() {
            return Err(ControlApiError::config(
                "local account username must not be empty",
            ));
        }
        if password.is_empty() {
            return Err(ControlApiError::config(
                "local account password must not be empty",
            ));
        }
        let username = username.to_owned();
        let password = Zeroizing::new(password.to_owned());
        // Hashing runs inside `with_conn`, i.e. on the blocking pool, never on
        // an async executor thread.
        self.db
            .with_conn(move |conn| {
                let hash = hash_password(password.as_bytes())?;
                conn.execute(
                    "INSERT INTO local_accounts
                        (username, password_hash, role, failed_attempts, window_started, locked_until)
                     VALUES (?1, ?2, ?3, 0, NULL, NULL)
                     ON CONFLICT(username) DO UPDATE SET
                        password_hash = excluded.password_hash,
                        role = excluded.role,
                        failed_attempts = 0,
                        window_started = NULL,
                        locked_until = NULL",
                    params![username, hash, role.as_str()],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await?;
        self.epoch.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Verifies `password` for `username`, enforcing lockout on the injected
    /// clock, and returns the account's role on success.
    ///
    /// Errors are [`ControlApiError::AuthLocal`] for an unknown account or a
    /// wrong password and [`ControlApiError::AuthLocked`] while the lock window
    /// is active. Each attempt is audited, including locked attempts.
    pub async fn authenticate(
        &self,
        username: &str,
        password: String,
    ) -> Result<Role, ControlApiError> {
        let username = username.trim().to_owned();
        let password = Zeroizing::new(password);
        let max_attempts = i64::from(self.max_attempts);
        let window = self.lock_window.as_secs() as i64;
        let now = self.db.now_unix();
        let username_for_db = username.clone();

        // One `with_conn` keeps the read-verify-update sequence atomic against
        // concurrent attempts (the single connection is serialized) and runs
        // the memory-hard verification on the blocking pool.
        let attempt = self
            .db
            .with_conn(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT password_hash, role, failed_attempts, window_started, locked_until
                         FROM local_accounts WHERE username = ?1",
                        params![username_for_db],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, Option<i64>>(3)?,
                                row.get::<_, Option<i64>>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(db_err)?;
                let Some((hash, role_str, failed, window_started, locked_until)) = row else {
                    // Unknown account: one generic credential error, and do the
                    // same memory-hard work as a real verification so response
                    // timing does not reveal whether the username exists.
                    let _ = hash_password(password.as_bytes());
                    return Ok(Attempt::Failure(ControlApiError::AuthLocal));
                };
                let role = Role::parse(&role_str).ok_or_else(|| ControlApiError::Internal {
                    message: format!("unknown local account role in storage: {role_str}"),
                })?;
                if locked_until.is_some_and(|until| now < until) {
                    return Ok(Attempt::Failure(ControlApiError::AuthLocked));
                }

                // Failures count only inside the window that started at the
                // first failure; an elapsed window resets the counter.
                let in_window =
                    window_started.is_some_and(|start| now.saturating_sub(start) < window);
                let effective_failed = if in_window { failed } else { 0 };
                let window_start = if in_window { window_started } else { Some(now) };

                if password_matches(password.as_bytes(), &hash) {
                    conn.execute(
                        "UPDATE local_accounts
                         SET failed_attempts = 0, window_started = NULL, locked_until = NULL
                         WHERE username = ?1",
                        params![username_for_db],
                    )
                    .map_err(db_err)?;
                    return Ok(Attempt::Success(role));
                }

                let attempts = effective_failed.saturating_add(1);
                let locked = attempts >= max_attempts;
                let locked_until = locked.then(|| now.saturating_add(window));
                conn.execute(
                    "UPDATE local_accounts
                     SET failed_attempts = ?1, window_started = ?2, locked_until = ?3
                     WHERE username = ?4",
                    params![attempts, window_start, locked_until, username_for_db],
                )
                .map_err(db_err)?;
                Ok(Attempt::Failure(if locked {
                    ControlApiError::AuthLocked
                } else {
                    ControlApiError::AuthLocal
                }))
            })
            .await?;

        let (result, error_code) = match &attempt {
            Attempt::Success(_) => ("ok", None),
            Attempt::Failure(err) => ("error", Some(err.code().to_owned())),
        };
        self.audit(&username, result, error_code).await?;

        match attempt {
            Attempt::Success(role) => Ok(role),
            Attempt::Failure(err) => Err(err),
        }
    }

    /// Appends one local-login audit record. The password is never included.
    async fn audit(
        &self,
        username: &str,
        result: &str,
        error_code: Option<String>,
    ) -> Result<(), ControlApiError> {
        let record = AuditRecord {
            id: 0,
            time: self.db.now_unix(),
            node_id: LOCAL_NODE_ID.to_owned(),
            actor_id: username.to_owned(),
            actor_type: "user".to_owned(),
            action: LOGIN_ACTION.to_owned(),
            object_type: "auth".to_owned(),
            object_id: username.to_owned(),
            config_version: None,
            before_digest: None,
            after_digest: None,
            before: None,
            after: None,
            result: result.to_owned(),
            error_code,
        };
        self.db.audit_insert(record).await.map(|_| ())
    }
}

/// `POST /api/v1/auth/local/login` request body.
///
/// Deliberately does not implement `Debug`, so the password cannot be logged by
/// a derived formatter.
#[derive(Deserialize)]
pub(crate) struct LocalLoginRequest {
    username: String,
    password: String,
}

/// `POST /api/v1/auth/local/login`: break-glass login.
///
/// On success a cookie session is created for the account's `viewer`/`admin`
/// role and the synchronizer CSRF token is returned in the body. The public
/// route is marked so by the RBAC middleware; no bearer token is required.
pub(crate) async fn local_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<LocalLoginRequest>,
) -> Result<Response, ControlApiError> {
    ensure_same_origin(&headers)?;
    let local = state
        .local_login_store()
        .ok_or_else(|| ControlApiError::Internal {
            message: "local login is not configured".to_owned(),
        })?
        .clone();
    let sessions = state
        .auth_state()
        .map(|auth| auth.sessions().store().clone())
        .ok_or_else(|| ControlApiError::Internal {
            message: "session authentication is not configured".to_owned(),
        })?;

    let actor_id = req.username.trim().to_owned();
    let role = local.authenticate(&req.username, req.password).await?;
    let created = sessions.create(actor_id, role).await?;

    // `Secure` follows direct TLS or a terminating reverse proxy's
    // `X-Forwarded-Proto`, so the cookie is never sent over plaintext.
    let secure = secure_cookie(
        state.tls_status().is_some(),
        headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok()),
    );
    let cookie = session_set_cookie(created.cookie().expose(), secure);
    let cookie = HeaderValue::from_str(&cookie).map_err(|err| ControlApiError::Internal {
        message: format!("build session cookie: {err}"),
    })?;

    let mut response = crate::api::response::success(json!({
        "actor_id": created.principal().actor_id,
        "role": role.as_str(),
        "csrf_token": created.csrf_token().expose(),
    }))
    .into_response();
    response.headers_mut().insert(header::SET_COOKIE, cookie);
    Ok(response)
}

/// Argon2id hash of `password` as a PHC string (`$argon2id$v=19$…`).
fn hash_password(password: &[u8]) -> Result<String, ControlApiError> {
    Argon2::default()
        .hash_password(password)
        .map(|hash| hash.to_string())
        .map_err(|err| ControlApiError::Internal {
            message: format!("argon2 hash failed: {err}"),
        })
}

/// Whether `password` matches the stored Argon2id PHC `hash`. A malformed hash
/// is treated as a mismatch (a credential failure), never as success.
fn password_matches(password: &[u8], hash: &str) -> bool {
    PasswordHash::new(hash)
        .ok()
        .is_some_and(|parsed| Argon2::default().verify_password(password, &parsed).is_ok())
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

    async fn store() -> (LocalAccountStore, Db) {
        let db = Db::open_in_memory(clock()).await.unwrap();
        let store = LocalAccountStore::new(db.clone(), 5, Duration::from_secs(15 * 60));
        (store, db)
    }

    #[tokio::test]
    async fn password_is_stored_only_as_an_argon2id_hash() {
        let (store, db) = store().await;
        store
            .upsert("admin", "correct horse battery staple", Role::Admin)
            .await
            .unwrap();

        let (hash, dump): (String, String) = db
            .with_conn(|conn| {
                let hash: String = conn
                    .query_row(
                        "SELECT password_hash FROM local_accounts WHERE username = 'admin'",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(db_err)?;
                let dump: String = conn
                    .query_row(
                        "SELECT username || '|' || password_hash || '|' || role
                         FROM local_accounts",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(db_err)?;
                Ok((hash, dump))
            })
            .await
            .unwrap();

        assert!(hash.starts_with("$argon2id$"), "not Argon2id: {hash}");
        assert!(hash.contains("v=19"), "unexpected Argon2 version: {hash}");
        assert!(!dump.contains("correct horse battery staple"));
        assert!(dump.contains("admin|$argon2id$"));
    }

    #[tokio::test]
    async fn wrong_password_fails_and_the_password_is_not_audited() {
        let (store, db) = store().await;
        store
            .upsert("admin", "right-password", Role::Viewer)
            .await
            .unwrap();

        let err = store
            .authenticate("admin", "wrong-password".into())
            .await
            .unwrap_err();
        assert_eq!(err.code(), "control_api.auth.local");

        let records = db.audit_list(10, 0).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].action, "auth.local.login");
        assert!(!format!("{records:?}").contains("wrong-password"));
    }

    #[tokio::test]
    async fn wrong_password_never_matches_a_malformed_hash() {
        assert!(!password_matches(b"x", "not-a-phc-string"));
        assert!(!password_matches(b"x", "$argon2id$broken"));
    }
}
