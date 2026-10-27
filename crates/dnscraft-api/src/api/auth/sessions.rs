//! Opaque cookie sessions: creation, validation (idle + absolute expiry) and
//! logout, backed by the SQLite `sessions` table.
//!
//! A session id is 32 random bytes (`ring::rand`), hex-encoded into the cookie
//! and stored only as its SHA-256 hash (`ring::digest`). The plaintext never
//! reaches SQLite; it is held in a [`Secret`] until the cookie is built.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{OptionalExtension, params};

use super::csrf::csrf_token_for;
use super::{SESSION_COOKIE, hex};
use crate::Secret;
use crate::error::ControlApiError;
use crate::storage::{Db, db_err};

/// A browser-session role. Cookie sessions are `viewer` or `admin` only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Read-only access on `/api/v1`.
    Viewer,
    /// Read/write access on `/api/v1`.
    Admin,
}

impl Role {
    /// The wire/config name (`viewer` | `admin`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Viewer => "viewer",
            Self::Admin => "admin",
        }
    }

    /// Parses the stored name; `None` for anything else.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "viewer" => Some(Self::Viewer),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// The authenticated principal established by a valid session cookie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Subject the session belongs to (actor id).
    pub actor_id: String,
    /// The session's role.
    pub role: Role,
}

/// The result of creating a session: the cookie value, its CSRF token, and the
/// principal. The two secrets are returned exactly once and never logged.
#[derive(Debug)]
pub struct CreatedSession {
    cookie: Secret,
    csrf_token: Secret,
    principal: Principal,
}

impl CreatedSession {
    /// The session id to place in the `dnscraft_session` cookie.
    pub fn cookie(&self) -> &Secret {
        &self.cookie
    }

    /// The synchronizer CSRF token the client must echo on mutating requests.
    pub fn csrf_token(&self) -> &Secret {
        &self.csrf_token
    }

    /// The principal this session authenticates.
    pub fn principal(&self) -> &Principal {
        &self.principal
    }
}

/// Persists opaque session ids as SHA-256 hashes and enforces idle + absolute
/// expiry on the injected [`Clock`](crate::Clock) held by the [`Db`].
#[derive(Clone)]
pub struct SessionStore {
    db: Db,
    idle: Duration,
    absolute: Duration,
    /// Auth epoch shared with [`AuthState`](super::AuthState); a session
    /// created under an older epoch is invalid.
    epoch: Arc<AtomicU64>,
}

impl SessionStore {
    /// Creates a store over `db` with the given idle and absolute lifetimes.
    pub fn new(db: Db, idle: Duration, absolute: Duration) -> Self {
        Self {
            db,
            idle,
            absolute,
            epoch: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Shares the surrounding auth state's session-invalidation epoch.
    pub(crate) fn set_epoch(&mut self, epoch: Arc<AtomicU64>) {
        self.epoch = epoch;
    }

    /// Creates a session for `actor_id` with `role`.
    pub async fn create(
        &self,
        actor_id: String,
        role: Role,
    ) -> Result<CreatedSession, ControlApiError> {
        let cookie = random_session_id()?;
        let id_hash = hash_session_id(cookie.expose());
        let role_str = role.as_str().to_owned();
        let actor_for_db = actor_id.clone();
        let epoch = i64::try_from(self.epoch.load(Ordering::Relaxed)).unwrap_or(i64::MAX);
        let now = self.db.now_unix();
        let expires_at = now.saturating_add(self.absolute.as_secs() as i64);
        self.db
            .with_conn(move |conn| {
                conn.execute(
                    "INSERT INTO sessions (id_hash, actor_id, role, created_at, last_active, expires_at, epoch)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![id_hash, actor_for_db, role_str, now, now, expires_at, epoch],
                )
                .map_err(db_err)?;
                Ok(())
            })
            .await?;
        let csrf_token = csrf_token_for(cookie.expose());
        Ok(CreatedSession {
            cookie,
            csrf_token,
            principal: Principal { actor_id, role },
        })
    }

    /// Validates a session cookie, returning its principal, or
    /// [`ControlApiError::AuthSessionExpired`] when absent or expired. A
    /// successful validation refreshes the idle deadline.
    pub async fn validate(&self, cookie: &str) -> Result<Principal, ControlApiError> {
        let id_hash = hash_session_id(cookie);
        let idle_secs = self.idle.as_secs() as i64;
        let now = self.db.now_unix();
        let current_epoch = self.epoch.load(Ordering::Relaxed);
        self.db
            .with_conn(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT actor_id, role, last_active, expires_at, epoch FROM sessions WHERE id_hash = ?1",
                        params![id_hash],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i64>(2)?,
                                row.get::<_, i64>(3)?,
                                row.get::<_, i64>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(db_err)?;
                let Some((actor_id, role_str, last_active, expires_at, epoch)) = row else {
                    return Err(ControlApiError::AuthSessionExpired);
                };
                // A session is valid only at or after the epoch it was created
                // under: bumping the epoch (global sign-out/revocation)
                // invalidates every older session.
                if now >= expires_at
                    || now >= last_active.saturating_add(idle_secs)
                    || epoch < i64::try_from(current_epoch).unwrap_or(i64::MAX)
                {
                    conn.execute("DELETE FROM sessions WHERE id_hash = ?1", params![id_hash])
                        .map_err(db_err)?;
                    return Err(ControlApiError::AuthSessionExpired);
                }
                let role = Role::parse(&role_str).ok_or_else(|| ControlApiError::Internal {
                    message: format!("unknown session role in storage: {role_str}"),
                })?;
                conn.execute(
                    "UPDATE sessions SET last_active = ?1 WHERE id_hash = ?2",
                    params![now, id_hash],
                )
                .map_err(db_err)?;
                Ok(Principal { actor_id, role })
            })
            .await
    }

    /// Invalidates a session immediately (unknown ids are a no-op).
    pub async fn logout(&self, cookie: &str) -> Result<(), ControlApiError> {
        let id_hash = hash_session_id(cookie);
        self.db
            .with_conn(move |conn| {
                conn.execute("DELETE FROM sessions WHERE id_hash = ?1", params![id_hash])
                    .map_err(db_err)?;
                Ok(())
            })
            .await
    }
}

/// Whether the session cookie must be flagged `Secure`: the request reached the
/// server over direct TLS or the (already trusted) proxy reported https.
pub fn secure_cookie(tls_terminated: bool, forwarded_proto: Option<&str>) -> bool {
    tls_terminated || forwarded_proto.is_some_and(|proto| proto.eq_ignore_ascii_case("https"))
}

/// Builds the `Set-Cookie` header value for a session cookie: always `HttpOnly`
/// and `SameSite=Lax`, plus `Secure` when `secure` is true.
pub fn session_set_cookie(value: &str, secure: bool) -> String {
    let mut cookie = format!("{SESSION_COOKIE}={value}; HttpOnly; SameSite=Lax; Path=/");
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// Generates a 256-bit random session id as lowercase hex.
fn random_session_id() -> Result<Secret, ControlApiError> {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes)
        .map_err(|_| ControlApiError::Internal {
            message: "failed to generate session id".to_owned(),
        })?;
    Ok(Secret::new(hex(&bytes)))
}

/// SHA-256 of the plaintext session id, hex-encoded (the only persisted form).
fn hash_session_id(session_id: &str) -> String {
    hex(digest(&SHA256, session_id.as_bytes()).as_ref())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::storage::{Db, db_err};
    use dnscraft_common::clock::ManualClock;
    use std::sync::Arc;
    use std::time::SystemTime;

    fn clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(SystemTime::UNIX_EPOCH))
    }

    #[tokio::test]
    async fn auth_session_plaintext_is_never_persisted() {
        let store = SessionStore::new(
            Db::open_in_memory(clock()).await.unwrap(),
            Duration::from_secs(3600),
            Duration::from_secs(12 * 3600),
        );
        let created = store.create("u1".into(), Role::Admin).await.unwrap();
        let plaintext = created.cookie().expose().to_owned();

        let stored: Vec<(String, String)> = store
            .db
            .with_conn(|conn| {
                let mut stmt = conn
                    .prepare("SELECT id_hash, actor_id FROM sessions")
                    .map_err(db_err)?;
                let rows = stmt
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .map_err(db_err)?;
                rows.collect::<Result<Vec<_>, _>>().map_err(db_err)
            })
            .await
            .unwrap();

        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, hash_session_id(&plaintext));
        assert_ne!(stored[0].0, plaintext);
        for (id_hash, actor_id) in &stored {
            assert!(!id_hash.contains(&plaintext), "plaintext in id_hash");
            assert!(!actor_id.contains(&plaintext), "plaintext in actor_id");
        }
    }
}
