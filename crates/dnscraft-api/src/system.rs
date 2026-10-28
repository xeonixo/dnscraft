//! Opt-in update check (WP2) and automatic SQLite backups (WP3).
//!
//! Both features keep their settings in the versioned config under the
//! `control_api_settings` section, so writes get a config version and audit row
//! like any other section. Neither feature makes an outbound call or writes a
//! file unless it is enabled. Backups use `VACUUM INTO`; the copy keeps the
//! credential hashes (so a restore can sign in) and drops the `sessions` rows.
//! The directory is created `0700` and the files `0600`.

use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ControlApiError;
use crate::notifications::ring_client;
use crate::server::AppState;
use crate::storage::{Db, db_err};

/// Snapshot section holding runtime settings that the control API owns.
pub(crate) const SETTINGS_SECTION: &str = "control_api_settings";
/// Successful update-check results are reused for this long.
const UPDATE_CACHE_OK_SECS: i64 = 24 * 3600;
/// Failed checks are retried after this long, so an unreachable GitHub is not hammered.
const UPDATE_CACHE_FAILED_SECS: i64 = 3600;
/// Default GitHub endpoint for the latest release.
pub(crate) const DEFAULT_RELEASE_API: &str =
    "https://api.github.com/repos/xeonixo/dnscraft/releases/latest";
/// Largest release document accepted from the release service.
const MAX_RELEASE_BYTES: usize = 64 * 1024;
/// Interval between automatic backups.
const BACKUP_INTERVAL_SECS: i64 = 24 * 3600;
/// Retention used when none is configured.
pub(crate) const DEFAULT_BACKUP_RETENTION: u32 = 7;
/// Largest accepted backup retention count.
pub(crate) const BACKUP_RETENTION_MAX: u32 = 365;
/// `kv` key of the last backup run (JSON).
const BACKUP_LAST_RUN_KEY: &str = "backups.last_run";
const BACKUP_PREFIX: &str = "dnscraft-backup-";
const BACKUP_SUFFIX: &str = ".sqlite";

/// Whether the opt-in update check is enabled (`control_api_settings.update_check`).
pub(crate) fn update_check_enabled(snapshot: &Value) -> bool {
    snapshot
        .pointer("/control_api_settings/update_check")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Backup settings as stored in the config snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BackupSettings {
    /// Whether scheduled backups run.
    pub enabled: bool,
    /// Number of backup files kept.
    pub retention_count: u32,
}

impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            retention_count: DEFAULT_BACKUP_RETENTION,
        }
    }
}

/// Reads the backup settings from a snapshot, defaulting when absent.
pub(crate) fn backup_settings(snapshot: &Value) -> BackupSettings {
    snapshot
        .pointer("/control_api_settings/backups")
        .and_then(|value| serde_json::from_value(value.clone()).ok())
        .unwrap_or_default()
}

/// Result of a GitHub release lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReleaseInfo {
    /// Tag without a leading `v`.
    pub latest: String,
    /// HTTPS release page, when GitHub returned one.
    pub url: Option<String>,
}

/// Cached lookup: the unix time of the check and its outcome.
pub(crate) type UpdateCache = Option<(i64, Result<ReleaseInfo, &'static str>)>;

/// Fetches the latest release from `api_url`. Returns a stable failure code.
async fn fetch_latest_release(api_url: &str) -> Result<ReleaseInfo, &'static str> {
    const UNREACHABLE: &str = "control_api.update.unreachable";
    let client = ring_client().ok_or(UNREACHABLE)?;
    let response = client
        .get(api_url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(
            reqwest::header::USER_AGENT,
            concat!("dnscraft/", env!("CARGO_PKG_VERSION")),
        )
        .send()
        .await
        .map_err(|_| UNREACHABLE)?;
    if !response.status().is_success() {
        return Err(UNREACHABLE);
    }
    // Bounded read: a release document is a few kilobytes.
    let bytes = response.bytes().await.map_err(|_| UNREACHABLE)?;
    if bytes.len() > MAX_RELEASE_BYTES {
        return Err(UNREACHABLE);
    }
    let body: Value = serde_json::from_slice(&bytes).map_err(|_| UNREACHABLE)?;
    let tag = body
        .get("tag_name")
        .and_then(Value::as_str)
        .ok_or(UNREACHABLE)?;
    let url = body
        .get("html_url")
        .and_then(Value::as_str)
        .filter(|url| url.starts_with("https://"))
        .map(str::to_owned);
    Ok(ReleaseInfo {
        latest: tag.trim_start_matches('v').to_owned(),
        url,
    })
}

/// Returns the release lookup, reusing the cache within its TTL.
pub(crate) async fn cached_latest_release(state: &AppState) -> Result<ReleaseInfo, &'static str> {
    let now = unix_now(state);
    let mut cache = state.update_cache().lock().await;
    if let Some((checked, result)) = cache.as_ref() {
        let ttl = if result.is_ok() {
            UPDATE_CACHE_OK_SECS
        } else {
            UPDATE_CACHE_FAILED_SECS
        };
        if now.saturating_sub(*checked) < ttl {
            return result.clone();
        }
    }
    let result = fetch_latest_release(state.update_api_url()).await;
    *cache = Some((now, result.clone()));
    result
}

/// Whether `latest` is a newer `major.minor.patch` than `current`. Pre-release
/// suffixes are ignored; anything unparsable is not newer.
pub(crate) fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(latest), Some(current)) => latest > current,
        _ => false,
    }
}

fn parse_version(text: &str) -> Option<[u64; 3]> {
    let core = text.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next()?;
    let mut parts = core.split('.');
    let mut out = [0u64; 3];
    for slot in &mut out {
        *slot = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Unix seconds from the injected clock.
pub(crate) fn unix_now(state: &AppState) -> i64 {
    state
        .clock()
        .now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Runs one backup into `dir` and prunes beyond `retention`. Returns the file name.
pub(crate) async fn run_backup(
    db: &Db,
    dir: &Path,
    retention: u32,
    now: i64,
) -> Result<String, ControlApiError> {
    std::fs::create_dir_all(dir).map_err(|err| ControlApiError::Internal {
        message: format!("backup directory: {err}"),
    })?;
    restrict_dir(dir);
    let name = format!("{BACKUP_PREFIX}{now}{BACKUP_SUFFIX}");
    let target = dir.join(&name);
    if target.exists() {
        return Err(ControlApiError::Internal {
            message: "backup file for this second already exists".to_owned(),
        });
    }
    let target_text = target.to_string_lossy().into_owned();
    db.with_conn(move |conn| {
        conn.execute("VACUUM INTO ?1", [target_text])
            .map(|_| ())
            .map_err(db_err)
    })
    .await?;
    // Sessions are ephemeral bearer state: drop them from the copy. Credential
    // hashes stay, so a restored backup can still sign in.
    strip_sessions(&target)?;
    restrict_file(&target);
    prune(dir, retention)?;
    Ok(name)
}

/// Removes the `sessions` rows from a freshly written backup file and rebuilds
/// it so the deleted pages are not left behind.
fn strip_sessions(target: &Path) -> Result<(), ControlApiError> {
    let conn = rusqlite::Connection::open(target).map_err(db_err)?;
    conn.execute_batch("DELETE FROM sessions; VACUUM;")
        .map_err(db_err)
}

/// Keeps the newest `retention` backup files in `dir` and removes older ones.
fn prune(dir: &Path, retention: u32) -> Result<(), ControlApiError> {
    let mut files = backup_files(dir)?;
    files.sort();
    let excess = files.len().saturating_sub(retention as usize);
    for name in files.into_iter().take(excess) {
        // Only files matching the backup name pattern are listed, so only our own files go.
        std::fs::remove_file(dir.join(&name)).map_err(|err| ControlApiError::Internal {
            message: format!("backup retention: {err}"),
        })?;
    }
    Ok(())
}

/// Backup file names in `dir`; a missing directory has none.
pub(crate) fn backup_files(dir: &Path) -> Result<Vec<String>, ControlApiError> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(ControlApiError::Internal {
                message: format!("backup directory: {err}"),
            });
        }
    };
    let mut names = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(BACKUP_PREFIX) && name.ends_with(BACKUP_SUFFIX) {
            names.push(name);
        }
    }
    Ok(names)
}

#[cfg(unix)]
fn restrict_dir(dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
}

#[cfg(not(unix))]
fn restrict_dir(_dir: &Path) {}

#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

/// The last run recorded in `kv`, if any.
pub(crate) async fn last_backup(db: &Db) -> Result<Option<Value>, ControlApiError> {
    Ok(db
        .kv_get(BACKUP_LAST_RUN_KEY)
        .await?
        .and_then(|raw| serde_json::from_str(&raw).ok()))
}

/// Records a run (success or failure) in `kv`.
async fn record_run(db: &Db, run: Value) -> Result<(), ControlApiError> {
    db.kv_set(BACKUP_LAST_RUN_KEY, &run.to_string()).await
}

/// Runs a backup when enabled and due (at least 24 h since the last run).
/// Returns `Ok(true)` when a backup ran. The binary calls this periodically
/// (for example hourly); failures are recorded in `kv` and returned.
pub async fn run_backup_if_due(state: &AppState) -> Result<bool, ControlApiError> {
    let (Some(db), Some(dir), Some(service)) =
        (state.db(), state.backup_dir(), state.config_service())
    else {
        return Ok(false);
    };
    let snapshot = service.current().await?.1.unwrap_or(Value::Null);
    let settings = backup_settings(&snapshot);
    if !settings.enabled {
        return Ok(false);
    }
    let now = unix_now(state);
    if let Some(last) = last_backup(db).await?
        && let Some(at) = last.get("at").and_then(Value::as_i64)
        && now.saturating_sub(at) < BACKUP_INTERVAL_SECS
    {
        return Ok(false);
    }
    match run_backup(db, dir, settings.retention_count, now).await {
        Ok(file) => {
            record_run(db, json!({ "at": now, "result": "ok", "file": file })).await?;
            Ok(true)
        }
        Err(error) => {
            record_run(
                db,
                json!({ "at": now, "result": "error", "code": error.code() }),
            )
            .await?;
            Err(error)
        }
    }
}

/// `next_run` as unix seconds: last run plus the interval, or now when never run.
pub(crate) fn next_run_at(last: Option<&Value>, now: i64) -> i64 {
    last.and_then(|run| run.get("at").and_then(Value::as_i64))
        .map_or(now, |at| at.saturating_add(BACKUP_INTERVAL_SECS))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backup_keeps_credentials_and_drops_sessions() {
        use std::sync::Arc;
        use std::time::{Duration, UNIX_EPOCH};
        let clock = Arc::new(dnscraft_common::clock::ManualClock::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        ));
        let db = Db::open_in_memory(clock).await.unwrap();
        db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id_hash, actor_id, created_at, last_active, expires_at)
                 VALUES ('h1', 'alice', 1, 1, 99999999999)",
                [],
            )
            .map_err(db_err)?;
            conn.execute(
                "INSERT INTO tokens (id_hash, name, scope, actor_id, created_at, expires_at)
                 VALUES ('t1', 'ci', 'api:read', 'alice', 1, NULL)",
                [],
            )
            .map_err(db_err)?;
            Ok(())
        })
        .await
        .unwrap();
        let dir = std::env::temp_dir().join(format!("dnscraft-backup-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let name = run_backup(&db, &dir, 3, 1_700_000_000).await.unwrap();
        let copy = rusqlite::Connection::open(dir.join(&name)).unwrap();
        let sessions: i64 = copy
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        let tokens: i64 = copy
            .query_row("SELECT COUNT(*) FROM tokens", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sessions, 0);
        assert_eq!(tokens, 1, "credential rows must survive");
        let mode = std::fs::metadata(dir.join(&name)).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode.mode() & 0o777, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_comparison_ignores_prefixes_and_prereleases() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("v1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0-rc1", "0.1.0"));
        assert!(!is_newer("not-a-version", "0.1.0"));
    }

    #[test]
    fn settings_default_to_off_and_seven_kept() {
        assert!(!update_check_enabled(&json!({})));
        assert_eq!(backup_settings(&json!({})), BackupSettings::default());
        let snapshot = json!({"control_api_settings": {
            "update_check": true,
            "backups": {"enabled": true, "retention_count": 3}
        }});
        assert!(update_check_enabled(&snapshot));
        assert_eq!(
            backup_settings(&snapshot),
            BackupSettings {
                enabled: true,
                retention_count: 3
            }
        );
    }

    #[test]
    fn next_run_is_one_interval_after_the_last_run() {
        assert_eq!(next_run_at(None, 500), 500);
        let last = json!({"at": 1000});
        assert_eq!(next_run_at(Some(&last), 500), 1000 + BACKUP_INTERVAL_SECS);
    }
}
