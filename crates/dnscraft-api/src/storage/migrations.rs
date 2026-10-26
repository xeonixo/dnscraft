//! SQLite schema migrations (idempotent, versioned via `PRAGMA user_version`).

use rusqlite::Connection;

use super::db_err;
use crate::error::ControlApiError;

/// Ordered migrations; index `i` is schema version `i + 1`.
pub(crate) const MIGRATIONS: &[&str] = &[
    // v1: core schema + reserved tables (refined in later tasks).
    "CREATE TABLE IF NOT EXISTS kv (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS config_versions (
        version    INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot   TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_log (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        time           INTEGER NOT NULL,
        node_id        TEXT NOT NULL,
        actor_id       TEXT NOT NULL,
        actor_type     TEXT NOT NULL,
        action         TEXT NOT NULL,
        object_type    TEXT NOT NULL,
        object_id      TEXT NOT NULL,
        config_version INTEGER,
        before_digest  TEXT,
        after_digest   TEXT,
        before         TEXT,
        after          TEXT,
        result         TEXT NOT NULL,
        error_code     TEXT
    );
    CREATE TABLE IF NOT EXISTS sessions (
        id_hash     TEXT PRIMARY KEY,
        actor_id    TEXT NOT NULL,
        created_at  INTEGER NOT NULL,
        last_active INTEGER NOT NULL,
        expires_at  INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tokens (
        id_hash    TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        scope      TEXT NOT NULL,
        actor_id   TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS query_log (
        id         TEXT PRIMARY KEY,
        time       INTEGER NOT NULL,
        node_id    TEXT NOT NULL,
        source_ip  TEXT NOT NULL,
        query_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS stats_hourly (
        hour          INTEGER NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (hour, profile_id, protocol, answer_source)
    );
    CREATE TABLE IF NOT EXISTS stats_daily (
        day           INTEGER NOT NULL,
        profile_id    TEXT NOT NULL,
        protocol      TEXT NOT NULL,
        answer_source TEXT NOT NULL,
        query_count   INTEGER NOT NULL,
        PRIMARY KEY (day, profile_id, protocol, answer_source)
    );",
    // v2: audit log is append-only — UPDATE/DELETE are rejected at the SQL
    // layer so no code path (including retention, which needs its own explicit
    // migration) can silently mutate recorded history.
    "CREATE TRIGGER audit_log_no_update
        BEFORE UPDATE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END;
    CREATE TRIGGER audit_log_no_delete
        BEFORE DELETE ON audit_log
    BEGIN
        SELECT RAISE(ABORT, 'audit_log is append-only');
    END;",
    // v3: cookie sessions carry a viewer/admin role (A6).
    "ALTER TABLE sessions ADD COLUMN role TEXT NOT NULL DEFAULT 'viewer';",
];

/// Applies every migration newer than the recorded version, then records it.
pub(crate) fn migrate(conn: &mut Connection) -> Result<(), ControlApiError> {
    let tx = conn.transaction().map_err(db_err)?;
    let current: i64 = tx
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_err)?;
    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let target = (index + 1) as i64;
        if current < target {
            tx.execute_batch(sql).map_err(db_err)?;
            tx.pragma_update(None, "user_version", target)
                .map_err(db_err)?;
        }
    }
    tx.commit().map_err(db_err)?;
    Ok(())
}

/// Reads the current `PRAGMA user_version`.
pub(crate) fn schema_version(conn: &Connection) -> Result<i64, ControlApiError> {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .map_err(db_err)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn audit_log_rejects_update_and_delete_after_v2() {
        let mut conn = Connection::open_in_memory().unwrap();
        migrate(&mut conn).unwrap();
        assert_eq!(schema_version(&conn).unwrap(), 3);

        conn.execute(
            "INSERT INTO audit_log (
                time, node_id, actor_id, actor_type, action, object_type, object_id, result
             ) VALUES (1, 'n', 'a', 'user', 'config.write', 'config', 'cfg', 'ok')",
            [],
        )
        .unwrap();

        // Append-only: UPDATE and DELETE are rejected by the v2 triggers.
        assert!(
            conn.execute("UPDATE audit_log SET action = 'x' WHERE id = 1", [])
                .is_err()
        );
        assert!(
            conn.execute("DELETE FROM audit_log WHERE id = 1", [])
                .is_err()
        );

        // INSERT and SELECT still work; the single row is intact.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
