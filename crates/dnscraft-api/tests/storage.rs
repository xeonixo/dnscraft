//! Storage integration tests (in-memory and temporary-file SQLite).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use dnscraft_api::{AuditRecord, Db, SystemClock};

fn db_clock() -> Arc<SystemClock> {
    Arc::new(SystemClock)
}

fn temp_db_path(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "dnscraft-api-{tag}-{}-{nanos}.db",
        std::process::id()
    ))
}

fn record(time: i64, action: &str) -> AuditRecord {
    AuditRecord {
        id: 0,
        time,
        node_id: "node1".into(),
        actor_id: "u1".into(),
        actor_type: "user".into(),
        action: action.into(),
        object_type: "config".into(),
        object_id: "cfg".into(),
        config_version: None,
        before_digest: None,
        after_digest: None,
        before: None,
        after: None,
        result: "ok".into(),
        error_code: None,
    }
}

#[tokio::test]
async fn migrations_are_idempotent() {
    let path = temp_db_path("idempotent");
    {
        let db = Db::open(&path, db_clock()).await.unwrap();
        assert_eq!(db.schema_version().await.unwrap(), 2);
    }
    // Reopening the same file re-runs migrations; they must be a no-op.
    let db = Db::open(&path, db_clock()).await.unwrap();
    assert_eq!(db.schema_version().await.unwrap(), 2);
    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn kv_round_trips() {
    let db = Db::open_in_memory(db_clock()).await.unwrap();
    assert_eq!(db.kv_get("missing").await.unwrap(), None);
    db.kv_set("a", "1").await.unwrap();
    db.kv_set("a", "2").await.unwrap(); // replace
    assert_eq!(db.kv_get("a").await.unwrap(), Some("2".into()));
    db.kv_delete("a").await.unwrap();
    assert_eq!(db.kv_get("a").await.unwrap(), None);
}

#[tokio::test]
async fn config_version_round_trips() {
    let db = Db::open_in_memory(db_clock()).await.unwrap();
    let v1 = db.config_version_insert("{\"v\":1}").await.unwrap();
    let v2 = db.config_version_insert("{\"v\":2}").await.unwrap();
    assert!(v2 > v1);
    assert_eq!(
        db.config_version_load(v1).await.unwrap(),
        Some("{\"v\":1}".into())
    );
    assert_eq!(
        db.config_version_load(v2).await.unwrap(),
        Some("{\"v\":2}".into())
    );
    assert_eq!(db.config_version_load(9999).await.unwrap(), None);
}

#[tokio::test]
async fn audit_insert_and_list_are_ordered() {
    let db = Db::open_in_memory(db_clock()).await.unwrap();
    db.audit_insert(record(10, "first")).await.unwrap();
    db.audit_insert(record(20, "second")).await.unwrap();
    db.audit_insert(record(15, "third")).await.unwrap();

    let rows = db.audit_list(10, 0).await.unwrap();
    let actions: Vec<&str> = rows.iter().map(|r| r.action.as_str()).collect();
    // Newest first: time 20, then 15, then 10.
    assert_eq!(actions, ["second", "third", "first"]);
    assert!(rows.iter().all(|r| r.id > 0));
}

#[tokio::test]
async fn sql_injection_is_treated_as_data() {
    let db = Db::open_in_memory(db_clock()).await.unwrap();
    let injection = "'; DROP TABLE audit_log; --";

    // kv: a key/value that looks like SQL round-trips as data.
    db.kv_set(injection, injection).await.unwrap();
    assert_eq!(db.kv_get(injection).await.unwrap(), Some(injection.into()));

    // query-log: an attacker-influenced name is bound, never interpolated.
    db.query_log_insert("q1", 1, "node1", "192.0.2.10", injection)
        .await
        .unwrap();
    assert_eq!(db.query_log_count_by_name(injection).await.unwrap(), 1);
    assert_eq!(db.query_log_count_by_name("x' OR '1'='1").await.unwrap(), 0);

    // The audit_log table still exists (nothing was dropped).
    assert!(db.audit_insert(record(1, injection)).await.unwrap() > 0);
}
