//! Config store + audit redaction integration tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use serde_json::{Value, json};

use dnscraft_api::{Audit, ConfigChangeRecord, ConfigStore, Db};

fn secret_snapshot() -> Value {
    json!({
        "control_api": {
            "auth": {
                "oidc_client_secret": "supersecret",
                "oidc_issuer": "https://auth.example.net"
            }
        },
        "tls": { "private_key": "-----BEGIN PRIVATE KEY-----" }
    })
}

#[tokio::test]
async fn config_version_round_trips_redacted() {
    let db = Db::open_in_memory().await.unwrap();
    let store = ConfigStore::new(db.clone());

    let v1 = store.store(&secret_snapshot()).await.unwrap();
    let v2 = store.store(&secret_snapshot()).await.unwrap();
    assert!(v2 > v1);
    assert_eq!(store.current().await.unwrap(), Some(v2));

    let loaded = store.load(v1).await.unwrap().unwrap();
    // Secrets are redacted; the plaintext never reached SQLite.
    assert_eq!(
        loaded["control_api"]["auth"]["oidc_client_secret"],
        "redacted"
    );
    assert_eq!(loaded["tls"]["private_key"], "redacted");
    // Non-secret values survive verbatim.
    assert_eq!(
        loaded["control_api"]["auth"]["oidc_issuer"],
        "https://auth.example.net"
    );

    assert_eq!(store.load(9999).await.unwrap(), None);
}

#[tokio::test]
async fn audit_redacts_secrets_and_digests() {
    let db = Db::open_in_memory().await.unwrap();
    let audit = Audit::new(db.clone());

    // Differ in both a secret and a non-secret field.
    let before = json!({ "auth": { "client_secret": "before-secret", "issuer": "https://old.example.net" } });
    let after =
        json!({ "auth": { "client_secret": "after-secret", "issuer": "https://new.example.net" } });

    let id = audit
        .record_config_change(ConfigChangeRecord {
            time: 123,
            node_id: "node1".into(),
            actor_id: "u1".into(),
            actor_type: "user".into(),
            config_version: Some(1),
            before: Some(before),
            after: Some(after),
            result: "ok".into(),
            error_code: None,
        })
        .await
        .unwrap();
    assert!(id > 0);

    let rows = db.audit_list(10, 0).await.unwrap();
    assert_eq!(rows.len(), 1);
    let row = &rows[0];

    // Secrets are redacted; the plaintext never reached SQLite.
    let before: Value = serde_json::from_str(row.before.as_deref().unwrap()).unwrap();
    assert_eq!(before["auth"]["client_secret"], "redacted");
    assert!(!row.before.as_deref().unwrap().contains("before-secret"));
    assert!(!row.after.as_deref().unwrap().contains("after-secret"));

    // Non-secret values survive, and the digest is computed over the redacted
    // snapshot, so it reflects non-secret changes.
    assert_eq!(before["auth"]["issuer"], "https://old.example.net");
    assert_eq!(row.before_digest.as_deref().unwrap().len(), 64);
    assert_eq!(row.after_digest.as_deref().unwrap().len(), 64);
    assert_ne!(row.before_digest, row.after_digest);
}

#[tokio::test]
async fn audit_digest_is_over_redacted_snapshot() {
    let db = Db::open_in_memory().await.unwrap();
    let audit = Audit::new(db.clone());

    let record = |secret: &str| ConfigChangeRecord {
        time: 1,
        node_id: "n".into(),
        actor_id: "a".into(),
        actor_type: "user".into(),
        config_version: None,
        before: Some(json!({ "client_secret": secret })),
        after: None,
        result: "ok".into(),
        error_code: None,
    };

    audit.record_config_change(record("alpha")).await.unwrap();
    audit.record_config_change(record("beta")).await.unwrap();

    let rows = db.audit_list(10, 0).await.unwrap();
    // Two different secrets yield the same digest: the digest is over the
    // redacted snapshot, so it cannot be used to confirm a secret value.
    assert_eq!(rows[0].before_digest, rows[1].before_digest);
}

#[tokio::test]
async fn rollback_by_version_reads_exact_snapshot() {
    let db = Db::open_in_memory().await.unwrap();
    let store = ConfigStore::new(db.clone());

    let v1 = store.store(&json!({ "version": "one" })).await.unwrap();
    let v2 = store.store(&json!({ "version": "two" })).await.unwrap();

    // Reading an older version yields exactly that snapshot (rollback source).
    let rolled_back = store.load(v1).await.unwrap().unwrap();
    assert_eq!(rolled_back, json!({ "version": "one" }));
    let latest = store.load(v2).await.unwrap().unwrap();
    assert_eq!(latest, json!({ "version": "two" }));
}
