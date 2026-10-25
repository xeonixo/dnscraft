//! Cloudflare DNS client against the hand-written mock API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;

use dnscraft_tls::{CloudflareClient, CloudflareConfig, Secret, TTL_ACME_TXT, TlsError};
use mock_cloudflare::{MockCloudflare, MockZone, OversizeBody};

const TOKEN: &str = "test-cf-token-do-not-leak";
const ZONE_ID: &str = "zone-example-com";
const DOMAIN: &str = "example.com";
const CHALLENGE: &str = "_acme-challenge.dns.example.com";

fn zone_fixture() -> MockZone {
    MockZone {
        id: ZONE_ID.into(),
        name: DOMAIN.into(),
        name_servers: vec![
            "ada.ns.cloudflare.com".into(),
            "bob.ns.cloudflare.com".into(),
        ],
    }
}

async fn mock_and_client() -> (MockCloudflare, CloudflareClient) {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    let client = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();
    (mock, client)
}

#[tokio::test]
async fn two_txt_values_coexist_and_delete_is_selective() {
    let (mock, client) = mock_and_client().await;
    let _guard = client.write_guard().await;

    let a = client
        .create_txt(CHALLENGE, "value-one", TTL_ACME_TXT)
        .await
        .unwrap();
    let b = client
        .create_txt(CHALLENGE, "value-two", TTL_ACME_TXT)
        .await
        .unwrap();
    assert_ne!(a.id, b.id);

    let listed = client.list_records(CHALLENGE, "TXT").await.unwrap();
    assert_eq!(listed.len(), 2);
    let contents: Vec<&str> = listed.iter().map(|r| r.content.as_str()).collect();
    assert!(contents.contains(&"value-one"));
    assert!(contents.contains(&"value-two"));

    client.delete_record(&a.id).await.unwrap();
    let after = client.list_records(CHALLENGE, "TXT").await.unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].content, "value-two");
    assert_eq!(after[0].id, b.id);

    let mem = mock.records().await;
    assert_eq!(mem.len(), 1);
    assert_eq!(mem[0].content, "value-two");
}

#[tokio::test]
async fn zone_by_name_returns_nameservers() {
    let (_mock, client) = mock_and_client().await;
    let z = client.zone().await.unwrap();
    assert_eq!(z.id, ZONE_ID);
    assert_eq!(z.name, DOMAIN);
    assert_eq!(
        z.name_servers,
        vec![
            "ada.ns.cloudflare.com".to_owned(),
            "bob.ns.cloudflare.com".to_owned()
        ]
    );
}

#[tokio::test]
async fn unknown_zone_is_tls_cloudflare_zone() {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    let client = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        "missing.example",
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();
    let err = client.zone().await.expect_err("unknown zone");
    assert_eq!(err.code(), "tls.cloudflare.zone");
    assert!(!format!("{err}").contains(TOKEN));
    assert!(!format!("{err:?}").contains(TOKEN));
}

#[tokio::test]
async fn zone_by_configured_id() {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    let client = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig {
            zone_id: Some(ZONE_ID.into()),
        },
        mock.base_url(),
    )
    .unwrap();
    let z = client.zone().await.unwrap();
    assert_eq!(z.id, ZONE_ID);
    assert_eq!(z.name_servers.len(), 2);
}

#[tokio::test]
async fn rate_limit_keeps_retry_after_hint() {
    let (mock, client) = mock_and_client().await;
    mock.force_next_status(429, Some("30")).await;
    let err = client.zone().await.expect_err("429");
    assert_eq!(err.code(), "tls.cloudflare.http");
    let TlsError::CloudflareHttp { message } = &err else {
        panic!("expected CloudflareHttp, got {err:?}");
    };
    assert!(
        message.contains("Retry-After: 30"),
        "retry hint missing in {message}"
    );
    assert!(!message.contains(TOKEN));
}

#[tokio::test]
async fn http_429_on_record_write_is_cloudflare_http() {
    let (mock, client) = mock_and_client().await;
    // Prime zone cache first so the forced 429 hits create_txt.
    let _ = client.zone().await.unwrap();
    mock.force_next_status(429, Some("60")).await;
    let err = client
        .create_txt(CHALLENGE, "x", TTL_ACME_TXT)
        .await
        .expect_err("429");
    assert_eq!(err.code(), "tls.cloudflare.http");
    let TlsError::CloudflareHttp { message } = &err else {
        panic!("expected CloudflareHttp");
    };
    assert!(message.contains("Retry-After: 60"), "{message}");
    assert!(!message.contains(TOKEN));
    assert!(!format!("{err:?}").contains(TOKEN));
}

#[tokio::test]
async fn bearer_token_sent_and_absent_from_errors() {
    let (mock, client) = mock_and_client().await;
    client.zone().await.unwrap();
    let reqs = mock.requests().await;
    assert!(!reqs.is_empty());
    let auth = reqs[0]
        .headers
        .get("authorization")
        .expect("Authorization header");
    assert_eq!(auth, &format!("Bearer {TOKEN}"));

    // Wrong token → 401; neither the good nor the bad secret may appear in errors.
    let bad_token = "wrong-token-must-not-leak";
    let bad = CloudflareClient::with_base_url(
        Secret::new(bad_token),
        DOMAIN,
        &CloudflareConfig { zone_id: None },
        mock.base_url(),
    )
    .unwrap();
    let err = bad.zone().await.expect_err("401");
    assert_eq!(err.code(), "tls.cloudflare.http");
    let shown = format!("{err} / {err:?}");
    assert!(!shown.contains(TOKEN), "good token leaked");
    assert!(!shown.contains(bad_token), "bad token leaked");
}

#[tokio::test]
async fn address_upsert_sets_proxied_false_and_ttl_auto() {
    let (mock, client) = mock_and_client().await;
    let name = "node1.dns.example.com";
    let rec = client
        .upsert_address(name, "A", "203.0.113.10")
        .await
        .unwrap();
    assert_eq!(rec.content, "203.0.113.10");
    assert!(!rec.proxied);
    assert_eq!(rec.ttl, 1);

    let again = client
        .upsert_address(name, "A", "203.0.113.11")
        .await
        .unwrap();
    assert_eq!(again.id, rec.id);
    assert_eq!(again.content, "203.0.113.11");

    let mem = mock.records().await;
    assert_eq!(mem.len(), 1);
    assert_eq!(mem[0].content, "203.0.113.11");
    assert!(!mem[0].proxied);
}

#[tokio::test]
async fn write_lock_is_shared_arc() {
    let (_mock, client) = mock_and_client().await;
    let a = client.write_lock().clone();
    let b = client.write_lock().clone();
    assert!(std::sync::Arc::ptr_eq(&a, &b));
    let _g = a.lock().await;
}

async fn assert_body_cap_enforced_promptly(kind: OversizeBody) {
    let (mock, client) = mock_and_client().await;
    // Resolve and cache the zone first so only the list request is oversized.
    client.zone().await.unwrap();
    mock.force_next_oversize(kind).await;
    // The mock holds the connection open for 10 s; a client that waits for EOF
    // before checking the size would blow this timeout.
    let err = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client.list_records(CHALLENGE, "TXT"),
    )
    .await
    .expect("cap must be enforced while reading, not after EOF")
    .unwrap_err();
    assert_eq!(err.code(), "tls.cloudflare.http");
    assert!(err.to_string().contains("cap"), "{err}");
}

#[tokio::test]
async fn oversized_content_length_rejected_before_reading_body() {
    assert_body_cap_enforced_promptly(OversizeBody::DeclaredOnly).await;
}

#[tokio::test]
async fn oversized_streamed_body_aborts_while_reading() {
    assert_body_cap_enforced_promptly(OversizeBody::Streamed).await;
}
