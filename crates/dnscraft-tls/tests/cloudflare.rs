//! Cloudflare DNS client against the hand-written mock API.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_cloudflare.rs"]
mod mock_cloudflare;

use dnscraft_tls::{
    CloudflareClient, CloudflareConfig, DnsRecordSpec, ListZoneRecordsQuery, Secret, TTL_ACME_TXT,
    TTL_AUTO, TlsError,
};
use mock_cloudflare::{MockCloudflare, MockRecord, MockZone, OversizeBody};

const TOKEN: &str = "test-cf-token-do-not-leak";
const ZONE_ID: &str = "zone-example-com";
const DOMAIN: &str = "example.com";
const CHALLENGE: &str = "_acme-challenge.dns.example.com";

fn zone_fixture() -> MockZone {
    MockZone {
        id: ZONE_ID.into(),
        name: DOMAIN.into(),
        status: "active".into(),
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
async fn record_outside_all_zones_is_dns_provider_zone() {
    let (_mock, client) = mock_and_client().await;

    // Nothing configured and the name is outside the fallback public_domain.
    let err = client
        .zone_for_name("host.unrelated.net")
        .await
        .expect_err("no zone owns the name");
    assert_eq!(err.code(), "tls.dns.provider.zone");
    assert!(err.to_string().contains("host.unrelated.net"));

    // A name under the fallback zone still resolves.
    let zone = client.zone_for_name("node1.dns.example.com").await.unwrap();
    assert_eq!(zone.name, DOMAIN);
}

#[tokio::test]
async fn rate_limit_keeps_retry_after_hint() {
    let (mock, client) = mock_and_client().await;
    mock.force_next_status(429, Some("30")).await;
    let err = client.zone().await.expect_err("429");
    assert_eq!(err.code(), "tls.cloudflare.http");
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(30)));
    let TlsError::CloudflareHttp {
        message, status, ..
    } = &err
    else {
        panic!("expected CloudflareHttp, got {err:?}");
    };
    assert_eq!(*status, Some(429));
    assert!(
        !message.contains("Retry-After"),
        "retry hint must be structured, not in message: {message}"
    );
    assert!(!message.contains(TOKEN));
}

#[tokio::test]
async fn unknown_zone_id_maps_via_http_status_not_message() {
    let mock = MockCloudflare::start(TOKEN, zone_fixture()).await;
    let client = CloudflareClient::with_base_url(
        Secret::new(TOKEN),
        DOMAIN,
        &CloudflareConfig {
            zone_id: Some("no-such-zone-id".into()),
        },
        mock.base_url(),
    )
    .unwrap();
    let err = client.zone().await.expect_err("missing zone id");
    assert_eq!(
        err.code(),
        "tls.cloudflare.zone",
        "404 on zone-by-id must become CloudflareZone (status-based), got {err:?}"
    );
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
    assert_eq!(err.retry_after(), Some(std::time::Duration::from_secs(60)));
    let TlsError::CloudflareHttp { message, .. } = &err else {
        panic!("expected CloudflareHttp");
    };
    assert!(!message.contains("Retry-After"), "{message}");
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

#[tokio::test]
async fn list_zones_returns_inventory_fields() {
    let (mock, client) = mock_and_client().await;
    mock.add_zone(MockZone {
        id: "zone-other".into(),
        name: "other.example".into(),
        status: "pending".into(),
        name_servers: vec!["ns1.cloudflare.com".into()],
    })
    .await;

    let zones = client.list_zones().await.unwrap();
    assert_eq!(zones.len(), 2);

    let example = zones.iter().find(|z| z.id == ZONE_ID).unwrap();
    assert_eq!(example.name, DOMAIN);
    assert_eq!(example.status, "active");
    assert_eq!(
        example.name_servers,
        vec![
            "ada.ns.cloudflare.com".to_owned(),
            "bob.ns.cloudflare.com".to_owned()
        ]
    );

    let other = zones.iter().find(|z| z.id == "zone-other").unwrap();
    assert_eq!(other.name, "other.example");
    assert_eq!(other.status, "pending");
    assert_eq!(other.name_servers, vec!["ns1.cloudflare.com".to_owned()]);

    // Inventory is read-only: no writer mutex held, ACME path still works.
    let _guard = client.write_guard().await;
    let txt = client
        .create_txt(CHALLENGE, "after-list-zones", TTL_ACME_TXT)
        .await
        .unwrap();
    assert_eq!(txt.content, "after-list-zones");
}

#[tokio::test]
async fn list_zone_records_paginates_and_filters() {
    let (mock, client) = mock_and_client().await;
    for i in 0..5 {
        mock.insert_record(MockRecord {
            id: format!("rec-{i}"),
            zone_id: ZONE_ID.into(),
            name: format!("host{i}.{DOMAIN}"),
            record_type: "A".into(),
            content: format!("203.0.113.{i}"),
            ttl: 300,
            proxied: i % 2 == 0,
        })
        .await;
    }
    mock.insert_record(MockRecord {
        id: "rec-special".into(),
        zone_id: ZONE_ID.into(),
        name: format!("special.{DOMAIN}"),
        record_type: "TXT".into(),
        content: "hello".into(),
        ttl: 120,
        proxied: false,
    })
    .await;

    let page1 = client
        .list_zone_records(
            ZONE_ID,
            &ListZoneRecordsQuery {
                page: 1,
                per_page: 2,
                name_substr: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page1.records.len(), 2);
    assert_eq!(page1.page, 1);
    assert_eq!(page1.per_page, 2);
    assert_eq!(page1.total_count, 6);
    assert_eq!(page1.total_pages, 3);
    assert_eq!(page1.records[0].id, "rec-0");
    assert_eq!(page1.records[0].name, format!("host0.{DOMAIN}"));
    assert_eq!(page1.records[0].record_type, "A");
    assert_eq!(page1.records[0].content, "203.0.113.0");
    assert_eq!(page1.records[0].ttl, 300);
    assert!(page1.records[0].proxied);

    let page2 = client
        .list_zone_records(
            ZONE_ID,
            &ListZoneRecordsQuery {
                page: 2,
                per_page: 2,
                name_substr: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(page2.records.len(), 2);
    assert_eq!(page2.page, 2);
    assert_eq!(page2.records[0].id, "rec-2");

    let filtered = client
        .list_zone_records(
            ZONE_ID,
            &ListZoneRecordsQuery {
                page: 1,
                per_page: 10,
                name_substr: Some("SPECIAL".into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(filtered.total_count, 1);
    assert_eq!(filtered.records.len(), 1);
    assert_eq!(filtered.records[0].id, "rec-special");
    assert_eq!(filtered.records[0].record_type, "TXT");
    assert_eq!(filtered.records[0].content, "hello");
    assert!(!filtered.records[0].proxied);

    // Existing name+type filter for ACME still returns every match (no page trim).
    let _ = client
        .create_txt(CHALLENGE, "v1", TTL_ACME_TXT)
        .await
        .unwrap();
    let _ = client
        .create_txt(CHALLENGE, "v2", TTL_ACME_TXT)
        .await
        .unwrap();
    let listed = client.list_records(CHALLENGE, "TXT").await.unwrap();
    assert_eq!(listed.len(), 2);
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

#[tokio::test]
async fn generic_create_update_delete_under_write_guard() {
    let (mock, client) = mock_and_client().await;
    let _guard = client.write_guard().await;

    let created = client
        .create_record_in(
            ZONE_ID,
            &DnsRecordSpec::new("www.example.com", "A", "203.0.113.50", 300, false),
        )
        .await
        .unwrap();
    assert_eq!(created.name, "www.example.com");
    assert_eq!(created.content, "203.0.113.50");

    let updated = client
        .update_record_in(
            ZONE_ID,
            &created.id,
            &DnsRecordSpec::new("www.example.com", "A", "203.0.113.51", 300, false),
        )
        .await
        .unwrap();
    assert_eq!(updated.id, created.id);
    assert_eq!(updated.content, "203.0.113.51");

    let mx = client
        .create_record_in(
            ZONE_ID,
            &DnsRecordSpec {
                name: "example.com".into(),
                record_type: "MX".into(),
                content: "10 mail.example.com".into(),
                ttl: TTL_AUTO,
                proxied: false,
                priority: None,
                weight: None,
                port: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(mx.record_type, "MX");
    assert_eq!(mx.content, "mail.example.com");

    client.delete_record_in(ZONE_ID, &created.id).await.unwrap();
    let mem = mock.records().await;
    assert!(mem.iter().all(|r| r.id != created.id));
    assert!(mem.iter().any(|r| r.id == mx.id));
}

#[tokio::test]
async fn upsert_record_in_is_idempotent() {
    let (_mock, client) = mock_and_client().await;
    let _guard = client.write_guard().await;
    let spec = DnsRecordSpec::new("api.example.com", "AAAA", "2001:db8::1", TTL_AUTO, false);
    let first = client.upsert_record_in(ZONE_ID, &spec).await.unwrap();
    let second = client.upsert_record_in(ZONE_ID, &spec).await.unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(second.content, "2001:db8::1");
}

#[tokio::test]
async fn set_zones_preserves_write_lock_arc() {
    let (_mock, mut client) = mock_and_client().await;
    let before = client.write_lock().clone();
    client.set_zones(vec![dnscraft_tls::ZoneConfig {
        name: "other.example".into(),
        zone_id: Some("z-other".into()),
    }]);
    assert!(std::sync::Arc::ptr_eq(client.write_lock(), &before));
}
