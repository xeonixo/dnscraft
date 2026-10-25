//! Integration API fetch against the HTTPS mock (C6).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_gateway.rs"]
mod mock_gateway;

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;

use dnscraft_clients::{
    DEFAULT_POLL_INTERVAL, GatewayClient, Secret, TlsMode, UnifiConfig, fetch_integration,
    leaf_sha256,
};
use mock_gateway::{CertKind, IntegrationFixture, MockGateway};
use serde_json::{Value, json};

const API_KEY: &str = "test-unifi-api-key-do-not-leak";
const SITE_A: &str = "11111111-1111-1111-1111-111111111111";
const SITE_B: &str = "22222222-2222-2222-2222-222222222222";
const NET_IOT: &str = "net-iot";

fn unifi(base: String, tls: TlsMode, site_id: Option<&str>) -> UnifiConfig {
    UnifiConfig {
        enabled: true,
        base_url: base,
        site_id: site_id.map(str::to_owned),
        poll_interval: DEFAULT_POLL_INTERVAL,
        classic_clients: true,
        tls,
    }
}

async fn client_for(mock: &MockGateway, site_id: Option<&str>) -> GatewayClient {
    GatewayClient::new(
        &unifi(
            mock.base_url(),
            TlsMode::Pin(leaf_sha256(&mock.leaf_der)),
            site_id,
        ),
        Secret::new(API_KEY),
    )
    .unwrap()
}

fn site(id: &str, name: &str) -> Value {
    json!({ "id": id, "name": name })
}

fn network_overview(id: &str, name: &str, vlan: u16) -> Value {
    json!({
        "id": id,
        "name": name,
        "vlanId": vlan,
        "enabled": true,
        "default": false
    })
}

fn network_details(host: &str, prefix: u8) -> Value {
    json!({
        "id": NET_IOT,
        "name": "IoT",
        "vlanId": 40,
        "ipv4Configuration": {
            "hostIpAddress": host,
            "prefixLength": prefix
        }
    })
}

fn client_row(id: &str, name: &str, ip: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "type": "WIRELESS",
        "ipAddress": ip,
        "macAddress": "aa:bb:cc:dd:ee:ff",
        "connectedAt": "2026-10-25T12:00:00Z"
    })
}

#[tokio::test]
async fn one_site_auto_picked() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![network_overview(NET_IOT, "IoT", 40)])]),
        network_details: HashMap::from([(
            format!("{SITE_A}/{NET_IOT}"),
            network_details("198.51.100.1", 24),
        )]),
        clients: HashMap::from([(
            SITE_A.into(),
            vec![client_row("c1", "Phone", "198.51.100.10")],
        )]),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, None).await;
    let fetched = fetch_integration(&gw, None).await.unwrap();
    assert_eq!(fetched.site_id, SITE_A);
    assert_eq!(fetched.networks.len(), 1);
    let pfx = fetched.networks[0].ipv4_prefix.unwrap();
    assert_eq!(pfx.prefix_len(), 24);
    assert!(pfx.contains(&IpAddr::from_str("198.51.100.10").unwrap()));
    assert_eq!(fetched.networks[0].vlan_id, Some(40));
    assert_eq!(fetched.observations.len(), 1);
    assert_eq!(
        fetched.observations[0].addresses,
        vec![IpAddr::from_str("198.51.100.10").unwrap()]
    );
}

#[tokio::test]
async fn two_sites_without_site_id_errors() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "A"), site(SITE_B, "B")],
        ..IntegrationFixture::default()
    })
    .await;
    let gw = client_for(&mock, None).await;
    let err = fetch_integration(&gw, None).await.expect_err("multi site");
    assert_eq!(err.code(), "clients.config.invalid");
}

#[tokio::test]
async fn four_hundred_fifty_clients_over_three_pages() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let mut rows = Vec::with_capacity(450);
    for i in 0..450 {
        rows.push(client_row(
            &format!("00000000-0000-0000-0000-{i:012}"),
            &format!("Host{i}"),
            &format!("198.51.{}.{}", i / 256, i % 256),
        ));
    }
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![])]),
        clients: HashMap::from([(SITE_A.into(), rows)]),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, Some(SITE_A)).await;
    let fetched = fetch_integration(&gw, Some(SITE_A)).await.unwrap();
    assert_eq!(fetched.observations.len(), 450);

    let log = mock.take_log().await;
    let client_reqs: Vec<_> = log.iter().filter(|r| r.path.contains("/clients")).collect();
    assert_eq!(client_reqs.len(), 3, "200+200+50 → 3 pages");
}

#[tokio::test]
async fn missing_network_details_keeps_vlan_from_overview() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![network_overview(NET_IOT, "IoT", 40)])]),
        // no details → 404 from mock
        network_details: HashMap::new(),
        clients: HashMap::from([(SITE_A.into(), vec![])]),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, Some(SITE_A)).await;
    let fetched = fetch_integration(&gw, Some(SITE_A)).await.unwrap();
    assert_eq!(fetched.networks[0].vlan_id, Some(40));
    assert!(fetched.networks[0].ipv4_prefix.is_none());
}

#[tokio::test]
async fn page_two_500_is_sync_partial() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let mut rows = Vec::with_capacity(250);
    for i in 0..250 {
        rows.push(client_row(
            &format!("00000000-0000-0000-0000-{i:012}"),
            &format!("H{i}"),
            "198.51.100.1",
        ));
    }
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![])]),
        clients: HashMap::from([(SITE_A.into(), rows)]),
        clients_fail_offset: Some(200),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, Some(SITE_A)).await;
    let err = fetch_integration(&gw, Some(SITE_A))
        .await
        .expect_err("partial");
    assert_eq!(err.code(), "clients.sync.partial");
}

#[tokio::test]
async fn truncated_clients_json_is_http_body() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![])]),
        clients: HashMap::from([(SITE_A.into(), vec![])]),
        clients_truncated_at_offset: Some(0),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, Some(SITE_A)).await;
    let err = fetch_integration(&gw, Some(SITE_A))
        .await
        .expect_err("truncated");
    assert_eq!(err.code(), "clients.http.body");
}

#[tokio::test]
async fn bad_client_rows_skipped() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![site(SITE_A, "Default")],
        networks: HashMap::from([(SITE_A.into(), vec![])]),
        clients: HashMap::from([(
            SITE_A.into(),
            vec![
                json!({ "name": "no-id" }),
                client_row("ok-id", "Ok", "198.51.100.2"),
                json!({ "id": "", "name": "empty-id" }),
            ],
        )]),
        ..IntegrationFixture::default()
    })
    .await;

    let gw = client_for(&mock, Some(SITE_A)).await;
    let fetched = fetch_integration(&gw, Some(SITE_A)).await.unwrap();
    assert_eq!(fetched.observations.len(), 1);
    assert_eq!(fetched.skipped_rows, 2);
}
