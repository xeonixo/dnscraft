//! Classic API + sync_once acceptance tests (C7).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_gateway.rs"]
mod mock_gateway;

use std::collections::HashMap;
use std::net::IpAddr;
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use dnscraft_clients::{
    ClientsConfig, DEFAULT_LOCAL_DOMAIN, DEFAULT_POLL_INTERVAL, GatewayClient, Secret, State,
    TlsMode, UnifiConfig, fetch_classic, leaf_sha256, sync_once,
};
use mock_gateway::{CertKind, ClassicFixture, IntegrationFixture, MockGateway};
use serde_json::{Value, json};

const API_KEY: &str = "test-unifi-api-key-do-not-leak";
const SITE_UUID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_KEY: &str = "default";
const NET_CLASSIC_ID: &str = "net-classic-iot";
const MAC: &str = "aa:bb:cc:dd:ee:01";
const INTEG_CLIENT: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

fn unifi(base: String, classic_clients: bool) -> UnifiConfig {
    UnifiConfig {
        enabled: true,
        base_url: base,
        site_id: Some(SITE_UUID.into()),
        poll_interval: DEFAULT_POLL_INTERVAL,
        classic_clients,
        tls: TlsMode::Insecure, // overwritten by caller via GatewayClient::new
    }
}

fn cfg() -> ClientsConfig {
    ClientsConfig {
        local_domain: DEFAULT_LOCAL_DOMAIN.into(),
        ..ClientsConfig::default()
    }
}

async fn gw(mock: &MockGateway, classic_clients: bool) -> (GatewayClient, UnifiConfig) {
    let tls = TlsMode::Pin(leaf_sha256(&mock.leaf_der));
    let mut u = unifi(mock.base_url(), classic_clients);
    u.tls = tls.clone();
    let client = GatewayClient::new(&u, Secret::new(API_KEY)).unwrap();
    (client, u)
}

fn integ_site() -> Value {
    json!({
        "id": SITE_UUID,
        "name": "Default",
        "internalReference": SITE_KEY
    })
}

fn classic_site() -> Value {
    json!({ "name": SITE_KEY, "desc": "Default" })
}

fn integ_client(ip: &str) -> Value {
    json!({
        "id": INTEG_CLIENT,
        "name": "Phone",
        "type": "WIRELESS",
        "ipAddress": ip,
        "macAddress": MAC,
        "connectedAt": "2026-10-25T12:00:00Z"
    })
}

fn classic_sta_rich() -> Value {
    json!({
        "_id": "classic-mongo-id-1",
        "mac": MAC,
        "hostname": "phone",
        "name": "Phone",
        "ip": "198.51.100.10",
        "ipv6_addresses": ["2001:db8::10", "2001:db8::11"],
        "network_id": NET_CLASSIC_ID,
        "last_seen": 1_729_863_600u64,
        "unknown_field": {"nested": true},
        "weird_number_as_ip": 42
    })
}

fn classic_networkconf() -> Value {
    json!({
        "_id": NET_CLASSIC_ID,
        "name": "IoT",
        "vlan": 40,
        "domain_name": "iot.home.arpa",
        "ip_subnet": "198.51.100.1/24"
    })
}

async fn seed_happy(mock: &MockGateway) {
    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        network_details: HashMap::from([(
            format!("{SITE_UUID}/integ-net"),
            json!({
                "id": "integ-net",
                "ipv4Configuration": {
                    "hostIpAddress": "198.51.100.1",
                    "prefixLength": 24
                }
            }),
        )]),
        clients: HashMap::from([(SITE_UUID.into(), vec![integ_client("198.51.100.10")])]),
        ..IntegrationFixture::default()
    })
    .await;

    mock.set_classic(ClassicFixture {
        sites: vec![classic_site()],
        sta: HashMap::from([(SITE_KEY.into(), vec![classic_sta_rich()])]),
        users: HashMap::from([(SITE_KEY.into(), vec![])]),
        networkconf: HashMap::from([(SITE_KEY.into(), vec![classic_networkconf()])]),
        ..ClassicFixture::default()
    })
    .await;
}

#[tokio::test]
async fn multi_ipv6_unknown_fields_and_bad_rows() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_classic(ClassicFixture {
        sites: vec![classic_site()],
        sta: HashMap::from([(
            SITE_KEY.into(),
            vec![
                classic_sta_rich(),
                json!({ "hostname": "no-id", "ip": "198.51.100.99" }),
                json!({
                    "_id": "ok-no-mac",
                    "hostname": "wired",
                    "ip": "198.51.100.20",
                    "ipv6_addresses": "not-an-array",
                    "last_seen": "not-a-number"
                }),
                json!({
                    "_id": "ok-wrong-types",
                    "mac": 12345,
                    "ip": ["array", "not", "string"],
                    "ipv6_addresses": [1, 2, 3],
                    "network_id": true
                }),
            ],
        )]),
        users: HashMap::from([(SITE_KEY.into(), vec![])]),
        networkconf: HashMap::from([(SITE_KEY.into(), vec![classic_networkconf()])]),
        ..ClassicFixture::default()
    })
    .await;

    let (client, _) = gw(&mock, true).await;
    let fetched = fetch_classic(&client, SITE_KEY).await.unwrap();

    // rich + ok-no-mac + ok-wrong-types (empty addrs still kept); no-id skipped
    assert_eq!(fetched.observations.len(), 3);
    assert!(fetched.skipped_rows >= 1);

    let rich = fetched
        .observations
        .iter()
        .find(|o| o.display_name == "phone" || o.macs.iter().any(|m| m.to_string() == MAC))
        .expect("rich row");
    assert!(
        rich.addresses
            .contains(&IpAddr::from_str("198.51.100.10").unwrap())
    );
    assert!(
        rich.addresses
            .contains(&IpAddr::from_str("2001:db8::10").unwrap())
    );
    assert!(
        rich.addresses
            .contains(&IpAddr::from_str("2001:db8::11").unwrap())
    );
    assert_eq!(rich.network_id.as_deref(), Some(NET_CLASSIC_ID));
    assert!(rich.online);

    let no_mac = fetched
        .observations
        .iter()
        .find(|o| o.id.as_str() == "ok-no-mac")
        .expect("missing MAC kept");
    assert!(no_mac.macs.is_empty());
    assert_eq!(
        no_mac.addresses,
        vec![IpAddr::from_str("198.51.100.20").unwrap()]
    );

    assert_eq!(fetched.networks.len(), 1);
    assert_eq!(
        fetched.networks[0].domain_name.as_deref(),
        Some("iot.home.arpa")
    );
}

#[tokio::test]
async fn invalid_classic_site_key_falls_back_to_integration() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![json!({
            "id": SITE_UUID,
            "name": "Default",
            "internalReference": "../evil"
        })],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        clients: HashMap::from([(SITE_UUID.into(), vec![integ_client("198.51.100.10")])]),
        ..IntegrationFixture::default()
    })
    .await;
    // Classic self/sites claims the evil key exists so resolve_site_key accepts it;
    // fetch must still reject the charset before interpolating into the URL.
    mock.set_classic(ClassicFixture {
        sites: vec![json!({ "name": "../evil" })],
        sta: HashMap::from([("../evil".into(), vec![classic_sta_rich()])]),
        ..ClassicFixture::default()
    })
    .await;

    let (client, u) = gw(&mock, true).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let result = sync_once(&client, &cfg(), &u, &State::default(), now)
        .await
        .expect("integration still succeeds");
    let err = result.classic_error.expect("classic site key rejected");
    assert_eq!(err.code(), "clients.http.body");
    assert!(
        result
            .merge
            .lookup
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn classic_down_integration_up_records_error() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    await_seed_integ_only(&mock).await;
    mock.set_classic(ClassicFixture {
        sites: vec![classic_site()],
        sta_fail: true,
        ..ClassicFixture::default()
    })
    .await;

    let (client, u) = gw(&mock, true).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let result = sync_once(&client, &cfg(), &u, &State::default(), now)
        .await
        .expect("integration alone succeeds");

    let err = result.classic_error.expect("classic error recorded");
    assert_eq!(err.code(), "clients.http.status");
    assert!(result.classic_site_key.is_none());

    // Integration singular IP still indexed.
    let phone = result
        .merge
        .lookup
        .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
        .expect("integration client present");
    assert_eq!(phone.source, dnscraft_clients::ClientSource::Unifi);
}

async fn await_seed_integ_only(mock: &MockGateway) {
    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        network_details: HashMap::new(),
        clients: HashMap::from([(SITE_UUID.into(), vec![integ_client("198.51.100.10")])]),
        ..IntegrationFixture::default()
    })
    .await;
}

#[tokio::test]
async fn classic_clients_false_skips_classic_http() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    await_seed_integ_only(&mock).await;
    // Classic fixture would 500 if hit — prove we never call it.
    mock.set_classic(ClassicFixture {
        sites: vec![classic_site()],
        sta_fail: true,
        networkconf_fail: true,
        ..ClassicFixture::default()
    })
    .await;

    let (client, u) = gw(&mock, false).await;
    let _ = mock.take_log().await; // clear startup noise
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let result = sync_once(&client, &cfg(), &u, &State::default(), now)
        .await
        .unwrap();
    assert!(result.classic_error.is_none());
    assert!(result.classic_site_key.is_none());

    let log = mock.take_log().await;
    let classic_hits: Vec<_> = log
        .iter()
        .filter(|r| r.path.contains("/proxy/network/api/"))
        .collect();
    assert!(
        classic_hits.is_empty(),
        "classic paths hit: {:?}",
        classic_hits.iter().map(|r| &r.path).collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn sync_merges_classic_ipv6_onto_integration_client() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed_happy(&mock).await;

    let (client, u) = gw(&mock, true).await;
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let result = sync_once(&client, &cfg(), &u, &State::default(), now)
        .await
        .unwrap();
    assert!(result.classic_error.is_none());
    assert_eq!(result.classic_site_key.as_deref(), Some(SITE_KEY));

    let v6 = IpAddr::from_str("2001:db8::10").unwrap();
    let info = result.merge.lookup.by_ip(v6).expect("classic IPv6 indexed");
    // Matched by MAC → keep Integration UUID.
    assert_eq!(info.id.as_str(), INTEG_CLIENT);
    assert!(info.addresses.contains(&v6));
    assert!(
        info.addresses
            .contains(&IpAddr::from_str("2001:db8::11").unwrap())
    );

    // Domain from classic networkconf via network_id join.
    let fqdn = result.merge.lookup.reverse(v6).expect("ptr");
    assert!(
        fqdn.ends_with(".iot.home.arpa"),
        "expected classic domain, got {fqdn}"
    );
}
