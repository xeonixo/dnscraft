//! Last-good disk cache acceptance tests (C9).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_gateway.rs"]
mod mock_gateway;

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_clients::{
    ClientEngine, ClientsConfig, DEFAULT_LOCAL_DOMAIN, ManualClock, Secret, TlsMode, UnifiConfig,
    cache_path, leaf_sha256,
};
use mock_gateway::{CertKind, ClassicFixture, IntegrationFixture, MockGateway};
use serde_json::json;

const API_KEY: &str = "test-unifi-api-key-do-not-leak";
const SITE_UUID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_KEY: &str = "default";
const NET_ID: &str = "net-classic-iot";
const MAC: &str = "aa:bb:cc:dd:ee:01";
const INTEG_ID: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

fn start() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("dnscraft-clients-c9-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

async fn seed(mock: &MockGateway) {
    mock.set_integration(IntegrationFixture {
        sites: vec![json!({
            "id": SITE_UUID,
            "name": "Default",
            "internalReference": SITE_KEY
        })],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        clients: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({
                "id": INTEG_ID,
                "name": "Phone",
                "ipAddress": "198.51.100.10",
                "macAddress": MAC,
                "connectedAt": "2026-10-25T12:00:00Z"
            })],
        )]),
        ..IntegrationFixture::default()
    })
    .await;
    mock.set_classic(ClassicFixture {
        sites: vec![json!({ "name": SITE_KEY })],
        sta: HashMap::from([(
            SITE_KEY.into(),
            vec![json!({
                "_id": "classic-1",
                "mac": MAC,
                "hostname": "phone",
                "ip": "198.51.100.10",
                "ipv6_addresses": ["2001:db8::10"],
                "network_id": NET_ID,
                "last_seen": 1_729_863_600u64
            })],
        )]),
        networkconf: HashMap::from([(
            SITE_KEY.into(),
            vec![json!({
                "_id": NET_ID,
                "name": "IoT",
                "vlan": 40,
                "domain_name": "iot.home.arpa"
            })],
        )]),
        ..ClassicFixture::default()
    })
    .await;
}

fn cfg(mock: &MockGateway) -> ClientsConfig {
    ClientsConfig {
        local_domain: DEFAULT_LOCAL_DOMAIN.into(),
        unifi: UnifiConfig {
            enabled: true,
            base_url: mock.base_url(),
            site_id: Some(SITE_UUID.into()),
            poll_interval: Duration::from_secs(60),
            classic_clients: true,
            tls: TlsMode::Pin(leaf_sha256(&mock.leaf_der)),
        },
        ..ClientsConfig::default()
    }
}

#[tokio::test]
async fn restart_with_gateway_down_serves_cache_stale() {
    let data = temp_dir("restart");
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));

    let eng1 = ClientEngine::new_with_secret(
        cfg(&mock),
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    eng1.sync_now().await.unwrap();
    let v6 = IpAddr::from_str("2001:db8::10").unwrap();
    assert!(eng1.lookup().by_ip(v6).is_some());
    let label = eng1.lookup().by_ip(v6).unwrap().dns_label.clone();
    drop(eng1);

    // New engine, gateway unreachable.
    let mut dead = cfg(&mock);
    dead.unifi.base_url = "https://127.0.0.1:1".into();
    let eng2 = ClientEngine::new_with_secret(
        dead,
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    assert!(eng2.status().stale);
    assert_eq!(
        eng2.lookup().by_ip(v6).unwrap().dns_label,
        label,
        "cached names served before first poll"
    );
    let _ = eng2.sync_now().await; // fails, still keeps cache
    assert!(eng2.lookup().by_ip(v6).is_some());
    assert!(eng2.status().stale);

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn labels_survive_restart() {
    let data = temp_dir("labels");
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));

    let eng1 = ClientEngine::new_with_secret(
        cfg(&mock),
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    eng1.sync_now().await.unwrap();
    let first_label = eng1
        .lookup()
        .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
        .unwrap()
        .dns_label
        .clone();
    drop(eng1);

    let eng2 = ClientEngine::new_with_secret(
        cfg(&mock),
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    // Before sync, cache already has the label.
    assert_eq!(
        eng2.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .unwrap()
            .dns_label,
        first_label
    );
    eng2.sync_now().await.unwrap();
    assert_eq!(
        eng2.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .unwrap()
            .dns_label,
        first_label,
        "label stable across restart"
    );

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn corrupt_cache_ignored_no_panic() {
    let data = temp_dir("corrupt");
    fs::create_dir_all(data.join("clients")).unwrap();
    fs::write(cache_path(&data), b"{broken").unwrap();

    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = ClientEngine::new_with_secret(
        cfg(&mock),
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    // Starts manuals-only (empty UniFi) despite corrupt cache.
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .is_none()
    );
    eng.sync_now().await.unwrap();
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .is_some()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(cache_path(&data))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let _ = fs::remove_dir_all(&data);
}
