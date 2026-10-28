//! ClientEngine acceptance tests (C8) + Checkpoint B failure matrix.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/mock_gateway.rs"]
mod mock_gateway;

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static DATA_SEQ: AtomicU64 = AtomicU64::new(0);

use dnscraft_clients::{
    ClientEngine, ClientId, ClientSource, ClientsConfig, DEFAULT_LOCAL_DOMAIN, MAX_CLIENT_COUNT,
    ManualClock, ManualEntry, Secret, TlsMode, UnifiConfig, UnifiObservation, UnifiProfile,
    leaf_sha256,
};
use mock_gateway::{CertKind, ClassicFixture, IntegrationFixture, MockGateway};
use serde_json::{Value, json};

const API_KEY: &str = "test-unifi-api-key-do-not-leak";
const SITE_UUID: &str = "11111111-1111-1111-1111-111111111111";
const SITE_KEY: &str = "default";
const NET_ID: &str = "net-classic-iot";
const MAC: &str = "aa:bb:cc:dd:ee:01";
const INTEG_ID: &str = "cccccccc-cccc-cccc-cccc-cccccccccccc";

fn start() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn integ_site() -> Value {
    json!({ "id": SITE_UUID, "name": "Default", "internalReference": SITE_KEY })
}

async fn seed(mock: &MockGateway) {
    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        network_details: HashMap::from([(
            format!("{SITE_UUID}/integ-net"),
            json!({
                "ipv4Configuration": {
                    "hostIpAddress": "198.51.100.1",
                    "prefixLength": 24
                }
            }),
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
                "ipv6_addresses": ["2001:db8::10", "2001:db8::11"],
                "network_id": NET_ID,
                "last_seen": 1_729_863_600u64
            })],
        )]),
        users: HashMap::new(),
        networkconf: HashMap::from([(
            SITE_KEY.into(),
            vec![json!({
                "_id": NET_ID,
                "name": "IoT",
                "vlan": 40,
                "domain_name": "iot.home.arpa",
                "ip_subnet": "198.51.100.1/24"
            })],
        )]),
        ..ClassicFixture::default()
    })
    .await;
}

fn cfg_for(mock: &MockGateway, poll: Duration) -> ClientsConfig {
    ClientsConfig {
        local_domain: DEFAULT_LOCAL_DOMAIN.into(),
        unifi: UnifiConfig {
            enabled: true,
            base_url: mock.base_url(),
            site_id: Some(SITE_UUID.into()),
            poll_interval: poll,
            classic_clients: true,
            tls: TlsMode::Pin(leaf_sha256(&mock.leaf_der)),
        },
        manual: vec![ManualEntry {
            name: "printer".into(),
            ip: Some(IpAddr::from_str("198.51.100.50").unwrap()),
            cidr: None,
            domain: None,
        }],
        ..ClientsConfig::default()
    }
}

fn unique_data_dir() -> PathBuf {
    let n = DATA_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("dnscraft-clients-eng-{}-{}", std::process::id(), n));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

async fn engine(mock: &MockGateway, clock: Arc<ManualClock>, poll: Duration) -> Arc<ClientEngine> {
    ClientEngine::new_with_secret(
        cfg_for(mock, poll),
        unique_data_dir(),
        clock,
        Some(Secret::new(API_KEY)),
    )
    .unwrap()
}

/// Waits until the boot sync has finished successfully (sets `last_success`).
async fn await_initial_sync(eng: &ClientEngine) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if eng.status().last_success.is_some() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for initial sync; status={:?} attempts={}",
                eng.status(),
                eng.sync_attempts()
            );
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until the poll loop has parked in `wait_until` after the first sync.
async fn await_scheduler_parked(eng: &ClientEngine) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if eng.scheduler_parked() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for scheduler park; attempts={} status={:?}",
                eng.sync_attempts(),
                eng.status()
            );
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Waits until `sync_attempts` reaches at least `min`.
async fn await_sync_attempts(eng: &ClientEngine, min: u64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if eng.sync_attempts() >= min {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            panic!(
                "timed out waiting for sync_attempts>={min}; have={} status={:?}",
                eng.sync_attempts(),
                eng.status()
            );
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn sync_builds_indexes_criteria_1_2_3_5_7() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    await_initial_sync(&eng).await;
    let report = eng.sync_now().await.unwrap();
    assert!(report.classic_error.is_none());

    let lookup = eng.lookup();
    assert_eq!(
        lookup
            .by_ip(IpAddr::from_str("198.51.100.50").unwrap())
            .unwrap()
            .dns_label,
        "printer"
    );
    for a in ["2001:db8::10", "2001:db8::11"] {
        let ip = IpAddr::from_str(a).unwrap();
        assert!(lookup.by_ip(ip).is_some(), "{a}");
        let ptr = lookup.reverse(ip).unwrap();
        assert!(ptr.ends_with(".iot.home.arpa"), "{ptr}");
    }
    assert!(lookup.by_name("phone.iot.home.arpa").is_some());
    let phone = lookup
        .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
        .unwrap();
    assert_eq!(phone.vlan.as_ref().map(|v| v.id), Some(40));
    assert_eq!(phone.vlan.as_ref().map(|v| v.name.as_str()), Some("IoT"));
}

#[tokio::test]
async fn unchanged_data_no_rebuild() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;

    await_initial_sync(&eng).await;

    let r1 = eng.sync_now().await.unwrap();
    let generation = eng.status().generation;
    // May or may not rebuild depending on whether the boot sync already landed.
    let r2 = eng.sync_now().await.unwrap();
    assert!(!r2.rebuilt, "identical feed must not bump generation");
    assert_eq!(r2.generation, generation);
    let _ = r1;
}

#[tokio::test]
async fn two_clients_unchanged_feed_does_not_rebuild() {
    // Regression: HashMap iteration order used to flap the content hash once
    // ≥ 2 clients existed, so every poll rebuilt.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let id_a = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    let id_b = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";
    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(SITE_UUID.into(), vec![])]),
        clients: HashMap::from([(
            SITE_UUID.into(),
            vec![
                json!({
                    "id": id_a,
                    "name": "A",
                    "ipAddress": "198.51.100.11",
                    "macAddress": "aa:bb:cc:dd:ee:11",
                    "connectedAt": "2026-10-25T12:00:00Z"
                }),
                json!({
                    "id": id_b,
                    "name": "B",
                    "ipAddress": "198.51.100.12",
                    "macAddress": "aa:bb:cc:dd:ee:22",
                    "connectedAt": "2026-10-25T12:00:00Z"
                }),
            ],
        )]),
        ..IntegrationFixture::default()
    })
    .await;
    mock.set_classic(ClassicFixture {
        sites: vec![json!({ "name": SITE_KEY })],
        sta: HashMap::from([(
            SITE_KEY.into(),
            vec![
                json!({
                    "_id": "c-a",
                    "mac": "aa:bb:cc:dd:ee:11",
                    "hostname": "a",
                    "ip": "198.51.100.11",
                    "ipv6_addresses": ["2001:db8::11"],
                    "last_seen": 1_729_863_600u64
                }),
                json!({
                    "_id": "c-b",
                    "mac": "aa:bb:cc:dd:ee:22",
                    "hostname": "b",
                    "ip": "198.51.100.12",
                    "ipv6_addresses": ["2001:db8::22"],
                    "last_seen": 1_729_863_600u64
                }),
            ],
        )]),
        networkconf: HashMap::from([(SITE_KEY.into(), vec![])]),
        ..ClassicFixture::default()
    })
    .await;

    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;

    eng.sync_now().await.unwrap();
    let generation = eng.status().generation;
    for i in 0..8 {
        let r = eng.sync_now().await.unwrap();
        assert!(
            !r.rebuilt,
            "poll {i}: identical 2-client feed rebuilt (hash order flap?)"
        );
        assert_eq!(r.generation, generation);
    }
}

#[tokio::test]
async fn unchanged_hash_still_refreshes_ipv6_ttl_state() {
    // Regression: install_snapshot used to drop merge State when the content
    // hash matched, freezing ipv6_last_seen at first sighting.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let mut cfg = cfg_for(&mock, Duration::from_secs(3600));
    cfg.ipv6_address_ttl = Duration::from_secs(100);
    let eng = ClientEngine::new_with_secret(
        cfg,
        unique_data_dir(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    await_initial_sync(&eng).await;

    eng.sync_now().await.unwrap();
    let v6 = IpAddr::from_str("2001:db8::10").unwrap();
    assert!(eng.lookup().by_ip(v6).is_some());

    // Refresh timestamps without changing the feed.
    clock.advance(Duration::from_secs(50));
    let r = eng.sync_now().await.unwrap();
    assert!(!r.rebuilt);

    // Drop IPv6 from the classic feed after the refresh.
    mock.set_classic(ClassicFixture {
        sites: vec![json!({ "name": SITE_KEY })],
        sta: HashMap::from([(
            SITE_KEY.into(),
            vec![json!({
                "_id": "classic-1",
                "mac": MAC,
                "hostname": "phone",
                "ip": "198.51.100.10",
                "ipv6_addresses": [],
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
                "domain_name": "iot.home.arpa",
                "ip_subnet": "198.51.100.1/24"
            })],
        )]),
        ..ClassicFixture::default()
    })
    .await;

    // t=120 from start: 70s after the refresh (within TTL 100), 120s after first
    // sighting (past TTL if state had frozen). Must still be indexed.
    clock.advance(Duration::from_secs(70));
    eng.sync_now().await.unwrap();
    assert!(
        eng.lookup().by_ip(v6).is_some(),
        "IPv6 must be retained via refreshed last-seen, not first-seen"
    );
}

#[tokio::test]
async fn failure_keeps_previous_snapshot() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();
    let v6 = IpAddr::from_str("2001:db8::10").unwrap();
    let generation = eng.status().generation;

    mock.force_status(401).await;
    let err = eng.sync_now().await.expect_err("401");
    assert_eq!(err.code(), "clients.http.status");

    let st = eng.status();
    assert!(st.stale);
    assert_eq!(st.last_error, Some("clients.http.status"));
    assert_eq!(st.generation, generation);
    assert!(eng.lookup().by_ip(v6).is_some());
}

#[tokio::test]
async fn bad_pin_keeps_snapshot() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();

    let mut cfg = cfg_for(&mock, Duration::from_secs(60));
    cfg.unifi.tls = TlsMode::Pin([0u8; 32]);
    eng.apply_config(cfg).await.unwrap();
    let err = eng.sync_now().await.expect_err("bad pin");
    assert_eq!(err.code(), "clients.tls.untrusted");
    assert!(eng.status().stale);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("2001:db8::10").unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn connect_refused_keeps_snapshot() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();

    let mut cfg = cfg_for(&mock, Duration::from_secs(60));
    cfg.unifi.base_url = "https://127.0.0.1:1".into();
    eng.apply_config(cfg).await.unwrap();
    let err = eng.sync_now().await.expect_err("refused");
    assert_eq!(err.code(), "clients.connect");
    assert!(eng.status().stale);
}

#[tokio::test]
async fn truncated_json_keeps_snapshot() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();

    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(SITE_UUID.into(), vec![])]),
        clients: HashMap::from([(SITE_UUID.into(), vec![])]),
        clients_truncated_at_offset: Some(0),
        ..IntegrationFixture::default()
    })
    .await;
    let err = eng.sync_now().await.expect_err("truncated");
    assert_eq!(err.code(), "clients.http.body");
    assert!(eng.status().stale);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("2001:db8::10").unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn empty_site_list_keeps_snapshot() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();

    mock.set_integration(IntegrationFixture {
        sites: vec![],
        ..IntegrationFixture::default()
    })
    .await;
    let mut cfg = cfg_for(&mock, Duration::from_secs(60));
    cfg.unifi.site_id = None;
    eng.apply_config(cfg).await.unwrap();
    let err = eng.sync_now().await.expect_err("no sites");
    assert_eq!(err.code(), "clients.config.invalid");
    assert!(eng.status().stale);
}

#[tokio::test]
async fn backoff_on_429_then_recovery_clears_stale() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(60)).await;
    eng.sync_now().await.unwrap();

    mock.force_status(429).await;
    assert!(eng.sync_now().await.is_err());
    assert!(eng.status().stale);

    // Immediate retry blocked by backoff window.
    let blocked = eng.sync_now().await.expect_err("backoff");
    assert_eq!(blocked.code(), "clients.sync.backoff");

    mock.clear_force_status().await;
    clock.advance(Duration::from_secs(6)); // past BACKOFF_BASE
    let ok = eng.sync_now().await.unwrap();
    assert!(ok.classic_error.is_none());
    assert!(!eng.status().stale);
    assert!(eng.status().last_error.is_none());
}

#[tokio::test]
async fn sync_success_failure_counters() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;

    let before = eng.status();
    eng.sync_now().await.unwrap();
    let after_ok = eng.status();
    assert_eq!(after_ok.sync_successes, before.sync_successes + 1);
    assert_eq!(after_ok.sync_failures, before.sync_failures);

    mock.force_status(401).await;
    assert!(eng.sync_now().await.is_err());
    let after_err = eng.status();
    assert_eq!(after_err.sync_successes, after_ok.sync_successes);
    assert_eq!(after_err.sync_failures, after_ok.sync_failures + 1);
}

#[tokio::test]
async fn ip_conflicts_surface_in_status() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;

    let shared = IpAddr::from_str("198.51.100.77").unwrap();
    let conflicting: Vec<UnifiObservation> = ["dup-a", "dup-b"]
        .into_iter()
        .map(|cid| UnifiObservation {
            id: ClientId::new(cid).unwrap(),
            display_name: cid.into(),
            macs: Vec::new(),
            addresses: vec![shared],
            network_id: None,
            last_seen: Some(start()),
            online: true,
        })
        .collect();
    eng.set_cached_observations_for_test(conflicting);

    let cfg = cfg_for(&mock, Duration::from_secs(3600));
    eng.apply_config_with_secret(cfg, |_| Ok(Secret::new(API_KEY)))
        .await
        .unwrap();
    assert!(eng.status().ip_conflicts >= 1);
}

#[tokio::test]
async fn poll_cadence_respects_jitter_bounds() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let poll = Duration::from_secs(100);
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, poll).await;

    // Immediate first sync, then park on wait_until — wait deterministically.
    await_initial_sync(&eng).await;
    await_scheduler_parked(&eng).await;
    let before = eng.sync_attempts();
    assert!(before >= 1, "first sync should run immediately");

    // Below -10% floor: should not fire another poll.
    clock.advance(Duration::from_secs(80));
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(eng.sync_attempts(), before);
    assert!(eng.scheduler_parked());

    // Past +10% ceiling: must fire.
    clock.advance(Duration::from_secs(40)); // total +120s into the wait
    await_sync_attempts(&eng, before + 1).await;
}

#[tokio::test]
async fn apply_config_refreshes_status_counts() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;
    eng.sync_now().await.unwrap();
    assert_eq!(eng.status().manual_count, 1);

    let mut cfg = cfg_for(&mock, Duration::from_secs(3600));
    cfg.manual.push(ManualEntry {
        name: "camera".into(),
        ip: Some(IpAddr::from_str("198.51.100.60").unwrap()),
        cidr: None,
        domain: None,
    });
    eng.apply_config(cfg).await.unwrap();
    let st = eng.status();
    assert_eq!(st.manual_count, 2);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.60").unwrap())
            .is_some()
    );
}

#[tokio::test]
async fn failed_apply_config_keeps_old_config_and_lookup() {
    // Regression: apply_config used to store the new config before merge::build,
    // so a TooMany failure left a broken config active for every later poll.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;
    eng.sync_now().await.unwrap();

    let before_status = eng.status();
    let before_gen = before_status.generation;
    let before_manual = before_status.manual_count;
    let printer = IpAddr::from_str("198.51.100.50").unwrap();
    assert!(eng.lookup().by_ip(printer).is_some());

    // Inflate the observation cache past the hard cap so build fails after
    // validate accepts the new manual entry.
    let mut obs = Vec::with_capacity(MAX_CLIENT_COUNT);
    for i in 0..MAX_CLIENT_COUNT {
        obs.push(UnifiObservation {
            id: ClientId::new(format!("pad-{i}")).unwrap(),
            display_name: format!("Pad{i}"),
            macs: Vec::new(),
            addresses: Vec::new(),
            network_id: None,
            last_seen: None,
            online: true,
        });
    }
    eng.set_cached_observations_for_test(obs);

    let mut bad = cfg_for(&mock, Duration::from_secs(3600));
    bad.manual.push(ManualEntry {
        name: "camera".into(),
        ip: Some(IpAddr::from_str("198.51.100.60").unwrap()),
        cidr: None,
        domain: None,
    });
    let err = eng.apply_config(bad).await.expect_err("TooMany");
    assert_eq!(err.code(), "clients.too_many");

    let st = eng.status();
    assert_eq!(st.generation, before_gen);
    assert_eq!(st.manual_count, before_manual);
    assert!(eng.lookup().by_ip(printer).is_some());
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.60").unwrap())
            .is_none()
    );

    // Restore a sane cache size and prove the next sync still uses the old config.
    eng.set_cached_observations_for_test(Vec::new());
    let ok = eng.sync_now().await.unwrap();
    assert!(ok.classic_error.is_none());
    assert_eq!(eng.status().manual_count, before_manual);
    assert!(eng.lookup().by_ip(printer).is_some());
}

fn unifi_client_count(eng: &ClientEngine) -> usize {
    eng.lookup()
        .clients()
        .iter()
        .filter(|c| c.source == ClientSource::Unifi)
        .count()
}

#[tokio::test]
async fn disable_unifi_clears_unifi_clients_keeps_manuals() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;
    assert_eq!(unifi_client_count(&eng), 1);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.50").unwrap())
            .is_some()
    );

    let mut cfg = cfg_for(&mock, Duration::from_secs(3600));
    cfg.unifi.enabled = false;
    eng.apply_config(cfg).await.unwrap();

    assert_eq!(unifi_client_count(&eng), 0);
    assert_eq!(eng.status().unifi_count, 0);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.50").unwrap())
            .is_some(),
        "manual printer must remain"
    );
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .is_none(),
        "UniFi phone must be gone"
    );
}

#[tokio::test]
async fn disabled_startup_does_not_serve_cached_unifi() {
    // GC3: cached observations/networks used to be merged even when UniFi was
    // disabled, so a manual-only engine still answered with stale UniFi rows.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let data = unique_data_dir();

    let eng1 = ClientEngine::new_with_secret(
        cfg_for(&mock, Duration::from_secs(3600)),
        data.clone(),
        Arc::clone(&clock) as Arc<_>,
        Some(Secret::new(API_KEY)),
    )
    .unwrap();
    eng1.sync_now().await.unwrap();
    let phone = IpAddr::from_str("198.51.100.10").unwrap();
    assert!(eng1.lookup().by_ip(phone).is_some());
    drop(eng1);

    let mut disabled = cfg_for(&mock, Duration::from_secs(3600));
    disabled.unifi.enabled = false;
    let eng2 =
        ClientEngine::new_with_secret(disabled, data.clone(), Arc::clone(&clock) as Arc<_>, None)
            .unwrap();

    // Check before any await: the background task has not run yet, so this is
    // the startup snapshot.
    assert!(
        eng2.lookup().by_ip(phone).is_none(),
        "cached UniFi must not be served"
    );
    assert_eq!(unifi_client_count(&eng2), 0);
    assert!(
        eng2.lookup()
            .by_ip(IpAddr::from_str("198.51.100.50").unwrap())
            .is_some(),
        "manual printer must remain"
    );

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn apply_config_enabling_unifi_reads_secret_at_apply_time() {
    // GC4: the key used to be read only at construction. An engine started
    // with UniFi disabled had no key, so enabling via apply_config always
    // failed. The apply path must load the secret afresh.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let data = unique_data_dir();

    let mut disabled = cfg_for(&mock, Duration::from_secs(3600));
    disabled.unifi.enabled = false;
    let eng = ClientEngine::new_with_secret(disabled, data.clone(), clock, None).unwrap();
    assert_eq!(unifi_client_count(&eng), 0);

    let enabled = cfg_for(&mock, Duration::from_secs(3600));
    eng.apply_config_with_secret(enabled, |_| Ok(Secret::new(API_KEY)))
        .await
        .unwrap();

    // The freshly loaded key was stored for sync.
    eng.sync_now().await.unwrap();
    assert_eq!(unifi_client_count(&eng), 1);

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn apply_config_reports_missing_secret_when_enabling_without_one() {
    let clock = Arc::new(ManualClock::new(start()));
    let data = unique_data_dir();
    let mut disabled = ClientsConfig::default();
    disabled.unifi.enabled = false;
    let eng = ClientEngine::new_with_secret(disabled, data.clone(), clock, None).unwrap();

    let mut enabled = ClientsConfig::default();
    enabled.unifi.enabled = true;
    enabled.unifi.base_url = "https://192.0.2.1".into();
    let err = eng
        .apply_config_with_secret(enabled, |name| {
            Err(dnscraft_clients::ClientsError::SecretMissing {
                name: name.to_owned(),
            })
        })
        .await
        .expect_err("no secret");
    assert_eq!(err.code(), "clients.secret.missing");

    let _ = fs::remove_dir_all(&data);
}

#[tokio::test]
async fn disable_unifi_during_slow_sync_discards_stale_fetch() {
    // Claude C12 probe: delay 400 ms, sync_now in flight, apply_config with
    // unifi.enabled = false → UniFi count must be 0 after apply and after the
    // in-flight sync finishes (not reinstalled by the stale fetch).
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;
    assert_eq!(unifi_client_count(&eng), 1);

    mock.set_response_delay(Some(Duration::from_millis(400)))
        .await;
    let sync_task = {
        let eng = Arc::clone(&eng);
        tokio::spawn(async move { eng.sync_now().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut cfg = cfg_for(&mock, Duration::from_secs(3600));
    cfg.unifi.enabled = false;
    eng.apply_config(cfg).await.unwrap();
    assert_eq!(unifi_client_count(&eng), 0, "after apply_config");

    let report = sync_task.await.unwrap().unwrap();
    assert!(report.superseded, "stale fetch must be discarded");
    assert!(!report.rebuilt);
    assert_eq!(unifi_client_count(&eng), 0, "after in-flight sync");
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.50").unwrap())
            .is_some()
    );
    mock.set_response_delay(None).await;
}

#[tokio::test]
async fn unifi_config_change_during_slow_fetch_discards_old_target() {
    // Mid-flight fetch must not install data from the old gateway after
    // base_url / site switch — even if the old fixture changed meanwhile.
    let mock_a = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    let mock_b = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock_a).await;
    seed(&mock_b).await;

    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock_a,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;

    // Make the in-flight fetch return a *new* UniFi IP that must never appear
    // after we switch away from mock_a.
    mock_a
        .set_integration(IntegrationFixture {
            sites: vec![integ_site()],
            networks: HashMap::from([(
                SITE_UUID.into(),
                vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
            )]),
            clients: HashMap::from([(
                SITE_UUID.into(),
                vec![json!({
                    "id": INTEG_ID,
                    "name": "Phone",
                    "ipAddress": "198.51.100.99",
                    "macAddress": MAC,
                    "connectedAt": "2026-10-25T12:00:00Z"
                })],
            )]),
            ..IntegrationFixture::default()
        })
        .await;

    mock_a
        .set_response_delay(Some(Duration::from_millis(400)))
        .await;
    let sync_task = {
        let eng = Arc::clone(&eng);
        tokio::spawn(async move { eng.sync_now().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cfg = cfg_for(&mock_b, Duration::from_secs(3600));
    eng.apply_config(cfg).await.unwrap();

    let report = sync_task.await.unwrap().unwrap();
    assert!(report.superseded);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.99").unwrap())
            .is_none(),
        "old-target fetch must not install"
    );
    mock_a.set_response_delay(None).await;
}

#[tokio::test]
async fn newer_fetch_wins_over_slower_older() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;

    mock.set_response_delay(Some(Duration::from_millis(500)))
        .await;
    let older = {
        let eng = Arc::clone(&eng);
        tokio::spawn(async move { eng.sync_now().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Newer fetch sees a different UniFi IP and is not delayed.
    mock.set_response_delay(None).await;
    mock.set_integration(IntegrationFixture {
        sites: vec![integ_site()],
        networks: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({ "id": "integ-net", "name": "IoT", "vlanId": 40 })],
        )]),
        clients: HashMap::from([(
            SITE_UUID.into(),
            vec![json!({
                "id": INTEG_ID,
                "name": "Phone",
                "ipAddress": "198.51.100.77",
                "macAddress": MAC,
                "connectedAt": "2026-10-25T12:00:00Z"
            })],
        )]),
        ..IntegrationFixture::default()
    })
    .await;
    // Classic still has .10 — merge by MAC keeps Integration id; classic IP may
    // enrich. Override classic too so the only IPv4 is .77.
    mock.set_classic(ClassicFixture {
        sites: vec![json!({ "name": SITE_KEY })],
        sta: HashMap::from([(
            SITE_KEY.into(),
            vec![json!({
                "_id": "classic-1",
                "mac": MAC,
                "hostname": "phone",
                "ip": "198.51.100.77",
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
                "domain_name": "iot.home.arpa",
                "ip_subnet": "198.51.100.1/24"
            })],
        )]),
        ..ClassicFixture::default()
    })
    .await;

    let newer = eng.sync_now().await.unwrap();
    assert!(!newer.superseded);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.77").unwrap())
            .is_some()
    );

    let older_report = older.await.unwrap().unwrap();
    assert!(
        older_report.superseded,
        "slower older fetch must not overwrite"
    );
    assert!(!older_report.rebuilt);
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.77").unwrap())
            .is_some(),
        "newer data must remain"
    );
    // Delayed older requests snapshot the pre-swap fixture (.10); discarding
    // them means .10 must not replace .77.
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.10").unwrap())
            .is_none(),
        "stale older fetch must not reinstall .10"
    );
}

#[tokio::test]
async fn apply_config_during_slow_sync_keeps_manual() {
    // Lock is held only around build+install; apply_config must succeed while
    // a delayed gateway fetch is in flight, and the new manual must survive.
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    mock.set_response_delay(Some(Duration::from_millis(400)))
        .await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(
        &mock,
        Arc::clone(&clock) as Arc<_>,
        Duration::from_secs(3600),
    )
    .await;
    await_initial_sync(&eng).await;
    mock.set_response_delay(Some(Duration::from_millis(400)))
        .await;

    let sync_task = {
        let eng = Arc::clone(&eng);
        tokio::spawn(async move { eng.sync_now().await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut cfg = cfg_for(&mock, Duration::from_secs(3600));
    cfg.manual.push(ManualEntry {
        name: "camera".into(),
        ip: Some(IpAddr::from_str("198.51.100.60").unwrap()),
        cidr: None,
        domain: None,
    });
    let apply_started = tokio::time::Instant::now();
    eng.apply_config(cfg).await.unwrap();
    assert!(
        apply_started.elapsed() < Duration::from_millis(300),
        "apply_config must not wait for the slow gateway fetch"
    );
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.60").unwrap())
            .is_some()
    );

    let report = sync_task.await.unwrap().unwrap();
    let _ = report;
    assert!(
        eng.lookup()
            .by_ip(IpAddr::from_str("198.51.100.60").unwrap())
            .is_some(),
        "manual must still be present after the in-flight sync installs"
    );
    mock.set_response_delay(None).await;
}

#[tokio::test]
async fn drop_stops_background_task() {
    let mock = MockGateway::start(API_KEY, CertKind::SelfSigned).await;
    seed(&mock).await;
    let clock = Arc::new(ManualClock::new(start()));
    let eng = engine(&mock, Arc::clone(&clock) as Arc<_>, Duration::from_secs(10)).await;
    let weak = Arc::downgrade(&eng);
    let attempts_ptr = eng.sync_attempts();
    drop(eng);
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(weak.upgrade().is_none());
    clock.advance(Duration::from_secs(30));
    tokio::time::sleep(Duration::from_millis(50)).await;
    // If the task were still alive it would panic on upgrade-none; we only
    // assert the Weak is gone and advancing time does not resurrect it.
    assert!(weak.upgrade().is_none());
    let _ = attempts_ptr;
}

#[tokio::test]
async fn non_owner_sync_returns_not_owner() {
    let clock = Arc::new(ManualClock::new(start()));
    let mut cfg = ClientsConfig::default();
    cfg.unifi_profiles = vec![UnifiProfile {
        id: "home".into(),
        sync_owner: "master".into(),
        connection: UnifiConfig {
            enabled: true,
            base_url: "https://192.0.2.1".into(),
            site_id: None,
            poll_interval: Duration::from_secs(60),
            classic_clients: false,
            tls: TlsMode::Insecure,
        },
    }];
    cfg.unifi_bindings.insert("master".into(), "home".into());
    cfg.unifi_bindings.insert("garage".into(), "home".into());
    let eng = ClientEngine::new_with_secret_and_node(
        cfg,
        unique_data_dir(),
        clock,
        Some(Secret::new(API_KEY)),
        "garage",
    )
    .unwrap();
    let err = eng.sync_now().await.unwrap_err();
    assert_eq!(err.code(), "clients.sync.not_owner");
    assert!(!eng.is_sync_owner());
}
