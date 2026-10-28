//! Assembler cluster smoke test: a master and a sub-node built from `[cluster]`
//! TOML run in-process on loopback. The sub-node enrolls with a one-time join
//! token minted through the master's admin API, receives the master's config
//! snapshot and client directory, and sees a later master write. Only loopback
//! is used; the resolver uses an unroutable root hint so nothing leaves the host.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dnscraft::{Config, Enrollment, build_with_enrollment};
use dnscraft_api::{Db, Scope, Secret, TokenStore};
use serde_json::{Value, json};

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-cluster-{tag}-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A loopback port that was free a moment ago.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// One node's TOML: a manual client named `client_name`, a plain-HTTP
/// control-api on `api_port`, and the given `[cluster]` section.
fn node_toml(data_dir: &Path, api_port: u16, client_name: &str, cluster: &str) -> String {
    format!(
        r#"
public_domain = "example.com"
data_dir = "{data}"

[[listeners]]
id = "lan"
protocol = "udp53"
address = "127.0.0.1:0"
exposure = "local"

[clients]
local_domain = "home.arpa"
local_domain_mode = "unifi_then_config"
offline_retain = "7d"
ipv6_address_ttl = "1d"
allow_http_for_tests = false

[clients.unifi]
enabled = false
base_url = ""
poll_interval = "1m"
classic_clients = true
insecure_skip_verify = false

[[clients.manual]]
name = "{client_name}"
cidr = "192.0.2.5/32"

[control_api]
bind = "127.0.0.1"
port = {api_port}
tls = false

{cluster}
"#,
        data = data_dir.display(),
    )
}

fn master_section(cluster_port: u16) -> String {
    format!(
        r#"[cluster]
role = "master"
node_id = "master-a"

[cluster.listen]
bind = "127.0.0.1"
port = {cluster_port}
"#
    )
}

fn sub_section(cluster_port: u16) -> String {
    format!(
        r#"[cluster]
role = "sub_node"
node_id = "sub-a"
master_url = "https://127.0.0.1:{cluster_port}"
"#
    )
}

/// Minimal HTTP/1.1 client: one request, `Connection: close`, returns the
/// status code and the body.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, String)],
    body: &str,
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect control-api");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str(&format!("Content-Length: {}\r\n\r\n{body}", body.len()));
    stream.write_all(request.as_bytes()).unwrap();
    let mut raw = String::new();
    stream.read_to_string(&mut raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").expect("HTTP response head");
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status code");
    (status, body.to_owned())
}

/// Waits until the control-api accepts connections (serve binds after boot).
fn wait_for_api(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "control-api did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn get(port: u16, path: &str, bearer: &str) -> (u16, String) {
    http(
        port,
        "GET",
        path,
        &[("Authorization", format!("Bearer {bearer}"))],
        "",
    )
}

/// Polls `check` until it holds or the deadline passes; the cluster stream is
/// asynchronous, so sync and replication are observed by polling.
fn wait_until(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A token of `scope` created straight in the data directory's database.
async fn token(data_dir: &Path, scope: Scope) -> String {
    let db = Db::open(
        &data_dir.join("dnscraft.db"),
        Arc::new(dnscraft_api::SystemClock),
    )
    .await
    .unwrap();
    let created = TokenStore::new(db, Duration::from_secs(3600))
        .create("cluster".to_owned(), "cluster".to_owned(), scope, None)
        .await
        .unwrap();
    created.plaintext().expose().to_owned()
}

fn parse(toml: &str) -> Config {
    let mut config: Config = toml::from_str(toml).expect("cluster config parses");
    // Unroutable root hint and ACME/DynDNS off: nothing reaches the internet.
    config.tls.public_domain = "example.com".to_owned();
    config.tls.acme.enabled = false;
    config.tls.dyndns.enabled = false;
    config.resolver = dnscraft_resolver::ResolverConfig {
        root_hints: vec!["127.0.0.1:9".parse().unwrap()],
        query_timeout: Duration::from_millis(200),
        ..dnscraft_resolver::ResolverConfig::default()
    };
    config
}

#[tokio::test(flavor = "multi_thread")]
async fn sub_node_enrolls_and_receives_master_config() {
    let master_dir = temp_dir("master");
    let sub_dir = temp_dir("sub");
    let master_api = free_port();
    let sub_api = free_port();
    let cluster_port = free_port();
    let clock = || Arc::new(dnscraft_filtering::SystemClock);

    let master = build_with_enrollment(
        parse(&node_toml(
            &master_dir,
            master_api,
            "paperless",
            &master_section(cluster_port),
        )),
        clock(),
        Enrollment::default(),
    )
    .await
    .expect("master boots with [cluster] role = master");
    wait_for_api(master_api);
    let admin = token(&master_dir, Scope::Admin).await;

    let (status, body) = get(master_api, "/api/v1/status", &admin);
    assert_eq!(status, 200, "status: {body}");
    let status: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(status["data"]["cluster"]["role"], "master", "{status}");

    // One-time join token for `sub-a`, minted through the admin API.
    let (status, body) = http(
        master_api,
        "POST",
        "/api/v1/cluster/join-tokens",
        &[
            ("Authorization", format!("Bearer {admin}")),
            ("Content-Type", "application/json".to_owned()),
        ],
        r#"{"node_id":"sub-a"}"#,
    );
    assert_eq!(status, 200, "mint token: {body}");
    let minted: Value = serde_json::from_str(&body).unwrap();
    let join_token = minted["data"]["token"].as_str().unwrap().to_owned();
    let master_cert = master.cluster().unwrap().server_cert_pem().unwrap();

    // The sub-node enrolls over loopback with the token and pinned master cert.
    let sub = build_with_enrollment(
        parse(&node_toml(
            &sub_dir,
            sub_api,
            "sub-local",
            &sub_section(cluster_port),
        )),
        clock(),
        Enrollment {
            join_token: Some(Secret::new(join_token)),
            master_cert_pem: Some(master_cert.to_owned()),
        },
    )
    .await
    .expect("sub-node enrolls and boots");
    wait_for_api(sub_api);

    let (status, body) = get(master_api, "/api/v1/cluster/nodes", &admin);
    assert_eq!(status, 200, "nodes: {body}");
    assert!(body.contains("sub-a"), "enrolled node listed: {body}");

    // The master's snapshot replaces the sub-node's TOML bootstrap config.
    wait_until("the master snapshot on the sub-node", || {
        let (status, body) = get(sub_api, "/api/v1/clients", &admin);
        status == 200 && body.contains("paperless")
    });
    let (_, body) = get(sub_api, "/api/v1/status", &admin);
    let sub_status: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(sub_status["data"]["cluster"]["role"], "sub_node", "{body}");
    assert_eq!(
        sub_status["data"]["cluster"]["applied_version"], 1,
        "{body}"
    );
    // The master-only admin routes are not mounted on a sub-node.
    let (status, _) = get(sub_api, "/api/v1/cluster/nodes", &admin);
    assert_eq!(status, 404, "sub-node exposes no cluster admin routes");

    // A config write on the master is pushed to the connected sub-node.
    let (status, body) = get(master_api, "/api/v1/config", &admin);
    assert_eq!(status, 200, "get config: {body}");
    let mut current: Value = serde_json::from_str(&body).unwrap();
    let mut snapshot = current["data"]["config"].take();
    snapshot["clients"]["manual"]
        .as_array_mut()
        .expect("manual list")
        .push(
            json!({ "name": "added-by-master", "ip": "192.0.2.9", "cidr": null, "domain": null }),
        );
    let (status, body) = http(
        master_api,
        "PUT",
        "/api/v1/config",
        &[
            ("Authorization", format!("Bearer {admin}")),
            ("Content-Type", "application/json".to_owned()),
        ],
        &snapshot.to_string(),
    );
    assert_eq!(status, 200, "put config: {body}");
    let put: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        put["data"]["version"], 2,
        "master should store version 2: {body}"
    );

    wait_until("the master write on the sub-node", || {
        let (status, body) = get(sub_api, "/api/v1/clients", &admin);
        status == 200 && body.contains("added-by-master")
    });
    let (_, body) = get(sub_api, "/api/v1/status", &admin);
    let sub_status: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        sub_status["data"]["cluster"]["applied_version"], 2,
        "{body}"
    );

    sub.shutdown(Duration::from_secs(1)).await;
    master.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_dir_all(&master_dir);
    let _ = std::fs::remove_dir_all(&sub_dir);
}
