//! Assembler smoke test: `build()` boots every engine from one TOML file, the
//! control-api answers `/healthz`, `/readyz`, `/api/v1/clients` and `/mcp/v1`,
//! and a second boot on the same `data_dir` keeps the first seeded config
//! (GA28 / D4). Runs in-process on loopback only; the resolver uses an
//! unroutable root hint so priming never touches the internet.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use dnscraft::{App, Config};
use dnscraft_api::{ConfigStore, Db, Scope, TokenStore};
use serde_json::{Value, json};

/// The MCP protocol version the endpoint negotiates (see `dnscraft-api` tests).
const MCP_VERSION: &str = "2026-07-28";

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "dnscraft-smoke-{tag}-{}-{nanos}",
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

/// TOML for one boot: a manual client named `client_name`, plain-HTTP
/// control-api on `port`, MCP enabled, and an unroutable root hint.
fn config_toml(data_dir: &Path, port: u16, client_name: &str) -> String {
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
port = {port}
tls = false

[control_api.mcp]
enabled = true
"#,
        data = data_dir.display(),
    )
}

/// Minimal HTTP/1.1 client: one request, `Connection: close`, returns the
/// status code and the body. Responses here carry a `Content-Length`.
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
    assert!(
        !head
            .to_ascii_lowercase()
            .contains("transfer-encoding: chunked"),
        "unexpected chunked response: {head}"
    );
    (status, body.to_owned())
}

/// Waits until the control-api answers `/healthz` (serve binds after boot).
fn wait_for_api(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "control-api did not start");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn get(port: u16, path: &str, bearer: &str) -> (u16, Value) {
    let (status, body) = http(
        port,
        "GET",
        path,
        &[("Authorization", format!("Bearer {bearer}"))],
        "",
    );
    (status, serde_json::from_str(&body).unwrap_or(Value::Null))
}

/// One MCP `tools/call`; returns the parsed tool output.
fn tool(port: u16, bearer: &str, name: &str, arguments: Value) -> Value {
    let params = json!({
        "name": name,
        "arguments": arguments,
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
        },
    });
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params });
    let (status, text) = http(
        port,
        "POST",
        "/mcp/v1",
        &[
            ("Authorization", format!("Bearer {bearer}")),
            ("Content-Type", "application/json".to_owned()),
            ("Accept", "application/json, text/event-stream".to_owned()),
            ("MCP-Protocol-Version", MCP_VERSION.to_owned()),
            ("Mcp-Method", "tools/call".to_owned()),
            ("Mcp-Name", name.to_owned()),
        ],
        &body.to_string(),
    );
    assert_eq!(status, 200, "tool {name}: {text}");
    let response: Value = serde_json::from_str(&text).unwrap();
    assert!(
        response["result"]["isError"].as_bool() != Some(true),
        "tool {name} failed: {text}"
    );
    serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
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
        .create("smoke".to_owned(), "smoke".to_owned(), scope, None)
        .await
        .unwrap();
    created.plaintext().expose().to_owned()
}

async fn boot(toml: &str) -> App {
    let mut config: Config = toml::from_str(toml).expect("smoke config parses");
    // Unroutable root hint: priming fails fast and never reaches the internet.
    // A TLS engine with ACME and DynDNS off: it builds from `[tls]` without
    // any outbound request.
    config.tls.public_domain = "example.com".to_owned();
    config.tls.acme.enabled = false;
    config.tls.dyndns.enabled = false;
    config.resolver = dnscraft_resolver::ResolverConfig {
        root_hints: vec!["127.0.0.1:9".parse().unwrap()],
        query_timeout: Duration::from_millis(200),
        ..dnscraft_resolver::ResolverConfig::default()
    };
    dnscraft::build(config, Arc::new(dnscraft_filtering::SystemClock))
        .await
        .expect("assembler boots every engine")
}

#[tokio::test(flavor = "multi_thread")]
async fn boots_every_engine_and_serves_the_control_api() {
    let data_dir = temp_dir("boot");
    let port = free_port();
    let app = boot(&config_toml(&data_dir, port, "paperless")).await;
    wait_for_api(port);

    // GA29: every module reported ready from its live engine.
    let (status, body) = http(port, "GET", "/readyz", &[], "");
    assert_eq!(status, 200, "readyz: {body}");

    let (status, body) = http(port, "GET", "/healthz", &[], "");
    assert_eq!(status, 200, "healthz: {body}");

    // GA6c: the client directory serves the manual entry.
    let admin = token(&data_dir, Scope::Admin).await;
    let (status, body) = get(port, "/api/v1/clients", &admin);
    assert_eq!(status, 200, "clients: {body}");
    assert!(body.to_string().contains("paperless"), "clients: {body}");

    // GM3: `list_clients` reads the same directory.
    let mcp_read = token(&data_dir, Scope::McpRead).await;
    let listed = tool(
        port,
        &mcp_read,
        "list_clients",
        json!({ "limit": 50, "offset": 0 }),
    );
    assert_eq!(
        listed["clients"][0]["display_name"], "paperless",
        "{listed}"
    );
    assert_eq!(listed["has_more"], false, "{listed}");

    // GM4: `get_status` reports the running listener and the resolver state.
    let status_out = tool(port, &mcp_read, "get_status", json!({}));
    assert_eq!(status_out["listeners"][0]["id"], "lan", "{status_out}");
    assert_eq!(
        status_out["listeners"][0]["status"], "running",
        "{status_out}"
    );
    assert!(
        status_out["resolver"]["cache_size"].is_u64(),
        "{status_out}"
    );

    // `/mcp/v1` is mounted and lists the tools.
    let (status, body) = http(
        port,
        "POST",
        "/mcp/v1",
        &[
            ("Authorization", format!("Bearer {mcp_read}")),
            ("Content-Type", "application/json".to_owned()),
            ("Accept", "application/json, text/event-stream".to_owned()),
            ("MCP-Protocol-Version", MCP_VERSION.to_owned()),
            ("Mcp-Method", "tools/list".to_owned()),
        ],
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#,
    );
    assert_eq!(status, 200, "tools/list: {body}");
    assert!(body.contains("list_clients"), "tools/list: {body}");

    // Backups are mounted with the assembler's backup directory.
    let (status, body) = get(port, "/api/v1/backups", &admin);
    assert_eq!(status, 200, "backups: {body}");

    // Services endpoint must answer. Offline boots report `available: false`;
    // when the filter scheduler can reach the default catalog URL (CI with
    // network), the same call may already show a live catalog — both are OK.
    let (status, services) = get(port, "/api/v1/filtering/services", &admin);
    assert_eq!(status, 200, "services: {services}");
    let available = services["data"]["available"]
        .as_bool()
        .expect("services.available bool");
    if available {
        let items = services["data"]["items"]
            .as_array()
            .expect("services.items array when available");
        assert!(
            !items.is_empty(),
            "available catalog must list services: {services}"
        );
    }

    app.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// GA28 / D4: the first boot seeds the store once; a later boot with a
/// different TOML keeps the stored configuration.
#[tokio::test(flavor = "multi_thread")]
async fn second_boot_keeps_the_seeded_config() {
    let data_dir = temp_dir("seed");

    let port = free_port();
    let first = boot(&config_toml(&data_dir, port, "first-boot")).await;
    wait_for_api(port);
    first.shutdown(Duration::from_secs(1)).await;

    let db = Db::open(
        &data_dir.join("dnscraft.db"),
        Arc::new(dnscraft_api::SystemClock),
    )
    .await
    .unwrap();
    let store = ConfigStore::new(db);
    assert_eq!(store.current().await.unwrap(), Some(1), "seeded once");

    let port = free_port();
    let second = boot(&config_toml(&data_dir, port, "second-boot")).await;
    wait_for_api(port);
    assert_eq!(store.current().await.unwrap(), Some(1), "no re-seed");
    let stored = store.load(1).await.unwrap().expect("version 1 exists");
    let stored = stored.to_string();
    assert!(stored.contains("first-boot"), "stored: {stored}");
    assert!(!stored.contains("second-boot"), "stored: {stored}");
    second.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// D4: after a config write, a restart must apply SQLite to live engines, not
/// revert to the unchanged TOML bootstrap snapshot.
#[tokio::test(flavor = "multi_thread")]
async fn second_boot_applies_stored_config_to_live_engines() {
    let data_dir = temp_dir("reboot-apply");

    let port = free_port();
    let first = boot(&config_toml(&data_dir, port, "first-seed")).await;
    wait_for_api(port);
    let admin = token(&data_dir, Scope::Admin).await;

    let (status, body) = get(port, "/api/v1/config", &admin);
    assert_eq!(status, 200, "get config: {body}");
    let mut snapshot = body["data"]["config"].clone();
    snapshot["clients"]["manual"]
        .as_array_mut()
        .expect("manual list")
        .push(json!({ "name": "from-api", "ip": "192.0.2.9", "cidr": null, "domain": null }));

    let (status, body) = http(
        port,
        "PUT",
        "/api/v1/config",
        &[
            ("Authorization", format!("Bearer {admin}")),
            ("Content-Type", "application/json".to_owned()),
        ],
        &snapshot.to_string(),
    );
    assert_eq!(status, 200, "put config: {body}");

    first.shutdown(Duration::from_secs(1)).await;

    let port = free_port();
    let second = boot(&config_toml(&data_dir, port, "second-toml-only")).await;
    wait_for_api(port);
    let admin = token(&data_dir, Scope::Admin).await;
    let (status, body) = get(port, "/api/v1/clients", &admin);
    assert_eq!(status, 200, "clients: {body}");
    let clients = body.to_string();
    assert!(
        clients.contains("from-api"),
        "SQLite change must survive reboot: {clients}"
    );
    assert!(
        clients.contains("first-seed"),
        "stored manual client must survive reboot: {clients}"
    );
    assert!(
        !clients.contains("second-toml-only"),
        "TOML manual must not override stored config: {clients}"
    );

    second.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Phase 2 e2e: `PUT /api/v1/config` stores a new version in SQLite and
/// applies it to the live client engine (ApplyClients), visible on the next
/// `GET /api/v1/clients`.
#[tokio::test(flavor = "multi_thread")]
async fn put_config_round_trips_and_applies_live() {
    let data_dir = temp_dir("put");
    let port = free_port();
    let app = boot(&config_toml(&data_dir, port, "paperless")).await;
    wait_for_api(port);
    let admin = token(&data_dir, Scope::Admin).await;

    let (status, body) = get(port, "/api/v1/config", &admin);
    assert_eq!(status, 200, "get config: {body}");
    let mut snapshot = body["data"]["config"].clone();
    snapshot["clients"]["manual"]
        .as_array_mut()
        .expect("manual list")
        .push(json!({ "name": "added", "ip": "192.0.2.9", "cidr": null, "domain": null }));

    let (status, body) = http(
        port,
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
    assert_eq!(put["data"]["version"], 2, "{put}");

    let (status, body) = get(port, "/api/v1/clients", &admin);
    assert_eq!(status, 200, "clients: {body}");
    assert!(body.to_string().contains("added"), "applied live: {body}");

    app.shutdown(Duration::from_secs(1)).await;
    let db = Db::open(
        &data_dir.join("dnscraft.db"),
        Arc::new(dnscraft_api::SystemClock),
    )
    .await
    .unwrap();
    assert_eq!(ConfigStore::new(db).current().await.unwrap(), Some(2));
    let _ = std::fs::remove_dir_all(&data_dir);
}

/// Policy TOML for the node-validity smoke tests: one local record with a
/// `lan` override, a `lan` view valid only on `node-a` (loopback subnet), and
/// the default view. `dns_port` is the UDP listener port.
fn node_policy_toml(data_dir: &Path, port: u16, dns_port: u16, node: &str) -> String {
    let base = config_toml(data_dir, port, "paperless").replace(
        "address = \"127.0.0.1:0\"",
        &format!("address = \"127.0.0.1:{dns_port}\""),
    );
    format!(
        r#"node_id = "{node}"
{base}
[filtering]
lists = []
update_interval = "1d"
max_list_size_mb = 16

[[filtering.sets]]
id = "default"
name = "Default"
lists = []
custom_rules = ""
services = []
block_mode = "Refused"
mcp_rules = []

[policy]
default_rebind = true
ptr_prefixes = []
local_nxdomain_suffixes = ["local", "lan", "internal"]
rebind_check_forward_zones = []

[[policy.profiles]]
id = "default"
filter_set = "default"
suppress_aaaa = false
firefox_canary = false
icloud_private_relay = false
rebind_exceptions = []
forward_zones = []
schedules = []
safesearch = {{ enabled = false, providers = [], youtube_mode = "Strict" }}

[[policy.views]]
id = "lan"
is_default = false
subnets = ["127.0.0.0/8"]
nodes = ["node-a"]
profile = "default"

[[policy.views]]
id = "default"
is_default = true
subnets = []
profile = "default"

[[policy.records]]
name = "nas.lan.example.com"
type = "A"
rdata = "192.0.2.10"
overrides = {{ lan = "192.0.2.50" }}
"#
    )
}

/// Sends one A query for `name` to the local UDP listener and returns the
/// IPv4 addresses found in the answer section.
fn udp_a_answers(dns_port: u16, name: &str) -> Vec<[u8; 4]> {
    let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        query.push(u8::try_from(label.len()).unwrap());
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&query, ("127.0.0.1", dns_port)).unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).expect("DNS answer");
    let reply = &buf[..len];
    // Answer RRs are 12-byte fixed parts after the question; scan for
    // A rdata of length 4 following the 0x0004 rdlength field.
    reply
        .windows(6)
        .filter(|w| w[0] == 0 && w[1] == 4)
        .map(|w| [w[2], w[3], w[4], w[5]])
        .filter(|addr| addr[0] == 192 && addr[1] == 0 && addr[2] == 2)
        .collect()
}

/// `node_id` reaches the listeners and the view `nodes` gate selection: the
/// `lan` view answers only on `node-a`; on `node-b` the default view answers.
#[tokio::test(flavor = "multi_thread")]
async fn node_id_and_source_ip_view_select_the_local_answer() {
    for (node, expected) in [("node-a", [192, 0, 2, 50]), ("node-b", [192, 0, 2, 10])] {
        let data_dir = temp_dir(&format!("node-{node}"));
        let port = free_port();
        let dns_port = free_port();
        let app = boot(&node_policy_toml(&data_dir, port, dns_port, node)).await;
        wait_for_api(port);

        let answers = udp_a_answers(dns_port, "nas.lan.example.com");
        assert_eq!(answers, vec![expected], "node {node}");

        app.shutdown(Duration::from_secs(1)).await;
        let _ = std::fs::remove_dir_all(&data_dir);
    }
}

/// A record the policy build rejects (an override for an unknown view) is not
/// stored: the config version and the record list stay as they were.
#[tokio::test(flavor = "multi_thread")]
async fn rejected_policy_record_keeps_the_stored_version() {
    let data_dir = temp_dir("reject");
    let port = free_port();
    let app = boot(&config_toml(&data_dir, port, "paperless")).await;
    wait_for_api(port);
    let admin = token(&data_dir, Scope::Admin).await;

    let (status, body) = get(port, "/api/v1/config", &admin);
    assert_eq!(status, 200, "get config: {body}");
    let before = body["data"]["version"].clone();

    let rejected = json!({
        "name": "nas.lan.example.com",
        "type": "A",
        "rdata": "192.0.2.10",
        "overrides": { "nowhere": "192.0.2.50" },
    });
    let (status, body) = http(
        port,
        "PUT",
        "/api/v1/policy/records",
        &[
            ("Authorization", format!("Bearer {admin}")),
            ("Content-Type", "application/json".to_owned()),
        ],
        &rejected.to_string(),
    );
    assert_eq!(status, 400, "record rejected by the policy build: {body}");
    assert!(body.contains("policy.config.invalid"), "{body}");

    let (status, body) = get(port, "/api/v1/config", &admin);
    assert_eq!(status, 200, "get config: {body}");
    assert_eq!(body["data"]["version"], before, "version unchanged: {body}");

    let (status, body) = get(port, "/api/v1/policy/records", &admin);
    assert_eq!(status, 200, "records: {body}");
    assert_eq!(body["data"]["records"], json!([]), "nothing stored: {body}");

    app.shutdown(Duration::from_secs(1)).await;
    let _ = std::fs::remove_dir_all(&data_dir);
}
