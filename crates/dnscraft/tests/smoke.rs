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
