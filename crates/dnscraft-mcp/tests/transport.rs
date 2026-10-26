//! End-to-end smoke tests for the stateless transport.
//!
//! The client speaks plain JSON (no handshake, no session header) and the
//! server is a real axum listener, not a direct service call.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::{Arc, Once};

use axum::Router;
use dnscraft_mcp::{
    FilteringStatus, ListenerStatus, McpConfig, NodeStatus, ResolverStatus, TlsStatus,
};
use serde_json::{Value, json};

const VERSION: &str = "2026-07-28";
const STATUS_DESCRIPTION: &str = "Get node status: resolver health, listener bindings, TLS certificate status, filter list update times, uptime.";

fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct TestServer {
    url: String,
    backend: Arc<support::MockBackend>,
}

fn hostile_status() -> NodeStatus {
    NodeStatus {
        node_id: "node\n1\r<script>".into(),
        version: "0.1.0\t".into(),
        uptime_seconds: 86400,
        resolver: ResolverStatus {
            primed: true,
            cache_size: 12345,
        },
        listeners: vec![ListenerStatus {
            id: "lan\nudp".into(),
            protocol: "udp53".into(),
            bind: "192.0.2.1:53".into(),
            status: "running".into(),
        }],
        tls: TlsStatus {
            mode: "self_signed".into(),
            cert_expiry: "2027-01-15T00:00:00Z".into(),
            fingerprint: "SHA256:abcd".into(),
        },
        filtering: FilteringStatus {
            lists_loaded: 19,
            rules_active: 2_250_000,
            last_update: "2026-10-26T08:00:00Z".into(),
        },
    }
}

async fn spawn(status: NodeStatus) -> TestServer {
    install_crypto();
    let backend = Arc::new(support::MockBackend::new(status, support::write_token()));
    let router = Router::new().nest_service(
        "/mcp/v1",
        dnscraft_mcp::service(backend.clone(), McpConfig::default()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    TestServer {
        url: format!("http://{address}/mcp/v1"),
        backend,
    }
}

fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn with_meta(params: Value) -> Value {
    match params {
        Value::Object(mut map) => {
            map.insert("_meta".into(), meta());
            Value::Object(map)
        }
        _ => json!({ "_meta": meta() }),
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> reqwest::Response {
    let body = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": with_meta(params),
    });
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", method)
        .body(body.to_string());
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }
    request.send().await.expect("request should be sent")
}

async fn post_json(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> (reqwest::StatusCode, Value) {
    let response = post(client, url, id, method, name, params).await;
    let status = response.status();
    let text = response.text().await.expect("response should have a body");
    let body: Value = serde_json::from_str(&text).expect("response should be JSON");
    (status, body)
}

#[tokio::test]
async fn smoke_discover_advertises_tools_only_without_handshake() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    let (status, body) =
        post_json(&client, &server.url, 1, "server/discover", None, json!({})).await;

    assert_eq!(status, 200, "discover: {body}");
    // rmcp shape (ADR 0006 contradiction 1): version list plus `_meta.serverInfo`.
    assert_eq!(body["result"]["resultType"], "complete");
    assert_eq!(body["result"]["supportedVersions"], json!([VERSION]));
    assert_eq!(body["result"]["capabilities"], json!({ "tools": {} }));
    assert_eq!(
        body["result"]["_meta"]["io.modelcontextprotocol/serverInfo"],
        json!({ "name": "dnscraft-mcp", "version": env!("CARGO_PKG_VERSION") })
    );
    assert!(body["result"]["instructions"].is_null());
    assert_eq!(
        server
            .backend
            .status_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn smoke_list_tools_exposes_static_read_only_status_tool() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(&client, &server.url, 2, "tools/list", None, json!({})).await;

    assert_eq!(status, 200, "tools/list: {body}");
    let tools = body["result"]["tools"].as_array().expect("tools array");
    assert_eq!(tools.len(), 1);
    let tool = &tools[0];
    assert_eq!(tool["name"], "get_status");
    assert_eq!(tool["description"], STATUS_DESCRIPTION);
    assert_eq!(tool["annotations"]["readOnlyHint"], true);
    assert_eq!(tool["annotations"]["idempotentHint"], true);
    assert_eq!(tool["inputSchema"]["type"], "object");
}

#[tokio::test]
async fn smoke_call_status_twice_sanitizes_backend_strings() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    let call = json!({ "name": "get_status", "arguments": {} });
    let (first_status, first) = post_json(
        &client,
        &server.url,
        3,
        "tools/call",
        Some("get_status"),
        call.clone(),
    )
    .await;
    let (second_status, second) = post_json(
        &client,
        &server.url,
        4,
        "tools/call",
        Some("get_status"),
        call,
    )
    .await;

    assert_eq!(first_status, 200, "tools/call: {first}");
    assert_eq!(second_status, 200, "tools/call: {second}");
    assert_eq!(
        first["result"], second["result"],
        "no session state may change the response"
    );
    assert_eq!(first["result"]["isError"], false);

    let text = first["result"]["content"][0]["text"]
        .as_str()
        .expect("one text item");
    assert!(!text.contains('\n'), "newlines must be neutralized: {text}");
    assert!(
        !text.contains('\r'),
        "carriage returns must be neutralized: {text}"
    );
    assert!(!text.contains('\t'), "tabs must be neutralized: {text}");

    let output: Value = serde_json::from_str(text).expect("tool text is JSON");
    assert_eq!(output["node_id"], "node\u{FFFD}1\u{FFFD}<script>");
    assert_eq!(output["version"], "0.1.0\u{FFFD}");
    assert_eq!(output["listeners"][0]["id"], "lan\u{FFFD}udp");
    assert_eq!(output["listeners"][0]["bind"], "192.0.2.1:53");
    assert_eq!(output["tls"]["mode"], "self_signed");
    assert_eq!(output["tls"]["fingerprint"], "SHA256:abcd");
    assert_eq!(output["filtering"]["lists_loaded"], 19);
    assert_eq!(output["uptime_seconds"], 86400);
    assert_eq!(
        server
            .backend
            .status_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        2
    );
}
