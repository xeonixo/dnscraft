//! End-to-end smoke tests for the stateless transport.
//!
//! The client speaks plain JSON (no handshake, no session header) and the
//! server is a real axum listener, not a direct service call.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use axum::Router;
use axum::body::{Body, to_bytes};
use dnscraft_mcp::{
    FilteringStatus, ListenerStatus, McpConfig, NodeStatus, ResolverStatus, TlsStatus,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VERSION: &str = "2026-07-28";
const TOKEN: &str = "test-token";
const STATUS_DESCRIPTION: &str = "Get node status: resolver health, listener bindings, TLS certificate status, filter list update times, uptime.";

fn install_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

struct TestServer {
    url: String,
    address: SocketAddr,
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
    spawn_with(status, McpConfig::default()).await
}

async fn spawn_with(status: NodeStatus, config: McpConfig) -> TestServer {
    install_crypto();
    let backend = Arc::new(support::MockBackend::new(status, support::write_token()));
    let router =
        Router::new().nest_service("/mcp/v1", dnscraft_mcp::service(backend.clone(), config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    TestServer {
        url: format!("http://{address}/mcp/v1"),
        address,
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

fn request_body(id: u64, method: &str, params: Value) -> String {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": with_meta(params),
    })
    .to_string()
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    id: u64,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> reqwest::Response {
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", method)
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(request_body(id, method, params));
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
    // Write gate defaults to false: only the 8 read tools are listed.
    assert_eq!(tools.len(), 8);
    let tool = tools
        .iter()
        .find(|tool| tool["name"] == "get_status")
        .expect("get_status is listed");
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

#[tokio::test]
async fn get_and_delete_are_method_not_allowed_envelopes() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    for response in [
        client.get(&server.url).send().await.unwrap(),
        client.delete(&server.url).send().await.unwrap(),
    ] {
        assert_eq!(response.status(), 405);
        assert!(response.headers().get("Mcp-Session-Id").is_none());
        let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
        assert_eq!(body["error"]["code"], "control_api.method_not_allowed");
    }
}

#[tokio::test]
async fn declared_body_over_cap_is_payload_too_large() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();
    let limit = McpConfig::default().max_request_body_size;

    let response = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "get_status")
        .body("x".repeat(limit + 1))
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
    let body: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "control_api.payload_too_large");
    assert_eq!(body["error"]["params"]["limit_bytes"], limit);
}

#[tokio::test]
async fn streamed_body_over_cap_without_content_length_is_payload_too_large() {
    let server = spawn(hostile_status()).await;
    let mut stream = tokio::net::TcpStream::connect(server.address)
        .await
        .unwrap();
    let head = format!(
        "POST /mcp/v1 HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\n\
         MCP-Protocol-Version: {VERSION}\r\nMcp-Method: tools/call\r\n\
         Mcp-Name: get_status\r\nAuthorization: Bearer {TOKEN}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
         200000\r\n",
        server.address,
    );
    stream.write_all(head.as_bytes()).await.unwrap();
    // One oversized chunk, never terminated: rmcp enforces the cap while streaming.
    let _ = stream.write_all(&vec![b'x'; 1_100_000]).await;
    let mut raw = Vec::new();
    // The server may reset the connection once it has rejected the chunk; the
    // bytes read so far still carry the response.
    let _ = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut raw))
        .await
        .expect("server should answer before the client finishes");
    let response = String::from_utf8_lossy(&raw);
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(
        response.contains("control_api.payload_too_large"),
        "{response}"
    );
}

#[tokio::test]
async fn origin_present_and_not_allowed_is_forbidden() {
    let config = McpConfig {
        allowed_origins: vec!["https://ui.example".into()],
        ..McpConfig::default()
    };
    let server = spawn_with(hostile_status(), config).await;
    let client = reqwest::Client::new();
    let body = request_body(10, "tools/list", json!({}));

    let invalid = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/list")
        .header("Origin", "https://evil.example")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 403);
    let json: Value = serde_json::from_str(&invalid.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], "control_api.auth.invalid_origin");

    for origin in [None, Some("https://ui.example")] {
        let mut request = client
            .post(&server.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", VERSION)
            .header("Mcp-Method", "tools/list")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .body(body.clone());
        if let Some(origin) = origin {
            request = request.header("Origin", origin);
        }
        assert_eq!(request.send().await.unwrap().status(), 200);
    }
}

#[tokio::test]
async fn missing_or_unsupported_protocol_version_lists_supported_versions() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();
    let body = request_body(11, "tools/list", json!({}));

    let missing = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Method", "tools/list")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 400);
    let json: Value = serde_json::from_str(&missing.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32022);
    assert_eq!(json["error"]["data"]["supportedVersions"], json!([VERSION]));
    assert_eq!(json["error"]["data"]["supported"], json!([VERSION]));

    let unsupported = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2099-01-01")
        .header("Mcp-Method", "tools/list")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(unsupported.status(), 400);
    let json: Value = serde_json::from_str(&unsupported.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32022);
    assert_eq!(json["error"]["data"]["requested"], "2099-01-01");
    assert_eq!(json["error"]["data"]["supportedVersions"], json!([VERSION]));
}

#[tokio::test]
async fn legacy_session_mode_still_requires_the_version_header_and_binds_headers() {
    let config = McpConfig {
        legacy_session_mode: true,
        ..McpConfig::default()
    };
    let server = spawn_with(hostile_status(), config).await;
    let client = reqwest::Client::new();

    // The accepted version list is widened, but the header is not optional.
    let missing = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("Mcp-Method", "tools/list")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(request_body(12, "tools/list", json!({})))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 400);
    let json: Value = serde_json::from_str(&missing.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32022);
    assert_eq!(json["error"]["data"]["requested"], Value::Null);

    // With the header present, rmcp's SEP-2243 binding still runs in legacy mode.
    let mismatch = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "get_status")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(request_body(
            13,
            "tools/call",
            json!({ "name": "remove_rule", "arguments": {} }),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status(), 400);
    let json: Value = serde_json::from_str(&mismatch.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32020);
}

#[tokio::test]
async fn header_body_mismatches_are_32020_and_run_nothing() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    let method_mismatch = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/list")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(request_body(
            12,
            "tools/call",
            json!({ "name": "get_status", "arguments": {} }),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(method_mismatch.status(), 400);
    let json: Value = serde_json::from_str(&method_mismatch.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32020);

    let name_mismatch = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "get_status")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(request_body(
            13,
            "tools/call",
            json!({ "name": "remove_rule", "arguments": {} }),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(name_mismatch.status(), 400);
    let json: Value = serde_json::from_str(&name_mismatch.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32020);

    assert_eq!(
        server
            .backend
            .status_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
}

#[tokio::test]
async fn unknown_method_is_404_minus_32601_and_notification_is_202_empty() {
    let server = spawn(hostile_status()).await;
    let client = reqwest::Client::new();

    let (status, body) = post_json(&client, &server.url, 14, "no/such", None, json!({})).await;
    assert_eq!(status, 404);
    assert_eq!(body["error"]["code"], -32601);

    let notification = client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "notifications/initialized")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": { "_meta": meta() },
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(notification.status(), 202);
    assert!(notification.text().await.unwrap().is_empty());
}

#[tokio::test(start_paused = true)]
async fn request_timeout_cancels_slow_backend_and_releases_the_call() {
    install_crypto();
    let backend = Arc::new(support::MockBackend::new(
        hostile_status(),
        support::write_token(),
    ));
    backend.delay_status_until(Arc::new(tokio::sync::Notify::new()));
    let config = McpConfig {
        request_timeout: Duration::from_secs(10),
        ..McpConfig::default()
    };
    let mut service = dnscraft_mcp::service(backend.clone(), config);
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/mcp/v1")
        .header("Host", "127.0.0.1")
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", "get_status")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(Body::from(request_body(
            15,
            "tools/call",
            json!({ "name": "get_status", "arguments": {} }),
        )))
        .unwrap();

    let response = tower::Service::call(&mut service, request).await.unwrap();
    assert_eq!(response.status(), 504);
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["code"], "control_api.internal");
    assert_eq!(body["error"]["params"]["reason"], "timeout");
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.active_status_calls() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout should cancel the slow backend call");
}

#[tokio::test]
async fn dropped_connection_cancels_in_flight_request() {
    let server = spawn(hostile_status()).await;
    server
        .backend
        .delay_status_until(Arc::new(tokio::sync::Notify::new()));
    let client = reqwest::Client::new();
    let url = server.url.clone();
    let task = tokio::spawn(async move {
        client
            .post(url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", VERSION)
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "get_status")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .body(request_body(
                16,
                "tools/call",
                json!({ "name": "get_status", "arguments": {} }),
            ))
            .send()
            .await
    });

    tokio::time::timeout(Duration::from_secs(5), async {
        while server
            .backend
            .status_calls
            .load(std::sync::atomic::Ordering::SeqCst)
            == 0
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backend call should start");

    task.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.backend.active_status_calls() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("dropped connection should cancel the in-flight call");
}
