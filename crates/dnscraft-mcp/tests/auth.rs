//! Authentication, scope isolation, write-gate and in-flight-cap tests.
//!
//! These speak real HTTP to an axum listener; only the timeout test calls the
//! tower service directly so tokio can pause and advance time.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use dnscraft_mcp::{BackendError, McpConfig, NodeStatus, TokenInfo};
use serde_json::{Value, json};

const VERSION: &str = "2026-07-28";
const TOKEN: &str = "raw-secret-token-never-log";
const TOKEN_B: &str = "second-secret-token-never-log";

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

async fn spawn(config: McpConfig, token: Result<TokenInfo, BackendError>) -> TestServer {
    install_crypto();
    let backend = Arc::new(support::MockBackend::default());
    backend.set_status(Ok(NodeStatus::default()));
    backend.set_token(token);
    let router =
        Router::new().nest_service("/mcp/v1", dnscraft_mcp::service(backend.clone(), config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
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

fn request_body(id: u64, method: &str, params: Value) -> String {
    let params = match params {
        Value::Object(mut map) => {
            map.insert("_meta".into(), meta());
            Value::Object(map)
        }
        _ => json!({ "_meta": meta() }),
    };
    json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string()
}

async fn call(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    id: u64,
    method: &str,
    name: Option<&str>,
    params: Value,
) -> (reqwest::StatusCode, Value) {
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", method)
        .body(request_body(id, method, params));
    if let Some(name) = name {
        request = request.header("Mcp-Name", name);
    }
    if let Some(token) = token {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    let response = request.send().await.expect("request should be sent");
    let status = response.status();
    let text = response.text().await.expect("response should have a body");
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

async fn tool_call(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    id: u64,
    name: &str,
) -> (reqwest::StatusCode, Value) {
    call(
        client,
        url,
        Some(token),
        id,
        "tools/call",
        Some(name),
        json!({ "name": name, "arguments": {} }),
    )
    .await
}

async fn list_tools(
    client: &reqwest::Client,
    url: &str,
    token: &str,
) -> (reqwest::StatusCode, Value) {
    call(client, url, Some(token), 1, "tools/list", None, json!({})).await
}

#[tokio::test]
async fn missing_and_invalid_tokens_are_401_without_reaching_json_rpc() {
    let server = spawn(McpConfig::default(), Ok(support::write_token())).await;
    let client = reqwest::Client::new();

    let (status, body) = call(&client, &server.url, None, 1, "tools/list", None, json!({})).await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");
    assert_eq!(body["error"]["params"], json!({}));
    assert!(body.get("jsonrpc").is_none());
    assert!(body.get("result").is_none());
    assert_eq!(
        server.backend.token_calls.load(Ordering::SeqCst),
        0,
        "a missing token is rejected before the backend"
    );

    server.backend.set_token(Err(BackendError::Unauthenticated));
    let (status, body) = call(
        &client,
        &server.url,
        Some(TOKEN),
        2,
        "tools/list",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, 401);
    assert_eq!(body["error"]["code"], "control_api.auth.unauthenticated");
    assert!(body.get("jsonrpc").is_none());
    assert_eq!(server.backend.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn wrong_scope_family_is_403_and_does_not_reach_json_rpc() {
    let server = spawn(McpConfig::default(), Err(BackendError::InvalidScope)).await;
    let client = reqwest::Client::new();

    let (status, body) = call(
        &client,
        &server.url,
        Some(TOKEN),
        1,
        "tools/list",
        None,
        json!({}),
    )
    .await;

    assert_eq!(status, 403);
    assert_eq!(body["error"]["code"], "control_api.auth.invalid_scope");
    assert_eq!(body["error"]["params"], json!({}));
    assert!(body.get("jsonrpc").is_none());
    assert!(body.get("result").is_none());
    assert_eq!(server.backend.token_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn read_token_calling_each_write_tool_is_insufficient_scope() {
    let config = McpConfig {
        write_tools_enabled: true,
        ..McpConfig::default()
    };
    let server = spawn(config, Ok(support::read_token())).await;
    let client = reqwest::Client::new();

    for (id, name) in [
        "allow_temporarily",
        "add_rule",
        "remove_rule",
        "pause_filter_set",
        "resume_filter_set",
    ]
    .into_iter()
    .enumerate()
    {
        let (status, body) = tool_call(&client, &server.url, TOKEN, id as u64 + 1, name).await;
        assert_eq!(status, 200, "{name}: {body}");
        assert_eq!(body["result"]["isError"], true, "{name}: {body}");
        assert_eq!(
            body["result"]["structuredContent"]["error"]["code"],
            "control_api.auth.insufficient_scope",
            "{name}: {body}"
        );
        assert_eq!(
            body["result"]["content"][0]["text"],
            "control_api.auth.insufficient_scope"
        );
    }
    assert_eq!(
        server.backend.token_calls.load(Ordering::SeqCst),
        5,
        "the token is validated once per request"
    );
}

#[tokio::test]
async fn write_token_is_allowed_through_scope_and_gate() {
    let config = McpConfig {
        write_tools_enabled: true,
        ..McpConfig::default()
    };
    let server = spawn(config, Ok(support::write_token())).await;
    let client = reqwest::Client::new();

    for (id, name) in [
        "allow_temporarily",
        "add_rule",
        "remove_rule",
        "pause_filter_set",
        "resume_filter_set",
    ]
    .into_iter()
    .enumerate()
    {
        let (status, body) = tool_call(&client, &server.url, TOKEN, id as u64 + 1, name).await;
        assert_eq!(status, 200, "{name}: {body}");
        if name == "resume_filter_set" {
            // `{}` is valid for resume, so the mock backend answers.
            assert_eq!(body["result"]["isError"], false, "{name}: {body}");
            continue;
        }
        assert_eq!(body["result"]["isError"], true, "{name}: {body}");
        let code = &body["result"]["structuredContent"]["error"]["code"];
        assert_ne!(code, "control_api.auth.insufficient_scope", "{name}");
        assert_ne!(code, "mcp.write_tools_disabled", "{name}");
    }
}

#[tokio::test]
async fn write_gate_controls_listing_and_calls() {
    let client = reqwest::Client::new();
    let read_names = [
        "search_query_log",
        "get_query",
        "explain_block",
        "test_query",
        "get_stats",
        "list_clients",
        "get_status",
        "list_mcp_rules",
    ];
    let write_names = [
        "allow_temporarily",
        "add_rule",
        "remove_rule",
        "pause_filter_set",
        "resume_filter_set",
    ];

    let off = spawn(McpConfig::default(), Ok(support::write_token())).await;
    let (status, body) = list_tools(&client, &off.url, TOKEN).await;
    assert_eq!(status, 200, "{body}");
    let listed: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed.len(), 8);
    for name in read_names {
        assert!(listed.contains(&name), "{name} missing from {listed:?}");
    }
    for name in write_names {
        assert!(!listed.contains(&name), "{name} must be hidden");
    }

    for (id, name) in write_names.into_iter().enumerate() {
        let (status, body) = tool_call(&client, &off.url, TOKEN, id as u64 + 2, name).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["result"]["isError"], true);
        assert_eq!(
            body["result"]["structuredContent"]["error"]["code"], "mcp.write_tools_disabled",
            "{name}: {body}"
        );
    }

    let on = spawn(
        McpConfig {
            write_tools_enabled: true,
            ..McpConfig::default()
        },
        Ok(support::write_token()),
    )
    .await;
    let (status, body) = list_tools(&client, &on.url, TOKEN).await;
    assert_eq!(status, 200, "{body}");
    let listed: Vec<&str> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    assert_eq!(listed.len(), 14);
    for name in read_names.into_iter().chain(write_names) {
        assert!(listed.contains(&name), "{name} missing from {listed:?}");
    }
}

#[tokio::test]
async fn unknown_tool_is_a_tool_error_not_a_protocol_error() {
    let server = spawn(McpConfig::default(), Ok(support::read_token())).await;
    let client = reqwest::Client::new();

    let (status, body) = tool_call(&client, &server.url, TOKEN, 1, "no_such_tool").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(
        body["result"]["structuredContent"]["error"]["code"],
        "mcp.tool_not_found"
    );
}

fn capped_config() -> McpConfig {
    McpConfig {
        max_concurrent_requests_per_token: 1,
        ..McpConfig::default()
    }
}

async fn wait_for_status_calls(server: &TestServer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.backend.status_calls.load(Ordering::SeqCst) < expected {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("backend call should start");
}

/// Release every gated `get_status` until none is still running.
///
/// `Notify` stores at most one permit, so wake in a loop rather than counting
/// notifications.
async fn release_all(server: &TestServer) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.backend.active_status_calls() > 0 {
            server.backend.release_status();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gated backend calls should complete");
}

#[tokio::test]
async fn in_flight_cap_rejects_n_plus_one_and_releases_on_completion() {
    let server = spawn(capped_config(), Ok(support::write_token())).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    server.backend.delay_status_until(Arc::clone(&gate));
    let client = reqwest::Client::new();

    let url = server.url.clone();
    let slow_client = client.clone();
    let first =
        tokio::spawn(async move { tool_call(&slow_client, &url, TOKEN, 1, "get_status").await });
    wait_for_status_calls(&server, 1).await;

    let (status, body) = tool_call(&client, &server.url, TOKEN, 2, "get_status").await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
    assert_eq!(body["error"]["params"]["limit"], 1);

    gate.notify_one();
    let (first_status, first_body) = first.await.unwrap();
    assert_eq!(first_status, 200);
    assert_eq!(first_body["result"]["isError"], false);

    // The completed request released its slot; the next one is admitted. Give
    // the backend a permit before it starts waiting.
    gate.notify_one();
    let (status, body) = tool_call(&client, &server.url, TOKEN, 3, "get_status").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], false);
}

#[tokio::test]
async fn in_flight_slot_is_released_on_tool_error() {
    let server = spawn(capped_config(), Ok(support::write_token())).await;
    server.backend.set_status(Err(BackendError::Internal {
        message: "boom".into(),
    }));
    let client = reqwest::Client::new();

    for id in [1, 2] {
        let (status, body) = tool_call(&client, &server.url, TOKEN, id, "get_status").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["result"]["isError"], true);
        assert_eq!(
            body["result"]["structuredContent"]["error"]["code"],
            "control_api.internal"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn in_flight_slot_is_released_on_timeout() {
    install_crypto();
    let backend = Arc::new(support::MockBackend::default());
    backend.set_token(Ok(support::write_token()));
    let gate = Arc::new(tokio::sync::Notify::new());
    backend.delay_status_until(Arc::clone(&gate));
    let config = McpConfig {
        max_concurrent_requests_per_token: 1,
        request_timeout: Duration::from_secs(10),
        ..McpConfig::default()
    };
    let mut service = dnscraft_mcp::service(backend.clone(), config);

    let request = |id| {
        axum::http::Request::builder()
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
                id,
                "tools/call",
                json!({ "name": "get_status", "arguments": {} }),
            )))
            .unwrap()
    };

    let response = tower::Service::call(&mut service, request(1))
        .await
        .unwrap();
    assert_eq!(response.status(), 504);
    tokio::time::timeout(Duration::from_secs(1), async {
        while backend.active_status_calls() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("timeout should cancel the backend call");

    gate.notify_one();
    let response = tower::Service::call(&mut service, request(2))
        .await
        .unwrap();
    assert_eq!(response.status(), 200, "the slot must be released");
}

#[tokio::test]
async fn in_flight_slot_is_released_on_client_disconnect() {
    let server = spawn(capped_config(), Ok(support::write_token())).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    server.backend.delay_status_until(Arc::clone(&gate));
    let client = reqwest::Client::new();

    let url = server.url.clone();
    let dropped_client = client.clone();
    let first =
        tokio::spawn(async move { tool_call(&dropped_client, &url, TOKEN, 1, "get_status").await });
    wait_for_status_calls(&server, 1).await;
    first.abort();
    tokio::time::timeout(Duration::from_secs(5), async {
        while server.backend.active_status_calls() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("disconnect should cancel the backend call");

    gate.notify_one();
    let (status, body) = tool_call(&client, &server.url, TOKEN, 2, "get_status").await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn in_flight_cap_is_per_token() {
    let server = spawn(capped_config(), Ok(support::write_token())).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    server.backend.delay_status_until(Arc::clone(&gate));
    let client = reqwest::Client::new();

    // A second token with the same cap and a distinct token id.
    server.backend.set_token_for(
        TOKEN_B,
        TokenInfo {
            token_id: "tok-b".into(),
            scope: support::write_token().scope,
            actor_id: "actor-b".into(),
        },
    );

    // Token A's first request occupies A's only slot.
    let url = server.url.clone();
    let slow_client = client.clone();
    let slow_a =
        tokio::spawn(async move { tool_call(&slow_client, &url, TOKEN, 1, "get_status").await });
    wait_for_status_calls(&server, 1).await;

    // Token B is admitted on its own cap while A is at its limit.
    let url = server.url.clone();
    let slow_client = client.clone();
    let slow_b =
        tokio::spawn(async move { tool_call(&slow_client, &url, TOKEN_B, 2, "get_status").await });
    wait_for_status_calls(&server, 2).await;

    // Token A's second request exceeds A's cap.
    let (status, body) = tool_call(&client, &server.url, TOKEN, 3, "get_status").await;
    assert_eq!(status, 429, "token A's second request is rejected: {body}");
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
    assert_eq!(body["error"]["params"]["limit"], 1);

    // Both admitted requests finish normally.
    release_all(&server).await;
    let (first_status, first_body) = slow_a.await.unwrap();
    assert_eq!(first_status, 200, "{first_body}");
    let (second_status, second_body) = slow_b.await.unwrap();
    assert_eq!(second_status, 200, "{second_body}");
    assert_eq!(second_body["result"]["isError"], false);
}

#[tokio::test]
async fn default_in_flight_cap_admits_five_and_rejects_the_sixth() {
    let server = spawn(McpConfig::default(), Ok(support::write_token())).await;
    let gate = Arc::new(tokio::sync::Notify::new());
    server.backend.delay_status_until(Arc::clone(&gate));
    let client = reqwest::Client::new();

    let mut slow = Vec::new();
    for id in 1..=5 {
        let url = server.url.clone();
        let slow_client = client.clone();
        slow.push(tokio::spawn(async move {
            tool_call(&slow_client, &url, TOKEN, id, "get_status").await
        }));
    }
    wait_for_status_calls(&server, 5).await;

    let (status, body) = tool_call(&client, &server.url, TOKEN, 6, "get_status").await;
    assert_eq!(status, 429, "the sixth request is rejected: {body}");
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
    assert_eq!(body["error"]["params"]["limit"], 5);

    release_all(&server).await;
    for request in slow {
        let (status, body) = request.await.unwrap();
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["result"]["isError"], false);
    }
}

#[tokio::test]
async fn legacy_session_mode_rejects_and_accepts_initialize() {
    install_crypto();
    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": { "name": "legacy", "version": "1.0" },
        },
    })
    .to_string();

    let stateless = spawn(McpConfig::default(), Ok(support::write_token())).await;
    let response = client
        .post(&stateless.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25")
        .header("Mcp-Method", "initialize")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    let json: Value = serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(json["error"]["code"], -32022);
    assert_eq!(json["error"]["message"], "UnsupportedProtocolVersionError");

    let legacy = spawn(
        McpConfig {
            legacy_session_mode: true,
            ..McpConfig::default()
        },
        Ok(support::write_token()),
    )
    .await;
    let response = client
        .post(&legacy.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", "2025-11-25")
        .header("Mcp-Method", "initialize")
        .header("Authorization", format!("Bearer {TOKEN}"))
        .body(body)
        .send()
        .await
        .unwrap();
    let status = response.status();
    let session = response.headers().get("Mcp-Session-Id").cloned();
    let text = response.text().await.unwrap();
    assert_eq!(status, 200, "{text}");
    // Legacy mode answers the handshake as SSE even with `json_response`.
    let json: Value = text
        .lines()
        .filter_map(|line| line.strip_prefix("data: "))
        .filter_map(|data| serde_json::from_str(data).ok())
        .find(|value: &Value| value.get("result").is_some())
        .unwrap_or_else(|| panic!("legacy initialize result not found in {text:?}"));
    assert_eq!(json["result"]["protocolVersion"], "2025-11-25", "{json}");
    assert!(session.is_some(), "legacy handshake issues a session id");
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn raw_token_never_appears_in_logs_errors_or_tool_output() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .finish();
    // A global subscriber is required because rmcp runs the tool handler on a
    // task that may not inherit this test's thread-local dispatcher.
    let _ = tracing::subscriber::set_global_default(subscriber);

    let server = spawn(McpConfig::default(), Ok(support::write_token())).await;
    server.backend.set_status(Err(BackendError::Internal {
        message: "boom".into(),
    }));
    let client = reqwest::Client::new();

    let (status, body) = tool_call(&client, &server.url, TOKEN, 1, "get_status").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["result"]["isError"], true, "{body}");
    let (_, list) = list_tools(&client, &server.url, TOKEN).await;
    assert!(!body.to_string().contains(TOKEN));
    assert!(!list.to_string().contains(TOKEN));

    server.backend.set_token(Err(BackendError::Unauthenticated));
    let (status, rejected) = call(
        &client,
        &server.url,
        Some(TOKEN),
        2,
        "tools/list",
        None,
        json!({}),
    )
    .await;
    assert_eq!(status, 401);
    assert!(!rejected.to_string().contains(TOKEN));

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(
        logs.contains("get_status backend error"),
        "capturing subscriber must see the warning, got: {logs}"
    );
    assert!(!logs.contains(TOKEN), "raw token leaked into logs: {logs}");
}
