//! Per-token rate-limit tests: bucket separation, isolation, the auth bucket
//! and the 429 envelope. These speak real HTTP to an axum listener.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::net::SocketAddr;
use std::sync::{Arc, Once};

use axum::Router;
use dnscraft_mcp::{BackendError, McpConfig, TokenInfo, TokenScope};
use serde_json::{Value, json};

const VERSION: &str = "2026-07-28";

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

async fn spawn(config: McpConfig) -> TestServer {
    install_crypto();
    let backend = Arc::new(support::MockBackend::default());
    backend.set_token(Ok(TokenInfo {
        token_id: "tok-default".into(),
        scope: TokenScope::McpWrite,
        actor_id: "actor".into(),
    }));
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

async fn call(
    client: &reqwest::Client,
    server: &TestServer,
    token: &str,
    name: &str,
) -> reqwest::Response {
    client
        .post(&server.url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json, text/event-stream")
        .header("MCP-Protocol-Version", VERSION)
        .header("Mcp-Method", "tools/call")
        .header("Mcp-Name", name)
        .header("Authorization", format!("Bearer {token}"))
        .body(
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": if name == "add_rule" {
                        json!({ "domain": "ads.example" })
                    } else {
                        json!({})
                    },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": VERSION,
                        "io.modelcontextprotocol/clientCapabilities": {},
                    },
                },
            })
            .to_string(),
        )
        .send()
        .await
        .expect("request should be sent")
}

fn rate_config(read: u32, write: u32, auth: u32) -> McpConfig {
    McpConfig {
        read_per_second: read,
        write_per_second: write,
        auth_per_second: auth,
        write_tools_enabled: true,
        ..McpConfig::default()
    }
}

#[tokio::test]
async fn excess_returns_429_with_the_control_api_envelope() {
    let server = spawn(rate_config(1, 100, 100)).await;
    let client = reqwest::Client::new();

    let first = call(&client, &server, "secret", "get_status").await;
    assert_eq!(first.status(), 200);

    let second = call(&client, &server, "secret", "get_status").await;
    assert_eq!(second.status(), 429);
    assert!(
        second.headers().contains_key("retry-after"),
        "429 must carry Retry-After"
    );
    let body: Value = serde_json::from_str(&second.text().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
}

#[tokio::test]
async fn read_and_write_tools_have_separate_buckets() {
    let server = spawn(rate_config(1, 100, 100)).await;
    let client = reqwest::Client::new();

    // Exhaust the read bucket.
    assert_eq!(
        call(&client, &server, "secret", "get_status")
            .await
            .status(),
        200
    );
    assert_eq!(
        call(&client, &server, "secret", "get_status")
            .await
            .status(),
        429
    );

    // The write bucket is untouched.
    let write = call(&client, &server, "secret", "add_rule").await;
    assert_eq!(write.status(), 200);
    let body: Value = serde_json::from_str(&write.text().await.unwrap()).unwrap();
    assert_eq!(body["result"]["isError"], false, "{body}");
    assert_eq!(server.backend.add_calls(), 1);
}

#[tokio::test]
async fn tokens_are_rate_limited_independently() {
    let server = spawn(rate_config(1, 100, 100)).await;
    server.backend.set_token_for(
        "secret-a",
        TokenInfo {
            token_id: "tok-a".into(),
            scope: TokenScope::McpRead,
            actor_id: "actor".into(),
        },
    );
    server.backend.set_token_for(
        "secret-b",
        TokenInfo {
            token_id: "tok-b".into(),
            scope: TokenScope::McpRead,
            actor_id: "actor".into(),
        },
    );
    let client = reqwest::Client::new();

    assert_eq!(
        call(&client, &server, "secret-a", "get_status")
            .await
            .status(),
        200
    );
    assert_eq!(
        call(&client, &server, "secret-a", "get_status")
            .await
            .status(),
        429
    );
    // A different token has its own bucket.
    assert_eq!(
        call(&client, &server, "secret-b", "get_status")
            .await
            .status(),
        200
    );
}

#[tokio::test]
async fn failed_authentication_uses_the_auth_bucket() {
    let server = spawn(rate_config(100, 100, 1)).await;
    server.backend.set_token(Err(BackendError::Unauthenticated));
    let client = reqwest::Client::new();

    let first = call(&client, &server, "bad-secret", "get_status").await;
    assert_eq!(first.status(), 401);

    let second = call(&client, &server, "bad-secret", "get_status").await;
    assert_eq!(second.status(), 429, "the auth bucket is exhausted");
    let body: Value = serde_json::from_str(&second.text().await.unwrap()).unwrap();
    assert_eq!(body["error"]["code"], "control_api.rate_limited");
}
