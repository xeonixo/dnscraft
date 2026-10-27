//! Configuration validation table and backend-trait smoke tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::time::Duration;

use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::config::{MIN_ACTION_DURATION, McpConfig};
use dnscraft_mcp::dto::{NodeStatus, TokenInfo, TokenScope};
use support::MockBackend;

fn config() -> McpConfig {
    McpConfig::default()
}

fn assert_invalid(config: &McpConfig, key: &str) {
    let error = config.validate().unwrap_err();
    assert_eq!(error.code(), "mcp.config.invalid", "{key}");
    let params = error.params().unwrap();
    assert_eq!(params["key"], key);
}

#[test]
fn defaults_are_valid() {
    config().validate().unwrap();
}

#[test]
fn concurrent_request_cap_boundaries() {
    for (value, valid) in [(0, false), (1, true), (50, true), (51, false)] {
        let config = McpConfig {
            max_concurrent_requests_per_token: value,
            ..config()
        };
        assert_eq!(
            config.validate().is_ok(),
            valid,
            "max_concurrent_requests_per_token {value}"
        );
        if !valid {
            assert_invalid(&config, "max_concurrent_requests_per_token");
        }
    }
}

#[test]
fn request_timeout_boundaries() {
    for (value, valid) in [(9, false), (10, true), (300, true), (301, false)] {
        let config = McpConfig {
            request_timeout: Duration::from_secs(value),
            ..config()
        };
        assert_eq!(config.validate().is_ok(), valid, "request_timeout {value}s");
        if !valid {
            assert_invalid(&config, "request_timeout");
        }
    }
}

#[test]
fn action_duration_boundaries() {
    for (value, valid) in [(299, false), (300, true), (3600, true), (3601, false)] {
        for key in ["max_temporary_allow_duration", "max_pause_duration"] {
            let config = match key {
                "max_temporary_allow_duration" => McpConfig {
                    max_temporary_allow_duration: Duration::from_secs(value),
                    ..config()
                },
                _ => McpConfig {
                    max_pause_duration: Duration::from_secs(value),
                    ..config()
                },
            };
            assert_eq!(config.validate().is_ok(), valid, "{key} {value}s");
            if !valid {
                assert_invalid(&config, key);
            }
        }
    }
    assert_eq!(MIN_ACTION_DURATION, Duration::from_secs(300));
}

#[test]
fn custom_rule_cap_boundaries() {
    for (value, valid) in [(9, false), (10, true), (1000, true), (1001, false)] {
        let config = McpConfig {
            max_custom_rules_per_set: value,
            ..config()
        };
        assert_eq!(
            config.validate().is_ok(),
            valid,
            "max_custom_rules_per_set {value}"
        );
        if !valid {
            assert_invalid(&config, "max_custom_rules_per_set");
        }
    }
}

#[test]
fn block_rule_lifetime_boundaries() {
    for (value, valid) in [
        (86_399, false),
        (86_400, true),
        (365 * 86_400, true),
        (365 * 86_400 + 1, false),
    ] {
        let config = McpConfig {
            max_block_rule_lifetime: Duration::from_secs(value),
            ..config()
        };
        assert_eq!(
            config.validate().is_ok(),
            valid,
            "max_block_rule_lifetime {value}s"
        );
        if !valid {
            assert_invalid(&config, "max_block_rule_lifetime");
        }
    }
}

#[test]
fn request_body_size_must_be_nonzero() {
    let config = McpConfig {
        max_request_body_size: 0,
        ..config()
    };
    assert_invalid(&config, "max_request_body_size");
    let config = McpConfig {
        max_request_body_size: 1,
        ..McpConfig::default()
    };
    config.validate().unwrap();
}

#[test]
fn rate_limit_boundaries() {
    for (value, valid) in [(0, false), (1, true), (10_000, true), (10_001, false)] {
        for key in ["read_per_second", "write_per_second", "auth_per_second"] {
            let config = match key {
                "read_per_second" => McpConfig {
                    read_per_second: value,
                    ..config()
                },
                "write_per_second" => McpConfig {
                    write_per_second: value,
                    ..config()
                },
                _ => McpConfig {
                    auth_per_second: value,
                    ..config()
                },
            };
            assert_eq!(config.validate().is_ok(), valid, "{key} {value}");
            if !valid {
                assert_invalid(&config, key);
            }
        }
    }

    for (value, valid) in [(0, false), (1, true), (1_000_000, true), (1_000_001, false)] {
        let config = McpConfig {
            max_tracked_tokens: value,
            ..config()
        };
        assert_eq!(
            config.validate().is_ok(),
            valid,
            "max_tracked_tokens {value}"
        );
        if !valid {
            assert_invalid(&config, "max_tracked_tokens");
        }
    }
}

#[test]
fn protected_domain_errors_use_the_config_code() {
    let config = McpConfig {
        protected_domains: vec!["https://example.com".into()],
        ..config()
    };
    let error = config.validate().unwrap_err();
    assert_eq!(error.code(), "mcp.config.protected_domain");
    assert_eq!(error.params().unwrap()["domain"], "https://example.com");
}

#[tokio::test]
async fn mock_backend_returns_configured_results_and_failures() {
    let backend = MockBackend::default();
    backend.set_status(Ok(NodeStatus {
        node_id: "node1".into(),
        ..NodeStatus::default()
    }));
    backend.set_token(Ok(TokenInfo {
        token_id: "tok".into(),
        scope: TokenScope::McpRead,
        actor_id: "actor".into(),
    }));
    let status = McpBackend::get_status(&backend).await.unwrap();
    assert_eq!(status.node_id, "node1");
    let token = McpBackend::validate_token(&backend, "secret")
        .await
        .unwrap();
    assert_eq!(token.scope, TokenScope::McpRead);

    backend.set_status(Err(BackendError::Internal {
        message: "boom".into(),
    }));
    let error = McpBackend::get_status(&backend).await.unwrap_err();
    assert_eq!(error.code(), "control_api.internal");
    assert_eq!(error.params(), None);

    backend.set_token(Err(BackendError::Unauthenticated));
    let error = McpBackend::validate_token(&backend, "secret")
        .await
        .unwrap_err();
    assert_eq!(error.code(), "control_api.auth.unauthenticated");
}
