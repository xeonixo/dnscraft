//! MCP-facing control-api endpoints.
//!
//! These routes back the MCP tools from `SPEC-mcp.md` § Required control-api
//! additions. They share their core logic with the MCP backend
//! ([`crate::mcp_backend`]) so the REST and MCP surfaces cannot drift.
//!
//! Module codes forwarded unchanged:
//! `filter_name.invalid_char`, `filter_build.*`,
//! `policy.config.unknown_filter_set`, `mcp.invalid_input`,
//! `mcp.domain_too_broad`, `mcp.protected_domain`,
//! `mcp.rule_limit_exceeded`, `mcp.duration_exceeds_maximum`.

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::json;

use crate::api::config_routes::{json_body, service, stored_snapshot};
use crate::api::pagination::Pagination;
use crate::api::response::success;
use crate::error::ControlApiError;
use crate::mcp_backend;
use crate::server::AppState;

use dnscraft_mcp::dto::{ListRulesParams, QType, TestQueryParams};

/// `POST /api/v1/filtering/explain-block`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExplainBlockBody {
    domain: String,
    #[serde(default)]
    profile_id: Option<String>,
    qtype: QType,
}

pub(crate) async fn explain_block(
    State(state): State<AppState>,
    body: Result<Json<ExplainBlockBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let result = mcp_backend::explain(
        filter,
        state.clock().now(),
        &body.domain,
        body.profile_id.as_deref(),
        body.qtype,
    )?;
    Ok(success(result))
}

/// `POST /api/v1/policy/test-query`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TestQueryBody {
    domain: String,
    qtype: QType,
    #[serde(default)]
    client_id: Option<String>,
    source_ip: String,
    protocol: String,
}

pub(crate) async fn test_query(
    State(state): State<AppState>,
    body: Result<Json<TestQueryBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    if body.source_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(ControlApiError::Module {
            code: "mcp.invalid_input",
            params: Some(json!({ "reason": "source_ip must be an IP address" })),
        });
    }
    if !matches!(
        body.protocol.as_str(),
        "udp53" | "tcp53" | "dot" | "doh" | "doq"
    ) {
        return Err(ControlApiError::Module {
            code: "mcp.invalid_input",
            params: Some(json!({ "reason": "unknown protocol" })),
        });
    }
    let policy = state
        .policy_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "policy engine is not configured".to_owned(),
        })?;
    let params = TestQueryParams {
        domain: body.domain,
        qtype: body.qtype,
        client_id: body.client_id,
        source_ip: Some(body.source_ip),
        protocol: body.protocol,
    };
    let (_, record) = mcp_backend::run_test_query(policy, &params).await?;
    Ok(success(record))
}

/// Query parameters of `GET /api/v1/filtering/mcp-rules`.
#[derive(Debug, Default, Deserialize)]
pub(crate) struct RulesQuery {
    filter_set_id: Option<String>,
    kind: Option<String>,
    limit: Option<String>,
    offset: Option<String>,
}

pub(crate) async fn list_mcp_rules(
    State(state): State<AppState>,
    Query(query): Query<RulesQuery>,
) -> Result<impl IntoResponse, ControlApiError> {
    let page = Pagination::parse(
        Some(query.limit.as_deref().unwrap_or("100")),
        query.offset.as_deref(),
    )?;
    let kind = query.kind.unwrap_or_else(|| "rules".to_owned());
    if !matches!(kind.as_str(), "rules" | "temporary_allows" | "pauses") {
        return Err(ControlApiError::Module {
            code: "mcp.invalid_input",
            params: Some(json!({
                "reason": "kind must be rules, temporary_allows or pauses"
            })),
        });
    }
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let snapshot = stored_snapshot(service(&state)?).await?;
    let offset = u32::try_from(page.offset).unwrap_or(u32::MAX);
    let result = mcp_backend::list_mcp_rules(
        filter,
        Some(&snapshot),
        state.clock().now(),
        &ListRulesParams {
            kind: kind.clone(),
            filter_set_id: query.filter_set_id,
            limit: page.limit,
            offset,
        },
    )?;
    let mut data = json!({
        "filter_set_id": result.filter_set_id,
        "kind": result.kind,
        "has_more": result.has_more,
        "next_offset": result.next_offset,
    });
    match kind.as_str() {
        "temporary_allows" => data["temporary_allows"] = json!(result.temporary_allows),
        "pauses" => data["pauses"] = json!(result.pauses),
        _ => data["rules"] = json!(result.rules),
    }
    Ok(success(data))
}
