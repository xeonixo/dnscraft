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

use std::time::{Duration, SystemTime};

use axum::Json;
use axum::extract::Extension;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::api::auth::Authenticated;
use crate::api::config_routes::{actor, json_body, service, stored_snapshot};
use crate::api::pagination::Pagination;
use crate::api::response::success;
use crate::config_apply::MutationAudit;
use crate::error::ControlApiError;
use crate::mcp_backend::{
    self, add_rule_to_snapshot, canonical_allow_domain, canonical_block_rule, duration_error,
    engine_error, parse_set, protected_for as derive_protected, reject_protected,
    remove_rule_from_snapshot, rfc3339, stored_time,
};
use crate::query_log::new_id;
use crate::server::AppState;
use dnscraft_common::clock::unix_seconds;

use dnscraft_filtering::{DomainName, TempAllow};
use dnscraft_mcp::dto::{ListRulesParams, PauseDuration, QType, TestQueryParams};
use dnscraft_mcp::{CAP_REASON, ProtectedDomains, sanitize};

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
    let snapshot = stored_snapshot(service(&state)?).await?;
    let result = mcp_backend::explain(
        filter,
        Some(&snapshot),
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

// ---------------------------------------------------------------------------
// Custom rules (versioned config mutations)
// ---------------------------------------------------------------------------

/// Body of `POST /api/v1/filtering/custom-rules`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustomRuleBody {
    domain: String,
    include_subdomains: bool,
    #[serde(default)]
    filter_set_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    expires_at: Option<Value>,
}

/// Body of `DELETE /api/v1/filtering/custom-rules`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoveRuleBody {
    domain: String,
    #[serde(default)]
    filter_set_id: Option<String>,
}

/// Protected domains derived from `snapshot` plus the owner's additions.
fn protected_for(state: &AppState, snapshot: &Value) -> Result<ProtectedDomains, ControlApiError> {
    derive_protected(
        Some(snapshot),
        state.oidc_issuer(),
        state.mcp_config().protected_domains.iter().cloned(),
    )
}

fn parse_expiry(value: &Value) -> Result<SystemTime, ControlApiError> {
    stored_time(value).ok_or_else(|| {
        mcp_backend::mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "expires_at must be unix seconds or an RFC 3339 timestamp" }),
        )
    })
}

// ---------------------------------------------------------------------------
// Temporary allows and pauses (runtime state, never a config version)
// ---------------------------------------------------------------------------
/// Body of `POST /api/v1/filtering/temporary-allows`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TempAllowBody {
    domain: String,
    include_subdomains: bool,
    duration: PauseDuration,
    #[serde(default)]
    filter_set_id: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Body of `POST /api/v1/filtering/pause`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PauseBody {
    #[serde(default)]
    filter_set_id: Option<String>,
    duration: PauseDuration,
}

/// Body of `POST /api/v1/filtering/resume`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResumeBody {
    #[serde(default)]
    filter_set_id: Option<String>,
}

/// `POST /api/v1/filtering/temporary-allows`.
pub(crate) async fn allow_temporarily(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<TempAllowBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let actor = actor(auth);
    if let Some(error) = duration_error(
        body.duration.seconds(),
        state.mcp_config().max_temporary_allow_duration,
    ) {
        return Err(error);
    }
    let domain = canonical_allow_domain(&body.domain)?;
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let service = service(&state)?;
    // Hold the apply lock across the snapshot read, the protected check and
    // the engine mutation so a concurrent config replace cannot interleave.
    let _guard = service.apply_guard().await;
    let snapshot = stored_snapshot(service).await?;
    reject_protected(
        &protected_for(&state, &snapshot)?,
        domain.as_str(),
        body.include_subdomains,
    )?;

    let set = parse_set(body.filter_set_id.as_deref())?;
    let now = state.clock().now();
    let until = now + Duration::from_secs(body.duration.seconds());
    let rule = TempAllow {
        domain: domain.clone(),
        include_subdomains: body.include_subdomains,
        until,
        created_at: now,
    };
    let reason = sanitize(body.reason.as_deref().unwrap_or(""), CAP_REASON);
    let after = json!({
        "domain": domain.as_str(),
        "include_subdomains": body.include_subdomains,
        "duration": body.duration.as_str(),
        "reason": reason,
        "created_at": rfc3339(now),
        "expires_at": rfc3339(until),
        "filter_set_id": set.as_str(),
    });
    if let Err(err) = filter.allow_temporarily(&set, rule) {
        let mapped = engine_error(err, set.as_str());
        service
            .record_action(
                &actor,
                "mcp.allow_temporarily",
                None,
                Some(&after),
                Some(mapped.code()),
            )
            .await;
        return Err(mapped);
    }
    service
        .record_action(&actor, "mcp.allow_temporarily", None, Some(&after), None)
        .await;
    state.broadcast_runtime_command(
        "temporary_allow",
        &json!({
            "filter_set_id": set.as_str(),
            "domain": domain.as_str(),
            "include_subdomains": body.include_subdomains,
            "expires_at": rfc3339(until),
        }),
    );

    Ok(success(json!({
        "domain": domain.as_str(),
        "include_subdomains": body.include_subdomains,
        "created_at": rfc3339(now),
        "expires_at": rfc3339(until),
        "filter_set_id": set.as_str(),
    })))
}

/// `POST /api/v1/filtering/pause`.
pub(crate) async fn pause_filter_set(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<PauseBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let actor = actor(auth);
    if let Some(error) = duration_error(
        body.duration.seconds(),
        state.mcp_config().max_pause_duration,
    ) {
        return Err(error);
    }
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let service = service(&state)?;
    let set = parse_set(body.filter_set_id.as_deref())?;
    let now = state.clock().now();
    let until = now + Duration::from_secs(body.duration.seconds());
    let before = json!({
        "filter_set_id": set.as_str(),
        "paused_until": filter.paused_until(&set).map(rfc3339),
    });
    let after = json!({
        "filter_set_id": set.as_str(),
        "duration": body.duration.as_str(),
        "paused_until": rfc3339(until),
    });
    if let Err(err) = filter.set_paused_until(&set, Some(until)) {
        let mapped = engine_error(err, set.as_str());
        service
            .record_action(
                &actor,
                "mcp.pause_filter_set",
                Some(&before),
                Some(&after),
                Some(mapped.code()),
            )
            .await;
        return Err(mapped);
    }
    service
        .record_action(
            &actor,
            "mcp.pause_filter_set",
            Some(&before),
            Some(&after),
            None,
        )
        .await;
    state.broadcast_runtime_command(
        "pause",
        &json!({
            "filter_set_id": set.as_str(),
            "expires_at": rfc3339(until),
        }),
    );

    Ok(success(json!({
        "filter_set_id": set.as_str(),
        "paused_until": rfc3339(until),
    })))
}

/// `POST /api/v1/filtering/resume`.
pub(crate) async fn resume_filter_set(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<ResumeBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let actor = actor(auth);
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let service = service(&state)?;
    let set = parse_set(body.filter_set_id.as_deref())?;
    let was_paused_until = filter.paused_until(&set).map(rfc3339);
    let after = json!({
        "filter_set_id": set.as_str(),
        "resumed": was_paused_until.is_some(),
    });
    if let Err(err) = filter.set_paused_until(&set, None) {
        let mapped = engine_error(err, set.as_str());
        service
            .record_action(
                &actor,
                "mcp.resume_filter_set",
                None,
                Some(&after),
                Some(mapped.code()),
            )
            .await;
        return Err(mapped);
    }
    service
        .record_action(&actor, "mcp.resume_filter_set", None, Some(&after), None)
        .await;
    state.broadcast_runtime_command("resume", &json!({ "filter_set_id": set.as_str() }));

    Ok(success(json!({
        "filter_set_id": set.as_str(),
        "resumed": was_paused_until.is_some(),
    })))
}

/// `POST /api/v1/filtering/custom-rules`.
pub(crate) async fn add_custom_rule(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<CustomRuleBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let actor = actor(auth);
    let (domain, rule_text) = canonical_block_rule(&body.domain, body.include_subdomains)?;
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    reject_protected(
        &protected_for(&state, &snapshot)?,
        domain.as_str(),
        body.include_subdomains,
    )?;

    let now = state.clock().now();
    let lifetime = state.mcp_config().max_block_rule_lifetime;
    let max_expiry = now + lifetime;
    let expires_at = match &body.expires_at {
        Some(value) => parse_expiry(value)?,
        None => max_expiry,
    };
    if expires_at <= now || expires_at > max_expiry {
        return Err(mcp_backend::mcp_error(
            "mcp.duration_exceeds_maximum",
            json!({ "max_seconds": lifetime.as_secs() }),
        ));
    }

    let set = parse_set(body.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let rule_id = new_id()?;
    let created_secs = unix_seconds(now);
    let expires_secs = unix_seconds(expires_at);
    let cap = state.mcp_config().max_custom_rules_per_set as usize;
    let actor_id = actor.actor_id.clone();
    let include = body.include_subdomains;
    let reason = sanitize(body.reason.as_deref().unwrap_or(""), CAP_REASON);
    let audit_after = json!({
        "domain": domain.as_str(),
        "include_subdomains": include,
        "filter_set_id": set_str,
        "reason": reason,
        "rule_text": rule_text,
        "rule_id": rule_id,
        "created_at": rfc3339(now),
        "expires_at": rfc3339(expires_at),
        "config_version": Value::Null,
    });
    let set_for_mutation = set.clone();
    let domain_for_mutation = domain.clone();
    let rule_id_for_mutation = rule_id.clone();
    let version = service
        .mutate_audited(&actor, "mcp.add_rule", None, move |snapshot| {
            add_rule_to_snapshot(
                snapshot,
                &set_for_mutation,
                &domain_for_mutation,
                include,
                &rule_id_for_mutation,
                created_secs,
                expires_secs,
                &actor_id,
                cap,
                now,
            )?;
            Ok(Some(MutationAudit {
                before: None,
                after: audit_after,
            }))
        })
        .await?
        .ok_or_else(|| ControlApiError::Internal {
            message: "custom-rule mutation made no change".to_owned(),
        })?;
    Ok(success(json!({
        "rule_text": rule_text,
        "domain": domain.as_str(),
        "include_subdomains": include,
        "created_at": rfc3339(now),
        "expires_at": rfc3339(expires_at),
        "filter_set_id": set_str,
        "config_version": version,
    })))
}

/// `DELETE /api/v1/filtering/custom-rules`.
pub(crate) async fn remove_custom_rule(
    State(state): State<AppState>,
    auth: Option<Extension<Authenticated>>,
    body: Result<Json<RemoveRuleBody>, JsonRejection>,
) -> Result<impl IntoResponse, ControlApiError> {
    let body = json_body(body, "mcp.invalid_input")?;
    let actor = actor(auth);
    let domain = DomainName::parse(&body.domain).map_err(|_| {
        mcp_backend::mcp_error("filter_name.invalid_char", json!({ "domain": body.domain }))
    })?;
    let set = parse_set(body.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    let protected = protected_for(&state, &snapshot)?;
    let version = service
        .mutate(&actor, "mcp.remove_rule", |snapshot| {
            remove_rule_from_snapshot(snapshot, &set, &domain, &protected)
        })
        .await?;
    let removed = version.is_some();

    Ok(success(json!({
        "removed": removed,
        "domain": domain.as_str(),
        "filter_set_id": set_str,
        "config_version": version,
    })))
}
