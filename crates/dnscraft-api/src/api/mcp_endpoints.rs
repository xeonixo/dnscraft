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
use crate::clock::unix_seconds;
use crate::error::ControlApiError;
use crate::mcp_backend::{self, rfc3339, stored_time};
use crate::protected_list::derive_protected_domains;
use crate::query_log::new_id;
use crate::server::AppState;

use dnscraft_filtering::{
    DomainName, FilterError, RecordTypeSel, RuleAction, RuleSpec, SetId, TempAllow, build_rule,
};
use dnscraft_mcp::ProtectedDomains;
use dnscraft_mcp::dto::{ListRulesParams, PauseDuration, QType, TestQueryParams};

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

fn mcp_error(code: &'static str, params: Value) -> ControlApiError {
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}

fn unknown_set(id: &str) -> ControlApiError {
    mcp_error(
        "policy.config.unknown_filter_set",
        json!({ "filter_set_id": id }),
    )
}

fn build_error(err: dnscraft_filtering::BuildError) -> ControlApiError {
    let params = err
        .params()
        .into_iter()
        .map(|(key, value)| (key.to_owned(), Value::String(value)))
        .collect::<serde_json::Map<_, _>>();
    mcp_error(err.code(), Value::Object(params))
}

fn resolve_set(id: Option<&str>) -> Result<SetId, ControlApiError> {
    let raw = id.unwrap_or("default");
    SetId::new(raw).map_err(|_| unknown_set(raw))
}

/// A mutable filter set from the stored snapshot, if it exists.
fn set_mut<'a>(snapshot: &'a mut Value, id: &str) -> Option<&'a mut Value> {
    snapshot
        .get_mut("filtering")?
        .get_mut("sets")?
        .as_array_mut()?
        .iter_mut()
        .find(|set| set.get("id").and_then(Value::as_str) == Some(id))
}

fn active_rule(rule: &Value, now: SystemTime) -> bool {
    rule.get("expires_at")
        .and_then(stored_time)
        .is_none_or(|expires| expires > now)
}

/// Protected domains derived from `snapshot` plus the owner's additions.
fn protected_for(state: &AppState, snapshot: &Value) -> Result<ProtectedDomains, ControlApiError> {
    derive_protected_domains(
        Some(snapshot),
        state.oidc_issuer(),
        state.mcp_config().protected_domains.iter().cloned(),
    )
    .map_err(|err| ControlApiError::Module {
        code: err.code(),
        params: err.params(),
    })
}

fn reject_protected(
    protected: ProtectedDomains,
    domain: &str,
    include: bool,
) -> Result<(), ControlApiError> {
    if let Some(hit) = protected.check(domain, include) {
        return Err(mcp_error(
            "mcp.protected_domain",
            json!({ "domain": domain, "protected_domain": hit }),
        ));
    }
    Ok(())
}

fn parse_expiry(value: &Value) -> Result<SystemTime, ControlApiError> {
    stored_time(value).ok_or_else(|| {
        mcp_error(
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

/// Canonicalises a temporary-allow target with the filtering builder.
fn canonical_allow_domain(raw: &str) -> Result<DomainName, ControlApiError> {
    let spec = RuleSpec {
        action: RuleAction::Allow,
        domain: raw.to_owned(),
        include_subdomains: false,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": raw })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.domain_too_broad",
            json!({ "domain": domain.as_str() }),
        ));
    }
    Ok(domain)
}

/// Rejects a fixed-set duration above the configured maximum.
fn duration_error(requested: PauseDuration, maximum: Duration) -> Option<ControlApiError> {
    (requested.seconds() > maximum.as_secs()).then(|| {
        mcp_error(
            "mcp.duration_exceeds_maximum",
            json!({ "requested": requested.as_str(), "maximum": iso_duration(maximum) }),
        )
    })
}

fn iso_duration(duration: Duration) -> String {
    match duration.as_secs() {
        300 => "PT5M".to_owned(),
        900 => "PT15M".to_owned(),
        3600 => "PT1H".to_owned(),
        seconds => format!("PT{seconds}S"),
    }
}

/// Maps a filtering engine error; anything but an unknown set is internal.
fn engine_error(err: FilterError, set: &str) -> ControlApiError {
    match err {
        FilterError::UnknownSet(_) => unknown_set(set),
        other => ControlApiError::Internal {
            message: other.to_string(),
        },
    }
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
        body.duration,
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
    let snapshot = stored_snapshot(service).await?;
    reject_protected(
        protected_for(&state, &snapshot)?,
        domain.as_str(),
        body.include_subdomains,
    )?;

    let set = resolve_set(body.filter_set_id.as_deref())?;
    let now = state.clock().now();
    let until = now + Duration::from_secs(body.duration.seconds());
    let rule = TempAllow {
        domain: domain.clone(),
        include_subdomains: body.include_subdomains,
        until,
        created_at: now,
    };
    let after = json!({
        "domain": domain.as_str(),
        "include_subdomains": body.include_subdomains,
        "duration": body.duration.as_str(),
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
    let _ = body.reason;

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
    if let Some(error) = duration_error(body.duration, state.mcp_config().max_pause_duration) {
        return Err(error);
    }
    let filter = state
        .filter_engine()
        .ok_or_else(|| ControlApiError::Internal {
            message: "filter engine is not configured".to_owned(),
        })?;
    let service = service(&state)?;
    let set = resolve_set(body.filter_set_id.as_deref())?;
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
    let set = resolve_set(body.filter_set_id.as_deref())?;
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
    let spec = RuleSpec {
        action: RuleAction::Block,
        domain: body.domain,
        include_subdomains: body.include_subdomains,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
    .normalized()
    .map_err(build_error)?;
    let domain = DomainName::parse(&spec.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": spec.domain })))?;
    if domain.label_count() < 2 {
        return Err(mcp_error(
            "mcp.invalid_input",
            json!({ "reason": "a block rule needs a domain with at least two labels" }),
        ));
    }
    let rule_text = build_rule(&spec).map_err(build_error)?;
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    reject_protected(
        protected_for(&state, &snapshot)?,
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
        return Err(mcp_error(
            "mcp.duration_exceeds_maximum",
            json!({ "max_seconds": lifetime.as_secs() }),
        ));
    }

    let set = resolve_set(body.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let rule_id = new_id()?;
    let created_secs = unix_seconds(now);
    let expires_secs = unix_seconds(expires_at);
    let cap = state.mcp_config().max_custom_rules_per_set as usize;
    let actor_id = actor.actor_id.clone();
    let stored_set = set_str.clone();
    let stored_domain = domain.as_str().to_owned();
    let version = service
        .mutate(&actor, "mcp.add_rule", |snapshot| {
            let set = set_mut(snapshot, &stored_set).ok_or_else(|| unknown_set(&stored_set))?;
            let rules = set
                .as_object_mut()
                .ok_or_else(|| ControlApiError::Internal {
                    message: "filter set is not an object".to_owned(),
                })?
                .entry("mcp_rules")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .ok_or_else(|| ControlApiError::Internal {
                    message: "mcp_rules is not an array".to_owned(),
                })?;
            let active = rules.iter().filter(|rule| active_rule(rule, now)).count();
            if active >= cap {
                return Err(mcp_error(
                    "mcp.rule_limit_exceeded",
                    json!({ "max_custom_rules_per_set": cap }),
                ));
            }
            rules.push(json!({
                "id": rule_id,
                "domain": stored_domain,
                "include_subdomains": body.include_subdomains,
                "created_at": created_secs,
                "expires_at": expires_secs,
                "token_id": actor_id,
            }));
            Ok(true)
        })
        .await?
        .ok_or_else(|| ControlApiError::Internal {
            message: "custom-rule mutation made no change".to_owned(),
        })?;

    let _ = body.reason;
    Ok(success(json!({
        "rule_text": rule_text,
        "domain": domain.as_str(),
        "include_subdomains": body.include_subdomains,
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
    let domain = DomainName::parse(&body.domain)
        .map_err(|_| mcp_error("filter_name.invalid_char", json!({ "domain": body.domain })))?;
    let set = resolve_set(body.filter_set_id.as_deref())?;
    let set_str = set.as_str().to_owned();
    let service = service(&state)?;
    let snapshot = stored_snapshot(service).await?;
    let protected = protected_for(&state, &snapshot)?;
    let stored_domain = domain.as_str().to_owned();
    let stored_set = set_str.clone();
    let mut removed = false;
    let version = service
        .mutate(&actor, "mcp.remove_rule", |snapshot| {
            let set = set_mut(snapshot, &stored_set).ok_or_else(|| unknown_set(&stored_set))?;
            let Some(rules) = set
                .as_object_mut()
                .and_then(|set| set.get_mut("mcp_rules"))
                .and_then(Value::as_array_mut)
            else {
                return Ok(false);
            };
            let existing = std::mem::take(rules);
            let mut kept = Vec::with_capacity(existing.len());
            for rule in existing {
                let rule_domain = rule
                    .get("domain")
                    .and_then(Value::as_str)
                    .and_then(|raw| DomainName::parse(raw).ok())
                    .is_some_and(|stored| stored.as_str() == stored_domain);
                if !rule_domain {
                    kept.push(rule);
                    continue;
                }
                let include = rule
                    .get("include_subdomains")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                // The stored flag decides coverage, not the request.
                reject_protected(protected.clone(), &stored_domain, include)?;
                removed = true;
            }
            *rules = kept;
            Ok(removed)
        })
        .await?;

    Ok(success(json!({
        "removed": removed,
        "domain": domain.as_str(),
        "filter_set_id": set_str,
        "config_version": version,
    })))
}
