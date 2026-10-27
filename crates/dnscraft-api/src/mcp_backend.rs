//! [`McpBackend`](dnscraft_mcp::backend::McpBackend) implementation backed by
//! the control-api services and module engines.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use dnscraft_filtering::{BlockMode, DomainName, FilterEngine, SetId, TempAllow, Verdict};
use dnscraft_mcp::backend::{BackendError, McpBackend};
use dnscraft_mcp::dto::{
    AddRuleParams, AddRuleResult, AnswerRecord, AuditEntry, AuditResult, DnssecCounts,
    ExplainBlockResult, ExplainReason, FilteringStatus, ListRulesParams, ListRulesResult,
    NodeStatus, PauseDuration, PauseInfo, PauseParams, PauseResult, QType, QueryClient,
    QueryDetail, QueryLogEntry, QueryLogFilter as McpQueryLogFilter, QueryLogResult,
    QueryLogSearch, QueryName, QueryTimings, RemoveRuleParams, RemoveRuleResult, ResolverStatus,
    ResumeResult, Selection, StatsParams, StatsPeriod, StatsResult, SynthesizedAnswer,
    TempAllowInfo, TempAllowParams, TempAllowResult, TestQueryFilter, TestQueryResult, TlsStatus,
    TokenInfo, TokenScope,
};
use dnscraft_policy::RequestContext;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::api::auth::roles::Scope;
use crate::api::query_log_routes::parse_timestamp;
use crate::audit::Audit;
use crate::error::ControlApiError;
use crate::query_log::{Order, OrderBy, QueryLog, QueryLogFilter};
use crate::stats::TopBy;
use crate::tls::TlsStatusProvider;

/// Service handles the MCP backend needs.
#[derive(Clone)]
pub(crate) struct McpBackendInner {
    pub policy: Option<Arc<dnscraft_policy::PolicyEngine>>,
    pub filter: Option<Arc<FilterEngine>>,
    pub query_log: Option<Arc<QueryLog>>,
    pub tokens: Option<crate::api::auth::TokenStore>,
    pub audit: Option<Arc<Audit>>,
    pub tls: Option<Arc<dyn TlsStatusProvider>>,
    pub resolver_cache_size: Arc<AtomicU64>,
    pub node_id: String,
    pub version: String,
    pub start_time: std::time::Instant,
    pub mcp_config: dnscraft_mcp::McpConfig,
}

pub(crate) struct ControlMcpBackend {
    inner: Arc<McpBackendInner>,
}

impl ControlMcpBackend {
    pub fn new(inner: Arc<McpBackendInner>) -> Self {
        Self { inner }
    }

    fn filter_engine(&self) -> Result<&Arc<FilterEngine>, BackendError> {
        self.inner
            .filter
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "filter engine not configured".into(),
            })
    }

    fn policy_engine(&self) -> Result<&Arc<dnscraft_policy::PolicyEngine>, BackendError> {
        self.inner
            .policy
            .as_ref()
            .ok_or_else(|| BackendError::Internal {
                message: "policy engine not configured".into(),
            })
    }
}

/// Builds a read-only backend over `query_log` for integration tests.
///
/// Engines and stores that the read tools do not need are left unconfigured.
#[doc(hidden)]
pub fn mcp_backend_for_test(query_log: Option<Arc<QueryLog>>) -> Arc<dyn McpBackend> {
    Arc::new(ControlMcpBackend::new(Arc::new(McpBackendInner {
        policy: None,
        filter: None,
        query_log,
        tokens: None,
        audit: None,
        tls: None,
        resolver_cache_size: Arc::new(AtomicU64::new(0)),
        node_id: "test".to_owned(),
        version: "0.0.0".to_owned(),
        start_time: std::time::Instant::now(),
        mcp_config: dnscraft_mcp::McpConfig::default(),
    })))
}

// ---- helpers ----

fn default_set() -> SetId {
    SetId::from_str("default").unwrap()
}

fn resolve_set(id: Option<&str>) -> SetId {
    id.and_then(|s| SetId::from_str(s).ok())
        .unwrap_or_else(default_set)
}

fn set_name(id: Option<&str>) -> String {
    id.unwrap_or("default").to_owned()
}

fn rfc3339(ts: SystemTime) -> String {
    let d = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    OffsetDateTime::from_unix_timestamp_nanos((d.as_nanos() as i128).min(i64::MAX as i128))
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn duration_secs(d: PauseDuration) -> Duration {
    Duration::from_secs(d.seconds())
}

fn map_mcp_scope(scope: Scope) -> TokenScope {
    match scope {
        Scope::McpRead => TokenScope::McpRead,
        Scope::McpWrite => TokenScope::McpWrite,
        _ => TokenScope::McpRead,
    }
}

fn filter_qtype(qtype: QType) -> u16 {
    match qtype {
        QType::A => 1,
        QType::Aaaa => 28,
        QType::Cname => 5,
        QType::Mx => 15,
        QType::Txt => 16,
        QType::Srv => 33,
        QType::Https => 65,
    }
}

fn record_qtype(rt: dnscraft_proto::RecordType) -> QType {
    match rt.0 {
        28 => QType::Aaaa,
        5 => QType::Cname,
        15 => QType::Mx,
        16 => QType::Txt,
        33 => QType::Srv,
        65 => QType::Https,
        _ => QType::A,
    }
}

fn block_mode_str(m: &BlockMode) -> String {
    match m {
        BlockMode::Refused => "refused".to_owned(),
        BlockMode::NxDomain => "nxdomain".to_owned(),
        BlockMode::NullIp => "null_ip".to_owned(),
        BlockMode::CustomIp { .. } => "custom_ip".to_owned(),
    }
}

fn reason_source_str(src: &dnscraft_filtering::RuleSource) -> String {
    match src {
        dnscraft_filtering::RuleSource::List { list, line } => format!("list:{list}:line {line}"),
        dnscraft_filtering::RuleSource::Custom { set, line } => format!("set:{set}:line {line}"),
        dnscraft_filtering::RuleSource::Mcp { set, id } => format!("mcp:{set}:{id}"),
        dnscraft_filtering::RuleSource::Service { id } => format!("service:{id}"),
        _ => "unknown".to_owned(),
    }
}

fn policy_protocol(s: &str) -> dnscraft_policy::DnsProtocol {
    match s {
        "tcp53" => dnscraft_policy::DnsProtocol::Tcp53,
        "dot" => dnscraft_policy::DnsProtocol::DoT,
        "doh" => dnscraft_policy::DnsProtocol::DoH,
        "doq" => dnscraft_policy::DnsProtocol::DoQ,
        _ => dnscraft_policy::DnsProtocol::Udp53,
    }
}

fn dnssec_status_str(s: &dnscraft_resolver::DnssecStatus) -> &'static str {
    match s {
        dnscraft_resolver::DnssecStatus::Secure => "secure",
        dnscraft_resolver::DnssecStatus::Insecure => "insecure",
        dnscraft_resolver::DnssecStatus::Bogus => "bogus",
        dnscraft_resolver::DnssecStatus::Indeterminate => "indeterminate",
    }
}

fn json_str(val: &Value, key: &str) -> String {
    val[key].as_str().unwrap_or_default().to_owned()
}

fn json_opt_str(val: &Value, key: &str) -> Option<String> {
    val[key].as_str().map(str::to_owned)
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn parse_time(raw: Option<&str>, field: &str) -> Result<Option<i64>, BackendError> {
    raw.map(|raw| parse_timestamp(raw, field))
        .transpose()
        .map_err(|e| BackendError::Coded {
            code: e.code().to_owned(),
            params: None,
        })
}

fn query_order_by(raw: &str) -> OrderBy {
    match raw {
        "client" => OrderBy::Client,
        "domain" => OrderBy::Domain,
        "rcode" => OrderBy::Rcode,
        _ => OrderBy::Time,
    }
}

fn query_order(raw: &str) -> Order {
    match raw {
        "asc" => Order::Asc,
        _ => Order::Desc,
    }
}

/// Maps a stored query-type string (`RecordType`'s display form) to a DTO type.
fn qtype_from_str(raw: &str) -> QType {
    match raw {
        "AAAA" => QType::Aaaa,
        "CNAME" => QType::Cname,
        "MX" => QType::Mx,
        "TXT" => QType::Txt,
        "SRV" => QType::Srv,
        "HTTPS" => QType::Https,
        _ => QType::A,
    }
}

fn query_entry(record: &Value) -> QueryLogEntry {
    let client = &record["client"];
    let query = &record["query"];
    QueryLogEntry {
        id: json_str(record, "id"),
        time: json_str(record, "time"),
        client: QueryClient {
            id: json_str(client, "id"),
            display_name: json_str(client, "display_name"),
            source: json_str(client, "source"),
        },
        query: QueryName {
            name: json_str(query, "name"),
            qtype: qtype_from_str(&json_str(query, "type")),
        },
        profile_id: json_str(record, "profile_id"),
        answer_source: json_str(record, "answer_source"),
        filter: record
            .get("filter")
            .filter(|filter| !filter.is_null())
            .map(|filter| McpQueryLogFilter {
                reason: json_str(filter, "reason"),
                rule_text: json_opt_str(filter, "rule_text"),
                list_id: json_opt_str(filter, "list_id"),
            }),
        rcode: json_str(record, "rcode"),
        timings: QueryTimings {
            total_us: record["timings"]["total_us"].as_u64().unwrap_or(0),
        },
    }
}

fn code_err(code: &str, domain: &str) -> BackendError {
    BackendError::Coded {
        code: code.to_owned(),
        params: Some(json!({ "domain": domain })),
    }
}

fn rdata_str(rdata: &dnscraft_proto::RData) -> String {
    match rdata {
        dnscraft_proto::RData::A(ip) => ip.to_string(),
        dnscraft_proto::RData::AAAA(ip) => ip.to_string(),
        dnscraft_proto::RData::CNAME(name) => name.to_string(),
        dnscraft_proto::RData::NS(name) => name.to_string(),
        dnscraft_proto::RData::PTR(name) => name.to_string(),
        dnscraft_proto::RData::MX {
            preference,
            exchange,
        } => {
            format!("{preference} {exchange}")
        }
        dnscraft_proto::RData::TXT(_) => "<TXT>".to_owned(),
        dnscraft_proto::RData::SOA { .. } => "<SOA>".to_owned(),
        dnscraft_proto::RData::SRV { .. } => "<SRV>".to_owned(),
        _ => "<rdata>".to_owned(),
    }
}

fn selection_cause_json(cause: &dnscraft_policy::SelectionCause) -> Selection {
    match cause {
        dnscraft_policy::SelectionCause::ClientId => Selection {
            cause: "client_id".to_owned(),
            prefix: None,
            client_id: None,
        },
        dnscraft_policy::SelectionCause::Subnet {
            network,
            prefix_len,
        } => Selection {
            cause: "subnet".to_owned(),
            prefix: Some(format!("{network}/{prefix_len}")),
            client_id: None,
        },
        dnscraft_policy::SelectionCause::Default => Selection {
            cause: "default".to_owned(),
            prefix: None,
            client_id: None,
        },
    }
}

// ---- trait impl ----

#[async_trait]
impl McpBackend for ControlMcpBackend {
    async fn validate_token(&self, token: &str) -> Result<TokenInfo, BackendError> {
        let store = self.inner.tokens.as_ref().ok_or(BackendError::Internal {
            message: "token store not configured".into(),
        })?;
        match store.authenticate(token).await {
            Ok(principal) => {
                if principal.scope().family() != crate::api::auth::EndpointFamily::Mcp {
                    return Err(BackendError::InvalidScope);
                }
                Ok(TokenInfo {
                    token_id: principal.id().to_owned(),
                    scope: map_mcp_scope(principal.scope()),
                    actor_id: principal.actor_id().to_owned(),
                })
            }
            Err(e) if matches!(e, ControlApiError::AuthUnauthenticated) => {
                Err(BackendError::Unauthenticated)
            }
            Err(e) => Err(BackendError::Internal {
                message: format!("token validation: {}", e.code()),
            }),
        }
    }

    async fn search_query_log(
        &self,
        params: QueryLogSearch,
    ) -> Result<QueryLogResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the query-log filter's is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let filter = QueryLogFilter {
            from_us,
            to_us,
            client_id: non_empty(params.client_id),
            client_name_substr: non_empty(params.client_name_substr),
            domain: non_empty(params.domain),
            domain_substr: non_empty(params.domain_substr),
            protocol: non_empty(params.protocol),
            view_id: non_empty(params.view_id),
            profile_id: non_empty(params.profile_id),
            status: non_empty(params.status),
            only_blocked: params.only_blocked,
            only_with_clients: false,
            order_by: query_order_by(&params.order_by),
            order: query_order(&params.order),
            limit: params.limit,
            offset: u64::from(params.offset),
        };
        let page = log
            .list(&filter)
            .await
            .map_err(|e| BackendError::Internal {
                message: format!("query-log list: {}", e.code()),
            })?;
        Ok(QueryLogResult {
            queries: page.records.iter().map(query_entry).collect(),
            has_more: page.has_more,
            next_offset: page.next_offset.map(|offset| offset as u32),
        })
    }

    async fn get_query(&self, id: &str) -> Result<QueryDetail, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let row = log.get(id).await.map_err(|e| BackendError::Internal {
            message: format!("query-log get: {}", e.code()),
        })?;
        let row = row.ok_or(BackendError::NotFound {
            what: format!("query {id}"),
        })?;
        Ok(QueryDetail {
            id: json_str(&row, "id"),
            view_id: json_str(&row, "view_id"),
            profile_id: json_str(&row, "profile_id"),
            selection: Selection {
                cause: json_str(&row["selection"], "cause"),
                prefix: json_opt_str(&row["selection"], "prefix"),
                client_id: json_opt_str(&row["selection"], "client_id"),
            },
            steps: row["steps"]
                .as_array()
                .map(|steps| {
                    steps
                        .iter()
                        .map(|s| dnscraft_mcp::dto::DecisionStep {
                            stage: json_str(s, "stage"),
                            verdict: json_str(s, "verdict"),
                            rule: json_opt_str(s, "rule"),
                            list_id: json_opt_str(s, "list_id"),
                        })
                        .collect()
                })
                .unwrap_or_default(),
            filter: json_opt_filter(row.get("filter")),
            dnssec: json_opt_str(&row, "dnssec"),
            answer_source: json_str(&row, "answer_source"),
            rcode: json_str(&row, "rcode"),
            timings: dnscraft_mcp::dto::DecisionTimings {
                select_us: row["timings"]["select_us"].as_u64().unwrap_or(0),
                filter_us: row["timings"]["filter_us"].as_u64().unwrap_or(0),
                total_us: row["timings"]["total_us"].as_u64().unwrap_or(0),
            },
        })
    }

    async fn explain_block(
        &self,
        domain: &str,
        profile_id: Option<&str>,
        qtype: QType,
    ) -> Result<ExplainBlockResult, BackendError> {
        let name =
            DomainName::parse(domain).map_err(|_| code_err("filter_name.invalid_char", domain))?;
        let set = resolve_set(profile_id);
        let now = SystemTime::now();
        let verdict = self
            .filter_engine()?
            .match_name(&set, &name, filter_qtype(qtype), now)
            .unwrap_or(Verdict::Pass);
        let set_str = set_name(profile_id);
        let (v, reason) = match &verdict {
            Verdict::Pass | Verdict::Allowed(_) => ("allowed".to_owned(), None),
            Verdict::Blocked(r) => {
                let reason = ExplainReason {
                    rule_text: r.rule.to_string(),
                    source: reason_source_str(&r.source),
                    important: r.important,
                    block_mode: String::new(),
                };
                ("blocked".to_owned(), Some(reason))
            }
            Verdict::Rewrite(_, _) => ("allowed".to_owned(), None),
        };
        Ok(ExplainBlockResult {
            domain: domain.to_owned(),
            profile_id: set_str.clone(),
            filter_set_id: set_str,
            verdict: v,
            reason,
        })
    }

    async fn test_query(
        &self,
        params: dnscraft_mcp::dto::TestQueryParams,
    ) -> Result<TestQueryResult, BackendError> {
        let source_ip: IpAddr = params
            .source_ip
            .as_deref()
            .and_then(|s| s.parse().ok())
            .unwrap_or(IpAddr::from([127, 0, 0, 1]));
        let listener_id =
            dnscraft_policy::ListenerId::new("mcp-test").map_err(|_| BackendError::Internal {
                message: "invalid listener id".into(),
            })?;
        let name = dnscraft_proto::Name::from_ascii(&params.domain)
            .map_err(|_| code_err("filter_name.invalid_char", &params.domain))?;
        let ctx = RequestContext {
            source_ip,
            protocol: policy_protocol(&params.protocol),
            listener_id,
            client_id: params
                .client_id
                .as_deref()
                .and_then(|id| dnscraft_policy::ClientId::new(id).ok()),
            query: dnscraft_resolver::Query {
                name,
                qtype: dnscraft_proto::RecordType(match params.qtype {
                    QType::A => 1,
                    QType::Aaaa => 28,
                    QType::Cname => 5,
                    QType::Mx => 15,
                    QType::Txt => 16,
                    QType::Srv => 33,
                    QType::Https => 65,
                }),
                qclass: dnscraft_proto::Class::IN,
            },
            flags: dnscraft_policy::ClientFlags::default(),
            test_query: true,
        };
        let answer = self
            .policy_engine()?
            .handle(ctx)
            .await
            .map_err(|e| BackendError::Coded {
                code: e.code().to_owned(),
                params: None,
            })?;
        let record = &answer.record;
        let verdict = record.filter.as_ref().map_or("allowed", |_| "blocked");
        let filter_dto = record.filter.as_ref().map(|f| TestQueryFilter {
            rule_text: f.reason.rule.to_string(),
            list_id: None,
            block_mode: f
                .block_mode
                .as_ref()
                .map(block_mode_str)
                .unwrap_or_default(),
        });
        let records: Vec<AnswerRecord> = answer
            .message
            .answers
            .iter()
            .map(|r| AnswerRecord {
                name: r.name.to_string(),
                qtype: record_qtype(r.rtype()),
                ttl: r.ttl,
                data: rdata_str(&r.rdata),
            })
            .collect();
        let rcode = answer.message.rcode().to_string();
        let sel = selection_cause_json(&record.selection);
        Ok(TestQueryResult {
            view_id: record.view_id.to_string(),
            profile_id: record.profile_id.to_string(),
            selection: Selection {
                cause: sel.cause,
                prefix: sel.prefix,
                client_id: record.client_id.as_ref().map(|id| id.to_string()),
            },
            verdict: verdict.to_owned(),
            filter: filter_dto,
            answer: SynthesizedAnswer { rcode, records },
            dnssec: record
                .dnssec
                .as_ref()
                .map(|s| dnssec_status_str(s).to_owned()),
            timings: dnscraft_mcp::dto::DecisionTimings {
                select_us: record.timings.select_us,
                filter_us: record.timings.filter_us,
                total_us: record.timings.select_us
                    + record.timings.filter_us
                    + record.timings.resolve_us,
            },
        })
    }

    async fn get_stats(&self, params: StatsParams) -> Result<StatsResult, BackendError> {
        let log = self
            .inner
            .query_log
            .as_ref()
            .ok_or(BackendError::Internal {
                message: "query log not configured".into(),
            })?;
        let from_us = parse_time(params.from.as_deref(), "from")?;
        // The MCP bound is exclusive; the stats window is inclusive.
        let to_us = parse_time(params.to.as_deref(), "to")?.map(|to| to.saturating_sub(1));
        let stats_err = |what: &str, e: ControlApiError| BackendError::Internal {
            message: format!("{what}: {}", e.code()),
        };
        let overview = log
            .stats_overview(from_us, to_us)
            .await
            .map_err(|e| stats_err("stats overview", e))?;
        let top_clients = log
            .top_clients(from_us, to_us, 10, TopBy::Queries)
            .await
            .map_err(|e| stats_err("stats top clients", e))?;
        let top_blocked = log
            .top_blocked_domains(from_us, to_us, 10)
            .await
            .map_err(|e| stats_err("stats top blocked domains", e))?;
        let cache = log
            .cache_stats(from_us, to_us)
            .await
            .map_err(|e| stats_err("stats cache", e))?;
        let count = |key: &str| overview.dnssec.get(key).copied().unwrap_or(0).max(0) as u64;
        Ok(StatsResult {
            period: StatsPeriod {
                from: overview.from.clone(),
                to: overview.to.clone(),
            },
            total_queries: overview.total.max(0) as u64,
            blocked_queries: overview.blocked.max(0) as u64,
            allowed_queries: overview.allowed.max(0) as u64,
            blocked_ratio: if overview.total <= 0 {
                0.0
            } else {
                overview.blocked as f64 / overview.total as f64
            },
            top_blocked_domains: top_blocked
                .domains
                .into_iter()
                .map(|domain| dnscraft_mcp::dto::TopDomain {
                    domain: domain.domain,
                    count: domain.blocked.max(0) as u64,
                })
                .collect(),
            top_clients: top_clients
                .clients
                .into_iter()
                .map(|client| dnscraft_mcp::dto::TopClient {
                    client_name: client.client_name,
                    queries: client.queries.max(0) as u64,
                })
                .collect(),
            cache_hit_ratio: cache.hit_ratio,
            dnssec: DnssecCounts {
                secure: count("secure"),
                insecure: count("insecure"),
                bogus: count("bogus"),
            },
        })
    }

    async fn list_clients(
        &self,
        _params: dnscraft_mcp::dto::ClientListParams,
    ) -> Result<dnscraft_mcp::dto::ClientListResult, BackendError> {
        Ok(dnscraft_mcp::dto::ClientListResult {
            clients: vec![],
            has_more: false,
            next_offset: None,
        })
    }

    async fn get_status(&self) -> Result<NodeStatus, BackendError> {
        let uptime = self.inner.start_time.elapsed().as_secs();
        let cache_size = self
            .inner
            .resolver_cache_size
            .load(std::sync::atomic::Ordering::Relaxed);
        let tls = self
            .inner
            .tls
            .as_ref()
            .map(|p| {
                let status = p.status();
                TlsStatus {
                    mode: status.mode.as_str().to_owned(),
                    cert_expiry: String::new(),
                    fingerprint: status.fingerprint,
                }
            })
            .unwrap_or_default();
        Ok(NodeStatus {
            node_id: self.inner.node_id.clone(),
            version: self.inner.version.clone(),
            uptime_seconds: uptime,
            resolver: ResolverStatus {
                primed: cache_size > 0,
                cache_size,
            },
            listeners: vec![],
            tls,
            filtering: FilteringStatus {
                lists_loaded: 0,
                rules_active: 0,
                last_update: String::new(),
            },
        })
    }

    async fn list_mcp_rules(
        &self,
        params: ListRulesParams,
    ) -> Result<ListRulesResult, BackendError> {
        let set = resolve_set(params.filter_set_id.as_deref());
        let set_str = set_name(params.filter_set_id.as_deref());
        let now = SystemTime::now();
        let mut result = ListRulesResult {
            filter_set_id: set_str.clone(),
            kind: params.kind.clone(),
            ..Default::default()
        };
        match params.kind.as_str() {
            "temporary_allows" => {
                let allows = self
                    .filter_engine()?
                    .list_temporary_allows(&set, now)
                    .unwrap_or_default();
                let all: Vec<_> = allows
                    .into_iter()
                    .map(|a| TempAllowInfo {
                        domain: a.domain.to_string(),
                        include_subdomains: a.include_subdomains,
                        created_at: rfc3339(a.created_at),
                        expires_at: rfc3339(a.until),
                        filter_set_id: set_str.clone(),
                    })
                    .collect();
                let skip = (params.offset as usize).min(all.len());
                let page = &all[skip..];
                let count = page.len().min(params.limit as usize);
                result.temporary_allows = page[..count].to_vec();
                result.has_more = count < page.len();
                result.next_offset = result.has_more.then(|| params.offset + count as u32);
            }
            "pauses" => {
                if let Some(until) = self.filter_engine()?.paused_until(&set) {
                    result.pauses = vec![PauseInfo {
                        filter_set_id: set_str.clone(),
                        paused_until: rfc3339(until),
                    }];
                }
            }
            _ => {
                result.rules = vec![];
            }
        }
        Ok(result)
    }

    async fn allow_temporarily(
        &self,
        params: TempAllowParams,
    ) -> Result<TempAllowResult, BackendError> {
        let set = resolve_set(params.filter_set_id.as_deref());
        let domain = DomainName::parse(&params.domain)
            .map_err(|_| code_err("filter_build.invalid_domain", &params.domain))?;
        let now = SystemTime::now();
        let until = now + duration_secs(params.duration);
        let rule = TempAllow {
            domain,
            include_subdomains: params.include_subdomains,
            until,
            created_at: now,
        };
        self.filter_engine()?
            .allow_temporarily(&set, rule)
            .map_err(|_| BackendError::Coded {
                code: "policy.config.unknown_filter_set".to_owned(),
                params: Some(json!({ "filter_set_id": set.as_str() })),
            })?;
        Ok(TempAllowResult {
            created_at: rfc3339(now),
            expires_at: rfc3339(until),
            filter_set_id: set_name(params.filter_set_id.as_deref()),
        })
    }

    async fn add_custom_rule(&self, params: AddRuleParams) -> Result<AddRuleResult, BackendError> {
        let now = SystemTime::now();
        let expires_at = now + Duration::from_secs(params.lifetime_seconds);
        let rule_text = format!(
            "{}{}^",
            if params.include_subdomains { "||" } else { "|" },
            params.domain
        );
        Ok(AddRuleResult {
            rule_id: String::new(),
            rule_text,
            filter_set_id: set_name(params.filter_set_id.as_deref()),
            created_at: rfc3339(now),
            expires_at: rfc3339(expires_at),
            config_version: None,
        })
    }

    async fn find_mcp_rule(
        &self,
        _domain: &str,
        _filter_set_id: Option<&str>,
    ) -> Result<Option<dnscraft_mcp::dto::McpRuleInfo>, BackendError> {
        Ok(None)
    }

    async fn remove_custom_rule(
        &self,
        params: RemoveRuleParams,
    ) -> Result<RemoveRuleResult, BackendError> {
        Ok(RemoveRuleResult {
            removed: true,
            filter_set_id: set_name(params.filter_set_id.as_deref()),
            config_version: None,
        })
    }

    async fn pause_filter_set(&self, params: PauseParams) -> Result<PauseResult, BackendError> {
        let set = resolve_set(params.filter_set_id.as_deref());
        let until = SystemTime::now() + duration_secs(params.duration);
        self.filter_engine()?
            .set_paused_until(&set, Some(until))
            .map_err(|_| BackendError::Coded {
                code: "policy.config.unknown_filter_set".to_owned(),
                params: Some(json!({ "filter_set_id": set.as_str() })),
            })?;
        Ok(PauseResult {
            filter_set_id: set_name(params.filter_set_id.as_deref()),
            paused_until: rfc3339(until),
        })
    }

    async fn resume_filter_set(
        &self,
        filter_set_id: Option<&str>,
    ) -> Result<ResumeResult, BackendError> {
        let set = resolve_set(filter_set_id);
        let was = self.filter_engine()?.paused_until(&set).map(rfc3339);
        self.filter_engine()?
            .set_paused_until(&set, None)
            .map_err(|_| BackendError::Coded {
                code: "policy.config.unknown_filter_set".to_owned(),
                params: Some(json!({ "filter_set_id": set.as_str() })),
            })?;
        Ok(ResumeResult {
            filter_set_id: set_name(filter_set_id),
            resumed: was.is_some(),
            was_paused_until: was,
        })
    }

    async fn record_audit(&self, entry: AuditEntry) -> Result<(), BackendError> {
        let audit = self.inner.audit.as_ref().ok_or(BackendError::Internal {
            message: "audit log not configured".into(),
        })?;
        let result = match entry.result {
            AuditResult::Success => "success".to_owned(),
            AuditResult::Error => "error".to_owned(),
        };
        let _version = audit
            .record_config_change(crate::audit::ConfigChangeRecord {
                node_id: self.inner.node_id.clone(),
                actor_id: entry.actor_id,
                actor_type: "token".to_owned(),
                action: entry.action,
                before: entry.before,
                after: Some(entry.after),
                config_version: None,
                result,
                error_code: entry.error_code,
            })
            .await
            .map_err(|_| BackendError::Internal {
                message: "audit write failed".into(),
            })?;
        Ok(())
    }
}

fn json_opt_filter(opt: Option<&Value>) -> Option<dnscraft_mcp::dto::DecisionFilter> {
    let f = opt?;
    Some(dnscraft_mcp::dto::DecisionFilter {
        reason: f
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        block_mode: f
            .get("block_mode")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned(),
        rule_text: f
            .get("rule_text")
            .and_then(|v| v.as_str())
            .map(str::to_owned),
        list_id: f.get("list_id").and_then(|v| v.as_str()).map(str::to_owned),
        important: f
            .get("important")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
    })
}
