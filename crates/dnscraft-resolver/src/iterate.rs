//! Iterative resolution: walk the delegation chain from the root servers.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};

use crate::config::ResolverConfig;
use crate::error::ResolveError;
use crate::limits::{Budget, Limits};
use crate::server_selection::ServerStats;
use crate::transport::{self, TransportError};

/// A server to try: a known address, or a name server host still to resolve.
#[derive(Debug)]
pub(crate) enum Candidate {
    Addr(SocketAddr),
    Host(Name),
}

/// A finished iteration: the authoritative response and the zone that gave it.
#[derive(Debug)]
pub(crate) struct Outcome {
    pub message: Message,
    /// The deepest zone cut reached (the zone whose server answered).
    pub zone: Name,
}

/// State shared by one resolution and its nested lookups.
pub(crate) struct Context<'a> {
    pub config: &'a ResolverConfig,
    pub roots: &'a [SocketAddr],
    pub total_sent: &'a AtomicU64,
    pub stats: ServerStats,
    pub limits: Limits,
    budget: Budget,
}

impl<'a> Context<'a> {
    pub fn new(
        config: &'a ResolverConfig,
        roots: &'a [SocketAddr],
        total_sent: &'a AtomicU64,
        stats: ServerStats,
    ) -> Self {
        Self {
            config,
            roots,
            total_sent,
            stats,
            limits: Limits::from(config),
            budget: Budget::new(config.max_queries_per_resolve),
        }
    }

    /// Sends one query; `Ok(None)` means the server gave no usable response.
    pub async fn query_server(
        &self,
        server: SocketAddr,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Option<Message>, ResolveError> {
        self.budget.charge(name)?;
        self.total_sent.fetch_add(1, Ordering::Relaxed);
        let query = transport::build_query(name, qtype);
        match transport::query_servers(&[server], &query, self.config.query_timeout, &self.stats)
            .await
        {
            Ok(resp) => Ok(Some(resp.message)),
            Err(TransportError::Encode(e)) => Err(ResolveError::Encode(e)),
            Err(e) => {
                tracing::debug!(%server, qname = %name, qtype = %qtype, error = %e, "query failed");
                Ok(None)
            }
        }
    }
}

enum Verdict {
    Final,
    Referral { cut: Name, next: Vec<Candidate> },
    Lame,
}

/// Port used when an address does not come from the test override map.
const DNS_PORT: u16 = 53;

/// Address candidates for the name servers named in `ns_names`, using glue
/// from `additionals` where it is in bailiwick of `cut`.
pub(crate) fn candidates_for(
    config: &ResolverConfig,
    cut: &Name,
    ns_names: &[Name],
    additionals: &[Record],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    for ns in ns_names {
        let glue: Vec<IpAddr> = if cut.zone_of(ns) {
            additionals
                .iter()
                .filter(|r| r.name == *ns)
                .filter_map(|r| match &r.rdata {
                    RData::A(a) => Some(IpAddr::V4(*a)),
                    RData::AAAA(a) => Some(IpAddr::V6(*a)),
                    _ => None,
                })
                .collect()
        } else {
            Vec::new()
        };
        if glue.is_empty() {
            out.push(Candidate::Host(ns.clone()));
        } else if let Some(addr) = config.nameserver_addr_overrides.get(ns) {
            out.push(Candidate::Addr(*addr));
        } else {
            out.extend(
                glue.into_iter()
                    .map(|ip| Candidate::Addr(SocketAddr::new(ip, DNS_PORT))),
            );
        }
    }
    out
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves `name`/`qtype` and follows CNAME and DNAME chains.
///
/// Records of the chain that the answering server is authoritative for
/// (in bailiwick of the answering zone) are used directly; for a target
/// outside that zone resolution restarts from the root. The returned message
/// is the last authoritative response; when links were followed its answer
/// section holds the chain in order followed by the target RRset, while the
/// rcode and authority section (SOA of a negative answer) are those of the
/// final target (RFC 6604). Responses without any link are returned untouched.
///
/// `chain` holds the lookups currently in progress (for loop detection);
/// `depth` is the nesting level of address lookups.
pub(crate) async fn resolve_iterative(
    ctx: &Context<'_>,
    name: &Name,
    qtype: RecordType,
    depth: u8,
    chain: Vec<(Name, RecordType)>,
) -> Result<Outcome, ResolveError> {
    let follow = !matches!(qtype, RecordType::CNAME | RecordType::ANY);
    let mut cur = name.clone();
    let mut links: Vec<Record> = Vec::new();
    let mut link_count: usize = 0;
    let mut seen = vec![name.clone()];
    loop {
        let mut outcome = resolve_once(ctx, &cur, qtype, depth, chain.clone()).await?;
        if !follow {
            return Ok(outcome);
        }
        let step = walk_answer(
            ctx,
            &outcome,
            &cur,
            qtype,
            &mut seen,
            &mut links,
            &mut link_count,
            name,
        )?;
        match step {
            Step::Restart(target) => {
                tracing::debug!(qname = %name, target = %target, links = link_count, "restarting at CNAME target");
                cur = target;
            }
            Step::Done(data) => {
                if link_count > 0 {
                    links.extend(data);
                    outcome.message.answers = links;
                }
                return Ok(outcome);
            }
            Step::End => {
                if link_count > 0 {
                    outcome.message.answers = links;
                }
                return Ok(outcome);
            }
        }
    }
}

/// What to do after inspecting one authoritative response.
enum Step {
    /// The answer holds the target RRset (records to append to the chain).
    Done(Vec<Record>),
    /// The chain continues at a name this response cannot answer.
    Restart(Name),
    /// No further data: NODATA, NXDOMAIN or an unusable response.
    End,
}

/// Follows CNAME/DNAME links inside `outcome`, appending them to `links`.
#[allow(clippy::too_many_arguments)]
fn walk_answer(
    ctx: &Context<'_>,
    outcome: &Outcome,
    start: &Name,
    qtype: RecordType,
    seen: &mut Vec<Name>,
    links: &mut Vec<Record>,
    link_count: &mut usize,
    origin_name: &Name,
) -> Result<Step, ResolveError> {
    let answers = &outcome.message.answers;
    let in_bailiwick = |r: &Record| outcome.zone.zone_of(&r.name);
    let rrsigs_at = |owner: &Name| {
        answers
            .iter()
            .filter(|r| r.rtype == RecordType::RRSIG && r.name == *owner && in_bailiwick(r))
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut at = start.clone();
    loop {
        let data: Vec<Record> = answers
            .iter()
            .filter(|r| r.name == at && r.rtype == qtype && in_bailiwick(r))
            .cloned()
            .collect();
        if !data.is_empty() {
            let mut out = data;
            out.extend(rrsigs_at(&at));
            return Ok(Step::Done(out));
        }
        let Some((records, target)) = next_link(answers, &outcome.zone, &at, &rrsigs_at) else {
            return Ok(if at == *start {
                Step::End
            } else {
                Step::Restart(at)
            });
        };
        let target = target.map_err(ResolveError::Encode)?;
        *link_count += 1;
        if *link_count > usize::from(ctx.limits.max_cname_chain) {
            return Err(ResolveError::CnameLimitExceeded {
                name: origin_name.clone(),
                limit: ctx.limits.max_cname_chain,
            });
        }
        if seen.contains(&target) {
            return Err(ResolveError::CnameLoop { name: target });
        }
        seen.push(target.clone());
        links.extend(records);
        at = target;
    }
}

/// The CNAME or DNAME (with synthesized CNAME) in `answers` that applies to
/// `at`, restricted to records in bailiwick of `zone`.
///
/// Returns the records to append to the chain and the next name.
fn next_link(
    answers: &[Record],
    zone: &Name,
    at: &Name,
    rrsigs_at: &dyn Fn(&Name) -> Vec<Record>,
) -> Option<(Vec<Record>, Result<Name, dnscraft_proto::ProtoError>)> {
    // DNAME (RFC 6672): owner is a proper ancestor of `at`.
    for r in answers {
        if let RData::DNAME(target) = &r.rdata
            && zone.zone_of(&r.name)
            && r.name != *at
            && r.name.zone_of(at)
        {
            let synthesized = substitute(at, &r.name, target);
            let mut records = vec![r.clone()];
            records.extend(rrsigs_at(&r.name));
            if let Ok(next) = &synthesized {
                records.push(Record {
                    name: at.clone(),
                    rtype: RecordType::CNAME,
                    class: Class::IN,
                    ttl: r.ttl,
                    rdata: RData::CNAME(next.clone()),
                });
            }
            return Some((records, synthesized));
        }
    }
    for r in answers {
        if let RData::CNAME(target) = &r.rdata
            && r.name == *at
            && zone.zone_of(&r.name)
        {
            let mut records = vec![r.clone()];
            records.extend(rrsigs_at(at));
            return Some((records, Ok(target.clone())));
        }
    }
    None
}

/// Replaces the `owner` suffix of `name` by `target` (DNAME substitution).
fn substitute(
    name: &Name,
    owner: &Name,
    target: &Name,
) -> Result<Name, dnscraft_proto::ProtoError> {
    let keep = name.label_count().saturating_sub(owner.label_count());
    let mut text = String::new();
    for label in name.labels().take(keep) {
        for &b in label {
            match b {
                b'.' | b'\\' => {
                    text.push('\\');
                    text.push(char::from(b));
                }
                0x21..=0x7E => text.push(char::from(b)),
                _ => text.push_str(&format!("\\{b:03}")),
            }
        }
        text.push('.');
    }
    text.push_str(&target.to_string());
    Name::from_ascii(&text)
}

/// Resolves `name`/`qtype` iteratively without following CNAMEs and returns
/// the authoritative response.
fn resolve_once<'a>(
    ctx: &'a Context<'a>,
    name: &'a Name,
    qtype: RecordType,
    depth: u8,
    chain: Vec<(Name, RecordType)>,
) -> BoxFuture<'a, Result<Outcome, ResolveError>> {
    Box::pin(async move {
        let mut chain = chain;
        chain.push((name.clone(), qtype));
        let mut zone = Name::root();
        let mut candidates: VecDeque<Candidate> = ctx
            .stats
            .order(ctx.roots)
            .into_iter()
            .map(Candidate::Addr)
            .collect();
        let max_depth = ctx.limits.max_referral_depth;

        for hop in 0..=max_depth {
            tracing::debug!(qname = %name, qtype = %qtype, zone = %zone, hop, "asking zone");
            let mut verdict = None;
            while let Some(candidate) = candidates.pop_front() {
                let server = match candidate {
                    Candidate::Addr(addr) => addr,
                    Candidate::Host(host) => {
                        let resolved = resolve_host(ctx, &host, depth, &chain).await?;
                        let resolved = ctx.stats.order(&resolved);
                        for addr in resolved.into_iter().rev() {
                            candidates.push_front(Candidate::Addr(addr));
                        }
                        continue;
                    }
                };
                let Some(resp) = ctx.query_server(server, name, qtype).await? else {
                    continue;
                };
                match classify(ctx.config, &resp, &zone, name) {
                    Verdict::Lame => {
                        tracing::debug!(%server, zone = %zone, "lame or unusable response");
                    }
                    v => {
                        verdict = Some((v, resp));
                        break;
                    }
                }
            }
            match verdict {
                None => return Err(ResolveError::Unreachable { zone }),
                Some((Verdict::Final, message)) => return Ok(Outcome { message, zone }),
                Some((Verdict::Referral { cut, next }, _)) => {
                    tracing::debug!(from = %zone, to = %cut, "following referral");
                    zone = cut;
                    candidates = order_candidates(&ctx.stats, next);
                }
                Some((Verdict::Lame, _)) => {}
            }
        }
        Err(ResolveError::ReferralDepthExceeded {
            name: name.clone(),
            limit: max_depth,
        })
    })
}

/// Puts the address candidates of a referral in server-statistics order, with
/// name server hosts still to be resolved after them.
fn order_candidates(stats: &ServerStats, next: Vec<Candidate>) -> VecDeque<Candidate> {
    let mut addrs = Vec::new();
    let mut hosts = Vec::new();
    for candidate in next {
        match candidate {
            Candidate::Addr(addr) => addrs.push(addr),
            host @ Candidate::Host(_) => hosts.push(host),
        }
    }
    let mut out: VecDeque<Candidate> = stats
        .order(&addrs)
        .into_iter()
        .map(Candidate::Addr)
        .collect();
    out.extend(hosts);
    out
}

fn classify(config: &ResolverConfig, resp: &Message, zone: &Name, qname: &Name) -> Verdict {
    let rcode = resp.rcode();
    if resp.header.aa && (rcode == Rcode::NOERROR || rcode == Rcode::NXDOMAIN) {
        return Verdict::Final;
    }
    if rcode != Rcode::NOERROR || !resp.answers.is_empty() {
        return Verdict::Lame;
    }
    let mut cut: Option<&Name> = None;
    let mut ns_names = Vec::new();
    for r in &resp.authorities {
        if let RData::NS(target) = &r.rdata
            && zone.zone_of(&r.name)
            && r.name != *zone
            && r.name.zone_of(qname)
            && cut.is_none_or(|c| *c == r.name)
        {
            cut = Some(&r.name);
            ns_names.push(target.clone());
        }
    }
    match cut {
        Some(cut) => Verdict::Referral {
            cut: cut.clone(),
            next: candidates_for(config, cut, &ns_names, &resp.additionals),
        },
        None => Verdict::Lame,
    }
}

/// Resolves the addresses of a name server host through a nested resolution.
///
/// Returns an empty list when the host cannot be resolved; only budget and
/// encoding errors propagate.
async fn resolve_host(
    ctx: &Context<'_>,
    host: &Name,
    depth: u8,
    chain: &[(Name, RecordType)],
) -> Result<Vec<SocketAddr>, ResolveError> {
    if depth >= ctx.limits.max_nested_depth {
        tracing::debug!(host = %host, depth, "nested lookup depth reached");
        return Ok(Vec::new());
    }
    let mut ips = Vec::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        if chain.iter().any(|(n, t)| n == host && *t == qtype) {
            tracing::debug!(host = %host, "nested lookup loop avoided");
            continue;
        }
        match resolve_once(ctx, host, qtype, depth + 1, chain.to_vec()).await {
            Ok(outcome) => ips.extend(outcome.message.answers.iter().filter_map(|r| {
                if r.name != *host {
                    return None;
                }
                match &r.rdata {
                    RData::A(a) if qtype == RecordType::A => Some(IpAddr::V4(*a)),
                    RData::AAAA(a) if qtype == RecordType::AAAA => Some(IpAddr::V6(*a)),
                    _ => None,
                }
            })),
            Err(e @ (ResolveError::QueryBudgetExceeded { .. } | ResolveError::Encode(_))) => {
                return Err(e);
            }
            Err(e) => {
                tracing::debug!(host = %host, error = %e, "nested address lookup failed");
            }
        }
        if !ips.is_empty() {
            break;
        }
    }
    if let Some(addr) = ctx.config.nameserver_addr_overrides.get(host) {
        return Ok(if ips.is_empty() {
            Vec::new()
        } else {
            vec![*addr]
        });
    }
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .collect())
}
