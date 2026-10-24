//! Iterative resolution: walk the delegation chain from the root servers.

use std::collections::VecDeque;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType};

use crate::config::ResolverConfig;
use crate::error::ResolveError;
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
    sent: AtomicU32,
}

impl<'a> Context<'a> {
    pub fn new(
        config: &'a ResolverConfig,
        roots: &'a [SocketAddr],
        total_sent: &'a AtomicU64,
    ) -> Self {
        Self {
            config,
            roots,
            total_sent,
            sent: AtomicU32::new(0),
        }
    }

    /// Sends one query; `Ok(None)` means the server gave no usable response.
    pub async fn query_server(
        &self,
        server: SocketAddr,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Option<Message>, ResolveError> {
        let limit = self.config.max_queries_per_resolve;
        if self.sent.fetch_add(1, Ordering::Relaxed) >= limit {
            return Err(ResolveError::QueryBudgetExceeded {
                name: name.clone(),
                limit,
            });
        }
        self.total_sent.fetch_add(1, Ordering::Relaxed);
        let query = transport::build_query(name, qtype);
        match transport::exchange(server, &query, self.config.query_timeout).await {
            Ok(resp) => Ok(Some(resp)),
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

/// Resolves `name`/`qtype` iteratively and returns the authoritative response.
///
/// `chain` holds the lookups currently in progress (for loop detection);
/// `depth` is the nesting level of address lookups.
pub(crate) fn resolve_iterative<'a>(
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
        let mut candidates: VecDeque<Candidate> =
            ctx.roots.iter().copied().map(Candidate::Addr).collect();
        let max_depth = ctx.config.max_referral_depth;

        for hop in 0..=max_depth {
            tracing::debug!(qname = %name, qtype = %qtype, zone = %zone, hop, "asking zone");
            let mut verdict = None;
            while let Some(candidate) = candidates.pop_front() {
                let server = match candidate {
                    Candidate::Addr(addr) => addr,
                    Candidate::Host(host) => {
                        let resolved = resolve_host(ctx, &host, depth, &chain).await?;
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
                    candidates = next.into();
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
    if depth >= ctx.config.max_nested_depth {
        tracing::debug!(host = %host, depth, "nested lookup depth reached");
        return Ok(Vec::new());
    }
    let mut ips = Vec::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        if chain.iter().any(|(n, t)| n == host && *t == qtype) {
            tracing::debug!(host = %host, "nested lookup loop avoided");
            continue;
        }
        match resolve_iterative(ctx, host, qtype, depth + 1, chain.to_vec()).await {
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
