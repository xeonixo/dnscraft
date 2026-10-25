//! Iterative resolution: walk the delegation chain from the root servers.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};

use crate::config::ResolverConfig;
use crate::dnssec::nta;
use crate::dnssec::status::{Status, Trust};
use crate::dnssec::walk::{self, TtlCap, apply_caps, covered_type};
use crate::dnssec::wildcard_source;
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
    /// Validation result of `message` (`Indeterminate` when validation is off).
    pub status: Status,
    /// Caps on the TTLs of the RRsets of this response that validated.
    pub ttl_caps: Vec<TtlCap>,
    /// Smallest TTL cap applied to a record of the returned message: no
    /// cache entry made from it may outlive that. Set by
    /// [`resolve_iterative`]; `None` when nothing was validated.
    pub sig_cap: Option<u32>,
}

/// State shared by one resolution and its nested lookups.
pub(crate) struct Context<'a> {
    pub config: &'a ResolverConfig,
    pub roots: &'a [SocketAddr],
    pub total_sent: &'a AtomicU64,
    pub stats: ServerStats,
    pub limits: Limits,
    /// Whether DNSSEC validation is on for this resolution (CD bit clear and
    /// trust anchors configured).
    pub validate: bool,
    /// Trust in the zones whose DNSKEY RRset was already fetched during this
    /// resolution.
    pub zone_trust: Mutex<HashMap<Name, Trust>>,
    /// Hidden-cut probes (DS queries) sent during this resolution.
    pub probes: std::sync::atomic::AtomicU32,
    /// Signature-verification and NSEC3-hash budget shared by every DNSSEC
    /// check of this resolution (DNSKEY, DS, answers, denial proofs, nested
    /// DS walks), against CPU exhaustion (KeyTrap, NSEC3 hashing).
    pub dnssec_budget: crate::dnssec::ValidationBudget,
    budget: Budget,
    /// Name server hosts looked up during this resolution: `Some` once
    /// resolved (empty when the lookup failed), `None` while in progress.
    /// A host is never resolved twice, and an in-progress entry marks a cycle.
    ns_hosts: Mutex<HashMap<Name, Option<Vec<SocketAddr>>>>,
}

/// Maximum number of glueless name server hosts resolved per zone cut.
const MAX_GLUELESS_PER_CUT: usize = 4;

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
            validate: false,
            zone_trust: Mutex::new(HashMap::new()),
            probes: std::sync::atomic::AtomicU32::new(0),
            dnssec_budget: crate::dnssec::ValidationBudget::default(),
            budget: Budget::new(config.max_queries_per_resolve),
            ns_hosts: Mutex::new(HashMap::new()),
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

/// Address candidates for the name servers named in `ns_names` of a referral
/// sent by a server authoritative for `responding_zone`.
///
/// Glue from `additionals` is used only when the name server host is in
/// bailiwick of `responding_zone` (the zone of the server that sent the
/// referral), not merely of the delegated child. The root zone is in bailiwick
/// of everything, so root-to-TLD glue for e.g. `a.gtld-servers.net.` is used.
/// Out-of-bailiwick glue is ignored: a server for `evil.example.` could
/// otherwise point `ns.bank.com.` at an address of its choosing (RFC 2181
/// section 5.4.1 credibility; same rule as unbound and BIND). Ignored glue
/// leaves the name server glueless (`Candidate::Host`), so it is resolved
/// independently.
///
/// Glue is still used when the host is out of bailiwick of the delegated cut
/// but in bailiwick of the responder (sibling glue such as `ns.sib.test.` for
/// `target.test.` served by `test.`). Glue is only a hint for reaching the
/// zone and is never trusted as an answer.
pub(crate) fn candidates_for(
    config: &ResolverConfig,
    responding_zone: &Name,
    ns_names: &[Name],
    additionals: &[Record],
) -> Vec<Candidate> {
    let mut out = Vec::new();
    let mut addrs = 0usize;
    for ns in ns_names {
        let glue: Vec<IpAddr> = if responding_zone.zone_of(ns) {
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
        // The override map is operator (test) configuration, not network
        // data, so it is not subject to the address filter.
        if !glue.is_empty()
            && let Some(addr) = config.nameserver_addr_overrides.get(ns)
        {
            if addrs < MAX_ADDRS_PER_REFERRAL {
                out.push(Candidate::Addr(*addr));
                addrs += 1;
            }
            continue;
        }
        let usable: Vec<IpAddr> = glue
            .into_iter()
            .filter(|ip| is_usable_server_ip(*ip, config.allow_private_nameservers))
            .collect();
        if usable.is_empty() {
            out.push(Candidate::Host(ns.clone()));
            continue;
        }
        for ip in usable {
            if addrs >= MAX_ADDRS_PER_REFERRAL {
                break;
            }
            out.push(Candidate::Addr(SocketAddr::new(ip, DNS_PORT)));
            addrs += 1;
        }
    }
    out
}

/// Most address candidates taken from one referral (glue and looked-up
/// addresses together). Real delegations list up to 13 servers with two
/// addresses each; the cap bounds the work a hostile referral can cause.
pub(crate) const MAX_ADDRS_PER_REFERRAL: usize = 16;

/// Whether an address learned from the network may be queried as a name
/// server.
///
/// Never usable: `0.0.0.0/8`, loopback `127.0.0.0/8`, link-local
/// `169.254.0.0/16`, multicast `224.0.0.0/4`, reserved `240.0.0.0/4`
/// (including the broadcast address), `::`, `::1`, `fe80::/10`, `ff00::/8`,
/// and IPv4-mapped (`::ffff:0:0/96`) or IPv4-compatible (`::/96`) addresses.
/// Usable only with `allow_private`: RFC 1918, `100.64.0.0/10` and `fc00::/7`.
/// Documentation ranges are not filtered.
pub(crate) fn is_usable_server_ip(ip: IpAddr, allow_private: bool) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 0 || o[0] == 127 || o[0] >= 224 || (o[0] == 169 && o[1] == 254) {
                return false;
            }
            let private = o[0] == 10
                || (o[0] == 172 && (o[1] & 0xF0) == 16)
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (o[1] & 0xC0) == 64);
            allow_private || !private
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            // ::/96 (unspecified, loopback, IPv4-compatible) and ::ffff:0:0/96.
            if s[..5].iter().all(|&x| x == 0) && (s[5] == 0 || s[5] == 0xFFFF) {
                return false;
            }
            if (s[0] & 0xFFC0) == 0xFE80 || (s[0] & 0xFF00) == 0xFF00 {
                return false;
            }
            allow_private || (s[0] & 0xFE00) != 0xFC00
        }
    }
}

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves `name`/`qtype` and follows CNAME and DNAME chains.
///
/// Records of the chain that the answering server is authoritative for
/// (in bailiwick of the answering zone) are used directly; for a target
/// outside that zone resolution restarts from the root.
///
/// The returned message is rebuilt from material the resolver accepted, not
/// passed through from the server (a malicious authority can add anything to
/// any section, validly signed or not):
/// - the answer section holds the RRset for `name`/`qtype` and the CNAME and
///   DNAME links actually followed, each taken from the response that was
///   authoritative for it (a server-sent CNAME below a DNAME is dropped; the
///   resolver synthesizes its own);
/// - the authority section holds, for a negative answer, the SOA and the
///   NSEC/NSEC3 records of the proof (with their RRSIGs), for a
///   wildcard-expanded answer the NSEC/NSEC3 proof, and is empty otherwise;
/// - the additional section is empty.
///
/// This applies whether or not validation is on. The rcode and the authority
/// section are those of the final target (RFC 6604). TTLs of validated RRsets
/// are capped by their RRSIG (RFC 4035 section 5.3.3); the smallest cap is
/// returned in [`Outcome::sig_cap`].
///
/// Each link is validated in the zone that served it; the returned status is
/// the weakest over all links (see [`Status::combine`]).
///
/// `chain` holds the lookups currently in progress (for loop detection);
/// `depth` is the nesting level of address lookups.
pub(crate) async fn resolve_iterative(
    ctx: &Context<'_>,
    name: &Name,
    qtype: RecordType,
    depth: u8,
    chain: Vec<(Name, RecordType)>,
) -> Result<(Outcome, Status), ResolveError> {
    let follow = !matches!(qtype, RecordType::CNAME | RecordType::ANY);
    let mut cur = name.clone();
    let mut links: Vec<Record> = Vec::new();
    let mut link_count: usize = 0;
    let mut seen = vec![name.clone()];
    let mut status = Status::Secure;
    let mut sig_cap: Option<u32> = None;
    loop {
        let mut outcome =
            resolve_once(ctx, &cur, qtype, depth, chain.clone(), ctx.validate).await?;
        status = status.combine(outcome.status);
        if matches!(status, Status::Bogus(_)) {
            // The caller replaces a bogus answer by SERVFAIL; nothing is kept.
            return Ok((outcome, status));
        }
        let step = walk_answer(
            ctx,
            &outcome,
            &cur,
            qtype,
            follow,
            &mut seen,
            &mut links,
            &mut link_count,
            name,
            &mut sig_cap,
        )?;
        let (data, negative) = match step {
            Step::Restart(target) => {
                tracing::debug!(qname = %name, target = %target, links = link_count, "restarting at CNAME target");
                cur = target;
                continue;
            }
            Step::Done(data) => (data, false),
            Step::End => (Vec::new(), true),
        };
        links.extend(data);
        let wildcard = links.iter().any(|r| match &r.rdata {
            RData::RRSIG { labels, .. } => wildcard_source(&r.name, *labels).is_some(),
            _ => false,
        });
        scrub_authority(&mut outcome, &cur, negative, wildcard, &mut sig_cap);
        outcome.message.answers = links;
        outcome.message.additionals.clear();
        outcome.sig_cap = sig_cap;
        return Ok((outcome, status));
    }
}

/// Reduces the authority section of the final response to the records that
/// belong to the answer: for a `negative` answer the SOA of the zone above
/// `qname` and the NSEC/NSEC3 proof, for a positive `wildcard` answer the
/// proof only; all of them in bailiwick of the answering zone. RRSIGs are
/// kept for those types. Validated sets get their TTL capped.
fn scrub_authority(
    outcome: &mut Outcome,
    qname: &Name,
    negative: bool,
    wildcard: bool,
    sig_cap: &mut Option<u32>,
) {
    let zone = outcome.zone.clone();
    let mut authorities = std::mem::take(&mut outcome.message.authorities);
    authorities.retain(|r| {
        if !zone.zone_of(&r.name) {
            return false;
        }
        match covered_type(r) {
            Some(RecordType::SOA) => negative && r.name.zone_of(qname),
            Some(RecordType::NSEC | RecordType::NSEC3) => negative || wildcard,
            _ => false,
        }
    });
    apply_caps(&mut authorities, &outcome.ttl_caps, sig_cap);
    outcome.message.authorities = authorities;
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
///
/// Only in-bailiwick records are used, and only RRsets for the names of the
/// chain. A DNAME takes precedence over any CNAME at a name below it: such a
/// CNAME can only be server-synthesized (RFC 6672 section 3.1) and is never
/// passed on; the resolver synthesizes the CNAME from the (validated) DNAME.
#[allow(clippy::too_many_arguments)]
fn walk_answer(
    ctx: &Context<'_>,
    outcome: &Outcome,
    start: &Name,
    qtype: RecordType,
    follow: bool,
    seen: &mut Vec<Name>,
    links: &mut Vec<Record>,
    link_count: &mut usize,
    origin_name: &Name,
    sig_cap: &mut Option<u32>,
) -> Result<Step, ResolveError> {
    let answers = &outcome.message.answers;
    let zone = &outcome.zone;
    let caps = &outcome.ttl_caps;
    let in_bailiwick = |r: &Record| zone.zone_of(&r.name);
    // Records of the RRset `rtype` at `owner`, with the RRSIGs covering it.
    let rrset_with_sigs = |owner: &Name, rtype: RecordType| -> Vec<Record> {
        answers
            .iter()
            .filter(|r| {
                r.name == *owner
                    && in_bailiwick(r)
                    && (r.rtype == rtype || covered_type(r) == Some(rtype))
            })
            .cloned()
            .collect()
    };
    let mut at = start.clone();
    loop {
        if let Some((dname, dtarget)) = dname_above(answers, zone, &at) {
            let target = substitute(&at, &dname.name, dtarget).map_err(ResolveError::Encode)?;
            let mut records = rrset_with_sigs(&dname.name, RecordType::DNAME);
            apply_caps(&mut records, caps, sig_cap);
            let ttl = records
                .iter()
                .find(|r| r.rtype == RecordType::DNAME)
                .map_or(dname.ttl, |r| r.ttl);
            records.push(Record {
                name: at.clone(),
                rtype: RecordType::CNAME,
                class: Class::IN,
                ttl,
                rdata: RData::CNAME(target.clone()),
            });
            if !follow {
                return Ok(Step::Done(records));
            }
            count_link(ctx, link_count, origin_name)?;
            if seen.contains(&target) {
                return Err(ResolveError::CnameLoop { name: target });
            }
            seen.push(target.clone());
            links.extend(records);
            at = target;
            continue;
        }
        let mut data: Vec<Record> = answers
            .iter()
            .filter(|r| {
                r.name == at
                    && in_bailiwick(r)
                    && (qtype == RecordType::ANY
                        || r.rtype == qtype
                        || covered_type(r) == Some(qtype))
            })
            .cloned()
            .collect();
        if data
            .iter()
            .any(|r| r.rtype != RecordType::RRSIG || qtype == RecordType::RRSIG)
        {
            apply_caps(&mut data, caps, sig_cap);
            return Ok(Step::Done(data));
        }
        let cname = follow
            .then(|| {
                answers.iter().find_map(|r| match &r.rdata {
                    RData::CNAME(target) if r.name == at && in_bailiwick(r) => Some(target),
                    _ => None,
                })
            })
            .flatten();
        let Some(target) = cname else {
            return Ok(if at == *start {
                Step::End
            } else {
                Step::Restart(at)
            });
        };
        let mut records = rrset_with_sigs(&at, RecordType::CNAME);
        apply_caps(&mut records, caps, sig_cap);
        count_link(ctx, link_count, origin_name)?;
        if seen.contains(target) {
            return Err(ResolveError::CnameLoop {
                name: target.clone(),
            });
        }
        seen.push(target.clone());
        links.extend(records);
        at = target.clone();
    }
}

/// Counts one followed link against the chain limit.
fn count_link(
    ctx: &Context<'_>,
    link_count: &mut usize,
    origin_name: &Name,
) -> Result<(), ResolveError> {
    *link_count += 1;
    if *link_count > usize::from(ctx.limits.max_cname_chain) {
        return Err(ResolveError::CnameLimitExceeded {
            name: origin_name.clone(),
            limit: ctx.limits.max_cname_chain,
        });
    }
    Ok(())
}

/// The DNAME (RFC 6672) in `answers`, in bailiwick of `zone`, whose owner is
/// a proper ancestor of `at`, with its target.
fn dname_above<'a>(
    answers: &'a [Record],
    zone: &Name,
    at: &Name,
) -> Option<(&'a Record, &'a Name)> {
    answers.iter().find_map(|r| match &r.rdata {
        RData::DNAME(target)
            if r.rtype == RecordType::DNAME
                && zone.zone_of(&r.name)
                && r.name != *at
                && r.name.zone_of(at) =>
        {
            Some((r, target))
        }
        _ => None,
    })
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
    validate: bool,
) -> BoxFuture<'a, Result<Outcome, ResolveError>> {
    Box::pin(async move {
        let mut trust = if !validate {
            Trust::Off
        } else if nta::covers(&ctx.config.negative_trust_anchors, name) {
            // RFC 7646: nothing below a negative trust anchor is validated.
            Trust::Insecure
        } else {
            Trust::Anchor
        };
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
            let mut glueless_tried = 0usize;
            let mut mini = Minimiser::new(ctx.config.qname_minimisation, &zone, name);
            while let Some(candidate) = candidates.pop_front() {
                let server = match candidate {
                    Candidate::Addr(addr) => addr,
                    Candidate::Host(host) => {
                        if glueless_tried >= MAX_GLUELESS_PER_CUT {
                            tracing::debug!(zone = %zone, host = %host, "glueless name server cap reached");
                            continue;
                        }
                        if zone.zone_of(&host) {
                            // Resolving the host needs this very zone: a cycle.
                            tracing::debug!(zone = %zone, host = %host, "skipping dependent name server");
                            continue;
                        }
                        glueless_tried += 1;
                        let resolved = resolve_host(ctx, &host, depth, &chain).await?;
                        let resolved = ctx.stats.order(&resolved);
                        for addr in resolved.into_iter().rev() {
                            candidates.push_front(Candidate::Addr(addr));
                        }
                        continue;
                    }
                };
                match ask_server(ctx, server, &zone, name, qtype, &mut mini).await? {
                    Some((v, message)) => {
                        // NXDOMAIN next to an RRset for the question: the
                        // rcode is unsigned. In a secure zone that is Bogus
                        // (assess_final); elsewhere the server is treated
                        // as broken and the next one is asked.
                        if matches!(v, Verdict::Final)
                            && walk::nxdomain_contradicted(&message, &zone, name, qtype)
                        {
                            let settled = if validate {
                                walk::settle(ctx, &zone, trust.clone(), server, &candidates).await?
                            } else {
                                Trust::Off
                            };
                            if !matches!(settled, Trust::Secure(_) | Trust::Bogus(_)) {
                                tracing::debug!(%server, zone = %zone, "NXDOMAIN with data, treating server as lame");
                                continue;
                            }
                        }
                        verdict = Some((v, message, server));
                        break;
                    }
                    None => {
                        tracing::debug!(%server, zone = %zone, "lame or unusable response");
                    }
                }
            }
            match verdict {
                None => return Err(ResolveError::Unreachable { zone }),
                Some((Verdict::Final, message, server)) => {
                    let trust = walk::settle(ctx, &zone, trust, server, &candidates).await?;
                    let mut ttl_caps = Vec::new();
                    let status = walk::assess_final(
                        ctx,
                        &zone,
                        &trust,
                        &message,
                        name,
                        qtype,
                        server,
                        &mut ttl_caps,
                    )
                    .await?;
                    return Ok(Outcome {
                        message,
                        zone,
                        status,
                        ttl_caps,
                        sig_cap: None,
                    });
                }
                Some((Verdict::Referral { cut, next }, message, server)) => {
                    tracing::debug!(from = %zone, to = %cut, "following referral");
                    trust = walk::descend(ctx, &zone, trust, &cut, &message, server, &candidates)
                        .await?;
                    zone = cut;
                    if let Trust::Bogus(reason) = trust {
                        // The chain of trust is broken: stop asking.
                        return Ok(Outcome {
                            message,
                            zone,
                            status: Status::Bogus(reason),
                            ttl_caps: Vec::new(),
                            sig_cap: None,
                        });
                    }
                    candidates = order_candidates(&ctx.stats, next);
                }
                Some((Verdict::Lame, _, _)) => {}
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

/// QNAME minimisation state for one zone cut (RFC 9156).
///
/// Names sent to a zone's servers are `name` truncated to `len` labels,
/// growing from one label below the zone to the full name. The first
/// `MINIMISE_ONE_LAB` steps add one label each; afterwards several labels are
/// added per step so that at most `MAX_MINIMISE_COUNT` queries (the final
/// full-name query included) are sent per zone.
struct Minimiser {
    /// Labels of the name to send next (`full` when minimisation is over).
    len: usize,
    full: usize,
    /// Minimised queries answered so far (progress, shared by all servers of the cut).
    steps: usize,
}

/// RFC 9156 section 2.3: maximum number of queries per zone, final one included.
const MAX_MINIMISE_COUNT: usize = 10;
/// RFC 9156 section 2.3: number of single-label steps before taking bigger ones.
const MINIMISE_ONE_LAB: usize = 4;

impl Minimiser {
    fn new(enabled: bool, zone: &Name, name: &Name) -> Self {
        let full = name.label_count();
        let len = if enabled {
            (zone.label_count() + 1).min(full)
        } else {
            full
        };
        Self {
            len,
            full,
            steps: 0,
        }
    }

    fn is_full(&self) -> bool {
        self.len >= self.full
    }

    /// The name to send now: `name` cut down to `len` labels.
    fn current(&self, name: &Name) -> Name {
        let mut n = name.clone();
        for _ in self.len..self.full {
            match n.parent() {
                Some(p) => n = p,
                None => break,
            }
        }
        n
    }

    /// Moves on after the minimised name got a non-referral answer.
    fn advance(&mut self) {
        self.steps += 1;
        if self.steps < MINIMISE_ONE_LAB {
            self.len += 1;
        } else {
            // Queries left including the final full one.
            let left = MAX_MINIMISE_COUNT.saturating_sub(self.steps).max(1);
            let remaining = self.full - self.len;
            self.len += remaining.div_ceil(left).max(1);
        }
        self.len = self.len.min(self.full);
    }
}

/// Asks one server for the next (possibly minimised) name of the zone.
///
/// Returns `Ok(None)` when the server is lame for this question or gave no
/// response at all. The caller then moves on to the next candidate server of
/// the zone cut, sharing the minimisation progress with it.
///
/// A minimised query that gets no response (timeout or network error) is not
/// retried with the full QNAME: the server is treated as unusable for this
/// question, so a dead server costs a single timeout. A minimised query that
/// gets anything but a referral or a plain NODATA (a name that exists, or an
/// empty non-terminal) is instead repeated once with the full QNAME and QTYPE
/// at the same server. That covers NXDOMAIN (RFC 9156 section 2.3, "relaxed"
/// handling of servers that wrongly return NXDOMAIN for empty non-terminals),
/// REFUSED/SERVFAIL/FORMERR and other lame responses, and CNAME/DNAME at the
/// minimised name (an alias node: the full name must be asked to follow it).
async fn ask_server(
    ctx: &Context<'_>,
    server: SocketAddr,
    zone: &Name,
    name: &Name,
    qtype: RecordType,
    mini: &mut Minimiser,
) -> Result<Option<(Verdict, Message)>, ResolveError> {
    while !mini.is_full() {
        let qname = mini.current(name);
        // RFC 9156 section 2.1: QTYPE A for minimised queries.
        let Some(resp) = ctx.query_server(server, &qname, RecordType::A).await? else {
            tracing::debug!(%server, qname = %qname, "no response to minimised query, trying next server");
            return Ok(None);
        };
        let reason = match classify(ctx.config, &resp, zone, &qname) {
            v @ Verdict::Referral { .. } => {
                return Ok(Some((v, resp)));
            }
            Verdict::Final if resp.rcode() == Rcode::NXDOMAIN => "NXDOMAIN",
            Verdict::Final
                if resp
                    .answers
                    .iter()
                    .any(|r| matches!(r.rtype, RecordType::CNAME | RecordType::DNAME)) =>
            {
                "alias"
            }
            Verdict::Final => {
                mini.advance();
                continue;
            }
            Verdict::Lame => "lame or error response",
        };
        tracing::debug!(%server, qname = %qname, reason, "minimised query failed, asking full name");
        break;
    }
    let Some(resp) = ctx.query_server(server, name, qtype).await? else {
        return Ok(None);
    };
    Ok(match classify(ctx.config, &resp, zone, name) {
        Verdict::Lame => None,
        v => Some((v, resp)),
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
            next: candidates_for(config, zone, &ns_names, &resp.additionals),
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
    {
        let mut map = ctx.ns_hosts.lock().unwrap_or_else(PoisonError::into_inner);
        match map.get(host) {
            Some(Some(addrs)) => {
                tracing::debug!(host = %host, "name server host already resolved");
                return Ok(addrs.clone());
            }
            Some(None) => {
                tracing::debug!(host = %host, "name server host lookup in progress (cycle)");
                return Ok(Vec::new());
            }
            None => {
                map.insert(host.clone(), None);
            }
        }
    }
    let result = lookup_host(ctx, host, depth, chain).await?;
    ctx.ns_hosts
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(host.clone(), Some(result.clone()));
    Ok(result)
}

async fn lookup_host(
    ctx: &Context<'_>,
    host: &Name,
    depth: u8,
    chain: &[(Name, RecordType)],
) -> Result<Vec<SocketAddr>, ResolveError> {
    let mut ips = Vec::new();
    for qtype in [RecordType::A, RecordType::AAAA] {
        if chain.iter().any(|(n, t)| n == host && *t == qtype) {
            tracing::debug!(host = %host, "nested lookup loop avoided");
            continue;
        }
        match resolve_once(ctx, host, qtype, depth + 1, chain.to_vec(), false).await {
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
                // The zone is unreachable; asking for AAAA would fail the same way.
                break;
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
        .filter(|ip| is_usable_server_ip(*ip, ctx.config.allow_private_nameservers))
        .take(MAX_ADDRS_PER_REFERRAL)
        .map(|ip| SocketAddr::new(ip, DNS_PORT))
        .collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::net::Ipv4Addr;

    fn n(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn glue(owner: &str, ip: Ipv4Addr) -> Record {
        Record {
            name: n(owner),
            rtype: RecordType::A,
            class: Class::IN,
            ttl: 3600,
            rdata: RData::A(ip),
        }
    }

    #[test]
    fn root_glue_for_tld_servers_is_used() {
        let cfg = ResolverConfig::default();
        let ip = Ipv4Addr::new(192, 5, 6, 30);
        let out = candidates_for(
            &cfg,
            &n("."),
            &[n("a.gtld-servers.net.")],
            &[glue("a.gtld-servers.net.", ip)],
        );
        assert!(matches!(
            out.as_slice(),
            [Candidate::Addr(addr)] if *addr == SocketAddr::new(IpAddr::V4(ip), DNS_PORT)
        ));
    }

    #[test]
    fn sibling_glue_in_bailiwick_of_responder_is_used() {
        let cfg = ResolverConfig::default();
        let sub_ip = Ipv4Addr::new(198, 51, 100, 1);
        let out = candidates_for(
            &cfg,
            &n("test."),
            &[n("ns.sub.test."), n("ns.other.example.")],
            &[
                glue("ns.sub.test.", sub_ip),
                glue("ns.other.example.", Ipv4Addr::new(198, 51, 100, 2)),
            ],
        );
        assert!(matches!(
            out.as_slice(),
            [Candidate::Addr(addr), Candidate::Host(host)]
                if *addr == SocketAddr::new(IpAddr::V4(sub_ip), DNS_PORT)
                    && *host == n("ns.other.example.")
        ));
    }

    #[test]
    fn out_of_bailiwick_glue_is_ignored() {
        let cfg = ResolverConfig::default();
        let out = candidates_for(
            &cfg,
            &n("example.com."),
            &[n("ns.bank.com.")],
            &[glue("ns.bank.com.", Ipv4Addr::new(203, 0, 113, 66))],
        );
        assert!(matches!(
            out.as_slice(),
            [Candidate::Host(host)] if *host == n("ns.bank.com.")
        ));
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn server_address_filter_classes() {
        for refused in [
            "0.0.0.0",
            "0.1.2.3",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.169.254",
            "224.0.0.251",
            "239.255.255.255",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "fe80::1",
            "febf::1",
            "ff02::1",
            "::ffff:192.0.2.1",
            "::192.0.2.1",
        ] {
            assert!(!is_usable_server_ip(ip(refused), false), "{refused}");
            assert!(
                !is_usable_server_ip(ip(refused), true),
                "{refused} (allowed)"
            );
        }
        for private in [
            "10.1.2.3",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "100.64.0.1",
            "100.127.255.254",
            "fc00::1",
            "fd12:3456::1",
        ] {
            assert!(!is_usable_server_ip(ip(private), false), "{private}");
            assert!(
                is_usable_server_ip(ip(private), true),
                "{private} (allowed)"
            );
        }
        for public in [
            "198.41.0.4",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.0.1",
            "100.128.0.1",
            "192.169.0.1",
            "2001:503:ba3e::2:30",
            "2606:4700::1111",
            "fec0::1",
            "192.0.2.1",
            "2001:db8::1",
        ] {
            assert!(is_usable_server_ip(ip(public), false), "{public}");
        }
    }

    #[test]
    fn unusable_glue_leaves_the_name_server_glueless() {
        let ns = [n("ns.example.com.")];
        let with = |ip: Ipv4Addr| [glue("ns.example.com.", ip)];
        let cfg = ResolverConfig::default();
        for bad in [
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(169, 254, 0, 1),
        ] {
            let out = candidates_for(&cfg, &n("com."), &ns, &with(bad));
            assert!(matches!(out.as_slice(), [Candidate::Host(_)]), "{bad}");
        }
        let allow = ResolverConfig {
            allow_private_nameservers: true,
            ..ResolverConfig::default()
        };
        let out = candidates_for(&allow, &n("com."), &ns, &with(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(matches!(out.as_slice(), [Candidate::Addr(_)]));
        let out = candidates_for(&allow, &n("com."), &ns, &with(Ipv4Addr::LOCALHOST));
        assert!(matches!(out.as_slice(), [Candidate::Host(_)]));
    }

    #[test]
    fn override_addresses_are_not_filtered() {
        let mut cfg = ResolverConfig::default();
        let operator = SocketAddr::from(([127, 0, 0, 1], 5353));
        cfg.nameserver_addr_overrides
            .insert(n("ns.example.com."), operator);
        let out = candidates_for(
            &cfg,
            &n("com."),
            &[n("ns.example.com.")],
            &[glue("ns.example.com.", Ipv4Addr::LOCALHOST)],
        );
        assert!(matches!(out.as_slice(), [Candidate::Addr(a)] if *a == operator));
    }

    #[test]
    fn at_most_sixteen_addresses_are_taken_from_a_referral() {
        let cfg = ResolverConfig::default();
        let names: Vec<Name> = (0..10).map(|i| n(&format!("ns{i}.example.com."))).collect();
        let glue_records: Vec<Record> = (0..10u8)
            .flat_map(|i| {
                (0..3u8).map(move |j| {
                    glue(
                        &format!("ns{i}.example.com."),
                        Ipv4Addr::new(198, 51, 100, 10 * i + j),
                    )
                })
            })
            .collect();
        let out = candidates_for(&cfg, &n("com."), &names, &glue_records);
        let addrs = out
            .iter()
            .filter(|c| matches!(c, Candidate::Addr(_)))
            .count();
        assert_eq!(addrs, MAX_ADDRS_PER_REFERRAL);
    }
}
