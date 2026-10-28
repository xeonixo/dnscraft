//! Transport-independent DNS message core (`handle_wire`).

use std::net::IpAddr;
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, Instant, SystemTime};

use dnscraft_filtering::SetId;
use dnscraft_policy::{
    AnswerOrigin, ClientFlags, ClientId, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId,
    NodeId, ProfileId, RequestContext, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Header, Message, Opcode, Question, Rcode};
use dnscraft_resolver::Query;

/// Placeholder ids for listener-generated (pre-policy) decision records.
#[allow(clippy::expect_used)]
static DEFAULT_VIEW: LazyLock<ViewId> =
    LazyLock::new(|| ViewId::new("default").expect("default view id"));
#[allow(clippy::expect_used)]
static DEFAULT_PROFILE: LazyLock<ProfileId> =
    LazyLock::new(|| ProfileId::new("default").expect("default profile id"));
#[allow(clippy::expect_used)]
static DEFAULT_SET: LazyLock<SetId> =
    LazyLock::new(|| SetId::new("default").expect("default set id"));

use crate::config::Exposure;
use crate::ddr::{DdrEndpoints, ddr_decision_record, try_answer_ddr};
use crate::edns::{build_response_edns, encode_padded, strip_ecs};
use crate::handler::QueryHandler;

/// Metadata the transport supplies for one wire query.
#[derive(Clone, Debug)]
pub struct QueryMeta {
    /// Transport protocol (also stored on [`RequestContext`]).
    pub protocol: DnsProtocol,
    /// Listener that accepted the query.
    pub listener_id: ListenerId,
    /// Listener exposure (DDR only on local Do53).
    pub exposure: Exposure,
    /// Client source address (IPv4-mapped forms are canonicalised).
    pub source: IpAddr,
    /// Arrival / local address for DDR hints (UDP `RecvMeta.dst_ip` or TCP `local_addr`).
    pub arrival: IpAddr,
    /// Client ID from SNI / DoH path, if any.
    pub client_id: Option<ClientId>,
    /// Cluster node that accepted the query, if configured.
    pub node_id: Option<NodeId>,
    /// Maximum encoded answer size (UDP EDNS/512, TCP 65 535, …).
    pub size_limit: usize,
    /// Pad the response to a multiple of 468 when the client sent OPT.
    pub pad: bool,
    /// Configured EDNS UDP payload maximum (echoed as `min(client, this)`).
    pub udp_payload_max: u16,
    /// Shared DDR endpoints (Do53). `None` skips DDR interception (encrypted listeners).
    pub ddr: Option<Arc<RwLock<DdrEndpoints>>>,
}

/// Structured query-log fields produced when the handler ran.
#[derive(Clone, Debug)]
pub struct QueryEvent {
    /// Wall-clock stamp; [`crate::emit_event`] overwrites this from the clock.
    pub time: SystemTime,
    /// Transport.
    pub protocol: DnsProtocol,
    /// Listener id.
    pub listener_id: ListenerId,
    /// Canonical client source.
    pub source: IpAddr,
    /// Client ID when present.
    pub client_id: Option<ClientId>,
    /// Question that was handled.
    pub query: Query,
    /// Response code of the answer.
    pub rcode: Rcode,
    /// Encoded answer size in octets.
    pub answer_size: usize,
    /// Wall time spent in `handle_wire` (including the handler).
    pub duration: Duration,
    /// Policy decision record.
    pub decision: DecisionRecord,
    /// When false, the sink must not write the query log (`test_query`).
    pub loggable: bool,
}

/// Result of [`handle_wire`]: wire bytes plus optional event data.
#[derive(Clone, Debug)]
pub struct HandleWireResult {
    /// Encoded DNS response.
    pub bytes: Vec<u8>,
    /// Present when a query decoded, including pre-policy error replies.
    /// Absent when there is no question to log (unparseable header) or the
    /// answer is not loggable (`test_query`).
    pub event: Option<QueryEvent>,
}

/// Decodes `bytes`, validates, calls `handler`, encodes the answer.
///
/// Returns `None` when the datagram should be dropped (no usable header, or
/// QR=1). Otherwise returns wire bytes (possibly a FORMERR/NOTIMP/…) and,
/// when the handler ran, query-event fields for N11.
pub async fn handle_wire(
    bytes: &[u8],
    meta: QueryMeta,
    handler: &impl QueryHandler,
) -> Option<HandleWireResult> {
    let started = Instant::now();
    let source = meta.source.to_canonical();

    let (header, _counts) = Header::decode(bytes).ok()?;
    if header.qr {
        return None;
    }

    let query_msg = match Message::decode(bytes) {
        Ok(m) => m,
        Err(_) => {
            // No question could be decoded: drop or FORMERR, but nothing to log.
            return Some(HandleWireResult {
                bytes: error_reply_from_header(&header, Rcode::FORMERR, None, meta.size_limit)?,
                event: None,
            });
        }
    };

    // Error replies generated after a successful decode echo the client's OPT
    // (RFC 6891 §6.1.1: a response to a request with OPT carries OPT).
    let client_opt = query_msg.edns.as_ref();
    if query_msg.opcode() != Opcode::QUERY {
        return Some(pre_policy_result(
            &meta,
            source,
            query_msg.questions.first(),
            Rcode::NOTIMP,
            error_reply(
                &query_msg,
                Rcode::NOTIMP,
                client_opt,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            started,
        ));
    }

    if query_msg.questions.len() != 1 {
        return Some(pre_policy_result(
            &meta,
            source,
            query_msg.questions.first(),
            Rcode::FORMERR,
            error_reply(
                &query_msg,
                Rcode::FORMERR,
                client_opt,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            started,
        ));
    }

    let question = &query_msg.questions[0];
    let qclass = question.qclass;
    if qclass != Class::IN && qclass != Class::CH && qclass != Class::ANY {
        return Some(pre_policy_result(
            &meta,
            source,
            Some(question),
            Rcode::REFUSED,
            error_reply(
                &query_msg,
                Rcode::REFUSED,
                client_opt,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            started,
        ));
    }
    if qclass == Class::CH {
        return Some(pre_policy_result(
            &meta,
            source,
            Some(question),
            Rcode::REFUSED,
            error_reply(
                &query_msg,
                Rcode::REFUSED,
                client_opt,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            started,
        ));
    }

    let client_had_opt = query_msg.edns.is_some();
    if let Some(edns) = &query_msg.edns
        && edns.version != 0
    {
        return Some(pre_policy_result(
            &meta,
            source,
            Some(question),
            Rcode::BADVERS,
            error_reply(
                &query_msg,
                Rcode::BADVERS,
                Some(edns),
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            started,
        ));
    }

    // Response OPT is built fresh by `build_response_edns` (no ECS/cookies), so
    // client ECS is never echoed; policy never sees ECS options either.

    // DDR (RFC 9462): local Do53 + enabled + IN SVCB `_dns.resolver.arpa.` only.
    if let Some(ddr_msg) = try_intercept_ddr(&query_msg, &meta) {
        return finish_response(FinishArgs {
            query: &query_msg,
            resp: ddr_msg,
            ede: None,
            decision: ddr_decision_record(Rcode::NOERROR),
            loggable: true,
            meta: &meta,
            source,
            client_had_opt,
            started,
        });
    }

    let dnssec_ok = query_msg.edns.as_ref().is_some_and(|e| e.dnssec_ok);
    let ctx = RequestContext {
        source_ip: source,
        protocol: meta.protocol,
        listener_id: meta.listener_id.clone(),
        node_id: meta.node_id.clone(),
        client_id: meta.client_id.clone(),
        query: Query {
            name: question.name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        },
        flags: ClientFlags {
            checking_disabled: query_msg.header.cd,
            dnssec_ok,
            recursion_desired: query_msg.header.rd,
        },
        test_query: false,
    };

    let answer = match handler.handle(ctx).await {
        Ok(a) => a,
        Err(_) => {
            return Some(pre_policy_result(
                &meta,
                source,
                Some(question),
                Rcode::SERVFAIL,
                error_reply(
                    &query_msg,
                    Rcode::SERVFAIL,
                    query_msg.edns.as_ref(),
                    meta.size_limit,
                    meta.udp_payload_max,
                )?,
                started,
            ));
        }
    };

    finish_response(FinishArgs {
        query: &query_msg,
        resp: answer.message,
        ede: answer.ede.as_ref(),
        decision: answer.record,
        loggable: answer.loggable,
        meta: &meta,
        source,
        client_had_opt,
        started,
    })
}

fn try_intercept_ddr(query: &Message, meta: &QueryMeta) -> Option<Message> {
    if !matches!(meta.protocol, DnsProtocol::Udp53 | DnsProtocol::Tcp53) {
        return None;
    }
    if meta.exposure != Exposure::Local {
        return None;
    }
    let guard = meta.ddr.as_ref()?.read().ok()?;
    try_answer_ddr(query, meta.arrival.to_canonical(), &guard)
}

/// Builds a [`QueryEvent`] for one answered query.
#[allow(clippy::too_many_arguments)]
fn make_event(
    meta: &QueryMeta,
    source: IpAddr,
    question: &Question,
    rcode: Rcode,
    answer_size: usize,
    duration: Duration,
    decision: DecisionRecord,
    loggable: bool,
) -> QueryEvent {
    QueryEvent {
        time: crate::events::placeholder_time(),
        protocol: meta.protocol,
        listener_id: meta.listener_id.clone(),
        source,
        client_id: meta.client_id.clone(),
        query: Query {
            name: question.name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        },
        rcode,
        answer_size,
        duration,
        decision,
        loggable,
    }
}

/// Listener-generated error record (no policy decision ran).
fn listener_error_decision(rcode: Rcode) -> DecisionRecord {
    DecisionRecord {
        view_id: DEFAULT_VIEW.clone(),
        profile_id: DEFAULT_PROFILE.clone(),
        selection: SelectionCause::Default,
        client_id: None,
        client_label: None,
        filter_set: DEFAULT_SET.clone(),
        steps: Vec::new(),
        filter: None,
        forward_zone: None,
        dnssec: None,
        // Pre-policy errors and timeouts are all listener-synthesised errors.
        answer_source: AnswerOrigin::ResolveError,
        timings: DecisionTimings::default(),
        rcode,
    }
}

/// Wraps a pre-policy error reply with its query event (when a question decoded).
fn pre_policy_result(
    meta: &QueryMeta,
    source: IpAddr,
    question: Option<&Question>,
    rcode: Rcode,
    bytes: Vec<u8>,
    started: Instant,
) -> HandleWireResult {
    let event = question.map(|q| {
        make_event(
            meta,
            source,
            q,
            rcode,
            bytes.len(),
            started.elapsed(),
            listener_error_decision(rcode),
            true,
        )
    });
    HandleWireResult { bytes, event }
}

/// Query event for a listener-generated error reply produced outside
/// [`handle_wire`] (admission refusal / deadline `SERVFAIL`).
///
/// Returns `None` when the wire has no decodable question.
pub fn error_event_from_wire(
    wire: &[u8],
    meta: &QueryMeta,
    rcode: Rcode,
    answer_size: usize,
    duration: Duration,
) -> Option<QueryEvent> {
    let msg = Message::decode(wire).ok()?;
    let question = msg.questions.first()?;
    Some(make_event(
        meta,
        meta.source.to_canonical(),
        question,
        rcode,
        answer_size,
        duration,
        listener_error_decision(rcode),
        true,
    ))
}

struct FinishArgs<'a> {
    query: &'a Message,
    resp: Message,
    ede: Option<&'a dnscraft_resolver::ExtendedError>,
    decision: DecisionRecord,
    loggable: bool,
    meta: &'a QueryMeta,
    source: IpAddr,
    client_had_opt: bool,
    started: Instant,
}

fn finish_response(args: FinishArgs<'_>) -> Option<HandleWireResult> {
    let FinishArgs {
        query,
        mut resp,
        ede,
        decision,
        loggable,
        meta,
        source,
        client_had_opt,
        started,
    } = args;
    let question = &query.questions[0];
    // Id: DoH/DoQ → 0 (RFC); else the client's id. Policy leaves id at 0.
    resp.header.id = match meta.protocol {
        DnsProtocol::DoH | DnsProtocol::DoQ => 0,
        _ => query.header.id,
    };
    resp.header.rd = query.header.rd;
    resp.header.ra = true;
    resp.header.qr = true;
    resp.header.cd = query.header.cd;
    if resp.questions.is_empty() {
        resp.questions = query.questions.clone();
    }

    if let Some(client_edns) = query.edns.as_ref() {
        resp.edns = Some(build_response_edns(client_edns, meta.udp_payload_max, ede));
    } else {
        resp.edns = None;
    }

    let bytes = if meta.pad && client_had_opt {
        encode_padded(&mut resp, meta.size_limit).ok()?
    } else {
        resp.encode_with_limit(meta.size_limit).ok()?
    };

    let event = make_event(
        meta,
        source,
        question,
        resp.rcode(),
        bytes.len(),
        started.elapsed(),
        decision,
        loggable,
    );

    Some(HandleWireResult {
        bytes,
        event: Some(event),
    })
}

fn error_reply_from_header(
    header: &Header,
    rcode: Rcode,
    edns: Option<&dnscraft_proto::Edns>,
    size_limit: usize,
) -> Option<Vec<u8>> {
    let mut resp = Message {
        header: Header {
            id: header.id,
            qr: true,
            opcode: header.opcode,
            rd: header.rd,
            ra: true,
            cd: header.cd,
            ..Header::default()
        },
        questions: Vec::new(),
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        edns: edns.cloned().map(|mut e| {
            strip_ecs(&mut e);
            e.options.clear();
            e
        }),
    };
    resp.set_rcode(rcode).ok()?;
    resp.encode_with_limit(size_limit).ok()
}

fn error_reply(
    query: &Message,
    rcode: Rcode,
    client_edns: Option<&dnscraft_proto::Edns>,
    size_limit: usize,
    udp_payload_max: u16,
) -> Option<Vec<u8>> {
    let mut resp = Message::response_to(query);
    resp.header.ra = true;
    if let Some(client) = client_edns {
        // BADVERS: echo OPT with version 0 and extended rcode.
        resp.edns = Some(build_response_edns(client, udp_payload_max, None));
    }
    resp.set_rcode(rcode).ok()?;
    resp.encode_with_limit(size_limit).ok()
}

/// Pre-policy error reply (REFUSED / SERVFAIL / …) from wire bytes.
///
/// Keeps the client id and question when the query decodes. Used by TCP
/// admission refusals and TCP `query_timeout` SERVFAIL answers.
pub fn error_reply_from_wire(
    bytes: &[u8],
    rcode: Rcode,
    size_limit: usize,
    udp_payload_max: u16,
) -> Option<Vec<u8>> {
    let msg = Message::decode(bytes).ok()?;
    error_reply(&msg, rcode, msg.edns.as_ref(), size_limit, udp_payload_max)
}

/// Pre-policy error reply plus its query event (admission / timeout answers).
///
/// Same bytes as [`error_reply_from_wire`]; `event` is present when the wire
/// carried a question, so the query log records admission refusals and
/// deadline `SERVFAIL`s too.
pub fn error_result_from_wire(
    bytes: &[u8],
    rcode: Rcode,
    size_limit: usize,
    udp_payload_max: u16,
    meta: &QueryMeta,
    since: Instant,
) -> Option<HandleWireResult> {
    let reply = error_reply_from_wire(bytes, rcode, size_limit, udp_payload_max)?;
    let event = error_event_from_wire(bytes, meta, rcode, reply.len(), since.elapsed());
    Some(HandleWireResult {
        bytes: reply,
        event,
    })
}
