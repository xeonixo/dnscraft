//! Transport-independent DNS message core (`handle_wire`).

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dnscraft_policy::{
    ClientFlags, ClientId, DecisionRecord, DnsProtocol, ListenerId, RequestContext,
};
use dnscraft_proto::{Class, Header, Message, Opcode, Rcode};
use dnscraft_resolver::Query;

use crate::edns::{build_response_edns, encode_padded, strip_ecs};
use crate::handler::QueryHandler;

/// Metadata the transport supplies for one wire query.
#[derive(Clone, Debug)]
pub struct QueryMeta {
    /// Transport protocol (also stored on [`RequestContext`]).
    pub protocol: DnsProtocol,
    /// Listener that accepted the query.
    pub listener_id: ListenerId,
    /// Client source address (IPv4-mapped forms are canonicalised).
    pub source: IpAddr,
    /// Client ID from SNI / DoH path, if any.
    pub client_id: Option<ClientId>,
    /// Maximum encoded answer size (UDP EDNS/512, TCP 65 535, …).
    pub size_limit: usize,
    /// Pad the response to a multiple of 468 when the client sent OPT.
    pub pad: bool,
    /// Configured EDNS UDP payload maximum (echoed as `min(client, this)`).
    pub udp_payload_max: u16,
}

/// Structured query-log fields produced when the handler ran (N11 sink later).
#[derive(Clone, Debug)]
pub struct QueryEvent {
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
    /// When false, the sink must not write the query log.
    pub loggable: bool,
}

/// Result of [`handle_wire`]: wire bytes plus optional event data.
#[derive(Clone, Debug)]
pub struct HandleWireResult {
    /// Encoded DNS response.
    pub bytes: Vec<u8>,
    /// Present when [`QueryHandler`] ran; absent for pre-handler error replies.
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
            return Some(HandleWireResult {
                bytes: error_reply_from_header(&header, Rcode::FORMERR, None, meta.size_limit)?,
                event: None,
            });
        }
    };

    if query_msg.opcode() != Opcode::QUERY {
        return Some(HandleWireResult {
            bytes: error_reply(
                &query_msg,
                Rcode::NOTIMP,
                None,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            event: None,
        });
    }

    if query_msg.questions.len() != 1 {
        return Some(HandleWireResult {
            bytes: error_reply(
                &query_msg,
                Rcode::FORMERR,
                None,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            event: None,
        });
    }

    let question = &query_msg.questions[0];
    let qclass = question.qclass;
    if qclass != Class::IN && qclass != Class::CH && qclass != Class::ANY {
        return Some(HandleWireResult {
            bytes: error_reply(
                &query_msg,
                Rcode::REFUSED,
                None,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            event: None,
        });
    }
    if qclass == Class::CH {
        return Some(HandleWireResult {
            bytes: error_reply(
                &query_msg,
                Rcode::REFUSED,
                None,
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            event: None,
        });
    }

    let client_had_opt = query_msg.edns.is_some();
    if let Some(edns) = &query_msg.edns
        && edns.version != 0
    {
        return Some(HandleWireResult {
            bytes: error_reply(
                &query_msg,
                Rcode::BADVERS,
                Some(edns),
                meta.size_limit,
                meta.udp_payload_max,
            )?,
            event: None,
        });
    }

    // Response OPT is built fresh by `build_response_edns` (no ECS/cookies), so
    // client ECS is never echoed; policy never sees ECS options either.

    let dnssec_ok = query_msg.edns.as_ref().is_some_and(|e| e.dnssec_ok);
    let ctx = RequestContext {
        source_ip: source,
        protocol: meta.protocol,
        listener_id: meta.listener_id.clone(),
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
            return Some(HandleWireResult {
                bytes: error_reply(
                    &query_msg,
                    Rcode::SERVFAIL,
                    query_msg.edns.as_ref(),
                    meta.size_limit,
                    meta.udp_payload_max,
                )?,
                event: None,
            });
        }
    };

    let mut resp = answer.message;
    // Id: DoH/DoQ → 0 (RFC); else the client's id. Policy leaves id at 0.
    resp.header.id = match meta.protocol {
        DnsProtocol::DoH | DnsProtocol::DoQ => 0,
        _ => query_msg.header.id,
    };
    resp.header.rd = query_msg.header.rd;
    resp.header.ra = true;
    resp.header.qr = true;
    resp.header.cd = query_msg.header.cd;
    // Questions: ensure we echo the client's question if policy omitted them.
    if resp.questions.is_empty() {
        resp.questions = query_msg.questions.clone();
    }

    if let Some(client_edns) = query_msg.edns.as_ref() {
        let ede = answer.ede.as_ref();
        resp.edns = Some(build_response_edns(client_edns, meta.udp_payload_max, ede));
    } else {
        resp.edns = None;
    }

    let bytes = if meta.pad && client_had_opt {
        encode_padded(&mut resp, meta.size_limit).ok()?
    } else {
        resp.encode_with_limit(meta.size_limit).ok()?
    };

    let event = QueryEvent {
        protocol: meta.protocol,
        listener_id: meta.listener_id,
        source,
        client_id: meta.client_id,
        query: Query {
            name: question.name.clone(),
            qtype: question.qtype,
            qclass: question.qclass,
        },
        rcode: resp.rcode(),
        answer_size: bytes.len(),
        duration: started.elapsed(),
        decision: answer.record,
        loggable: answer.loggable,
    };

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
