//! Root priming (RFC 8109): refresh the root NS set from the hints.
//!
//! With trust anchors configured the answer must prove itself: the `. NS`
//! RRset is validated with the root DNSKEY RRset (itself validated against the
//! anchors), otherwise the reply is ignored and the next hint is tried, until
//! the built-in hints are kept. Glue in the additional section is unsigned,
//! so only addresses for names under `root-servers.net.` are taken from it,
//! and they go through the same address filter as any other glue.

use std::net::SocketAddr;

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType};

use crate::dnssec::validate_rrset_budgeted;
use crate::dnssec::{DelegationTrust, KeysOutcome, validate_dnskey_rrset_budgeted};
use crate::iterate::{Candidate, Context, candidates_for};
use crate::types::PrimingStatus;

/// Maximum number of hints tried before falling back.
const MAX_HINT_ATTEMPTS: usize = 4;

/// The only zone root server names may live in; glue for anything else is
/// not accepted from an (unsigned) additional section.
const ROOT_SERVERS_ZONE: &str = "root-servers.net.";

/// Queries `. NS` against the hints. Returns the root server addresses to use
/// and the priming status; falls back to the hints themselves on failure.
pub(crate) async fn prime(ctx: &Context<'_>) -> (Vec<SocketAddr>, PrimingStatus) {
    let root = Name::root();
    let servers_zone = Name::from_ascii(ROOT_SERVERS_ZONE).ok();
    let validating = !ctx.config.trust_anchors.anchors().is_empty();
    for &hint in ctx.roots.iter().take(MAX_HINT_ATTEMPTS) {
        let resp = match ctx.query_server(hint, &root, RecordType::NS).await {
            Ok(Some(resp)) => resp,
            Ok(None) | Err(_) => continue,
        };
        if !resp.header.aa || resp.rcode() != Rcode::NOERROR {
            continue;
        }
        if validating && !ns_set_is_signed(ctx, hint, &resp).await {
            tracing::warn!(from = %hint, "priming answer failed validation, ignored");
            continue;
        }
        let ns_names: Vec<Name> = resp
            .answers
            .iter()
            .filter(|r| r.name.is_root())
            .filter_map(|r| match &r.rdata {
                RData::NS(n) if servers_zone.as_ref().is_some_and(|z| z.zone_of(n)) => {
                    Some(n.clone())
                }
                _ => None,
            })
            .collect();
        let addrs: Vec<SocketAddr> =
            candidates_for(ctx.config, &root, &ns_names, &resp.additionals)
                .into_iter()
                .filter_map(|c| match c {
                    Candidate::Addr(a) => Some(a),
                    Candidate::Host(_) => None,
                })
                .collect();
        if addrs.is_empty() {
            continue;
        }
        tracing::info!(from = %hint, servers = addrs.len(), "root priming succeeded");
        let status = PrimingStatus::Primed {
            from: hint,
            servers: addrs.len(),
        };
        return (addrs, status);
    }
    tracing::warn!(hints = ctx.roots.len(), "root priming failed, using hints");
    (ctx.roots.to_vec(), PrimingStatus::FellBack)
}

/// Whether the `. NS` RRset of `resp` validates against the root DNSKEY
/// RRset, which is fetched from `server` and validated against the trust
/// anchors.
async fn ns_set_is_signed(ctx: &Context<'_>, server: SocketAddr, resp: &Message) -> bool {
    let root = Name::root();
    let ns: Vec<Record> = resp
        .answers
        .iter()
        .filter(|r| r.name.is_root() && r.rtype() == RecordType::NS)
        .cloned()
        .collect();
    if ns.is_empty() {
        return false;
    }
    let keys_msg = match ctx.query_server(server, &root, RecordType::DNSKEY).await {
        Ok(Some(msg)) if msg.rcode() == Rcode::NOERROR => msg,
        _ => return false,
    };
    let now = ctx.config.clock.now();
    let keys = match validate_dnskey_rrset_budgeted(
        &root,
        &keys_msg.answers,
        &keys_msg.answers,
        DelegationTrust::Anchors(&ctx.config.trust_anchors),
        now,
        &ctx.dnssec_budget,
    ) {
        Ok(KeysOutcome::Secure(keys)) => {
            // A validated root DNSKEY RRset is also the RFC 5011 observation
            // point: the 24 h priming refresh drives trust-anchor rollover.
            ctx.config.trust_anchors.observe_dnskeys(
                &root,
                keys.keys(),
                &keys_msg.answers,
                now,
                &ctx.dnssec_budget,
            );
            keys
        }
        _ => return false,
    };
    validate_rrset_budgeted(&ns, &resp.answers, &keys, now, &ctx.dnssec_budget)
        .is_ok_and(|v| v.wildcard.is_none())
}
