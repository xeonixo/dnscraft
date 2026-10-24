//! Root priming (RFC 8109): refresh the root NS set from the hints.

use std::net::SocketAddr;

use dnscraft_proto::{Name, RData, Rcode, RecordType};

use crate::iterate::{Candidate, Context, candidates_for};
use crate::types::PrimingStatus;

/// Maximum number of hints tried before falling back.
const MAX_HINT_ATTEMPTS: usize = 4;

/// Queries `. NS` against the hints. Returns the root server addresses to use
/// and the priming status; falls back to the hints themselves on failure.
pub(crate) async fn prime(ctx: &Context<'_>) -> (Vec<SocketAddr>, PrimingStatus) {
    let root = Name::root();
    for &hint in ctx.roots.iter().take(MAX_HINT_ATTEMPTS) {
        let resp = match ctx.query_server(hint, &root, RecordType::NS).await {
            Ok(Some(resp)) => resp,
            Ok(None) | Err(_) => continue,
        };
        if !resp.header.aa || resp.rcode() != Rcode::NOERROR {
            continue;
        }
        let ns_names: Vec<Name> = resp
            .answers
            .iter()
            .filter(|r| r.name.is_root())
            .filter_map(|r| match &r.rdata {
                RData::NS(n) => Some(n.clone()),
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
