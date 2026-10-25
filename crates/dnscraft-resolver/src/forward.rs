//! Stub forwarding of configured zones.
//!
//! A query covered by a [`ForwardZone`](crate::ForwardZone) is sent to that
//! zone's targets with RD set, in smoothed-RTT order, instead of being
//! resolved from the root. The most specific configured zone wins.
//! `validate = false` is an implicit negative trust anchor: the answer is
//! `Insecure`, the AD bit stays clear, and the records are not checked.
//! `validate = true` checks positive RRsets in the zone against DNSKEY
//! material fetched from the same targets and a trust anchor for the zone
//! apex. Denial of existence is not reconstructed from a stub answer; a
//! response with no in-zone answer RRset stays `Indeterminate` when
//! validation is on. A signature failure or a missing anchor is `Bogus`.
//!
//! Loop protection: when the peer that asked this question is itself one of
//! the zone's forward targets (passed as [`RequestFlags::client`](crate::RequestFlags::client)),
//! resolution returns [`ResolveError::ForwardLoop`](crate::ResolveError::ForwardLoop)
//! instead of forwarding again. That is the misconfiguration where the remote
//! side forwards back to this resolver. Concurrent clients still coalesce on
//! the same in-flight forward; only a peer that is a configured target is
//! refused. The check compares addresses, so `RequestFlags::client` must be the
//! real peer address. A loop through NAT is not recognised; it ends when the
//! upstream query times out (`query_timeout`), so it is bounded but slow.
//!
//! Failover: a target that times out, or answers with anything other than
//! NOERROR or NXDOMAIN (SERVFAIL, REFUSED, FORMERR, NOTIMP), is skipped and the
//! next target is tried. When every target fails that way the last error
//! response is returned to the client as it is.

use std::net::SocketAddr;

use dnscraft_proto::{Message, Name, Rcode, Record, RecordType};

use crate::config::ForwardZone;
use crate::dnssec::status::{BogusReason, Status, rrsets};
use crate::dnssec::{
    ChainFailure, DelegationTrust, KeysOutcome, validate_dnskey_rrset, validate_rrset,
};
use crate::error::ResolveError;
use crate::types::RequestFlags;
use crate::{Shared, transport};

/// The most specific configured zone that contains `name`, if any.
///
/// When two zones share the same label count (unusual), the later entry in
/// `zones` wins (`Iterator::max_by_key` keeps the last maximum).
pub(crate) fn covering<'a>(zones: &'a [ForwardZone], name: &Name) -> Option<&'a ForwardZone> {
    zones
        .iter()
        .filter(|zone| zone.zone.zone_of(name))
        .max_by_key(|zone| zone.zone.label_count())
}

impl Shared {
    /// One stub query to `targets`. An empty list or no usable answer is
    /// [`ResolveError::Unreachable`] for `zone`.
    pub(crate) async fn exchange_forward(
        &self,
        targets: &[SocketAddr],
        zone: &Name,
        name: &Name,
        qtype: RecordType,
    ) -> Result<Message, ResolveError> {
        if targets.is_empty() {
            return Err(ResolveError::Unreachable { zone: zone.clone() });
        }
        self.counters
            .outgoing()
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let query = transport::build_forward_query(name, qtype);
        // Only NOERROR and NXDOMAIN end the search. A target that answers
        // SERVFAIL, REFUSED, FORMERR or NOTIMP is as useless as a silent one,
        // so the next target is tried. When every target answered with such
        // an error, the last one is passed on unchanged.
        let accept =
            |message: &Message| matches!(message.rcode(), Rcode::NOERROR | Rcode::NXDOMAIN);
        match transport::query_servers_with(
            targets,
            &query,
            self.config.query_timeout,
            &self.stats,
            accept,
        )
        .await
        {
            Ok(resp) => Ok(resp.message),
            Err(transport::TransportError::Encode(err)) => Err(ResolveError::Encode(err)),
            Err(err) => {
                tracing::debug!(qname = %name, qtype = %qtype, zone = %zone, error = %err, "forward failed");
                Err(ResolveError::Unreachable { zone: zone.clone() })
            }
        }
    }

    /// DNSSEC status of a stub answer.
    ///
    /// `validate == false` is always `Insecure`. Otherwise CD, or no trust
    /// anchors at all, yields `Indeterminate` (validation is off), matching
    /// a recursive answer. With validation on, the zone apex must have a
    /// trust anchor; DNSKEY is fetched from the same targets and positive
    /// in-zone RRsets are checked against it. A response with nothing to
    /// check stays `Indeterminate` — a stub answer does not carry a denial
    /// proof this resolver rebuilds.
    pub(crate) async fn forwarded_status(
        &self,
        zone: &ForwardZone,
        flags: RequestFlags,
        message: &Message,
    ) -> Result<Status, ResolveError> {
        if !zone.validate {
            return Ok(Status::Insecure);
        }
        let validating =
            !flags.checking_disabled && !self.config.trust_anchors.anchors().is_empty();
        if !validating {
            return Ok(Status::Indeterminate);
        }
        if !self.config.trust_anchors.has_zone(&zone.zone) {
            return Ok(Status::Bogus(BogusReason::Chain(
                ChainFailure::NoTrustAnchor,
            )));
        }
        tracing::debug!(zone = %zone.zone, "validating forwarded answer");
        let keys_msg = match self
            .exchange_forward(&zone.targets, &zone.zone, &zone.zone, RecordType::DNSKEY)
            .await
        {
            Ok(message) => message,
            Err(ResolveError::Unreachable { .. }) => {
                return Ok(Status::Bogus(BogusReason::DnskeyUnavailable));
            }
            Err(err) => return Err(err),
        };
        let keys = match validate_dnskey_rrset(
            &zone.zone,
            &keys_msg.answers,
            &keys_msg.answers,
            DelegationTrust::Anchors(&self.config.trust_anchors),
            self.config.clock.now(),
        ) {
            Ok(KeysOutcome::Secure(keys)) => keys,
            Ok(KeysOutcome::Insecure(_)) => return Ok(Status::Insecure),
            Err(err) => return Ok(Status::Bogus(BogusReason::Chain(err))),
        };
        let now = self.config.clock.now();
        let mut saw = false;
        for set in rrsets(&message.answers, &zone.zone, |_| true) {
            let owned: Vec<Record> = set.into_iter().cloned().collect();
            if let Err(err) = validate_rrset(&owned, &message.answers, &keys, now) {
                return Ok(Status::Bogus(BogusReason::Verify(err)));
            }
            saw = true;
        }
        if saw {
            Ok(Status::Secure)
        } else {
            Ok(Status::Indeterminate)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::config::ForwardZone;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn zone(text: &str) -> ForwardZone {
        ForwardZone {
            zone: name(text),
            targets: vec![SocketAddr::from(([127, 0, 0, 1], 53))],
            validate: false,
        }
    }

    #[test]
    fn most_specific_zone_wins() {
        let zones = vec![
            zone("internal."),
            zone("corp.internal."),
            zone("other.internal."),
        ];
        let hit = covering(&zones, &name("www.corp.internal.")).unwrap();
        assert_eq!(hit.zone, name("corp.internal."));
        assert_eq!(
            covering(&zones, &name("corp.internal.")).unwrap().zone,
            name("corp.internal.")
        );
        assert_eq!(
            covering(&zones, &name("internal.")).unwrap().zone,
            name("internal.")
        );
        assert!(covering(&zones, &name("example.test.")).is_none());
        assert!(covering(&[], &name("www.corp.internal.")).is_none());
    }
}
