//! Stub forwarding of configured zones.
//!
//! A query covered by a [`ForwardZone`](crate::ForwardZone) is sent to that
//! zone's targets with RD set, in smoothed-RTT order, instead of being
//! resolved from the root. The most specific configured zone wins.
//! [`RequestFlags::forward_zones`](crate::RequestFlags::forward_zones)
//! restricts that choice per query: `None` allows every configured zone, and
//! `Some` allows only the listed ids. A name with no allowed covering zone is
//! resolved from the root.
//! `validate = false` is an implicit negative trust anchor: the answer is
//! `Insecure`, the AD bit stays clear, and the records are not checked.
//! `validate = true` checks positive RRsets in the zone against DNSKEY
//! material fetched from the same targets and a trust anchor for the zone
//! apex. Denial of existence is not reconstructed from a stub answer; a
//! response with no in-zone answer RRset stays `Indeterminate` when
//! validation is on. A signature failure or a missing anchor is `Bogus`.
//!
//! The answer a target returns is rebuilt before it is used (see
//! [`scrub`]): only the RRsets of the CNAME/DNAME chain from the question
//! and the SOA/NSEC/NSEC3 records of a negative answer are kept, so records a
//! target (or someone on the path) adds for unrelated names never reach the
//! client or the cache.
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

use dnscraft_proto::{Message, Name, RData, Rcode, Record, RecordType};

use crate::config::{ForwardZone, ForwardZoneId};
use crate::dnssec::status::{BogusReason, Status, rrsets};
use crate::dnssec::walk::TtlCap;
use crate::dnssec::{
    ChainFailure, DelegationTrust, KeysOutcome, ValidationBudget, validate_dnskey_rrset_budgeted,
    validate_rrset_budgeted,
};
use crate::error::ResolveError;
use crate::types::{Query, RequestFlags, Route};
use crate::{Shared, transport};

/// Longest CNAME chain followed when scrubbing a forwarded answer.
const MAX_SCRUB_CHAIN: usize = 32;

/// Reduces a forwarded response to what answers the question
/// `qname`/`qtype`.
///
/// The answer section keeps the records owned by the names of the CNAME
/// chain that starts at `qname` (RRsets of the queried type and the CNAMEs
/// themselves, plus their RRSIGs) and the DNAMEs above those names. The
/// authority section keeps the SOA and NSEC/NSEC3 records (with RRSIGs) of a
/// negative answer; the additional section is emptied. Everything else,
/// whatever its owner, is dropped: a forwarder is trusted for the answer to
/// the question, not for unrelated names.
pub(crate) fn scrub(mut message: Message, qname: &Name, qtype: RecordType) -> Message {
    let mut names = vec![qname.clone()];
    let mut i = 0;
    while i < names.len() && names.len() < MAX_SCRUB_CHAIN {
        for r in &message.answers {
            if let RData::CNAME(target) = &r.rdata
                && r.rtype() == RecordType::CNAME
                && r.name == names[i]
                && !names.contains(target)
            {
                names.push(target.clone());
            }
        }
        i += 1;
    }
    let covered = |r: &Record| match &r.rdata {
        RData::RRSIG { type_covered, .. } if r.rtype() == RecordType::RRSIG => Some(*type_covered),
        _ if r.rtype() == RecordType::RRSIG => None,
        _ => Some(r.rtype()),
    };
    message.answers.retain(|r| {
        let Some(kind) = covered(r) else {
            return false;
        };
        if kind == RecordType::DNAME {
            return names.iter().any(|n| r.name != *n && r.name.zone_of(n));
        }
        names.contains(&r.name)
            && (qtype == RecordType::ANY || kind == RecordType::CNAME || kind == qtype)
    });
    message.authorities.retain(|r| match covered(r) {
        Some(RecordType::SOA) => names.iter().any(|n| r.name.zone_of(n)),
        Some(RecordType::NSEC | RecordType::NSEC3) => true,
        _ => false,
    });
    message.additionals.clear();
    message
}

/// Whether `allow` permits `zone` to forward.
///
/// `None` permits every zone. `Some` permits a zone only when its id is listed.
fn is_allowed(zone: &ForwardZone, allow: Option<&[ForwardZoneId]>) -> bool {
    match allow {
        None => true,
        Some(ids) => ids.iter().any(|id| id == &zone.id),
    }
}

/// Forward zones that apply to a query with this allow-list.
///
/// Passed to local-zone synthesis so a zone the query may not use does not
/// suppress a local answer.
pub(crate) fn allowed_names<'a>(
    zones: &'a [ForwardZone],
    allow: Option<&[ForwardZoneId]>,
) -> impl Iterator<Item = &'a Name> {
    zones
        .iter()
        .filter(move |zone| is_allowed(zone, allow))
        .map(|zone| &zone.zone)
}

/// The most specific allowed zone that contains `name`, if any.
///
/// `allow` is [`RequestFlags::forward_zones`](crate::RequestFlags::forward_zones):
/// `None` considers every configured zone, `Some` only the listed ids. When no
/// allowed zone covers `name`, the caller resolves from the root.
///
/// When two zones share the same label count (unusual), the later entry in
/// `zones` wins (`Iterator::max_by_key` keeps the last maximum).
pub(crate) fn covering<'a>(
    zones: &'a [ForwardZone],
    name: &Name,
    allow: Option<&[ForwardZoneId]>,
) -> Option<&'a ForwardZone> {
    zones
        .iter()
        .filter(|zone| zone.zone.zone_of(name) && is_allowed(zone, allow))
        .max_by_key(|zone| zone.zone.label_count())
}

/// Route of `query`: the most specific allowed forward zone, or recursion.
///
/// A class other than IN is always recursive. Forwarding is defined for IN.
pub(crate) fn route_for(
    zones: &[ForwardZone],
    query: &Query,
    allow: Option<&[ForwardZoneId]>,
) -> Route {
    if query.qclass != dnscraft_proto::Class::IN {
        return Route::Recursive;
    }
    match covering(zones, &query.name, allow) {
        Some(zone) => Route::Forward(zone.id.clone()),
        None => Route::Recursive,
    }
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
    /// proof this resolver rebuilds. The longest TTL of every validated
    /// RRset (RFC 4035 section 5.3.3) is appended to `caps`.
    pub(crate) async fn forwarded_status(
        &self,
        zone: &ForwardZone,
        flags: &RequestFlags,
        message: &Message,
        budget: &ValidationBudget,
        caps: &mut Vec<TtlCap>,
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
        let keys = match validate_dnskey_rrset_budgeted(
            &zone.zone,
            &keys_msg.answers,
            &keys_msg.answers,
            DelegationTrust::Anchors(&self.config.trust_anchors),
            self.config.clock.now(),
            budget,
        ) {
            Ok(KeysOutcome::Secure(keys)) => keys,
            Ok(KeysOutcome::Insecure(_)) => return Ok(Status::Insecure),
            Err(err) => return Ok(Status::Bogus(BogusReason::Chain(err))),
        };
        let now = self.config.clock.now();
        let mut saw = false;
        for set in rrsets(&message.answers, &zone.zone, |_| true) {
            let owned: Vec<Record> = set.into_iter().cloned().collect();
            match validate_rrset_budgeted(&owned, &message.answers, &keys, now, budget) {
                Ok(valid) => {
                    if let Some(first) = owned.first() {
                        caps.push(TtlCap {
                            name: first.name.clone(),
                            rtype: first.rtype(),
                            max_ttl: valid.max_ttl,
                        });
                    }
                }
                Err(err) => return Ok(Status::Bogus(BogusReason::Verify(err))),
            }
            saw = true;
        }
        // RRsets outside the zone (a CNAME target elsewhere) have no keys
        // here; the answer is not Secure as a whole.
        let outside = message
            .answers
            .iter()
            .any(|r| r.rtype() != RecordType::RRSIG && !zone.zone.zone_of(&r.name));
        if saw && !outside {
            Ok(Status::Secure)
        } else {
            Ok(Status::Indeterminate)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::config::ForwardZone;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn zone(text: &str) -> ForwardZone {
        let id = text.trim_end_matches('.').replace('.', "-");
        ForwardZone {
            id: ForwardZoneId::new(&id).unwrap(),
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
        let hit = covering(&zones, &name("www.corp.internal."), None).unwrap();
        assert_eq!(hit.zone, name("corp.internal."));
        assert_eq!(
            covering(&zones, &name("corp.internal."), None)
                .unwrap()
                .zone,
            name("corp.internal.")
        );
        assert_eq!(
            covering(&zones, &name("internal."), None).unwrap().zone,
            name("internal.")
        );
        assert!(covering(&zones, &name("example.test."), None).is_none());
        assert!(covering(&[], &name("www.corp.internal."), None).is_none());
    }

    #[test]
    fn allow_list_keeps_the_most_specific_permitted_zone() {
        let zones = vec![zone("internal."), zone("corp.internal.")];
        let parent = [ForwardZoneId::new("internal").unwrap()];
        let hit = covering(&zones, &name("www.corp.internal."), Some(&parent)).unwrap();
        assert_eq!(hit.id.as_str(), "internal");
        assert!(covering(&zones, &name("www.corp.internal."), Some(&[])).is_none());
        let child = [ForwardZoneId::new("corp-internal").unwrap()];
        assert_eq!(
            covering(&zones, &name("www.corp.internal."), Some(&child))
                .unwrap()
                .id
                .as_str(),
            "corp-internal"
        );
        let q = Query {
            name: name("www.corp.internal."),
            qtype: RecordType::A,
            qclass: dnscraft_proto::Class::IN,
        };
        assert_eq!(route_for(&zones, &q, Some(&[])), Route::Recursive);
        assert_eq!(
            route_for(&zones, &q, None),
            Route::Forward(ForwardZoneId::new("corp-internal").unwrap())
        );
    }

    #[tokio::test]
    async fn forwarded_validation_spends_one_shared_budget() {
        use crate::dnssec::{TrustAnchors, VerifyFailure};
        use crate::types::RequestFlags;
        use dnscraft_proto::{Class, RData};
        use dnscraft_testkit::{
            Hierarchy, ServerSpec, SigAlgorithm, SigningOptions, Zone, ZoneKey, sign_zone,
        };
        use hickory_proto::serialize::binary::BinEncodable;

        let origin = name("fz.test.");
        let key = ZoneKey::generate(SigAlgorithm::default()).unwrap();
        let zone = Zone::new("fz.test.")
            .unwrap()
            .with_soa("ns1.fz.test.", "hostmaster.fz.test.")
            .unwrap()
            .with_ns("fz.test.", "ns1.fz.test.")
            .unwrap()
            .with_a("ns1.fz.test.", std::net::Ipv4Addr::LOCALHOST)
            .unwrap()
            .with_a("www.fz.test.", std::net::Ipv4Addr::new(192, 0, 2, 7))
            .unwrap();
        let signed = sign_zone(zone, &key, &SigningOptions::now()).unwrap();
        let h = Hierarchy::start_with(vec![ServerSpec::new("ns1.fz.test.", signed).unwrap()])
            .await
            .unwrap();
        let target = h.server("fz.test.").unwrap().addr();
        let ds = key
            .ds(&dnscraft_testkit::parse_name("fz.test.").unwrap())
            .unwrap();
        let bytes = ds.to_bytes().unwrap();
        let anchors = TrustAnchors::from_records(&[Record {
            name: origin.clone(),
            class: Class::IN,
            ttl: 3600,
            rdata: RData::decode(&bytes, RecordType::DS, 0, bytes.len()).unwrap(),
        }])
        .unwrap();
        let fz = ForwardZone {
            id: ForwardZoneId::new("fz-test").unwrap(),
            zone: origin.clone(),
            targets: vec![target],
            validate: true,
        };
        let r = crate::Resolver::new(crate::ResolverConfig {
            root_hints: vec![target],
            trust_anchors: anchors,
            query_timeout: std::time::Duration::from_millis(500),
            forward_zones: vec![fz.clone()],
            ..crate::ResolverConfig::default()
        })
        .await
        .unwrap();
        let message = r
            .shared
            .exchange_forward(&fz.targets, &origin, &name("www.fz.test."), RecordType::A)
            .await
            .unwrap();
        let flags = RequestFlags::default();
        let mut caps = Vec::new();
        let status = r
            .shared
            .forwarded_status(
                &fz,
                &flags,
                &message,
                &ValidationBudget::default(),
                &mut caps,
            )
            .await
            .unwrap();
        assert_eq!(status, Status::Secure);
        assert_eq!(caps.len(), 1);
        // The DNSKEY RRset and the answer RRset are checked against the same
        // budget: with room for one verification the second one fails.
        let status = r
            .shared
            .forwarded_status(
                &fz,
                &flags,
                &message,
                &ValidationBudget::with_limits(1, 1),
                &mut Vec::new(),
            )
            .await
            .unwrap();
        assert_eq!(
            status,
            Status::Bogus(BogusReason::Verify(VerifyFailure::BudgetExhausted))
        );
    }
}
