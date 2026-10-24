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
//! refused.

use dnscraft_proto::Name;

use crate::config::ForwardZone;

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
