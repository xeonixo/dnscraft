//! Negative trust anchors (RFC 7646): domains below which validation is
//! skipped, for operators working around a broken signed zone.

use dnscraft_proto::Name;

/// Whether `name` is at or below one of the negative trust anchors `ntas`.
pub(crate) fn covers(ntas: &[Name], name: &Name) -> bool {
    ntas.iter().any(|nta| nta.zone_of(name))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    #[test]
    fn covers_the_domain_and_its_descendants_only() {
        let ntas = [n("Bogus.Example.")];
        assert!(covers(&ntas, &n("bogus.example.")));
        assert!(covers(&ntas, &n("www.bogus.example.")));
        assert!(!covers(&ntas, &n("example.")));
        assert!(!covers(&ntas, &n("other.example.")));
        assert!(!covers(&[], &n("example.")));
        assert!(covers(&[Name::root()], &n("example.")));
    }
}
