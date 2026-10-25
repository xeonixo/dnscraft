//! SNI helpers for encrypted DNS listeners.
//!
//! Listeners use [`parse_client_id_sni`] and [`accept_public_sni`] to decide
//! whether a public handshake may proceed. This crate does **not** own the
//! Client-ID registry; callers pass a [`ClientIdRegistry`].
//!
//! ## Ban strikes
//!
//! [`SniKind::NodeHostname`] and [`SniKind::Apex`] are rejected by
//! [`accept_public_sni`] on a public listener, but they carry **no** Client ID.
//! The listener must **not** count them as an unknown-ID ban strike — only a
//! [`SniKind::ClientId`] that fails the registry check is an unknown ID.

use std::collections::HashSet;

/// Fixed labels that are never Client IDs, in addition to configured node names.
pub const FIXED_RESERVED_LABELS: &[&str] = &["dns", "www", "api", "admin", "ns"];

/// Labels that are never Client IDs: configured node names plus
/// [`FIXED_RESERVED_LABELS`].
///
/// Cheap to clone (`HashSet` of lower-case labels). Client-ID registration
/// (policy / control-api) must reject IDs that collide with a reserved label.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ReservedLabels {
    labels: HashSet<String>,
}

impl ReservedLabels {
    /// Builds the set from configured node names plus the fixed reserved set.
    ///
    /// Node names are normalised to lower-case; empty and dotted names are
    /// ignored (callers should validate config separately).
    pub fn new(node_names: impl IntoIterator<Item = String>) -> Self {
        let mut labels = HashSet::new();
        for fixed in FIXED_RESERVED_LABELS {
            labels.insert((*fixed).to_owned());
        }
        for name in node_names {
            let label = name.trim().to_ascii_lowercase();
            if label.is_empty() || label.contains('.') {
                continue;
            }
            labels.insert(label);
        }
        Self { labels }
    }

    /// Returns true if `label` is reserved (case-insensitive).
    pub fn contains(&self, label: &str) -> bool {
        self.labels.contains(&label.to_ascii_lowercase())
    }
}

/// Classification of a TLS SNI name relative to `dns.<public_domain>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SniKind<'a> {
    /// `<id>.dns.<public_domain>` where `<id>` is not reserved.
    ClientId(&'a str),
    /// `<reserved>.dns.<public_domain>` (e.g. a node hostname).
    ///
    /// Rejected on public listeners, but **not** an unknown Client-ID strike.
    NodeHostname,
    /// Exactly `dns.<public_domain>`.
    ///
    /// Rejected on public listeners, but **not** an unknown Client-ID strike.
    Apex,
    /// Missing under the domain, too many labels, or unrelated name.
    Other,
}

/// Registry of registered Client IDs (owned by policy / control-api).
pub trait ClientIdRegistry: Send + Sync {
    /// Returns true if `client_id` is a registered DoH/DoT Client ID.
    fn is_registered(&self, client_id: &str) -> bool;
}

/// Classifies `sni` relative to `dns.<public_domain>`.
///
/// Matching is case-insensitive; a single trailing dot is accepted. Only
/// exactly one label below `dns.<domain>` can be a Client ID —
/// `a.b.dns.<domain>` is [`SniKind::Other`].
pub fn parse_client_id_sni<'a>(
    sni: &'a str,
    public_domain: &str,
    reserved: &ReservedLabels,
) -> SniKind<'a> {
    let sni = strip_trailing_dot(sni);
    let domain = strip_trailing_dot(public_domain);
    if sni.is_empty() || domain.is_empty() {
        return SniKind::Other;
    }

    let dns_prefix = "dns.";
    // Expected apex: "dns." + domain (compared case-insensitively).
    let apex_len = dns_prefix.len() + domain.len();
    if sni.len() == apex_len && eq_ignore_ascii_case(sni, dns_prefix, domain) {
        return SniKind::Apex;
    }

    // Client / node: "<label>.dns.<domain>"
    let Some((label, rest)) = sni.split_once('.') else {
        return SniKind::Other;
    };
    if label.is_empty() || label.contains('.') {
        return SniKind::Other;
    }
    // rest must be exactly "dns.<domain>" (one label "dns" then the domain).
    let Some((dns_label, rest_domain)) = rest.split_once('.') else {
        return SniKind::Other;
    };
    if !dns_label.eq_ignore_ascii_case("dns") {
        return SniKind::Other;
    }
    if !rest_domain.eq_ignore_ascii_case(domain) {
        return SniKind::Other;
    }
    // Reject multi-label under dns (e.g. a.b.dns.example.com): the first split
    // already took one label; if rest_domain equals domain we have exactly one.
    // Suffix tricks like dns.example.com.evil.net fail the domain equality.

    if reserved.contains(label) {
        SniKind::NodeHostname
    } else {
        SniKind::ClientId(label)
    }
}

/// Hook for public listeners: unknown or missing Client ID → reject handshake.
///
/// - Missing SNI, [`SniKind::Apex`], [`SniKind::NodeHostname`], [`SniKind::Other`]
///   → `false` (no Client ID to accept).
/// - [`SniKind::ClientId`] → `true` only when registered.
///
/// **Ban strikes:** Apex and NodeHostname must **not** be counted as an
/// unknown Client-ID strike by the caller — only an unregistered
/// [`SniKind::ClientId`] is an unknown ID.
pub fn accept_public_sni(
    sni: Option<&str>,
    public_domain: &str,
    reserved: &ReservedLabels,
    registry: &dyn ClientIdRegistry,
) -> bool {
    let Some(sni) = sni else {
        return false;
    };
    match parse_client_id_sni(sni, public_domain, reserved) {
        SniKind::ClientId(id) => registry.is_registered(id),
        SniKind::NodeHostname | SniKind::Apex | SniKind::Other => false,
    }
}

fn strip_trailing_dot(s: &str) -> &str {
    s.strip_suffix('.').unwrap_or(s)
}

/// `sni == prefix + domain` ignoring ASCII case, without allocating.
fn eq_ignore_ascii_case(sni: &str, prefix: &str, domain: &str) -> bool {
    if sni.len() != prefix.len() + domain.len() {
        return false;
    }
    let (head, tail) = sni.split_at(prefix.len());
    head.eq_ignore_ascii_case(prefix) && tail.eq_ignore_ascii_case(domain)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn fixed_labels_always_reserved() {
        let r = ReservedLabels::new(std::iter::empty());
        for label in FIXED_RESERVED_LABELS {
            assert!(r.contains(label), "{label}");
            assert!(r.contains(&label.to_ascii_uppercase()), "{label}");
        }
    }

    #[test]
    fn node_names_are_reserved() {
        let r = ReservedLabels::new(["Node1".into(), "node2".into()]);
        assert!(r.contains("node1"));
        assert!(r.contains("NODE2"));
        assert!(!r.contains("phone"));
    }
}
