//! Protected-domain engine.
//!
//! A server-side list of domains that MCP tools can never block, allow or
//! remove rules for (`SPEC-mcp.md` § Protected domains). The list is consumed
//! here; its derivation from the module configs lives in control-api.
//!
//! Every entry and every checked target is canonicalised the same way as
//! `filtering::build_rule`: one trailing dot is stripped, ASCII is lowercased
//! and IDNA input is converted to punycode. Comparison therefore happens on
//! canonical forms only.
//!
//! This module is pure logic: no I/O, no clock.

use crate::error::McpError;

/// A canonicalised set of protected domains.
///
/// The coverage rule is bidirectional (`SPEC-mcp.md` § Coverage rule): an
/// operation on `(target, include_subdomains)` is rejected when a protected
/// domain `P` is the target itself, when `P` is a strict subdomain of the
/// target and `include_subdomains` is true, or when the target is a strict
/// subdomain of `P` (regardless of the flag).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProtectedDomains {
    entries: Vec<String>,
}

impl ProtectedDomains {
    /// Canonicalise and store `entries`.
    ///
    /// # Errors
    ///
    /// Returns [`McpError::ConfigProtectedDomain`] for an empty or malformed
    /// entry. The error carries the entry as written plus the reason.
    pub fn new(entries: impl IntoIterator<Item = String>) -> Result<Self, McpError> {
        let entries = entries
            .into_iter()
            .map(|raw| {
                canonicalize(&raw).map_err(|reason| McpError::ConfigProtectedDomain {
                    domain: raw,
                    reason: reason.to_owned(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }

    /// The canonical protected entries, in insertion order.
    pub fn entries(&self) -> &[String] {
        &self.entries
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check `(target, include_subdomains)` against the coverage rule.
    ///
    /// Returns the matching protected entry (canonical form) when the
    /// operation must be rejected. A target that cannot be canonicalised is
    /// not a protected-domain hit; the domain validator rejects it earlier.
    pub fn check(&self, target: &str, include_subdomains: bool) -> Option<String> {
        let target = canonicalize(target).ok()?;
        self.entries
            .iter()
            .find(|protected| {
                covers(&target, include_subdomains, protected)
                    || is_strict_subdomain(&target, protected)
            })
            .cloned()
    }
}

/// `covers(D, S, N)` from `SPEC-mcp.md` § Coverage rule.
fn covers(domain: &str, include_subdomains: bool, name: &str) -> bool {
    name == domain || (include_subdomains && is_strict_subdomain(name, domain))
}

/// Whether `name` is a strict subdomain of `parent`, on a label boundary.
fn is_strict_subdomain(name: &str, parent: &str) -> bool {
    name.len() > parent.len()
        && name
            .strip_suffix(parent)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Canonical form: surrounding whitespace trimmed, one trailing dot stripped,
/// ASCII lowercased, punycode.
///
/// Mirrors `filtering::build_rule`'s canonicalisation. On failure returns the
/// filtering-namespace code (`filter_name.*`, `filter_rule.invalid_idna`), or
/// `filter_build.pattern_not_allowed` for a wildcard, regex, path, port,
/// scheme or IP-literal-shaped input, so callers forward the same codes the
/// config path reports.
pub(crate) fn canonicalize(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("filter_name.empty");
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("filter_name.invalid_char");
    }
    if raw
        .chars()
        .any(|c| matches!(c, '/' | ':' | '*' | '@' | '?' | '#' | '$' | '|' | '^'))
    {
        return Err("filter_build.pattern_not_allowed");
    }
    if raw.starts_with('.') || raw.contains("..") {
        return Err("filter_name.empty_label");
    }
    let without_dot = raw.strip_suffix('.').unwrap_or(raw);
    let ascii = idna::domain_to_ascii(without_dot).map_err(|_| "filter_rule.invalid_idna")?;
    let ascii = ascii.to_ascii_lowercase();
    if ascii.len() > 253 {
        return Err("filter_name.too_long");
    }
    for label in ascii.split('.') {
        if label.len() > 63 {
            return Err("filter_name.label_too_long");
        }
        if label.is_empty()
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("filter_name.invalid_char");
        }
    }
    Ok(ascii)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn protected(entries: &[&str]) -> ProtectedDomains {
        ProtectedDomains::new(entries.iter().map(|entry| (*entry).to_owned())).unwrap()
    }

    #[test]
    fn canonicalize_trims_and_reports_filtering_codes() {
        // GM17: surrounding whitespace is trimmed, inner whitespace is not.
        assert_eq!(canonicalize("  Example.COM.\n").unwrap(), "example.com");
        assert_eq!(
            canonicalize("example.com\nIGNORE").unwrap_err(),
            "filter_name.invalid_char"
        );
        // GM8: the forwarded codes match the filtering crate's namespace.
        assert_eq!(canonicalize("").unwrap_err(), "filter_name.empty");
        assert_eq!(
            canonicalize("*.example.com").unwrap_err(),
            "filter_build.pattern_not_allowed"
        );
        assert_eq!(
            canonicalize("example.com/path").unwrap_err(),
            "filter_build.pattern_not_allowed"
        );
        assert_eq!(
            canonicalize("-com").unwrap_err(),
            "filter_name.invalid_char"
        );
    }

    #[test]
    fn equal_target_is_rejected_with_both_flags() {
        let list = protected(&["example.net"]);
        for flag in [true, false] {
            assert_eq!(
                list.check("example.net", flag).as_deref(),
                Some("example.net"),
                "include_subdomains = {flag}"
            );
        }
    }

    #[test]
    fn ancestor_target_is_rejected_only_with_include_subdomains() {
        let list = protected(&["auth.example.net"]);
        assert_eq!(
            list.check("example.net", true).as_deref(),
            Some("auth.example.net")
        );
        assert!(list.check("example.net", false).is_none());
    }

    #[test]
    fn descendant_target_is_rejected_with_both_flags() {
        let list = protected(&["example.net"]);
        for flag in [true, false] {
            assert_eq!(
                list.check("auth.example.net", flag).as_deref(),
                Some("example.net"),
                "include_subdomains = {flag}"
            );
        }
    }

    #[test]
    fn sibling_target_is_accepted() {
        let list = protected(&["auth.example.net"]);
        assert!(list.check("other.example.net", true).is_none());
        assert!(list.check("other.example.net", false).is_none());
    }

    #[test]
    fn comparison_uses_label_boundaries() {
        let list = protected(&["example.net"]);
        assert!(list.check("notexample.net", true).is_none());
        assert!(list.check("notexample.net", false).is_none());
        assert!(list.check("example.network", true).is_none());
    }

    #[test]
    fn canonicalisation_matches_case_trailing_dot_and_punycode() {
        let list = protected(&["xn--bcher-kva.example"]);
        for target in [
            "xn--bcher-kva.example",
            "XN--BCHER-KVA.EXAMPLE.",
            "bücher.example",
            "BÜCHER.EXAMPLE.",
        ] {
            assert_eq!(
                list.check(target, true).as_deref(),
                Some("xn--bcher-kva.example"),
                "{target}"
            );
        }
        assert_eq!(list.entries(), ["xn--bcher-kva.example"]);
    }

    #[test]
    fn canonicalisation_accepts_underscore_labels() {
        assert_eq!(
            canonicalize("_dmarc.Example.COM."),
            Ok("_dmarc.example.com".into())
        );
    }

    #[test]
    fn invalid_and_empty_entries_are_rejected_at_construction() {
        for entry in [
            "",
            "https://example.com",
            "example.com/path",
            "*.example.com",
            "example..com",
            ".example.com",
            "exa mple.com",
            "-example.com",
            "example.com:443",
        ] {
            let error = ProtectedDomains::new([entry.to_owned()]).unwrap_err();
            assert_eq!(error.code(), "mcp.config.protected_domain", "{entry}");
            assert_eq!(error.params().unwrap()["domain"], entry);
        }
    }

    #[test]
    fn empty_list_accepts_everything() {
        let list = ProtectedDomains::new(std::iter::empty()).unwrap();
        assert!(list.is_empty());
        assert!(list.check("example.com", true).is_none());
    }

    #[test]
    fn invalid_target_is_not_a_protected_hit() {
        let list = protected(&["example.net"]);
        assert!(list.check("bad target", true).is_none());
        assert!(list.check("", true).is_none());
    }

    proptest! {
        #[test]
        fn check_is_insensitive_to_case_and_trailing_dot(
            label in "[a-z]{1,10}",
            tld in "[a-z]{2,6}",
        ) {
            let name = format!("{label}.{tld}.example");
            let list = protected(&[&name]);
            let upper = format!("{}.", name.to_ascii_uppercase());
            prop_assert_eq!(list.check(&name, true), list.check(&upper, true));
            prop_assert_eq!(list.check(&name, false), list.check(&upper, false));
        }

        #[test]
        fn a_descendant_is_never_accepted_when_its_ancestor_is_protected(
            protected_name in "[a-z]{1,10}\\.[a-z]{2,6}\\.example",
            label in "[a-z]{1,10}",
        ) {
            let list = protected(&[&protected_name]);
            let descendant = format!("{label}.{protected_name}");
            prop_assert!(list.check(&descendant, true).is_some());
            prop_assert!(list.check(&descendant, false).is_some());
        }

        #[test]
        fn unicode_and_punycode_targets_behave_identically(
            flag in any::<bool>(),
        ) {
            let list = protected(&["xn--bcher-kva.example"]);
            prop_assert_eq!(
                list.check("bücher.example", flag),
                list.check("xn--bcher-kva.example", flag)
            );
            prop_assert_eq!(
                list.check("shop.bücher.example", flag),
                list.check("shop.xn--bcher-kva.example", flag)
            );
        }
    }
}
