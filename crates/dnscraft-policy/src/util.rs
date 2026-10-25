//! Small shared helpers used by more than one pipeline step.

use dnscraft_filtering::{DomainName, Reason};
use dnscraft_proto::Name;

/// Maximum EXTRA-TEXT bytes for filter-derived EDE (before the ellipsis).
pub(crate) const EDE_TEXT_MAX: usize = 200;

/// Converts a wire name to a filtering [`DomainName`], or `None` if unsupported.
pub(crate) fn name_to_domain(name: &Name) -> Option<DomainName> {
    DomainName::parse(&name.to_string()).ok()
}

/// EXTRA-TEXT for a filter hit: the rule text, truncated on a char boundary.
pub(crate) fn ede_text(reason: &Reason) -> String {
    truncate_ede_text(reason.rule.as_ref())
}

/// Truncates `rule` to at most [`EDE_TEXT_MAX`] bytes on a UTF-8 boundary,
/// appending `…` when truncated. Never panics on multi-byte characters.
pub(crate) fn truncate_ede_text(rule: &str) -> String {
    if rule.len() <= EDE_TEXT_MAX {
        return rule.to_owned();
    }
    let mut end = EDE_TEXT_MAX;
    while end > 0 && !rule.is_char_boundary(end) {
        end -= 1;
    }
    let mut s = rule[..end].to_owned();
    s.push('…');
    s
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn truncate_on_multibyte_boundary_is_valid_utf8() {
        // `ä` starts at byte 199 so index 200 is mid-character → walk back.
        let head = "/^ads\\.example$|^";
        let pad = EDE_TEXT_MAX.saturating_sub(1).saturating_sub(head.len());
        let rule = format!("{head}{}äx$/", "x".repeat(pad));
        assert_eq!(head.len() + pad, EDE_TEXT_MAX - 1);
        assert!(rule.len() > EDE_TEXT_MAX);
        assert!(!rule.is_char_boundary(EDE_TEXT_MAX));
        let out = truncate_ede_text(&rule);
        assert!(out.ends_with('…'));
        assert!(std::str::from_utf8(out.as_bytes()).is_ok());
        let without_ellipsis = out.len() - '…'.len_utf8();
        assert!(without_ellipsis <= EDE_TEXT_MAX);
        assert!(rule.is_char_boundary(without_ellipsis));
    }

    #[test]
    fn name_to_domain_accepts_common_names() {
        assert_eq!(
            name_to_domain(&Name::from_ascii("Ads.Example.COM.").unwrap())
                .unwrap()
                .as_str(),
            "ads.example.com"
        );
    }
}
