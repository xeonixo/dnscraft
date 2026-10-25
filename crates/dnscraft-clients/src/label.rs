//! DNS label normalisation and FQDN building for client names.
//!
//! Implements SPEC-clients.md § Name normalisation. The left-most label of
//! `<device>.<local-domain>` is folded with UTS 46, scrubbed to `[a-z0-9-]`,
//! and kept ≤ 63 octets.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::config::normalise_domain;
use crate::error::ClientsError;
use crate::types::ClientId;

/// Maximum DNS label length in octets (RFC 1035).
pub const MAX_LABEL_LEN: usize = 63;

/// Length of the short id / hash suffix used in fallback and collision labels.
const SUFFIX_LEN: usize = 8;

/// Normalises a display name into a single DNS label.
///
/// Steps (SPEC-clients.md):
/// 1. UTS 46 compatibility mapping via `idna`, then lower-case.
/// 2. Spaces and `_` → `-`; strip anything outside `[a-z0-9-]`.
/// 3. Collapse repeated `-`; trim leading/trailing `-`.
/// 4. Empty → `client-<id8>`.
/// 5. Longer than 63 octets → truncate at a hyphen when possible, then a hash suffix.
pub fn normalise_label(display: &str, id: &ClientId) -> String {
    let mapped = uts46_map(display);
    let scrubbed = scrub_label(&mapped);
    if scrubbed.is_empty() {
        return format!("client-{}", id_suffix8(id));
    }
    fit_label(&scrubbed, id)
}

/// Returns true when `label` is something [`normalise_label`] can produce:
/// `[a-z0-9-]{1,63}` with no leading or trailing hyphen.
pub fn is_normalised_label(label: &str) -> bool {
    if label.is_empty() || label.len() > MAX_LABEL_LEN {
        return false;
    }
    if label.as_bytes().first() == Some(&b'-') || label.as_bytes().last() == Some(&b'-') {
        return false;
    }
    label
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// Builds `<label>.<domain>` with the parent domain converted via UTS 46.
///
/// `label` must already be a normalised single DNS label (see
/// [`is_normalised_label`]); this rejects dots, upper case, and other bytes
/// so a tampered cache cannot leak into FQDNs / PTR names.
pub fn fqdn(label: &str, domain: &str) -> Result<String, ClientsError> {
    let domain = normalise_domain(domain)?;
    if domain.is_empty() {
        return Err(ClientsError::config("fqdn domain is empty"));
    }
    if !is_normalised_label(label) {
        return Err(ClientsError::config(
            "fqdn label is not a normalised DNS label",
        ));
    }
    Ok(format!("{label}.{domain}"))
}

/// Returns `{label}-{id_suffix8}`, truncated so the result still fits in 63 octets.
///
/// Used when a first-seen label collides and a newcomer must be re-labelled.
pub fn suffixed(label: &str, id: &ClientId) -> String {
    let suffix = id_suffix8(id);
    // `{base}-{suffix}` needs room for '-' + 8.
    let budget = MAX_LABEL_LEN.saturating_sub(SUFFIX_LEN + 1);
    let base = truncate_at_hyphen(label, budget);
    let base = base.trim_end_matches('-');
    if base.is_empty() {
        format!("client-{suffix}")
    } else {
        format!("{base}-{suffix}")
    }
}

/// First 8 hex characters of a stable hash of the client id.
fn id_suffix8(id: &ClientId) -> String {
    let mut h = DefaultHasher::new();
    id.as_str().hash(&mut h);
    let n = h.finish();
    format!("{n:016x}")[..SUFFIX_LEN].to_owned()
}

/// Short hash of the scrubbed label content (for long-name uniqueness).
fn content_hash8(label: &str) -> String {
    let mut h = DefaultHasher::new();
    label.hash(&mut h);
    let n = h.finish();
    format!("{n:016x}")[..SUFFIX_LEN].to_owned()
}

fn uts46_map(input: &str) -> String {
    // ToUnicode applies UTS 46 mapping (full-width → ASCII, ligatures, case
    // fold) without Punycode-encoding remaining non-ASCII. Scrub then keeps
    // only `[a-z0-9-]`, so umlauts drop out and emoji-only labels become empty
    // → `client-<id8>`. Always succeeds with a string (errors appear as U+FFFD).
    let (mapped, _) = idna::domain_to_unicode(input);
    mapped.to_ascii_lowercase()
}

fn scrub_label(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut last_hyphen = false;
    for c in input.chars() {
        let mapped = match c {
            ' ' | '_' => Some('-'),
            c if c.is_ascii_lowercase() || c.is_ascii_digit() => Some(c),
            '-' => Some('-'),
            _ => None,
        };
        match mapped {
            Some('-') => {
                if !last_hyphen && !out.is_empty() {
                    out.push('-');
                    last_hyphen = true;
                }
            }
            Some(ch) => {
                out.push(ch);
                last_hyphen = false;
            }
            None => {}
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out
}

fn fit_label(scrubbed: &str, id: &ClientId) -> String {
    if scrubbed.len() <= MAX_LABEL_LEN {
        return scrubbed.to_owned();
    }
    // Truncate, then append `-<hash8>` derived from the full scrubbed form so
    // two long names that share a prefix stay distinct.
    let hash = content_hash8(scrubbed);
    let budget = MAX_LABEL_LEN.saturating_sub(SUFFIX_LEN + 1);
    let base = truncate_at_hyphen(scrubbed, budget);
    let base = base.trim_end_matches('-');
    if base.is_empty() {
        // Extremely pathological; fall back to id-based label.
        format!("client-{}", id_suffix8(id))
    } else {
        format!("{base}-{hash}")
    }
}

/// Truncates `s` to at most `max` octets, preferring a hyphen boundary.
fn truncate_at_hyphen(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let cut = &s[..max];
    if let Some(i) = cut.rfind('-') {
        // Keep something useful: at least one character before the hyphen.
        if i > 0 {
            return &cut[..i];
        }
    }
    cut
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn id(s: &str) -> ClientId {
        ClientId::new(s).unwrap()
    }

    #[test]
    fn docker_on_server1() {
        assert_eq!(
            normalise_label("Docker on server1", &id("m1")),
            "docker-on-server1"
        );
    }

    #[test]
    fn umlauts_and_fullwidth() {
        // Umlauts are not ASCII-folded by non-transitional UTS 46; scrub drops
        // them (Büro → bro). Full-width Ｄ maps to D → d.
        assert_eq!(normalise_label("Büro", &id("x")), "bro");
        assert_eq!(normalise_label("Ｄocker", &id("x")), "docker");
    }

    #[test]
    fn ligature_ffi() {
        // U+FB03 LATIN SMALL LIGATURE FFI → ffi under UTS 46.
        assert_eq!(normalise_label("o\u{fb03}ce", &id("x")), "office");
    }

    #[test]
    fn emoji_only_falls_back_to_client_id() {
        let label = normalise_label("📱💻", &id("deadbeef-cafe-0001"));
        assert!(label.starts_with("client-"), "{label}");
        assert_eq!(label.len(), "client-".len() + SUFFIX_LEN);
    }

    #[test]
    fn long_name_truncated_with_hash() {
        let long = "a".repeat(80);
        let label = normalise_label(&long, &id("long-1"));
        assert!(label.len() <= MAX_LABEL_LEN, "{label}");
        assert!(label.contains('-'), "{label}");
        // Different content → different hash suffix.
        let other = format!("{}b", "a".repeat(79));
        let label2 = normalise_label(&other, &id("long-1"));
        assert_ne!(label, label2);
    }

    #[test]
    fn hyphens_collapsed_and_trimmed() {
        assert_eq!(normalise_label("--foo__bar--", &id("x")), "foo-bar");
        assert_eq!(
            normalise_label("  hello   world  ", &id("x")),
            "hello-world"
        );
    }

    #[test]
    fn suffixed_fits_and_differs() {
        let a = suffixed("phone", &id("id-aaa"));
        let b = suffixed("phone", &id("id-bbb"));
        assert_ne!(a, b);
        assert!(a.len() <= MAX_LABEL_LEN);
        assert!(b.len() <= MAX_LABEL_LEN);
        assert!(a.starts_with("phone-"));
    }

    #[test]
    fn suffixed_truncates_long_base() {
        let long = "a".repeat(60);
        let s = suffixed(&long, &id("z"));
        assert!(s.len() <= MAX_LABEL_LEN, "{s} len={}", s.len());
        assert!(s.contains('-'));
    }

    #[test]
    fn fqdn_normalises_domain() {
        assert_eq!(fqdn("phone", "Home.ARPA.").unwrap(), "phone.home.arpa");
    }

    #[test]
    fn fqdn_rejects_non_normalised_labels() {
        for bad in ["evil.example", "UPPER", "-x", "x-", &"a".repeat(64), "büro"] {
            assert!(fqdn(bad, "home.arpa").is_err(), "{bad}");
        }
        assert!(is_normalised_label("phone"));
        assert!(!is_normalised_label("evil.example"));
    }
}
