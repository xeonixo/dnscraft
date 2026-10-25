//! Integration / table / proptest coverage for DNS label normalisation.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use dnscraft_clients::{ClientId, MAX_LABEL_LEN, fqdn, normalise_label, suffixed};
use proptest::prelude::*;

fn id(s: &str) -> ClientId {
    ClientId::new(s).expect("id")
}

/// Labels must be a single DNS label: 1–63 chars, `[a-z0-9-]` with no leading
/// or trailing hyphen (and therefore no lone hyphen).
fn is_valid_label(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > MAX_LABEL_LEN {
        return false;
    }
    if !b[0].is_ascii_alphanumeric() || !b[b.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

#[test]
fn table_cases() {
    let cases: &[(&str, &str, &str)] = &[
        ("Docker on server1", "m1", "docker-on-server1"),
        ("Büro", "x", "bro"),
        ("Ｄocker", "x", "docker"),
        ("o\u{fb03}ce", "x", "office"),
        ("--foo__bar--", "x", "foo-bar"),
        ("  hello   world  ", "x", "hello-world"),
        ("paperless", "m2", "paperless"),
    ];
    for &(display, cid, expect) in cases {
        assert_eq!(
            normalise_label(display, &id(cid)),
            expect,
            "display={display:?}"
        );
        assert!(is_valid_label(expect), "{expect}");
    }
}

#[test]
fn emoji_only_becomes_client_suffix() {
    let label = normalise_label("📱💻", &id("deadbeef-cafe-0001"));
    assert!(label.starts_with("client-"), "{label}");
    assert!(is_valid_label(&label), "{label}");
}

#[test]
fn eighty_char_name_fits() {
    let label = normalise_label(&"a".repeat(80), &id("long-1"));
    assert!(label.len() <= MAX_LABEL_LEN);
    assert!(is_valid_label(&label), "{label}");
}

#[test]
fn suffixed_differs_and_fits() {
    let a = suffixed("phone", &id("aaa"));
    let b = suffixed("phone", &id("bbb"));
    assert_ne!(a, b);
    assert!(is_valid_label(&a));
    assert!(is_valid_label(&b));
    let long = suffixed(&"z".repeat(60), &id("z"));
    assert!(is_valid_label(&long), "{long}");
}

#[test]
fn fqdn_joins_normalised_domain() {
    assert_eq!(fqdn("phone", "Home.ARPA.").unwrap(), "phone.home.arpa");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn normalise_label_always_valid(
        display in ".*",
        cid in "[a-z0-9-]{1,36}"
    ) {
        let id = ClientId::new(&cid).unwrap();
        let label = normalise_label(&display, &id);
        prop_assert!(
            is_valid_label(&label),
            "display={display:?} → {label:?}"
        );
    }

    #[test]
    fn suffixed_always_valid(
        label in "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?",
        cid in "[a-z0-9-]{1,36}"
    ) {
        let id = ClientId::new(&cid).unwrap();
        let out = suffixed(&label, &id);
        prop_assert!(is_valid_label(&out), "base={label:?} → {out:?}");
        prop_assert!(out.len() <= MAX_LABEL_LEN);
    }
}
