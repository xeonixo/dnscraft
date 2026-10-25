#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscraft_filtering::{
    BuildError, MatchKind, RecordTypeSel, RewriteSpec, RuleAction, RuleSpec, build_rule,
    describe_rule, parse_rule,
};
use proptest::prelude::*;

fn spec(action: RuleAction, domain: &str) -> RuleSpec {
    RuleSpec {
        action,
        domain: domain.to_string(),
        include_subdomains: true,
        record_types: RecordTypeSel::default(),
        important: false,
        rewrite: None,
    }
}

fn block(domain: &str) -> RuleSpec {
    spec(RuleAction::Block, domain)
}

fn built(s: &RuleSpec) -> String {
    build_rule(s).unwrap_or_else(|e| panic!("{s:?}: {e} ({})", e.code()))
}

fn code(s: &RuleSpec) -> &'static str {
    build_rule(s).expect_err("must be rejected").code()
}

#[test]
fn basic_forms() {
    assert_eq!(built(&block("example.com")), "||example.com^");
    let mut s = block("example.com");
    s.include_subdomains = false;
    assert_eq!(built(&s), "|example.com^");
    s.action = RuleAction::Allow;
    assert_eq!(built(&s), "@@|example.com^");
    s.include_subdomains = true;
    assert_eq!(built(&s), "@@||example.com^");
}

#[test]
fn each_option() {
    let mut s = block("a.example");
    s.important = true;
    assert_eq!(built(&s), "||a.example^$important");

    let mut s = block("a.example");
    s.record_types = RecordTypeSel {
        types: vec![28, 1, 1, 65, 999],
        negated: false,
    };
    assert_eq!(built(&s), "||a.example^$dnstype=A|AAAA|HTTPS|TYPE999");
    s.record_types.negated = true;
    assert_eq!(built(&s), "||a.example^$dnstype=~A|~AAAA|~HTTPS|~TYPE999");

    let rewrites = [
        (RewriteSpec::Refused, "REFUSED"),
        (RewriteSpec::NxDomain, "NXDOMAIN"),
        (RewriteSpec::ServFail, "SERVFAIL"),
        (RewriteSpec::NoError, "NOERROR"),
        (
            RewriteSpec::A(Ipv4Addr::new(10, 0, 0, 1)),
            "NOERROR;A;10.0.0.1",
        ),
        (RewriteSpec::Aaaa(Ipv6Addr::LOCALHOST), "NOERROR;AAAA;::1"),
        (
            RewriteSpec::Cname("Target.Example.".into()),
            "NOERROR;CNAME;target.example",
        ),
        (
            RewriteSpec::Txt("hello, world".into()),
            "NOERROR;TXT;hello\\, world",
        ),
    ];
    for (rw, text) in rewrites {
        let mut s = block("a.example");
        s.rewrite = Some(rw);
        assert_eq!(built(&s), format!("||a.example^$dnsrewrite={text}"));
        assert_eq!(
            describe_rule(&parse_rule(&built(&s)).unwrap()),
            Some(s.normalized().unwrap())
        );
    }
}

#[test]
fn modifier_order_is_canonical() {
    let mut s = block("a.example");
    s.important = true;
    s.record_types = RecordTypeSel {
        types: vec![1],
        negated: false,
    };
    s.rewrite = Some(RewriteSpec::A(Ipv4Addr::new(1, 2, 3, 4)));
    assert_eq!(
        built(&s),
        "||a.example^$important,dnstype=A,dnsrewrite=NOERROR;A;1.2.3.4"
    );
}

#[test]
fn domain_normalisation() {
    assert_eq!(built(&block("  Example.COM.  ")), "||example.com^");
    assert_eq!(built(&block("\tex.com\n")), "||ex.com^");
    assert_eq!(built(&block("bücher.example")), "||xn--bcher-kva.example^");
    assert_eq!(built(&block("BÜCHER.example.")), "||xn--bcher-kva.example^");
    assert_eq!(built(&block("_dmarc.example")), "||_dmarc.example^");
}

#[test]
fn invalid_inputs_have_codes() {
    for d in [
        "",
        "  ",
        ".",
        "a..b",
        "a b.example",
        "a|b",
        "a^b",
        "a$b",
        "@@a.b",
        "a,b",
        "||a.b^",
        "a.b..",
    ] {
        let c = code(&block(d));
        assert_eq!(c, "filter_build.invalid_domain", "{d:?}");
    }
    for d in ["*.example.com", "ad*.example", "/ads?/", "a/b"] {
        assert_eq!(code(&block(d)), "filter_build.pattern_not_allowed", "{d:?}");
    }
    assert_eq!(
        code(&block(&format!("{}.com", "a".repeat(64)))),
        "filter_build.invalid_domain"
    );

    let mut s = spec(RuleAction::Allow, "a.example");
    s.rewrite = Some(RewriteSpec::NxDomain);
    assert_eq!(code(&s), "filter_build.rewrite_on_allow");

    let mut s = block("a.example");
    s.record_types.negated = true;
    assert_eq!(code(&s), "filter_build.empty_negated_types");

    let mut s = block("a.example");
    s.rewrite = Some(RewriteSpec::Cname("*.x".into()));
    assert_eq!(code(&s), "filter_build.pattern_not_allowed");
    s.rewrite = Some(RewriteSpec::Cname("".into()));
    assert_eq!(code(&s), "filter_build.invalid_domain");

    for t in [
        "",
        "back\\slash",
        "a/b",
        "a$b",
        "a$b",
        "new\nline",
        " lead",
        "trail ",
        &"x".repeat(256),
    ] {
        let mut s = block("a.example");
        s.rewrite = Some(RewriteSpec::Txt(t.into()));
        assert_eq!(code(&s), "filter_build.invalid_txt", "{t:?}");
    }
}

#[test]
fn txt_specials_round_trip() {
    for t in [
        "a;b;c",
        "k=v,k2=v2",
        "x^y|z",
        "ünï",
        "a, ,b",
        "@@x",
        "!c",
        "a,,b",
        ",",
    ] {
        let mut s = block("a.example");
        s.rewrite = Some(RewriteSpec::Txt(t.into()));
        let text = built(&s);
        let rule = parse_rule(&text).unwrap();
        assert_eq!(describe_rule(&rule), Some(s.normalized().unwrap()), "{t:?}");
    }
}

#[test]
fn describe_rejects_unrepresentable() {
    for t in [
        "||a.example^$badfilter",
        "||a.example^$denyallow=b.example",
        "@@||a.example^$dnsrewrite",
    ] {
        assert_eq!(describe_rule(&parse_rule(t).unwrap()), None, "{t}");
    }
    // Plain-domain and hosts forms are representable.
    let r = parse_rule("example.com").unwrap();
    assert_eq!(r.kind(), MatchKind::Subdomains);
    assert_eq!(describe_rule(&r), Some(block("example.com")));
}

#[test]
fn normalized_matches_describe() {
    let mut s = block("  BÜCHER.example. ");
    s.record_types = RecordTypeSel {
        types: vec![28, 1, 28],
        negated: true,
    };
    s.important = true;
    let n = s.normalized().unwrap();
    assert_eq!(n.domain, "xn--bcher-kva.example");
    assert_eq!(n.record_types.types, vec![1, 28]);
    assert_eq!(describe_rule(&parse_rule(&built(&s)).unwrap()), Some(n));
}

// ---------- property tests ----------

fn label() -> impl Strategy<Value = String> {
    "[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,10}[a-zA-Z0-9_])?"
}

fn domain_input() -> impl Strategy<Value = String> {
    (
        prop::collection::vec(label(), 1..5),
        prop::bool::ANY,
        "[ \t]{0,3}",
        "[ \t]{0,3}",
    )
        .prop_map(|(labels, dot, pre, post)| {
            format!(
                "{pre}{}{}{post}",
                labels.join("."),
                if dot { "." } else { "" }
            )
        })
}

fn unicode_domain() -> impl Strategy<Value = String> {
    (
        prop::collection::vec("[a-z0-9äöüßéñ]{1,8}", 1..4),
        "[a-z]{2,5}",
    )
        .prop_map(|(labels, tld)| format!("{}.{tld}", labels.join(".")))
}

fn type_codes() -> impl Strategy<Value = Vec<u16>> {
    prop::collection::vec(
        prop_oneof![
            Just(1u16),
            Just(5),
            Just(16),
            Just(28),
            Just(65),
            Just(255),
            any::<u16>()
        ],
        0..6,
    )
}

fn txt_text() -> impl Strategy<Value = String> {
    "[!\"%-.0-\\[\\]-~]([ !\"%-.0-\\[\\]-~]{0,60}[!\"%-.0-\\[\\]-~])?"
}

fn rewrite() -> impl Strategy<Value = RewriteSpec> {
    prop_oneof![
        Just(RewriteSpec::Refused),
        Just(RewriteSpec::NxDomain),
        Just(RewriteSpec::ServFail),
        Just(RewriteSpec::NoError),
        any::<[u8; 4]>().prop_map(|b| RewriteSpec::A(Ipv4Addr::from(b))),
        any::<[u16; 8]>().prop_map(|w| RewriteSpec::Aaaa(Ipv6Addr::from(w))),
        domain_input().prop_map(RewriteSpec::Cname),
        txt_text().prop_map(RewriteSpec::Txt),
    ]
}

fn any_spec() -> impl Strategy<Value = RuleSpec> {
    (
        prop_oneof![domain_input(), unicode_domain()],
        prop::bool::ANY,
        prop::bool::ANY,
        prop::bool::ANY,
        type_codes(),
        prop::bool::ANY,
        prop::option::of(rewrite()),
    )
        .prop_map(|(domain, allow, sub, important, types, neg, rw)| {
            let action = if allow {
                RuleAction::Allow
            } else {
                RuleAction::Block
            };
            RuleSpec {
                action,
                domain,
                include_subdomains: sub,
                important,
                record_types: RecordTypeSel {
                    negated: neg && !types.is_empty(),
                    types,
                },
                rewrite: if allow { None } else { rw },
            }
        })
}

/// Characters the builder may emit outside domains, type names and values.
fn allowed_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || "@|^$,=~;:.-_\\ ".contains(c)
        || !c.is_ascii()
        || c.is_ascii_graphic()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn round_trip(s in any_spec()) {
        let text = build_rule(&s).unwrap();
        let rule = parse_rule(&text).unwrap();
        let n = s.normalized().unwrap();
        prop_assert_eq!(rule.action(), s.action);
        prop_assert_eq!(rule.domain().unwrap().as_str(), n.domain.as_str());
        prop_assert_eq!(
            rule.kind(),
            if s.include_subdomains { MatchKind::Subdomains } else { MatchKind::Exact }
        );
        prop_assert_eq!(describe_rule(&rule), Some(n));
        // Building the described spec reproduces the exact text (canonical).
        let again = build_rule(&describe_rule(&rule).unwrap()).unwrap();
        prop_assert_eq!(again, text);
    }

    #[test]
    fn output_is_minimal(s in any_spec()) {
        let t = build_rule(&s).unwrap();
        prop_assert!(t.chars().all(allowed_char));
        prop_assert_eq!(t.starts_with("@@"), s.action == RuleAction::Allow);
        let body = t.strip_prefix("@@").unwrap_or(&t);
        let prefix = if s.include_subdomains { "||" } else { "|" };
        prop_assert!(body.starts_with(prefix));
        prop_assert!(!body.starts_with("|||"));
        if !matches!(s.rewrite, Some(RewriteSpec::Txt(_))) {
            prop_assert_eq!(t.matches('^').count(), 1);
        }
        prop_assert_eq!(t.trim(), t.as_str());
        let n = s.normalized().unwrap();
        let has_mods = s.important || !n.record_types.types.is_empty() || s.rewrite.is_some();
        prop_assert_eq!(t.contains('$'), has_mods);
        if !has_mods {
            prop_assert!(t.ends_with('^'));
            prop_assert!(!t.contains(','));
            prop_assert!(!t.contains('='));
        }
        // No `$` beyond the modifier separator unless it comes from TXT text.
        if !matches!(s.rewrite, Some(RewriteSpec::Txt(_))) {
            prop_assert!(t.matches('$').count() <= 1);
        }
    }

    #[test]
    fn arbitrary_input_never_panics_and_output_always_parses(
        domain in ".{0,40}",
        txt in ".{0,40}",
        sub in prop::bool::ANY,
    ) {
        let mut s = block(&domain);
        s.include_subdomains = sub;
        s.rewrite = Some(RewriteSpec::Txt(txt));
        match build_rule(&s) {
            Ok(t) => {
                prop_assert!(parse_rule(&t).is_ok());
                let rule = parse_rule(&t).unwrap();
                prop_assert_eq!(describe_rule(&rule), Some(s.normalized().unwrap()));
            }
            Err(e) => prop_assert!(!matches!(e, BuildError::Unparsable { .. }), "{e}"),
        }
    }
}
