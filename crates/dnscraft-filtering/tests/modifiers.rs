#![allow(clippy::unwrap_used, clippy::expect_used)]

mod modifiers {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use dnscraft_filtering::{
        DnsRewrite, ListSource, Rewrite, Rule, RuleAction, RuleError, SkipReason, UnsupportedKind,
        parse_list, parse_rule,
    };

    fn rule(s: &str) -> Rule {
        parse_rule(s).unwrap_or_else(|e| panic!("{s:?}: {e} ({})", e.code()))
    }

    fn err(s: &str) -> RuleError {
        parse_rule(s).expect_err(s)
    }

    /// (code, detail-if-invalid-modifier, text covered by the span)
    fn shape(s: &str) -> (&'static str, String, String) {
        let e = err(s);
        let detail = match &e {
            RuleError::InvalidModifier { detail, .. } => (*detail).to_string(),
            _ => String::new(),
        };
        (e.code(), detail, s[e.span()].to_string())
    }

    fn rw(s: &str) -> Rewrite {
        match rule(s).modifiers().dnsrewrite.clone() {
            Some(DnsRewrite::Set(r)) => r,
            other => panic!("{s}: {other:?}"),
        }
    }

    #[test]
    fn flags() {
        let m = rule("||a.example^$important").modifiers().clone();
        assert!(m.important && !m.badfilter);
        let m = rule("||a.example^$badfilter,important").modifiers().clone();
        assert!(m.important && m.badfilter);
        let m = rule("||A.example^$IMPORTANT").modifiers().clone();
        assert!(m.important, "names are case-insensitive");
        assert!(rule("||a.example^").modifiers().is_empty());
        assert_eq!(rule("@@||a.example^$important").action(), RuleAction::Allow);
    }

    #[test]
    fn flag_errors() {
        let t: &[(&str, &str, &str, &str)] = &[
            (
                "||a.example^$important=1",
                "filter_rule.invalid_modifier",
                "unexpected_value",
                "1",
            ),
            (
                "||a.example^$~important",
                "filter_rule.invalid_modifier",
                "negation_not_allowed",
                "~important",
            ),
            (
                "||a.example^$important,important",
                "filter_rule.duplicate_modifier",
                "",
                "important",
            ),
            (
                "||a.example^$important,,badfilter",
                "filter_rule.invalid_syntax",
                "",
                "",
            ),
        ];
        for (input, code, detail, text) in t {
            assert_eq!(
                shape(input),
                (*code, detail.to_string(), text.to_string()),
                "{input}"
            );
        }
    }

    #[test]
    fn dnstype() {
        let f = rule("||a.example^$dnstype=aaaa|A|a|TYPE65|type257")
            .modifiers()
            .dnstype
            .clone()
            .unwrap();
        assert_eq!(f.types(), &[1, 28, 65, 257]);
        assert!(!f.is_negated());
        assert!(f.matches(28) && !f.matches(15));

        let f = rule("||a.example^$dnstype=~A|~CNAME")
            .modifiers()
            .dnstype
            .clone()
            .unwrap();
        assert_eq!(f.types(), &[1, 5]);
        assert!(f.is_negated());
        assert!(!f.matches(1) && f.matches(28));

        for (n, c) in [
            ("MX", 15),
            ("TXT", 16),
            ("SRV", 33),
            ("HTTPS", 65),
            ("SVCB", 64),
            ("PTR", 12),
            ("NS", 2),
            ("SOA", 6),
            ("CAA", 257),
            ("ANY", 255),
        ] {
            let f = rule(&format!("@@||a.example^$dnstype={n}"))
                .modifiers()
                .dnstype
                .clone()
                .unwrap();
            assert_eq!(f.types(), &[c], "{n}");
        }
    }

    #[test]
    fn dnstype_errors() {
        let im = "filter_rule.invalid_modifier";
        let t: &[(&str, &str, &str)] = &[
            ("||a.example^$dnstype", "missing_value", "dnstype"),
            ("||a.example^$dnstype=", "missing_value", "dnstype="),
            ("||a.example^$dnstype=A|~AAAA", "mixed_negation", "~AAAA"),
            ("||a.example^$dnstype=~A|AAAA", "mixed_negation", "AAAA"),
            ("||a.example^$dnstype=A||AAAA", "empty_entry", ""),
            ("||a.example^$dnstype=BOGUS", "unknown_type", "BOGUS"),
            ("||a.example^$dnstype=TYPE", "unknown_type", "TYPE"),
            (
                "||a.example^$dnstype=TYPE70000",
                "unknown_type",
                "TYPE70000",
            ),
        ];
        for (input, detail, text) in t {
            assert_eq!(
                shape(input),
                (im, detail.to_string(), text.to_string()),
                "{input}"
            );
        }
        assert_eq!(
            shape("||a.example^$dnstype=A,dnstype=AAAA").0,
            "filter_rule.duplicate_modifier"
        );
    }

    #[test]
    fn denyallow() {
        let d = rule("||a.example^$denyallow=b.com|B.org|b.com")
            .modifiers()
            .denyallow
            .clone()
            .unwrap();
        let names: Vec<_> = d.iter().map(|n| n.as_str()).collect();
        assert_eq!(names, ["b.com", "b.org"]);
        let d = rule("||a.example^$denyallow=bücher.example")
            .modifiers()
            .denyallow
            .clone()
            .unwrap();
        assert_eq!(d[0].as_str(), "xn--bcher-kva.example");
    }

    #[test]
    fn denyallow_errors() {
        let t: &[(&str, &str, &str, &str)] = &[
            (
                "||a.example^$denyallow",
                "filter_rule.invalid_modifier",
                "missing_value",
                "denyallow",
            ),
            (
                "||a.example^$denyallow=b.com||c.com",
                "filter_rule.invalid_modifier",
                "empty_entry",
                "",
            ),
            (
                "||a.example^$denyallow=b.com|bad..name",
                "filter_rule.invalid_domain",
                "",
                "bad..name",
            ),
            (
                "@@||a.example^$denyallow=b.com",
                "filter_rule.invalid_modifier",
                "not_allowed_on_exception",
                "denyallow=b.com",
            ),
        ];
        for (input, code, detail, text) in t {
            assert_eq!(
                shape(input),
                (*code, detail.to_string(), text.to_string()),
                "{input}"
            );
        }
    }

    #[test]
    fn dnsrewrite_forms() {
        let t: Vec<(&str, Rewrite)> = vec![
            ("||a.example^$dnsrewrite=REFUSED", Rewrite::Refused),
            ("||a.example^$dnsrewrite=nxdomain", Rewrite::NxDomain),
            ("||a.example^$dnsrewrite=SERVFAIL", Rewrite::ServFail),
            ("||a.example^$dnsrewrite=NOERROR", Rewrite::NoErrorEmpty),
            (
                "||a.example^$dnsrewrite=1.2.3.4",
                Rewrite::A(Ipv4Addr::new(1, 2, 3, 4)),
            ),
            (
                "||a.example^$dnsrewrite=::1",
                Rewrite::Aaaa(Ipv6Addr::LOCALHOST),
            ),
            (
                "||a.example^$dnsrewrite=NOERROR;A;1.2.3.4",
                Rewrite::A(Ipv4Addr::new(1, 2, 3, 4)),
            ),
            (
                "||a.example^$dnsrewrite=noerror;aaaa;::1",
                Rewrite::Aaaa(Ipv6Addr::LOCALHOST),
            ),
        ];
        for (input, expected) in t {
            assert_eq!(rw(input), expected, "{input}");
        }
        assert_eq!(
            rw("||a.example^$dnsrewrite=Target.Example").to_owned(),
            Rewrite::Cname("target.example".parse().unwrap())
        );
        assert_eq!(
            rw("||a.example^$dnsrewrite=NOERROR;CNAME;bücher.example"),
            Rewrite::Cname("xn--bcher-kva.example".parse().unwrap())
        );
        assert_eq!(
            rw("||a.example^$dnsrewrite=NOERROR;TXT;hello; world"),
            Rewrite::Txt("hello; world".into())
        );
        assert_eq!(
            rw(r"||a.example^$dnsrewrite=NOERROR;TXT;a\,b,important"),
            Rewrite::Txt("a,b".into())
        );
        assert!(
            rule(r"||a.example^$dnsrewrite=NOERROR;TXT;a\,b,important")
                .modifiers()
                .important
        );
    }

    #[test]
    fn dnsrewrite_errors() {
        let im = "filter_rule.invalid_modifier";
        let t: &[(&str, &str, &str)] = &[
            ("||a.example^$dnsrewrite", "missing_value", "dnsrewrite"),
            ("||a.example^$dnsrewrite=1.2.3", "invalid_ip", "1.2.3"),
            (
                "||a.example^$dnsrewrite=1.2.3.4.5",
                "invalid_ip",
                "1.2.3.4.5",
            ),
            ("||a.example^$dnsrewrite=::zz", "invalid_ip", "::zz"),
            ("||a.example^$dnsrewrite=NOERROR;A;::1", "invalid_ip", "::1"),
            (
                "||a.example^$dnsrewrite=NOERROR;AAAA;1.2.3.4",
                "invalid_ip",
                "1.2.3.4",
            ),
            ("||a.example^$dnsrewrite=NOERROR;A;", "missing_value", ""),
            (
                "||a.example^$dnsrewrite=NXDOMAIN;A;1.2.3.4",
                "rcode_with_record",
                "NXDOMAIN",
            ),
            (
                "||a.example^$dnsrewrite=NOERROR;MX;10 mail.example",
                "unsupported_rewrite_type",
                "MX",
            ),
            (
                "||a.example^$dnsrewrite=NOERROR;A",
                "malformed_value",
                "NOERROR;A",
            ),
            (
                "@@||a.example^$dnsrewrite=1.2.3.4",
                "value_on_exception",
                "1.2.3.4",
            ),
        ];
        for (input, detail, text) in t {
            assert_eq!(
                shape(input),
                (im, detail.to_string(), text.to_string()),
                "{input}"
            );
        }
        assert_eq!(
            shape("||a.example^$dnsrewrite=bad..name"),
            (
                "filter_rule.invalid_domain",
                String::new(),
                "bad..name".into()
            )
        );
    }

    #[test]
    fn dnsrewrite_disable_on_exception() {
        let r = rule("@@||a.example^$dnsrewrite");
        assert_eq!(r.modifiers().dnsrewrite, Some(DnsRewrite::Disable));
        let p = parse_list("@@||a.example^$dnsrewrite\n", ListSource::List);
        assert_eq!(p.rules.len(), 1, "disabling is harmless in lists");
    }

    #[test]
    fn dnsrewrite_source_policy() {
        let body = "\
||rc.example^$dnsrewrite=REFUSED
||nx.example^$dnsrewrite=NXDOMAIN
||a.example^$dnsrewrite=1.2.3.4
||aaaa.example^$dnsrewrite=::1
||cname.example^$dnsrewrite=other.example
||full.example^$dnsrewrite=NOERROR;A;1.2.3.4
||txt.example^$dnsrewrite=NOERROR;TXT;x
";
        let l = parse_list(body, ListSource::List);
        let names: Vec<_> = l.rules.iter().map(|r| r.domain().as_str()).collect();
        assert_eq!(names, ["rc.example", "nx.example"]);
        assert_eq!(l.skipped.get(SkipReason::RewriteFromList), 5);
        assert_eq!(l.skipped.total(), 5);
        assert_eq!(l.samples[0].code, "filter_rule.rewrite_from_list");
        assert_eq!(l.samples[0].line, 3);
        assert_eq!(SkipReason::RewriteFromList.as_str(), "rewrite_from_list");

        let c = parse_list(body, ListSource::Custom);
        assert_eq!(c.rules.len(), 7);
        assert_eq!(c.skipped.total(), 0);
        assert_eq!(
            c.rules[2].modifiers().dnsrewrite,
            Some(DnsRewrite::Set(Rewrite::A(Ipv4Addr::new(1, 2, 3, 4))))
        );
        assert_eq!(
            c.rules[2].text(body),
            Some("||a.example^$dnsrewrite=1.2.3.4")
        );

        // The editor path is trusted like custom rules.
        rule("||a.example^$dnsrewrite=1.2.3.4");
    }

    #[test]
    fn rewrite_from_list_span() {
        let e = parse_list("||a.example^$dnsrewrite=1.2.3.4", ListSource::List).samples[0].clone();
        assert_eq!(e.reason, SkipReason::RewriteFromList);
    }

    #[test]
    fn client_and_ctag() {
        for input in [
            "||a.example^$client=1.2.3.4",
            "||a.example^$important,ctag=device_pc",
            "||a.example^$CLIENT=~'x'",
        ] {
            let e = err(input);
            assert_eq!(e.code(), "filter_rule.client_modifier", "{input}");
            assert_eq!(e.params(), vec![("hint", "profiles".to_string())]);
            let l = parse_list(input, ListSource::List);
            assert!(l.rules.is_empty());
            assert_eq!(l.skipped.get(SkipReason::ClientModifier), 1);
        }
        let e = err("||a.example^$important,client=1.2.3.4");
        assert_eq!(
            &"||a.example^$important,client=1.2.3.4"[e.span()],
            "client=1.2.3.4"
        );
        let l = parse_list("||a.example^$client=1.2.3.4", ListSource::Custom);
        assert_eq!(l.skipped.get(SkipReason::ClientModifier), 1);
    }

    #[test]
    fn unknown_and_duplicate_and_browser() {
        let e = err("||a.example^$important,frobnicate=1");
        assert_eq!(e.code(), "filter_rule.unknown_modifier");
        assert_eq!(
            &"||a.example^$important,frobnicate=1"[e.span()],
            "frobnicate=1"
        );
        let l = parse_list("||a.example^$frobnicate\n", ListSource::List);
        assert_eq!(l.skipped.get(SkipReason::UnknownModifier), 1);
        assert_eq!(l.samples[0].code, "filter_rule.unknown_modifier");

        let e = err("||a.example^$badfilter,BADFILTER");
        assert_eq!(e.code(), "filter_rule.duplicate_modifier");
        assert_eq!(&"||a.example^$badfilter,BADFILTER"[e.span()], "BADFILTER");
        let l = parse_list("||a.example^$badfilter,badfilter\n", ListSource::List);
        assert_eq!(l.skipped.get(SkipReason::InvalidSyntax), 1);

        // Browser-only wins over unknown/client and stays a skip.
        let e = err("||a.example^$frobnicate,script");
        assert!(matches!(
            e,
            RuleError::Unsupported {
                kind: UnsupportedKind::BrowserOnly,
                ..
            }
        ));
        let e = err("||a.example^$important,third-party");
        assert_eq!(e.span(), 12..34);
        let l = parse_list("||a.example^$important,~third-party\n", ListSource::Custom);
        assert_eq!(
            l.skipped
                .get(SkipReason::Unsupported(UnsupportedKind::BrowserOnly)),
            1
        );
    }

    #[test]
    fn idna() {
        let cases = [
            ("||bücher.example^", "xn--bcher-kva.example"),
            ("||BÜCHER.Example^", "xn--bcher-kva.example"),
            ("|bücher.example|", "xn--bcher-kva.example"),
            ("bücher.example", "xn--bcher-kva.example"),
            ("@@||bücher.example^", "xn--bcher-kva.example"),
            ("0.0.0.0 bücher.example", "xn--bcher-kva.example"),
            ("||xn--bcher-kva.example^", "xn--bcher-kva.example"),
            ("||faß.de^", "xn--fa-hia.de"),
        ];
        for (input, expected) in cases {
            assert_eq!(rule(input).domain().as_str(), expected, "{input}");
        }
    }

    #[test]
    fn invalid_idna() {
        // A lone combining mark at the start of a label is not valid UTS 46.
        let input = "||\u{0308}bücher.example^";
        let e = err(input);
        assert_eq!(e.code(), "filter_rule.invalid_idna");
        assert_eq!(&input[e.span()], "\u{0308}bücher.example");
        let l = parse_list(&format!("{input}\n||ok.example^\n"), ListSource::List);
        assert_eq!(l.rules.len(), 1);
        assert_eq!(l.skipped.get(SkipReason::InvalidIdna), 1);
        assert_eq!(SkipReason::InvalidIdna.as_str(), "invalid_idna");
        let input = "||a.example^$dnsrewrite=\u{0308}x.example";
        assert_eq!(err(input).code(), "filter_rule.invalid_idna");
    }

    #[test]
    fn badfilter_key() {
        let a = rule("||a.example^$dnstype=A,important");
        let b = rule("||a.example^$important,dnstype=a,badfilter");
        assert_eq!(a.badfilter_key(), b.badfilter_key());
        assert_eq!(
            rule("||a.example^").badfilter_key(),
            rule("||A.example^$badfilter").badfilter_key()
        );
        assert_eq!(
            rule("||a.example^").badfilter_key(),
            rule("||a.example").badfilter_key()
        );
        for other in [
            "|a.example^",
            "@@||a.example^",
            "||b.example^",
            "||a.example^$important",
            "||a.example^$dnstype=A",
        ] {
            assert_ne!(
                rule("||a.example^").badfilter_key(),
                rule(other).badfilter_key(),
                "{other}"
            );
        }
        assert_ne!(
            rule("||a.example^$dnstype=A").badfilter_key(),
            rule("||a.example^$dnstype=~A").badfilter_key()
        );
    }

    #[test]
    fn modifiers_do_not_change_plain_rules() {
        let p = parse_list("||a.example^\n||b.example^$important\n", ListSource::List);
        assert!(p.rules[0].modifiers().is_empty());
        assert!(p.rules[1].modifiers().important);
    }
}
