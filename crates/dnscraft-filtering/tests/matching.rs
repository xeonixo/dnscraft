#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Instant;

use dnscraft_filtering::{
    DomainName, Index, IndexBuilder, ListId, ListSource, MatchKind, Reason, Rewrite, Rule,
    RuleAction, RuleSource, SetId, SourceKind, Verdict, parse_list,
};

const A: u16 = 1;
const AAAA: u16 = 28;

fn list(id: &str) -> SourceKind {
    SourceKind::List(ListId::new(id).unwrap())
}

fn custom(id: &str) -> SourceKind {
    SourceKind::Custom(SetId::new(id).unwrap())
}

/// Builds an index from `(kind, body)` sources, in order.
fn build(sources: &[(SourceKind, &str)]) -> Index {
    let mut b = IndexBuilder::new();
    for (kind, body) in sources {
        let ls = if matches!(kind, SourceKind::Custom(_)) {
            ListSource::Custom
        } else {
            ListSource::List
        };
        let id = b
            .add_source_with_body(kind.clone(), Arc::from(*body))
            .unwrap();
        b.add_rules(id, parse_list(body, ls).rules).unwrap();
    }
    b.build_in_memory()
}

fn one(body: &str) -> Index {
    build(&[(list("l"), body)])
}

fn dn(s: &str) -> DomainName {
    DomainName::parse(s).unwrap()
}

/// Compact verdict form: `pass`, `allow|<rule>`, `block|<rule>`, `rw|<rule>`.
fn show(v: &Verdict) -> String {
    match v {
        Verdict::Pass => "pass".into(),
        Verdict::Allowed(r) => format!("allow|{}", r.rule),
        Verdict::Blocked(r) => format!("block|{}", r.rule),
        Verdict::Rewrite(_, r) => format!("rw|{}", r.rule),
    }
}

fn reason(v: Verdict) -> Reason {
    match v {
        Verdict::Allowed(r) | Verdict::Blocked(r) | Verdict::Rewrite(_, r) => r,
        other => panic!("no reason in {other:?}"),
    }
}

#[test]
fn priority_and_semantics_table() {
    // (rules, name, qtype, expected)
    let table: &[(&[&str], &str, u16, &str)] = &[
        // block / allow / important variants
        (&["||a.com^"], "a.com", A, "block|||a.com^"),
        (&["||a.com^"], "x.y.a.com", A, "block|||a.com^"),
        (&["||a.com^"], "b.com", A, "pass"),
        (&["||a.com^"], "xa.com", A, "pass"),
        (&["||a.com^", "@@||a.com^"], "a.com", A, "allow|@@||a.com^"),
        (&["@@||a.com^", "||a.com^"], "a.com", A, "allow|@@||a.com^"),
        (
            &["||a.com^$important", "@@||a.com^"],
            "a.com",
            A,
            "block|||a.com^$important",
        ),
        (
            &["||a.com^$important", "@@||a.com^$important"],
            "a.com",
            A,
            "allow|@@||a.com^$important",
        ),
        (
            &["@@||a.com^$important", "||a.com^$important"],
            "a.com",
            A,
            "allow|@@||a.com^$important",
        ),
        (
            &["@@||a.com^$important"],
            "a.com",
            A,
            "allow|@@||a.com^$important",
        ),
        (
            &["||a.com^", "||a.com^$important"],
            "a.com",
            A,
            "block|||a.com^$important",
        ),
        // exact vs subdomain
        (&["|a.com^"], "a.com", A, "block||a.com^"),
        (&["|a.com^"], "www.a.com", A, "pass"),
        (&["|a.com^", "||a.com^"], "www.a.com", A, "block|||a.com^"),
        (&["|a.com^", "||a.com^"], "a.com", A, "block||a.com^"),
        // apex vs subdomain rules
        (&["||www.a.com^"], "a.com", A, "pass"),
        (&["||www.a.com^"], "x.www.a.com", A, "block|||www.a.com^"),
        (
            &["||a.com^", "@@||www.a.com^"],
            "www.a.com",
            A,
            "allow|@@||www.a.com^",
        ),
        (
            &["||a.com^", "@@||www.a.com^"],
            "a.com",
            A,
            "block|||a.com^",
        ),
        (
            &["||a.com^", "@@||www.a.com^"],
            "x.a.com",
            A,
            "block|||a.com^",
        ),
        (
            &["||a.com^", "@@||www.a.com^"],
            "m.www.a.com",
            A,
            "allow|@@||www.a.com^",
        ),
        (
            &["@@||a.com^", "||www.a.com^"],
            "www.a.com",
            A,
            "allow|@@||a.com^",
        ),
        // tie-break: longest matching name
        (
            &["||a.com^", "||b.a.com^"],
            "c.b.a.com",
            A,
            "block|||b.a.com^",
        ),
        (
            &["||b.a.com^", "||a.com^"],
            "c.b.a.com",
            A,
            "block|||b.a.com^",
        ),
        // dnstype
        (
            &["||a.com^$dnstype=AAAA"],
            "a.com",
            AAAA,
            "block|||a.com^$dnstype=AAAA",
        ),
        (&["||a.com^$dnstype=AAAA"], "a.com", A, "pass"),
        (&["||a.com^$dnstype=A|AAAA"], "a.com", 16, "pass"),
        (&["||a.com^$dnstype=~A"], "a.com", A, "pass"),
        (
            &["||a.com^$dnstype=~A"],
            "a.com",
            AAAA,
            "block|||a.com^$dnstype=~A",
        ),
        (
            &["||a.com^", "@@||a.com^$dnstype=A"],
            "a.com",
            A,
            "allow|@@||a.com^$dnstype=A",
        ),
        (
            &["||a.com^", "@@||a.com^$dnstype=A"],
            "a.com",
            AAAA,
            "block|||a.com^",
        ),
        // denyallow
        (
            &["||a.com^$denyallow=x.a.com"],
            "y.a.com",
            A,
            "block|||a.com^$denyallow=x.a.com",
        ),
        (&["||a.com^$denyallow=x.a.com"], "x.a.com", A, "pass"),
        (&["||a.com^$denyallow=x.a.com"], "s.x.a.com", A, "pass"),
        (
            &["||a.com^$denyallow=x.a.com|z.org"],
            "a.com",
            A,
            "block|||a.com^$denyallow=x.a.com|z.org",
        ),
        (&["||com^$denyallow=a.com|b.com"], "w.b.com", A, "pass"),
        (
            &["||com^$denyallow=a.com|b.com"],
            "w.c.com",
            A,
            "block|||com^$denyallow=a.com|b.com",
        ),
        // rewrite: rcode (allowed in lists), disable, allow beats rewrite
        (
            &["||a.com^$dnsrewrite=NXDOMAIN"],
            "a.com",
            A,
            "rw|||a.com^$dnsrewrite=NXDOMAIN",
        ),
        (
            &["||a.com^$dnsrewrite=NXDOMAIN", "@@||a.com^$dnsrewrite"],
            "a.com",
            A,
            "pass",
        ),
        (
            &[
                "||a.com^$dnsrewrite=NXDOMAIN",
                "||a.com^",
                "@@||a.com^$dnsrewrite",
            ],
            "a.com",
            A,
            "block|||a.com^",
        ),
        (
            &["||a.com^$dnsrewrite=NXDOMAIN", "@@||a.com^"],
            "a.com",
            A,
            "allow|@@||a.com^",
        ),
        (
            &["||a.com^$dnsrewrite=NXDOMAIN"],
            "a.com",
            AAAA,
            "rw|||a.com^$dnsrewrite=NXDOMAIN",
        ),
        // case-insensitivity comes from DomainName
        (&["||A.Com^"], "WWW.A.COM.", A, "block|||A.Com^"),
        // glob and regex candidates combined with domain rules
        (
            &["||ad*.example^"],
            "ads.example",
            A,
            "block|||ad*.example^",
        ),
        (
            &["||ad*.example^", "@@||ads.example^"],
            "ads.example",
            A,
            "allow|@@||ads.example^",
        ),
        (
            &["||ads.example^", "||ad*.example^"],
            "ads.example",
            A,
            "block|||ads.example^",
        ),
        (
            &["/^track[0-9]+\\./"],
            "track7.foo.net",
            A,
            "block|/^track[0-9]+\\./",
        ),
        (&["/^track[0-9]+\\./"], "xtrack7.foo.net", A, "pass"),
        (
            &["/^track[0-9]+\\./", "@@||track7.foo.net^"],
            "track7.foo.net",
            A,
            "allow|@@||track7.foo.net^",
        ),
        (
            &["@@/^track[0-9]+\\./", "||track7.foo.net^"],
            "track7.foo.net",
            A,
            "allow|@@/^track[0-9]+\\./",
        ),
        (
            &["*ads*$important", "@@||ads.example^"],
            "ads.example",
            A,
            "block|*ads*$important",
        ),
        (
            &["ads*.example.com$dnstype=AAAA"],
            "ads1.example.com",
            A,
            "pass",
        ),
    ];
    for (rules, name, qtype, want) in table {
        let idx = one(&rules.join("\n"));
        let got = show(&idx.match_name(&dn(name), *qtype));
        assert_eq!(&got, want, "rules {rules:?}, name {name}, qtype {qtype}");
    }
}

#[test]
fn rewrite_values_from_custom_source() {
    let idx = build(&[
        (
            list("l"),
            "||a.com^$dnsrewrite=REFUSED\n||v4.com^$dnsrewrite=9.9.9.9\n",
        ),
        (
            custom("home"),
            "||v4.com^$dnsrewrite=1.2.3.4\n||nas.lan^$dnsrewrite=192.168.1.5\n",
        ),
    ]);
    // list rcode rewrite
    match idx.match_name(&dn("a.com"), A) {
        Verdict::Rewrite(rw, r) => {
            assert_eq!(rw, Rewrite::Refused);
            assert_eq!(&*r.rule, "||a.com^$dnsrewrite=REFUSED");
        }
        v => panic!("{v:?}"),
    }
    // record rewrite from custom source; the list's record rewrite was refused by the parser
    match idx.match_name(&dn("nas.lan"), A) {
        Verdict::Rewrite(rw, r) => {
            assert_eq!(rw, Rewrite::A("192.168.1.5".parse().unwrap()));
            assert_eq!(
                r.source,
                RuleSource::Custom {
                    set: SetId::new("home").unwrap(),
                    line: 2
                }
            );
        }
        v => panic!("{v:?}"),
    }
    match idx.match_name(&dn("v4.com"), A) {
        Verdict::Rewrite(rw, _) => assert_eq!(rw, Rewrite::A("1.2.3.4".parse().unwrap())),
        v => panic!("{v:?}"),
    }
}

#[test]
fn reason_points_at_list_and_custom_lines() {
    let idx = build(&[
        (
            list("ads"),
            "! header\n\n||x.com^\r\n  ||ads.example^$important  \n0.0.0.0 hosts.example\n",
        ),
        (custom("me"), "# c\n@@||ok.example^\n"),
    ]);
    let r = reason(idx.match_name(&dn("www.ads.example"), A));
    assert_eq!(&*r.rule, "||ads.example^$important");
    assert!(r.important);
    assert_eq!(
        r.source,
        RuleSource::List {
            list: ListId::new("ads").unwrap(),
            line: 4
        }
    );
    let r = reason(idx.match_name(&dn("x.com"), A));
    assert_eq!(&*r.rule, "||x.com^");
    assert!(!r.important);
    let r = reason(idx.match_name(&dn("hosts.example"), A));
    assert_eq!(&*r.rule, "0.0.0.0 hosts.example");
    let v = idx.match_name(&dn("ok.example"), A);
    assert!(matches!(v, Verdict::Allowed(_)));
    let r = reason(v);
    assert_eq!(&*r.rule, "@@||ok.example^");
    assert_eq!(
        r.source,
        RuleSource::Custom {
            set: SetId::new("me").unwrap(),
            line: 2
        }
    );
}

#[test]
fn reason_for_rule_without_source_text_is_synthesised() {
    let mut b = IndexBuilder::new();
    let s = b.add_source(SourceKind::Service("tiktok".into())).unwrap();
    b.add_rule(
        Rule::new(RuleAction::Block, MatchKind::Subdomains, dn("tiktok.com")),
        s,
    )
    .unwrap();
    let idx = b.build_in_memory();
    let r = reason(idx.match_name(&dn("a.tiktok.com"), A));
    assert_eq!(&*r.rule, "||tiktok.com^");
    assert_eq!(
        r.source,
        RuleSource::Service {
            id: "tiktok".into()
        }
    );
}

#[test]
fn badfilter_removes_across_sources() {
    let idx = build(&[
        (list("one"), "||a.com^\n||b.com^\n||c.com^$dnstype=A\n"),
        (
            list("two"),
            "||a.com^$badfilter\n||c.com^$dnstype=A,badfilter\n||keep.com^\n",
        ),
    ]);
    assert_eq!(show(&idx.match_name(&dn("a.com"), A)), "pass");
    assert_eq!(show(&idx.match_name(&dn("c.com"), A)), "pass");
    assert_eq!(show(&idx.match_name(&dn("b.com"), A)), "block|||b.com^");
    assert_eq!(
        show(&idx.match_name(&dn("keep.com"), A)),
        "block|||keep.com^"
    );
    assert_eq!(idx.badfiltered(), 2);
    // the badfilter rule itself is not a matching rule and a different modifier set is untouched
    let idx = one("||a.com^$important\n||a.com^$badfilter\n");
    assert_eq!(
        show(&idx.match_name(&dn("a.com"), A)),
        "block|||a.com^$important"
    );
    // badfilter on a pattern rule
    let idx = build(&[
        (list("one"), "||ad*.example^\n"),
        (list("two"), "||ad*.example^$badfilter\n"),
    ]);
    assert_eq!(show(&idx.match_name(&dn("ads.example"), A)), "pass");
}

#[test]
fn dedup_keeps_first_source_and_counts_duplicates() {
    let idx = build(&[
        (list("first"), "||a.com^\n||b.com^\n"),
        (list("second"), "||b.com^\n||a.com^\n||c.com^\n"),
        (list("third"), "||c.com^\n||a.com^$important\n"),
    ]);
    assert_eq!(idx.len(), 4); // a, b, c, a$important
    assert_eq!(idx.duplicates(), 3);
    let r = reason(idx.match_name(&dn("b.com"), A));
    assert_eq!(
        r.source,
        RuleSource::List {
            list: ListId::new("first").unwrap(),
            line: 2
        }
    );
    let r = reason(idx.match_name(&dn("c.com"), A));
    assert_eq!(
        r.source,
        RuleSource::List {
            list: ListId::new("second").unwrap(),
            line: 3
        }
    );
    // Same name but a different semantic rule (important) is a separate entry.
    let r = reason(idx.match_name(&dn("a.com"), A));
    assert!(r.important);
}

#[test]
fn dedup_counts_per_source() {
    let mut b = IndexBuilder::new();
    let s0 = b
        .add_source_with_body(list("a"), Arc::from("||x.com^\n"))
        .unwrap();
    let s1 = b
        .add_source_with_body(list("b"), Arc::from("||x.com^\n||y.com^\n"))
        .unwrap();
    b.add_rules(s0, parse_list("||x.com^\n", ListSource::List).rules)
        .unwrap();
    b.add_rules(
        s1,
        parse_list("||x.com^\n||y.com^\n", ListSource::List).rules,
    )
    .unwrap();
    let idx = b.build_in_memory();
    assert_eq!(idx.duplicates_of(s0), 0);
    assert_eq!(idx.duplicates_of(s1), 1);
}

#[test]
fn identical_modifier_rules_dedup_but_different_ones_do_not() {
    let idx = build(&[
        (list("a"), "||x.com^$dnstype=A\n||x.com^$dnstype=AAAA\n"),
        (list("b"), "||x.com^$dnstype=A\n"),
    ]);
    assert_eq!(idx.len(), 2);
    assert_eq!(idx.duplicates(), 1);
    assert_eq!(
        show(&idx.match_name(&dn("x.com"), AAAA)),
        "block|||x.com^$dnstype=AAAA"
    );
}

#[test]
fn build_is_deterministic() {
    let body = "||a.com^\n@@||a.com^\n||b.net^$dnstype=A\n||b.net^\n|c.org^\n";
    let q = ["a.com", "b.net", "c.org", "x.c.org", "zz.com"];
    let i1 = build(&[(list("x"), body), (custom("y"), "||a.com^$important\n")]);
    let i2 = build(&[(list("x"), body), (custom("y"), "||a.com^$important\n")]);
    for n in q {
        for t in [A, AAAA] {
            assert_eq!(i1.match_name(&dn(n), t), i2.match_name(&dn(n), t), "{n}");
        }
    }
}

#[test]
fn deep_and_long_names_do_not_panic() {
    let idx = one("||a.com^\n||a.a.a.a.a.a.a.a.a.a.a.a.a.a^\n");
    let deep = vec!["a"; 127].join(".");
    assert_eq!(deep.len(), 253);
    let v = idx.match_name(&dn(&deep), A);
    assert!(matches!(v, Verdict::Blocked(_)));
    let deep_com = format!("{}.a.com", vec!["b"; 100].join("."));
    assert!(matches!(
        idx.match_name(&dn(&deep_com), A),
        Verdict::Blocked(_)
    ));
    let empty = IndexBuilder::new().build_in_memory();
    assert_eq!(empty.match_name(&dn(&deep), A), Verdict::Pass);
    assert!(empty.is_empty());
}

#[test]
fn unknown_source_is_rejected() {
    let mut b = IndexBuilder::new();
    let other = IndexBuilder::new().add_source(list("x")).unwrap();
    let r = Rule::new(RuleAction::Block, MatchKind::Subdomains, dn("a.com"));
    assert_eq!(
        b.add_rule(r, other).unwrap_err().code(),
        "filter_index.unknown_source"
    );
}

/// Synthetic list: `n` rules, mostly plain domains with a few patterns.
fn synthetic(n: u32) -> Vec<Rule> {
    (0..n)
        .map(|i| {
            let name = format!("h{}.d{}.t{}.example", i, i % 7919, i % 31);
            Rule::new(RuleAction::Block, MatchKind::Subdomains, dn(&name))
        })
        .collect()
}

#[test]
#[ignore = "timing run; use --release --nocapture"]
fn timing_one_million_rules() {
    let rules = synthetic(1_000_000);
    let t = Instant::now();
    let mut b = IndexBuilder::new();
    let s = b.add_source(list("synthetic")).unwrap();
    b.add_rules(s, rules).unwrap();
    let idx = b.build_in_memory();
    let build = t.elapsed();
    let m = idx.memory();
    println!(
        "build 1M rules: {build:?}; {} entries, names {} B, overhead {} B ({:.1} B/entry)",
        idx.len(),
        m.name_bytes,
        m.overhead_bytes,
        m.overhead_per_entry()
    );
    let hits: Vec<DomainName> = (0..1000u32)
        .map(|i| {
            dn(&format!(
                "www.h{}.d{}.t{}.example",
                i * 997,
                (i * 997) % 7919,
                (i * 997) % 31
            ))
        })
        .collect();
    let misses: Vec<DomainName> = (0..1000u32)
        .map(|i| dn(&format!("www.site{i}.some-domain-{i}.org")))
        .collect();
    for (label, set) in [("hit", &hits), ("miss", &misses)] {
        let rounds = 200u32;
        let t = Instant::now();
        let mut blocked = 0usize;
        for _ in 0..rounds {
            for n in set {
                if matches!(idx.match_name(n, A), Verdict::Blocked(_)) {
                    blocked += 1;
                }
            }
        }
        let el = t.elapsed();
        let per = el.as_secs_f64() * 1e6 / f64::from(rounds * 1000);
        println!("lookup ({label}): {per:.2} us/lookup, blocked {blocked}");
    }
}
