#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::Instant;

use dnscraft_filtering::{
    DomainName, ListSource, MatchKind, Rule, RuleAction, RuleError, SkipReason, UnsupportedKind,
    parse_list, parse_rule,
};

fn rule(s: &str) -> Rule {
    parse_rule(s).unwrap_or_else(|e| panic!("{s:?}: {e} ({})", e.code()))
}

fn hit(r: &Rule, name: &str) -> bool {
    let n = DomainName::parse(name).unwrap();
    r.pattern_matches(n.as_str())
}

// ---------------------------------------------------------------- globs

#[test]
fn glob_semantics_table() {
    // (rule, [names that match], [names that do not match])
    let table: &[(&str, &[&str], &[&str])] = &[
        (
            "||ad*.example^",
            &[
                "ad1.example",
                "ads.example",
                "a.ad1.example",
                "ad.sub.example",
                "AD1.EXAMPLE",
            ],
            &[
                "xad.example",
                "ad1.example.com",
                "example",
                "bad.example",
                "ad1.examples",
            ],
        ),
        (
            "||*.example^",
            &["a.example", "a.b.example", "x.example"],
            &["example", "badexample", "a.example.com", "notexample"],
        ),
        (
            "ads*.example.com",
            &[
                "ads.example.com",
                "ads1.example.com",
                "xads.example.com",
                "ads.example.com.evil.net",
            ],
            &["ad.example.com", "ads.example.org"],
        ),
        (
            "*ads*",
            &["ads.example", "x.badads.y", "adserver", "myads"],
            &["ad.example", "a.ds"],
        ),
        (
            "|ad*^",
            &["ad", "ad1.example", "adx.y.z"],
            &["xad", "a.ad", "bad.example"],
        ),
        ("|ad*|", &["ad", "ad1.example"], &["xad.example", "a.ad1"]),
        (
            "|*.example.com^",
            &["a.example.com", "a.b.example.com"],
            &["example.com", "a.example.com.x"],
        ),
        (
            "ad*.example^",
            &["ad1.example", "xad1.example", "a.ad.example"],
            &["ad1.example.com", "ad.exampl"],
        ),
        // `*` crosses dots.
        (
            "||a*z^",
            &["az", "a.z", "abcz", "a.b.c.z", "x.a.b.z"],
            &["xaz", "a.zx", "z.a"],
        ),
        // Mid-pattern wildcard, anchored both sides.
        (
            "|track*.cdn.*.example^",
            &["track1.cdn.eu.example", "track.cdn.a.b.example"],
            &["track1.cdn.example", "xtrack1.cdn.eu.example"],
        ),
        // `^` followed by a wildcard is still "end of name".
        (
            "||ad*^*",
            &["ad1.example", "adx.example.com"],
            &["xad.example"],
        ),
        // Hyphen and underscore literals.
        (
            "||_dmarc*.example^",
            &["_dmarc1.example"],
            &["dmarc1.example"],
        ),
    ];
    for (pat, yes, no) in table {
        let r = rule(pat);
        assert_eq!(r.kind(), MatchKind::Pattern, "{pat}");
        for n in *yes {
            assert!(hit(&r, n), "{pat} should match {n}");
        }
        for n in *no {
            assert!(!hit(&r, n), "{pat} should not match {n}");
        }
    }
}

#[test]
fn glob_is_case_insensitive_and_canonical() {
    let r = rule("||AD*.Example^");
    assert_eq!(r.glob().unwrap().canonical(), "||ad*.example^");
    assert!(hit(&r, "Ad1.EXAMPLE"));
    // The matcher tolerates upper-case input as well.
    assert!(r.glob().unwrap().matches("AD1.EXAMPLE"));
}

#[test]
fn glob_canonical_roundtrips() {
    for p in [
        "||ad*.example^",
        "*ads*",
        "|a*b|",
        "ads*.example.com",
        "||*.x^",
        "||a*^*",
    ] {
        let g = rule(p).glob().unwrap().clone();
        let again = rule(&g.canonical());
        assert_eq!(**again.glob().unwrap(), *g, "{p}");
    }
    // Equivalent spellings share a canonical form.
    assert_eq!(
        rule("*ads*").glob().unwrap().canonical(),
        rule("ads*").glob().unwrap().canonical()
    );
    assert_eq!(
        rule("||a*b^").glob().unwrap().canonical(),
        rule("||a**b|").glob().unwrap().canonical()
    );
}

#[test]
fn glob_rejections() {
    let bad: &[(&str, &str)] = &[
        ("*", "filter_rule.invalid_syntax"),
        ("**", "filter_rule.invalid_syntax"),
        ("||*^", "filter_rule.invalid_syntax"),
        ("*.*", "filter_rule.invalid_syntax"),
        ("||a*|b^", "filter_rule.invalid_syntax"),
        ("||a^b*", "filter_rule.invalid_syntax"),
        ("||a*!b^", "filter_rule.invalid_domain"),
        ("||a* b^", "filter_rule.invalid_domain"),
    ];
    for (r, code) in bad {
        assert_eq!(parse_rule(r).expect_err(r).code(), *code, "{r}");
    }
}

#[test]
fn glob_idna() {
    let r = rule("||m\u{fc}nchen*.example^");
    assert_eq!(r.glob().unwrap().canonical(), "||xn--mnchen-3ya*.example^");
    assert!(hit(&r, "xn--mnchen-3ya1.example"));
}

#[test]
fn unanchored_non_glob_rules_stay_domain_rules() {
    let r = rule("ads.example");
    assert_eq!(r.kind(), MatchKind::Subdomains);
    assert!(r.domain().is_some());
    assert!(r.glob().is_none());
    assert!(r.prefilter().is_none());
    assert!(!r.pattern_matches("ads.example"));
}

#[test]
fn pathological_glob_is_fast() {
    let r = rule("*a*a*a*a*a*b");
    let name = format!("{}example", "a.".repeat(120));
    let n = DomainName::parse(&name).unwrap();
    let start = Instant::now();
    for _ in 0..20 {
        assert!(!r.glob().unwrap().matches(n.as_str()));
    }
    let per_call = start.elapsed() / 20;
    assert!(per_call.as_millis() < 50, "took {per_call:?}");
    // A long pattern against a long name, boundary start (two runs).
    let long = format!("||{}b^", "a*".repeat(500));
    let r = rule(&long);
    let start = Instant::now();
    assert!(!r.glob().unwrap().matches(n.as_str()));
    assert!(start.elapsed().as_millis() < 50);
}

/// Tiny deterministic generator (xorshift64*).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[(self.next() % xs.len() as u64) as usize]
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

const NAME_PARTS: &[&str] = &[
    "a", "b", "ad", "ads", "x1", "track", "cdn", "example", "com", "net", "-", "_", ".", ".", ".",
];

fn random_name(rng: &mut Rng) -> String {
    loop {
        let mut s = String::new();
        for _ in 0..1 + rng.below(7) {
            s.push_str(rng.pick(NAME_PARTS));
        }
        if let Ok(n) = DomainName::parse(&s) {
            return n.as_str().to_string();
        }
    }
}

#[test]
fn glob_matches_reference_regex_and_prefilter_has_no_false_negatives() {
    // Independent oracle: translate the glob to a regex and compare on
    // random names; also check prefilter ⊇ match.
    let lits = [
        "a", "ad", "ads", "b", ".", ".example", "com", "-", "x1", "track",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let names: Vec<String> = (0..600).map(|_| random_name(&mut rng)).collect();
    let mut checked = 0usize;
    let mut positives = 0usize;
    for _ in 0..600 {
        let start = rng.below(3); // 0 anywhere, 1 `||`, 2 `|`
        let end = rng.below(3); // 0 none, 1 `^`, 2 `|`
        let mut pat = String::from(["", "||", "|"][start]);
        let mut re = String::from(["", r"(?:^|\.)", "^"][start]);
        let n_tok = 1 + rng.below(5);
        let mut has_star = false;
        for _ in 0..n_tok {
            if rng.below(3) == 0 {
                pat.push('*');
                re.push_str(".*");
                has_star = true;
            } else {
                let l = *rng.pick(&lits);
                pat.push_str(l);
                re.push_str(&regex_escape(l));
            }
        }
        if end > 0 {
            pat.push(['^', '|'][end - 1]);
            re.push('$');
        }
        if !has_star {
            continue;
        }
        let Ok(r) = parse_rule(&pat) else { continue };
        let Some(g) = r.glob() else { continue };
        let oracle = regex_like(&re);
        for n in &names {
            let want = oracle(n);
            let got = g.matches(n);
            assert_eq!(got, want, "{pat} vs {n} (oracle {re})");
            if got {
                positives += 1;
                if let Some(p) = g.prefilter() {
                    assert!(n.contains(p), "{pat}: prefilter {p:?} missing in {n}");
                }
                assert!(r.pattern_matches(n), "{pat} {n}");
            }
            checked += 1;
        }
    }
    assert!(checked > 50_000, "checked {checked}");
    assert!(positives > 500, "positives {positives}");
}

fn regex_escape(s: &str) -> String {
    s.replace('.', r"\.")
}

/// Oracle closure over the `regex` crate semantics, built via the library's
/// own regex rule path to avoid a direct dev-dependency.
fn regex_like(src: &str) -> impl Fn(&str) -> bool {
    let r = rule(&format!("/{src}/"));
    move |n: &str| r.regex().unwrap().is_match(n)
}

// -------------------------------------------------------------- regexes

#[test]
fn regex_semantics_table() {
    let table: &[(&str, &[&str], &[&str])] = &[
        (
            r"/^ads?[0-9]*\.example$/",
            &["ad.example", "ads.example", "ads12.example", "ADS.EXAMPLE"],
            &["xads.example", "ads.example.com", "adsx.example"],
        ),
        // Unanchored: substring search.
        (
            r"/track/",
            &["track.example", "a.mytracker.com"],
            &["trac.example"],
        ),
        (
            r"/^(ads|track)\.example$/",
            &["ads.example", "track.example"],
            &["ad.example"],
        ),
        (
            r"/\.cdn\d+\.example$/",
            &["a.cdn1.example", "x.y.cdn22.example"],
            &["cdn1.example"],
        ),
        // Case-insensitive even for upper-case pattern text.
        (
            r"/^ADS/",
            &["ads.example", "adserver.net"],
            &["xads.example"],
        ),
        // Matched against the name without trailing dot.
        (r"/example$/", &["a.example"], &[]),
        (r"/example\.$/", &[], &["a.example", "example"]),
    ];
    for (pat, yes, no) in table {
        let r = rule(pat);
        assert_eq!(r.kind(), MatchKind::Regex, "{pat}");
        assert!(r.domain().is_none() && r.glob().is_none());
        for n in *yes {
            assert!(hit(&r, n), "{pat} should match {n}");
        }
        for n in *no {
            assert!(!hit(&r, n), "{pat} should not match {n}");
        }
    }
}

#[test]
fn regex_rule_with_dollar_and_modifiers() {
    // `$` inside the regex must not be taken for a modifier separator.
    let r = rule("/^ads$/");
    assert!(hit(&r, "ads"));
    let r = rule(r"/^ads\d$/$important,dnstype=A");
    assert!(r.modifiers().important);
    assert!(hit(&r, "ads1"));
}

#[test]
fn regex_errors_per_source() {
    for (src, code) in [
        ("/(/", "filter_rule.invalid_regex"),
        ("/a{2,1}/", "filter_rule.invalid_regex"),
        ("/(?=a)/", "filter_rule.invalid_regex"), // look-around unsupported
        (r"/(a)\1/", "filter_rule.invalid_regex"), // backreference unsupported
        ("/(?:a{1000}){1000}/", "filter_rule.regex_too_large"),
        ("//", "filter_rule.invalid_syntax"),
    ] {
        // Custom rules: error with code.
        let e = parse_rule(src).expect_err(src);
        assert_eq!(e.code(), code, "{src}");
        // Lists: skipped with the matching reason, never a rule.
        let p = parse_list(src, ListSource::List);
        assert!(p.rules.is_empty(), "{src}");
        assert_eq!(p.skipped.total(), 1, "{src}");
    }
    let e = parse_rule("/(/").unwrap_err();
    assert!(matches!(e, RuleError::InvalidRegex { .. }));
    let params = e.params();
    assert_eq!(params[0].0, "message");
    assert!(!params[0].1.is_empty() && params[0].1.len() <= 203);
    assert_eq!(e.span(), 0..3);
    let p = parse_list("/(/\n/(?:a{1000}){1000}/\n", ListSource::Custom);
    assert_eq!(p.skipped.get(SkipReason::InvalidRegex), 1);
    assert_eq!(p.skipped.get(SkipReason::RegexTooLarge), 1);
    assert_eq!(SkipReason::InvalidRegex.as_str(), "invalid_regex");
    assert_eq!(SkipReason::RegexTooLarge.as_str(), "regex_too_large");
}

#[test]
fn long_regex_message_is_truncated() {
    let src = format!("/{}(/", "a".repeat(3000));
    let e = parse_rule(&src);
    // Over the 4 KiB line cap is a different error; stay below it.
    assert!(e.is_err());
    let src = format!("/[{}/", "z-a".repeat(300));
    let e = parse_rule(&src).unwrap_err();
    assert!(e.params().iter().all(|(_, v)| v.len() <= 203), "{e:?}");
}

#[test]
fn url_path_regex_is_browser_only() {
    let e = parse_rule(r"/\/ads\/banner/").unwrap_err();
    assert_eq!(
        SkipReason::from(&e),
        SkipReason::Unsupported(UnsupportedKind::BrowserOnly)
    );
}

#[test]
fn regex_prefilter_has_no_false_negatives() {
    let frags = [
        "ads",
        "track",
        r"\.",
        "[a-z]+",
        "(x)?",
        "a*",
        "^",
        "$",
        "b?",
        "(?:ab|cd)",
        r"\d",
        "example",
        ".",
        "a{2}",
        "x+",
        "(?i)",
        "com",
        "-",
        r"\w",
        "[0-9]",
        "(ad|b)+",
        "c{0,2}",
        r"\bad",
        "net",
    ];
    let mut rng = Rng(0xDEAD_BEEF_CAFE_F00D);
    let names: Vec<String> = (0..500).map(|_| random_name(&mut rng)).collect();
    let (mut checked, mut positives, mut with_prefilter) = (0usize, 0usize, 0usize);
    for _ in 0..800 {
        let mut src = String::new();
        for _ in 0..1 + rng.below(5) {
            src.push_str(rng.pick(&frags));
        }
        let Ok(r) = parse_rule(&format!("/{src}/")) else {
            continue;
        };
        let re = r.regex().unwrap();
        if re.prefilter().is_some() {
            with_prefilter += 1;
        }
        for n in &names {
            checked += 1;
            if re.is_match(n) {
                positives += 1;
                if let Some(p) = re.prefilter() {
                    assert!(n.contains(p), "/{src}/: prefilter {p:?} missing in {n}");
                }
            }
        }
    }
    assert!(checked > 20_000);
    assert!(positives > 1_000, "positives {positives}");
    assert!(with_prefilter > 100, "prefilters {with_prefilter}");
}

#[test]
fn regex_prefilter_examples() {
    assert_eq!(
        rule(r"/^ads?[0-9]*\.example$/").prefilter(),
        Some(".example")
    );
    assert_eq!(rule("/ads|track/").prefilter(), None);
    assert_eq!(rule("||ad*.example^").prefilter(), Some(".example"));
    assert_eq!(rule("*ads*").prefilter(), Some("ads"));
    assert_eq!(rule("||a*bc*d^").prefilter(), Some("bc"));
}

// ------------------------------------------------- modifiers and sources

#[test]
fn modifiers_apply_to_patterns_and_regexes() {
    let r = rule("@@||ad*.example^$important,dnstype=A|AAAA");
    assert_eq!(r.action(), RuleAction::Allow);
    assert_eq!(r.kind(), MatchKind::Pattern);
    assert!(r.modifiers().important);
    assert!(r.modifiers().dnstype.as_ref().unwrap().matches(1));

    let r = rule("||ad*.example^$denyallow=cdn.example");
    assert!(r.modifiers().denyallow.is_some());
    let r = rule("/^ads/$dnsrewrite=NXDOMAIN");
    assert!(r.modifiers().dnsrewrite.is_some());

    // Source policy: record rewrites refused in lists, allowed in custom.
    let body = "||ad*.example^$dnsrewrite=1.2.3.4\n/^ads/$dnsrewrite=1.2.3.4\n";
    let l = parse_list(body, ListSource::List);
    assert!(l.rules.is_empty());
    assert_eq!(l.skipped.get(SkipReason::RewriteFromList), 2);
    let c = parse_list(body, ListSource::Custom);
    assert_eq!(c.rules.len(), 2);

    // `$denyallow` is invalid on exceptions.
    assert!(parse_rule("@@||ad*.example^$denyallow=a.com").is_err());
}

#[test]
fn badfilter_key_for_patterns_and_regexes() {
    let a = rule("||ad*.example^");
    let b = rule("||AD*.example^$badfilter");
    assert!(b.modifiers().badfilter);
    assert_eq!(a.badfilter_key(), b.badfilter_key());
    // Equivalent spelling of the same glob.
    assert_eq!(
        a.badfilter_key(),
        rule("||ad**.example|$badfilter").badfilter_key()
    );
    // Differences: pattern text, action, modifiers, kind.
    assert_ne!(
        a.badfilter_key(),
        rule("||ad*.example.com^").badfilter_key()
    );
    assert_ne!(a.badfilter_key(), rule("@@||ad*.example^").badfilter_key());
    assert_ne!(
        a.badfilter_key(),
        rule("||ad*.example^$important").badfilter_key()
    );
    assert_ne!(a.badfilter_key(), rule("|ad*.example^").badfilter_key());

    let r1 = rule("/^ads\\d+$/");
    let r2 = rule("/^ads\\d+$/$badfilter");
    assert_eq!(r1.badfilter_key(), r2.badfilter_key());
    assert_ne!(r1.badfilter_key(), rule("/^ads\\d*$/").badfilter_key());
    // A regex and a glob with the same text are different rules.
    assert_ne!(rule("/ads/").badfilter_key(), rule("*ads*").badfilter_key());
}

#[test]
fn list_with_mixed_rules_and_text_recovery() {
    let body = "||ad*.example^\n/^t[0-9]+\\./\nplain.example\n*\n";
    let l = parse_list(body, ListSource::List);
    assert_eq!(l.rules.len(), 3);
    assert_eq!(l.rules[0].text(body), Some("||ad*.example^"));
    assert_eq!(l.rules[1].text(body), Some("/^t[0-9]+\\./"));
    assert_eq!(l.skipped.get(SkipReason::InvalidSyntax), 1);
    let cloned = l.rules[0].clone();
    assert!(std::sync::Arc::ptr_eq(
        cloned.glob().unwrap(),
        l.rules[0].glob().unwrap()
    ));
}
