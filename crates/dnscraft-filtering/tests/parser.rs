#![allow(clippy::unwrap_used, clippy::expect_used)]

use dnscraft_filtering::{
    ListSource, MatchKind, RuleAction, RuleError, SkipReason, UnsupportedKind, parse_list,
    parse_rule,
};

use MatchKind::{Exact, Subdomains};
use RuleAction::{Allow, Block};

fn ok(s: &str) -> (RuleAction, MatchKind, String) {
    let r = parse_rule(s).unwrap_or_else(|e| panic!("{s:?}: {e} ({})", e.code()));
    (r.action(), r.kind(), r.domain().to_string())
}

fn err(s: &str) -> RuleError {
    parse_rule(s).expect_err(s)
}

fn code(s: &str) -> &'static str {
    err(s).code()
}

fn kind(k: UnsupportedKind) -> SkipReason {
    SkipReason::Unsupported(k)
}

#[test]
fn accepted_forms_table() {
    let cases: &[(&str, RuleAction, MatchKind, &str)] = &[
        ("||ads.example^", Block, Subdomains, "ads.example"),
        ("||ads.example^|", Block, Subdomains, "ads.example"),
        ("||ads.example", Block, Subdomains, "ads.example"),
        ("||ads.example|", Block, Subdomains, "ads.example"),
        ("@@||cdn.example^", Allow, Subdomains, "cdn.example"),
        ("@@|cdn.example^", Allow, Exact, "cdn.example"),
        ("|ads.example^", Block, Exact, "ads.example"),
        ("|ads.example|", Block, Exact, "ads.example"),
        ("|ads.example", Block, Exact, "ads.example"),
        ("ads.example", Block, Subdomains, "ads.example"),
        ("ads.example^", Block, Subdomains, "ads.example"),
        ("ads.example|", Block, Subdomains, "ads.example"),
        ("@@ads.example", Allow, Subdomains, "ads.example"),
        ("||ADS.Example^", Block, Subdomains, "ads.example"),
        ("||example.org.^", Block, Subdomains, "example.org"),
        ("Example.ORG.", Block, Subdomains, "example.org"),
        (
            "||_dmarc.example.org^",
            Block,
            Subdomains,
            "_dmarc.example.org",
        ),
        ("||com^", Block, Subdomains, "com"),
        ("  ||ads.example^  ", Block, Subdomains, "ads.example"),
        ("\t||ads.example^\t", Block, Subdomains, "ads.example"),
        ("||ads.example^\r", Block, Subdomains, "ads.example"),
    ];
    for (input, action, k, domain) in cases {
        assert_eq!(ok(input), (*action, *k, domain.to_string()), "{input:?}");
    }
}

#[test]
fn hosts_lines_are_exact_blocks() {
    for (input, domain) in [
        ("0.0.0.0 ads.example", "ads.example"),
        ("127.0.0.1 ads.example", "ads.example"),
        ("1.2.3.4\tads.example", "ads.example"),
        ("::1 ads.example", "ads.example"),
        ("fe80::1 ads.example", "ads.example"),
        ("0.0.0.0   Ads.Example   # inline comment", "ads.example"),
        ("0.0.0.0 ads.example#nospace", "ads.example"),
    ] {
        assert_eq!(ok(input), (Block, Exact, domain.to_string()), "{input:?}");
    }
}

#[test]
fn hosts_multiple_names() {
    let body = "0.0.0.0 a.example b.example\tc.example # trailing\n";
    let p = parse_list(body, ListSource::List);
    let names: Vec<_> = p.rules.iter().map(|r| r.domain().to_string()).collect();
    assert_eq!(names, ["a.example", "b.example", "c.example"]);
    assert!(
        p.rules
            .iter()
            .all(|r| r.kind() == Exact && r.action() == Block)
    );
    assert!(
        p.rules
            .iter()
            .all(|r| r.text(body) == Some("0.0.0.0 a.example b.example\tc.example # trailing"))
    );
    assert_eq!(p.skipped.total(), 0);

    // Strict: one rule only.
    let e = err("0.0.0.0 a.example b.example");
    assert_eq!(e.code(), "filter_rule.multiple_names");
    assert_eq!(e.span(), 18..27);
}

#[test]
fn hosts_reserved_names_are_skipped() {
    let body = "127.0.0.1 localhost\n\
                127.0.0.1 localhost.localdomain local\n\
                255.255.255.255 broadcasthost\n\
                ::1 ip6-localhost ip6-loopback\n\
                fe00::0 ip6-localnet\n\
                0.0.0.0 0.0.0.0\n\
                127.0.0.1 LOCALHOST real.example\n";
    let p = parse_list(body, ListSource::List);
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.rules[0].domain().as_str(), "real.example");
    assert_eq!(p.skipped.get(SkipReason::ReservedHost), 9);
    assert_eq!(code("127.0.0.1 localhost"), "filter_rule.reserved_host");
}

#[test]
fn hosts_errors() {
    assert_eq!(code("127.0.0.1"), "filter_rule.invalid_syntax");
    assert_eq!(
        code("127.0.0.1 # only comment"),
        "filter_rule.invalid_syntax"
    );
    assert_eq!(code("127.0.0.1 bad..name"), "filter_rule.invalid_domain");
    // `@@` with hosts syntax is invalid.
    assert_eq!(code("@@0.0.0.0 ads.example"), "filter_rule.invalid_domain");
    // A bare IP is not a rule.
    assert_eq!(code("1.2.3.4"), "filter_rule.invalid_syntax");
    assert_eq!(code("||1.2.3.4^"), "filter_rule.invalid_syntax");
}

#[test]
fn comments_blank_and_headers() {
    for c in [
        "! comment",
        "# comment",
        "#",
        "####",
        "[Adblock Plus 2.0]",
        "[adblock]",
        "#nospace",
    ] {
        assert_eq!(code(c), "filter_rule.comment", "{c:?}");
    }
    assert_eq!(code(""), "filter_rule.empty");
    assert_eq!(code("  \t "), "filter_rule.empty");
    let p = parse_list("! a\n# b\n\n[Adblock Plus]\n   \n####\n", ListSource::List);
    assert_eq!(p.comment_lines, 4);
    assert_eq!(p.blank_lines, 2);
    assert_eq!(p.total_lines, 6);
    assert!(p.rules.is_empty());
    assert_eq!(p.skipped.total(), 0);
}

#[test]
fn cosmetic_rules() {
    for c in [
        "##.banner",
        "example.org##.ad",
        "example.org#@#.ad",
        "example.org#$#body{x:y}",
        "example.org#?#div:has(.ad)",
        "example.org#%#//scriptlet('x')",
        "example.org#@$#.a { x: y }",
        "example.org$$script[data-src]",
        "#@#.ad",
    ] {
        let e = err(c);
        assert_eq!(e.code(), "filter_rule.unsupported_syntax", "{c}");
        assert_eq!(SkipReason::from(&e), kind(UnsupportedKind::Cosmetic), "{c}");
    }
    assert_eq!(err("example.org##.ad").span(), 11..16);
}

#[test]
fn browser_only_rules() {
    for c in [
        "||example.org/path^",
        "/ads/banner.gif",
        "|http://example.org/x",
        "||example.org^$script",
        "||example.org^$third-party",
        "||example.org^$domain=a.com|b.com",
        "||example.org^$image,~third-party",
        "@@||example.org^$document",
        "/ads/*.js$script",
    ] {
        let e = err(c);
        assert_eq!(
            SkipReason::from(&e),
            kind(UnsupportedKind::BrowserOnly),
            "{c}"
        );
    }
}

#[test]
fn supported_modifiers_are_accepted() {
    for c in [
        "||example.org^$important",
        "@@||example.org^$important",
        "||example.org^$badfilter",
        "||example.org^$dnstype=A|AAAA",
        "||example.org^$dnstype=~A",
        "||example.org^$denyallow=a.com|b.com",
        "||example.org^$dnsrewrite=NXDOMAIN",
    ] {
        let r = parse_rule(c).unwrap();
        assert!(!r.modifiers().is_empty(), "{c}");
        assert_eq!(r.domain().as_str(), "example.org");
    }
    // Span covers `$` and the modifier list for browser-only modifiers.
    assert_eq!(err("||example.org^$script").span(), 14..21);
}

#[test]
fn patterns_and_regex_are_unsupported_until_f4() {
    for c in ["*", "||ad*.example^", "*.example.org", "ads*", "@@||a*b^"] {
        assert_eq!(
            SkipReason::from(&err(c)),
            kind(UnsupportedKind::Pattern),
            "{c}"
        );
    }
    for c in [
        "/^ads?[0-9]*\\.example\\.$/",
        "/ads/",
        "@@/x/",
        "/a$/",
        "/ads/$important",
    ] {
        assert_eq!(
            SkipReason::from(&err(c)),
            kind(UnsupportedKind::Regex),
            "{c}"
        );
    }
}

#[test]
fn invalid_rules_with_spans() {
    let e = err("||bad_domain!^");
    assert_eq!(e.code(), "filter_rule.invalid_domain");
    assert_eq!(e.span(), 2..13);
    assert_eq!(
        e.params(),
        vec![("reason", "filter_name.invalid_char".to_string())]
    );

    assert_eq!(code("||a..b^"), "filter_rule.invalid_domain");
    assert_eq!(code("||.example^"), "filter_rule.invalid_domain");
    assert_eq!(code("||^"), "filter_rule.invalid_syntax");
    assert_eq!(code("||"), "filter_rule.invalid_syntax");
    assert_eq!(code("|"), "filter_rule.invalid_syntax");
    assert_eq!(code("@@"), "filter_rule.invalid_syntax");
    assert_eq!(code("^"), "filter_rule.invalid_syntax");
    assert_eq!(code("|||a.example^"), "filter_rule.invalid_syntax");
    assert_eq!(code("||a.example^^"), "filter_rule.invalid_syntax");
    assert_eq!(code("||a.example^b"), "filter_rule.invalid_syntax");
    assert_eq!(code("||a b.example^"), "filter_rule.invalid_domain");
    assert_eq!(code("||münchen!.de^"), "filter_rule.invalid_domain");
    assert_eq!(code("just some words"), "filter_rule.invalid_domain");
    assert_eq!(err("||a.example^b").span(), 2..13);
    assert_eq!(code("@@@@a.example"), "filter_rule.invalid_domain");
}

#[test]
fn too_long_lines() {
    let ok_line = format!("||{}.example^", "a".repeat(40));
    assert!(parse_rule(&ok_line).is_ok());
    let long = format!("||{}.example^", "a".repeat(4100));
    let e = err(&long);
    assert_eq!(e.code(), "filter_rule.too_long");
    assert_eq!(e.span(), 0..long.len());
    assert_eq!(e.params()[0].0, "len");

    let body = format!("{long}\n||ok.example^\n");
    let p = parse_list(&body, ListSource::List);
    assert_eq!(p.rules.len(), 1);
    assert_eq!(p.skipped.get(SkipReason::TooLong), 1);
    assert!(p.samples[0].text.len() <= 200);
    // Exactly 4096 bytes is accepted by the cap (then fails as a domain here).
    let edge = "a".repeat(4096);
    assert_ne!(code(&edge), "filter_rule.too_long");
}

#[test]
fn strict_vs_lenient() {
    let body = "||ads.example^\ngarbage line here\n||ok.example^\n";
    let p = parse_list(body, ListSource::List);
    assert_eq!(p.rules.len(), 2);
    assert_eq!(p.skipped.get(SkipReason::InvalidDomain), 1);
    assert_eq!(
        parse_rule("garbage line here").unwrap_err().code(),
        "filter_rule.invalid_domain"
    );
    assert!(parse_rule("||ads.example^").is_ok());
}

#[test]
fn crlf_bom_and_final_line() {
    let body = "\u{feff}||a.example^\r\n! c\r\n\r\n0.0.0.0 b.example\r\n||c.example^";
    let p = parse_list(body, ListSource::Custom);
    assert_eq!(p.total_lines, 5);
    assert_eq!(p.rules.len(), 3);
    assert_eq!(p.comment_lines, 1);
    assert_eq!(p.blank_lines, 1);
    let texts: Vec<_> = p.rules.iter().map(|r| r.text(body).unwrap()).collect();
    assert_eq!(texts, ["||a.example^", "0.0.0.0 b.example", "||c.example^"]);
    let lines: Vec<_> = p.rules.iter().map(|r| r.line()).collect();
    assert_eq!(lines, [1, 4, 5]);

    // No trailing newline vs trailing newline count the same.
    assert_eq!(parse_list("a.example\n", ListSource::List).total_lines, 1);
    assert_eq!(parse_list("a.example", ListSource::List).total_lines, 1);
    assert_eq!(parse_list("", ListSource::List).total_lines, 0);
    // BOM only on the first line; a lone CR is not a line break.
    let p = parse_list("a.example\rb.example\n", ListSource::List);
    assert_eq!(p.total_lines, 1);
    assert!(p.rules.is_empty());
}

#[test]
fn rule_text_roundtrip_and_span() {
    let body = "  ||a.example^  \n\t@@||b.example^\t\n";
    let p = parse_list(body, ListSource::List);
    assert_eq!(p.rules[0].text(body), Some("||a.example^"));
    assert_eq!(p.rules[1].text(body), Some("@@||b.example^"));
    assert_eq!(&body[p.rules[1].span()], "@@||b.example^");
    assert_eq!(p.rules[1].text("short"), None);
    let r = parse_rule("  ||a.example^ ").unwrap();
    assert_eq!(r.text("  ||a.example^ "), Some("||a.example^"));
    assert_eq!(r.line(), 1);
}

#[test]
fn mixed_fixture_counts() {
    let body = "\
[Adblock Plus 2.0]
! Title: test
# hosts style comment

||ads.example^
@@||good.ads.example^
|exact.example^
plain.example
0.0.0.0 h1.example h2.example # c
127.0.0.1 localhost
example.org##.ad
example.org#@#.ad
||x.example/path^
||x.example^$script
||x.example^$important
||ad*.example^
/ban[0-9]/
garbage here
||bad..name^
127.0.0.1
";
    let p = parse_list(body, ListSource::List);
    assert_eq!(p.total_lines, 20);
    assert_eq!(p.comment_lines, 3);
    assert_eq!(p.blank_lines, 1);
    assert_eq!(p.rules.len(), 7);
    assert_eq!(p.skipped.get(kind(UnsupportedKind::Cosmetic)), 2);
    assert_eq!(p.skipped.get(kind(UnsupportedKind::BrowserOnly)), 2);
    assert_eq!(p.skipped.get(kind(UnsupportedKind::Pattern)), 1);
    assert_eq!(p.skipped.get(kind(UnsupportedKind::Regex)), 1);
    assert_eq!(p.skipped.get(SkipReason::ReservedHost), 1);
    assert_eq!(p.skipped.get(SkipReason::InvalidDomain), 2);
    assert_eq!(p.skipped.get(SkipReason::InvalidSyntax), 1);
    assert_eq!(p.skipped.get(SkipReason::TooLong), 0);
    assert_eq!(p.skipped.total(), 10);
    assert_eq!(p.samples.len(), 10);
    assert_eq!(p.samples[0].line, 10);
    assert_eq!(p.samples[0].text, "127.0.0.1 localhost");
    assert_eq!(p.samples[0].code, "filter_rule.reserved_host");
    assert_eq!(p.skipped.iter().map(|(_, c)| c).sum::<usize>(), 10);
}

#[test]
fn sample_is_capped_and_truncated() {
    let mut body = String::new();
    for _ in 0..50 {
        body.push_str("###bad\u{e9}\n"); // cosmetic
    }
    body.push_str(&format!("x{}\u{e9}\n", "a".repeat(199)));
    let p = parse_list(&body, ListSource::List);
    assert_eq!(p.skipped.total(), 51);
    assert_eq!(p.samples.len(), 20);
    let p = parse_list(&format!("x{}\u{e9}\n", "a".repeat(199)), ListSource::List);
    // 200 bytes would split the two-byte char: truncated before it.
    assert_eq!(p.samples[0].text.len(), 200);
}

#[test]
fn no_panic_on_random_input() {
    let alphabet: Vec<&str> = vec![
        "|",
        "||",
        "@@",
        "^",
        "$",
        "#",
        "##",
        "#@#",
        "!",
        "*",
        "/",
        ".",
        "-",
        "_",
        " ",
        "\t",
        "\r",
        "\n",
        "a",
        "b",
        "0",
        "1",
        ":",
        "::",
        "0.0.0.0 ",
        "127.0.0.1 ",
        "example",
        "example.org",
        "important",
        "script",
        ",",
        "=",
        "~",
        "\u{e9}",
        "\u{feff}",
        "\u{1f600}",
        "[Adblock",
        "localhost",
        "ip6-",
    ];
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..3000 {
        let n = (next() % 24) as usize;
        let mut s = String::new();
        for _ in 0..n {
            s.push_str(alphabet[(next() as usize) % alphabet.len()]);
        }
        let _ = parse_rule(&s);
        let p = parse_list(&s, ListSource::List);
        for r in &p.rules {
            assert!(r.text(&s).is_some(), "{s:?}");
        }
    }
    // Arbitrary bytes, lossily decoded (as a download would be).
    for _ in 0..500 {
        let n = (next() % 200) as usize;
        let bytes: Vec<u8> = (0..n).map(|_| next() as u8).collect();
        let s = String::from_utf8_lossy(&bytes);
        let _ = parse_rule(&s);
        let _ = parse_list(&s, ListSource::List);
    }
}

#[test]
#[ignore = "performance measurement; run with --release -- --ignored --nocapture"]
fn perf_one_million_hosts_lines() {
    use std::fmt::Write as _;
    let mut body = String::with_capacity(40_000_000);
    for i in 0..1_000_000u32 {
        let _ = writeln!(body, "0.0.0.0 host{i}.tracker{}.example.com", i % 1000);
    }
    let t = std::time::Instant::now();
    let p = parse_list(&body, ListSource::List);
    let dt = t.elapsed();
    println!(
        "parsed {} lines ({} MB) into {} rules in {:?}",
        p.total_lines,
        body.len() / 1_000_000,
        p.rules.len(),
        dt
    );
    assert_eq!(p.rules.len(), 1_000_000);
}
