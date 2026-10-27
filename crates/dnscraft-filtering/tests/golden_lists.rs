#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Golden test over a checked-in excerpt of the list styles the parser accepts
//! (see `SPEC-filtering.md` → Testing). The excerpt is test-authored; no
//! third-party list content is bundled.

use dnscraft_filtering::{
    DnsRewrite, ListSource, MatchKind, Rewrite, RuleAction, SkipReason, UnsupportedKind, parse_list,
};

const EXCERPT: &str = include_str!("data/adblock_excerpt.txt");

#[test]
fn adblock_excerpt_yields_the_expected_rules_and_skips() {
    let p = parse_list(EXCERPT, ListSource::List);

    assert_eq!(p.total_lines, 15);
    assert_eq!(p.blank_lines, 1);
    assert_eq!(p.comment_lines, 3);

    let got: Vec<_> = p
        .rules
        .iter()
        .map(|r| {
            (
                r.line(),
                r.action(),
                r.kind(),
                r.domain().map(|d| d.as_str()),
                r.modifiers().important,
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            (
                5,
                RuleAction::Block,
                MatchKind::Subdomains,
                Some("ads.example"),
                false
            ),
            (
                6,
                RuleAction::Block,
                MatchKind::Subdomains,
                Some("tracker.example"),
                true
            ),
            (
                7,
                RuleAction::Allow,
                MatchKind::Subdomains,
                Some("cdn.example"),
                false
            ),
            (
                8,
                RuleAction::Block,
                MatchKind::Subdomains,
                Some("plain.example"),
                false
            ),
            // Hosts-file form: always an exact block, whatever the IP.
            (
                9,
                RuleAction::Block,
                MatchKind::Exact,
                Some("hosts.example"),
                false
            ),
            (
                10,
                RuleAction::Block,
                MatchKind::Exact,
                Some("real.example"),
                false
            ),
            (
                11,
                RuleAction::Block,
                MatchKind::Subdomains,
                Some("rcode.example"),
                false
            ),
        ]
    );

    // An rcode rewrite from a downloaded list is honoured …
    assert_eq!(
        p.rules[6].modifiers().dnsrewrite,
        Some(DnsRewrite::Set(Rewrite::Refused))
    );

    // … while a record rewrite drops the whole rule, a cosmetic rule is
    // unsupported, and malformed lines are counted by reason.
    assert_eq!(p.skipped.get(SkipReason::RewriteFromList), 1);
    assert_eq!(
        p.skipped
            .get(SkipReason::Unsupported(UnsupportedKind::Cosmetic)),
        1
    );
    assert_eq!(p.skipped.get(SkipReason::InvalidDomain), 1);
    assert_eq!(p.skipped.get(SkipReason::InvalidSyntax), 1);
    assert_eq!(p.skipped.total(), 4);

    let skipped: Vec<_> = p
        .samples
        .iter()
        .map(|s| (s.line, s.code, s.text.as_str()))
        .collect();
    assert_eq!(
        skipped,
        [
            (
                12,
                "filter_rule.rewrite_from_list",
                "||record.example^$dnsrewrite=1.2.3.4"
            ),
            (
                13,
                "filter_rule.unsupported_syntax",
                "example.com##.ad-banner"
            ),
            (14, "filter_rule.invalid_domain", "||bad_domain!^"),
            (15, "filter_rule.invalid_syntax", "||"),
        ]
    );
}
