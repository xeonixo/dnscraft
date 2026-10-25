#![no_main]

use dnscraft_filtering::{ListSource, build_rule, describe_rule, parse_list, parse_rule};
use libfuzzer_sys::fuzz_target;

fn check_list(body: &str, source: ListSource) {
    let parsed = parse_list(body, source);
    for rule in &parsed.rules {
        let text = rule.text(body);
        assert!(text.is_some(), "list rule without source text: {rule:?}");
        assert!(
            !text.unwrap_or_default().is_empty(),
            "list rule with empty source text: {rule:?}"
        );
        let _ = rule.pattern_matches("a.example");
    }
}

fn check_line(line: &str) {
    let Ok(rule) = parse_rule(line) else {
        return;
    };
    let text = rule.text(line);
    assert!(text.is_some(), "rule without source text: {rule:?}");
    assert!(
        !text.unwrap_or_default().is_empty(),
        "rule with empty source text: {rule:?}"
    );
    let _ = rule.pattern_matches("a.example");

    if let Some(spec) = describe_rule(&rule) {
        let built = build_rule(&spec).expect("build_rule of a described rule");
        parse_rule(&built).expect("parse_rule of a built rule");
    }
}

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    check_list(&s, ListSource::List);
    check_list(&s, ListSource::Custom);
    for line in s.lines() {
        check_line(line);
    }
});
