//! Control-character neutralisation and length caps for tool output.
//!
//! Strings that come from DNS, clients, filter lists or the assistant are
//! untrusted data. They reach tool output only through [`sanitize`], which
//! replaces every control code point (`U+0000..=U+001F`, `U+007F..=U+009F`)
//! with `U+FFFD` and truncates on a character boundary with a `...` suffix.
//!
//! Markup characters (`<`, `>`, `&`, `[`, `]`, `` ` ``) are deliberately left
//! unchanged: tool output is JSON, not markup, and the assistant must treat
//! field values as data (SPEC-mcp.md § Output rules).

/// Cap for domain names (DNS maximum).
pub const CAP_DOMAIN: usize = 253;
/// Cap for client display names.
pub const CAP_CLIENT_NAME: usize = 100;
/// Cap for rule text.
pub const CAP_RULE_TEXT: usize = 1000;
/// Cap for list ids.
pub const CAP_LIST_ID: usize = 100;
/// Cap for assistant-supplied reasons.
pub const CAP_REASON: usize = 200;

/// Replace control characters and truncate to at most `cap` characters.
///
/// The result is at most `cap + 3` characters: the suffix `...` is added only
/// when input remains after the cap. Exactly-at-cap input is unchanged.
pub fn sanitize(input: &str, cap: usize) -> String {
    let mut out = String::with_capacity(input.len().min(cap));
    let mut truncated = false;
    for (index, ch) in input.chars().enumerate() {
        if index == cap {
            truncated = true;
            break;
        }
        out.push(if is_control(ch) { '\u{FFFD}' } else { ch });
    }
    if truncated {
        out.push_str("...");
    }
    out
}

fn is_control(ch: char) -> bool {
    matches!(ch, '\u{0000}'..='\u{001F}' | '\u{007F}'..='\u{009F}')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn every_control_code_point_is_replaced() {
        for code in (0u32..=0x1f).chain(0x7f..=0x9f) {
            let ch = char::from_u32(code).unwrap();
            assert_eq!(
                sanitize(&format!("a{ch}b"), 10),
                "a\u{FFFD}b",
                "U+{code:04X}"
            );
        }
    }

    #[test]
    fn printable_text_emoji_and_markup_pass_unchanged() {
        let input = "Hello <script>&[x]` 😀 — ünïcode";
        assert_eq!(sanitize(input, CAP_DOMAIN), input);
    }

    #[test]
    fn exactly_at_cap_is_unchanged_and_over_cap_is_truncated() {
        assert_eq!(sanitize("abc", 3), "abc");
        assert_eq!(sanitize("abcd", 3), "abc...");
        assert_eq!(sanitize("", 0), "");
        assert_eq!(sanitize("a", 0), "...");
    }

    #[test]
    fn truncation_never_splits_a_code_point() {
        let out = sanitize("😀😀😀", 1);
        assert_eq!(out, "😀...");
        assert_eq!(out.chars().count(), 4);
    }

    proptest! {
        #[test]
        fn output_has_no_control_characters_and_respects_the_cap(
            input in proptest::collection::vec(any::<char>(), 0..400)
                .prop_map(|chars| chars.into_iter().collect::<String>()),
            cap in 0usize..500,
        ) {
            let out = sanitize(&input, cap);
            prop_assert!(!out.chars().any(is_control));
            prop_assert!(out.chars().count() <= cap + 3);
        }

        #[test]
        fn clean_printable_input_is_never_changed(input in "[ -~]{0,300}") {
            prop_assert_eq!(sanitize(&input, 300), input);
        }
    }
}
