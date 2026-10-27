//! Error types with stable, locale-neutral codes.
//!
//! Every error exposes a `code()` of the form `area.reason` for APIs and i18n.
//! Human-readable text is for logs, not for end users.
//!
//! ## `NameError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`NameError::Empty`] | `filter_name.empty` |
//! | [`NameError::EmptyLabel`] | `filter_name.empty_label` |
//! | [`NameError::LabelTooLong`] | `filter_name.label_too_long` |
//! | [`NameError::TooLong`] | `filter_name.too_long` |
//! | [`NameError::InvalidChar`] | `filter_name.invalid_char` |
//! | [`NameError::NonAscii`] | `filter_name.non_ascii` |
//!
//! ## `IdError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`IdError::Empty`] | `filter_id.empty` |
//! | [`IdError::TooLong`] | `filter_id.too_long` |
//! | [`IdError::InvalidChar`] | `filter_id.invalid_char` |
//!
//! ## `RuleError` codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`RuleError::Empty`] | `filter_rule.empty` |
//! | [`RuleError::Comment`] | `filter_rule.comment` |
//! | [`RuleError::TooLong`] | `filter_rule.too_long` |
//! | [`RuleError::InvalidDomain`] | `filter_rule.invalid_domain` |
//! | [`RuleError::Unsupported`] | `filter_rule.unsupported_syntax` |
//! | [`RuleError::InvalidSyntax`] | `filter_rule.invalid_syntax` |
//! | [`RuleError::MultipleNames`] | `filter_rule.multiple_names` |
//! | [`RuleError::ReservedHost`] | `filter_rule.reserved_host` |
//! | [`RuleError::UnknownModifier`] | `filter_rule.unknown_modifier` |
//! | [`RuleError::DuplicateModifier`] | `filter_rule.duplicate_modifier` |
//! | [`RuleError::InvalidModifier`] | `filter_rule.invalid_modifier` |
//! | [`RuleError::ClientModifier`] | `filter_rule.client_modifier` |
//! | [`RuleError::RewriteFromList`] | `filter_rule.rewrite_from_list` |
//! | [`RuleError::InvalidIdna`] | `filter_rule.invalid_idna` |
//! | [`RuleError::InvalidRegex`] | `filter_rule.invalid_regex` |
//! | [`RuleError::RegexTooLarge`] | `filter_rule.regex_too_large` |
//! | [`FilterError::UnknownSet`] | `filter_set.unknown` |
//! | [`FilterError::BuildFailed`] | `filter_engine.build_failed` |
//! | [`FilterError::NoStore`] | `filter_engine.no_store` |
//!
//! [`FilterError`] delegates to the code of the wrapped error when nested.

/// A domain name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum NameError {
    /// The input is empty or only a dot (the root is not a matchable name).
    #[error("domain name is empty")]
    Empty,
    /// Two consecutive dots or a leading dot.
    #[error("domain name has an empty label")]
    EmptyLabel,
    /// A label is longer than 63 octets.
    #[error("label is {len} octets long, maximum is 63")]
    LabelTooLong {
        /// Length of the offending label.
        len: usize,
    },
    /// The whole name is longer than 253 octets (without trailing dot).
    #[error("domain name is {len} octets long, maximum is 253")]
    TooLong {
        /// Length of the name.
        len: usize,
    },
    /// A character outside letters, digits, hyphen and underscore.
    #[error("invalid character {ch:?} in domain name")]
    InvalidChar {
        /// The offending character.
        ch: char,
    },
    /// A non-ASCII character; IDNA conversion must happen before this point.
    #[error("domain name contains non-ASCII character {ch:?}")]
    NonAscii {
        /// The offending character.
        ch: char,
    },
}

impl NameError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "filter_name.empty",
            Self::EmptyLabel => "filter_name.empty_label",
            Self::LabelTooLong { .. } => "filter_name.label_too_long",
            Self::TooLong { .. } => "filter_name.too_long",
            Self::InvalidChar { .. } => "filter_name.invalid_char",
            Self::NonAscii { .. } => "filter_name.non_ascii",
        }
    }
}

/// A list or set id was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum IdError {
    /// The id is empty.
    #[error("id is empty")]
    Empty,
    /// The id is longer than 64 characters.
    #[error("id is {len} characters long, maximum is 64")]
    TooLong {
        /// Length of the id.
        len: usize,
    },
    /// A character outside `a-z`, `0-9`, `-`.
    #[error("invalid character {ch:?} in id")]
    InvalidChar {
        /// The offending character.
        ch: char,
    },
}

impl IdError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty => "filter_id.empty",
            Self::TooLong { .. } => "filter_id.too_long",
            Self::InvalidChar { .. } => "filter_id.invalid_char",
        }
    }
}

/// Category of rule syntax that is recognised but not supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]

pub enum UnsupportedKind {
    /// Element hiding, scriptlets and other cosmetic rules (`##`, `#@#`, ...).
    Cosmetic,
    /// Rules that only make sense in a browser (URL paths, `$script`, `$domain=`, ...).
    BrowserOnly,
}

impl UnsupportedKind {
    /// Short stable identifier used as the `kind` message parameter.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cosmetic => "cosmetic",
            Self::BrowserOnly => "browser_only",
        }
    }
}

/// A rule line was rejected (strict parsing) or skipped (list parsing).
///
/// Every variant carries the byte span of the offending part, relative to the
/// start of the parsed input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum RuleError {
    /// The line is blank.
    #[error("rule is empty")]
    Empty {
        /// Span of the input.
        span: std::ops::Range<usize>,
    },
    /// The line is a comment, not a rule.
    #[error("line is a comment, not a rule")]
    Comment {
        /// Span of the comment.
        span: std::ops::Range<usize>,
    },
    /// The line is longer than the 4 KiB cap.
    #[error("rule line is {len} bytes long, maximum is 4096")]
    TooLong {
        /// Length of the line in bytes.
        len: usize,
        /// Span of the input.
        span: std::ops::Range<usize>,
    },
    /// The domain part is not a valid domain name.
    #[error("invalid domain in rule: {source}")]
    InvalidDomain {
        /// Why the name was rejected.
        #[source]
        source: NameError,
        /// Span of the domain text.
        span: std::ops::Range<usize>,
    },
    /// Valid syntax of a kind this engine does not implement.
    #[error("unsupported rule syntax: {}", kind.as_str())]
    Unsupported {
        /// Which kind of syntax.
        kind: UnsupportedKind,
        /// Span of the unsupported part.
        span: std::ops::Range<usize>,
    },
    /// Malformed rule (misplaced anchors, missing pattern, hosts line without
    /// a name, `@@` on a hosts line, ...).
    #[error("invalid rule syntax: {detail}")]
    InvalidSyntax {
        /// Stable identifier of the problem (for example `empty_pattern`).
        detail: &'static str,
        /// Span of the offending part.
        span: std::ops::Range<usize>,
    },
    /// A hosts line with several names where exactly one rule was requested.
    #[error("hosts line has more than one name")]
    MultipleNames {
        /// Span of the second name.
        span: std::ops::Range<usize>,
    },
    /// A hosts name such as `localhost` that is never filtered.
    #[error("reserved host name is ignored")]
    ReservedHost {
        /// Span of the name.
        span: std::ops::Range<usize>,
    },
    /// A modifier this engine does not know.
    #[error("unknown modifier")]
    UnknownModifier {
        /// Span of the modifier (`name` or `name=value`).
        span: std::ops::Range<usize>,
    },
    /// The same modifier appears twice.
    #[error("duplicate modifier")]
    DuplicateModifier {
        /// Span of the second occurrence.
        span: std::ops::Range<usize>,
    },
    /// A known modifier with a bad or missing value, or used where it is
    /// not allowed.
    #[error("invalid ${modifier} modifier: {detail}")]
    InvalidModifier {
        /// The modifier name, lower-case.
        modifier: &'static str,
        /// Stable identifier of the problem (for example `mixed_negation`).
        detail: &'static str,
        /// Span of the offending part (the value if there is one).
        span: std::ops::Range<usize>,
    },
    /// `$client` / `$ctag`: per-client scoping is done by profiles, not rules.
    #[error("$client and $ctag are not supported; use profiles")]
    ClientModifier {
        /// Span of the modifier.
        span: std::ops::Range<usize>,
    },
    /// A `$dnsrewrite` record rewrite in a downloaded list.
    #[error("record rewrites are only honoured in custom rules")]
    RewriteFromList {
        /// Span of the `$dnsrewrite` value.
        span: std::ops::Range<usize>,
    },
    /// A non-ASCII domain that cannot be converted to punycode.
    #[error("domain cannot be converted with IDNA")]
    InvalidIdna {
        /// Span of the domain text.
        span: std::ops::Range<usize>,
    },
    /// A `/regex/` rule whose regex does not compile.
    #[error("invalid regular expression: {message}")]
    InvalidRegex {
        /// The regex engine's message, whitespace-collapsed and truncated.
        message: String,
        /// Span of the regex including the slashes.
        span: std::ops::Range<usize>,
    },
    /// A `/regex/` rule whose compiled program exceeds the size limit.
    #[error("regular expression is too large")]
    RegexTooLarge {
        /// Span of the regex including the slashes.
        span: std::ops::Range<usize>,
    },
}

impl RuleError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Empty { .. } => "filter_rule.empty",
            Self::Comment { .. } => "filter_rule.comment",
            Self::TooLong { .. } => "filter_rule.too_long",
            Self::InvalidDomain { .. } => "filter_rule.invalid_domain",
            Self::Unsupported { .. } => "filter_rule.unsupported_syntax",
            Self::InvalidSyntax { .. } => "filter_rule.invalid_syntax",
            Self::MultipleNames { .. } => "filter_rule.multiple_names",
            Self::ReservedHost { .. } => "filter_rule.reserved_host",
            Self::UnknownModifier { .. } => "filter_rule.unknown_modifier",
            Self::DuplicateModifier { .. } => "filter_rule.duplicate_modifier",
            Self::InvalidModifier { .. } => "filter_rule.invalid_modifier",
            Self::ClientModifier { .. } => "filter_rule.client_modifier",
            Self::RewriteFromList { .. } => "filter_rule.rewrite_from_list",
            Self::InvalidIdna { .. } => "filter_rule.invalid_idna",
            Self::InvalidRegex { .. } => "filter_rule.invalid_regex",
            Self::RegexTooLarge { .. } => "filter_rule.regex_too_large",
        }
    }

    /// Byte span of the problem within the parsed input.
    pub fn span(&self) -> std::ops::Range<usize> {
        match self {
            Self::Empty { span }
            | Self::Comment { span }
            | Self::TooLong { span, .. }
            | Self::InvalidDomain { span, .. }
            | Self::Unsupported { span, .. }
            | Self::InvalidSyntax { span, .. }
            | Self::MultipleNames { span }
            | Self::ReservedHost { span }
            | Self::UnknownModifier { span }
            | Self::DuplicateModifier { span }
            | Self::InvalidModifier { span, .. }
            | Self::ClientModifier { span }
            | Self::RewriteFromList { span }
            | Self::InvalidIdna { span }
            | Self::InvalidRegex { span, .. }
            | Self::RegexTooLarge { span } => span.clone(),
        }
    }

    /// Message parameters for localisation, as `(name, value)` pairs.
    pub fn params(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::TooLong { len, .. } => vec![("len", len.to_string()), ("max", "4096".into())],
            Self::InvalidDomain { source, .. } => vec![("reason", source.code().to_string())],
            Self::Unsupported { kind, .. } => vec![("kind", kind.as_str().to_string())],
            Self::InvalidSyntax { detail, .. } => vec![("detail", (*detail).to_string())],
            Self::InvalidModifier {
                modifier, detail, ..
            } => vec![
                ("modifier", (*modifier).to_string()),
                ("detail", (*detail).to_string()),
            ],
            Self::ClientModifier { .. } => vec![("hint", "profiles".to_string())],
            Self::InvalidRegex { message, .. } => vec![("message", message.clone())],
            Self::RegexTooLarge { .. } => {
                vec![("limit", crate::pattern::REGEX_SIZE_LIMIT.to_string())]
            }
            _ => Vec::new(),
        }
    }
}

/// Top-level error of the filtering module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]

pub enum FilterError {
    /// A domain name was rejected.
    #[error(transparent)]
    Name(#[from] NameError),
    /// An id was rejected.
    #[error(transparent)]
    Id(#[from] IdError),
    /// A rule was rejected.
    #[error(transparent)]
    Rule(#[from] RuleError),
    /// No filter set with this id exists in the snapshot.
    #[error("unknown filter set {0:?}")]
    UnknownSet(String),
    /// Building a snapshot from the current config failed.
    #[error("cannot build filter snapshot: {message}")]
    BuildFailed {
        /// Human-readable detail for logs.
        message: String,
    },
    /// The engine was constructed without a list store (matching-only).
    #[error("filter engine has no list store")]
    NoStore,
}

impl FilterError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Name(e) => e.code(),
            Self::Id(e) => e.code(),
            Self::Rule(e) => e.code(),
            Self::UnknownSet(_) => "filter_set.unknown",
            Self::BuildFailed { .. } => "filter_engine.build_failed",
            Self::NoStore => "filter_engine.no_store",
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::set::SnapshotError;
    use crate::types::{ListId, McpRuleId, SetId};

    #[test]
    fn codes_are_unique_and_well_formed() {
        let all: Vec<(&str, FilterError)> = vec![
            ("filter_name.empty", NameError::Empty.into()),
            ("filter_name.empty_label", NameError::EmptyLabel.into()),
            (
                "filter_name.label_too_long",
                NameError::LabelTooLong { len: 64 }.into(),
            ),
            (
                "filter_name.too_long",
                NameError::TooLong { len: 254 }.into(),
            ),
            (
                "filter_name.invalid_char",
                NameError::InvalidChar { ch: ' ' }.into(),
            ),
            (
                "filter_name.non_ascii",
                NameError::NonAscii { ch: 'ü' }.into(),
            ),
            ("filter_rule.empty", RuleError::Empty { span: 0..0 }.into()),
            (
                "filter_rule.comment",
                RuleError::Comment { span: 0..1 }.into(),
            ),
            (
                "filter_rule.too_long",
                RuleError::TooLong {
                    len: 5000,
                    span: 0..5000,
                }
                .into(),
            ),
            (
                "filter_rule.invalid_domain",
                RuleError::InvalidDomain {
                    source: NameError::Empty,
                    span: 0..1,
                }
                .into(),
            ),
            (
                "filter_rule.unsupported_syntax",
                RuleError::Unsupported {
                    kind: UnsupportedKind::BrowserOnly,
                    span: 0..1,
                }
                .into(),
            ),
            (
                "filter_rule.invalid_syntax",
                RuleError::InvalidSyntax {
                    detail: "x",
                    span: 0..1,
                }
                .into(),
            ),
            (
                "filter_rule.multiple_names",
                RuleError::MultipleNames { span: 0..1 }.into(),
            ),
            (
                "filter_rule.reserved_host",
                RuleError::ReservedHost { span: 0..1 }.into(),
            ),
            (
                "filter_rule.unknown_modifier",
                RuleError::UnknownModifier { span: 0..1 }.into(),
            ),
            (
                "filter_rule.duplicate_modifier",
                RuleError::DuplicateModifier { span: 0..1 }.into(),
            ),
            (
                "filter_rule.invalid_modifier",
                RuleError::InvalidModifier {
                    modifier: "dnstype",
                    detail: "x",
                    span: 0..1,
                }
                .into(),
            ),
            (
                "filter_rule.client_modifier",
                RuleError::ClientModifier { span: 0..1 }.into(),
            ),
            (
                "filter_rule.rewrite_from_list",
                RuleError::RewriteFromList { span: 0..1 }.into(),
            ),
            (
                "filter_rule.invalid_idna",
                RuleError::InvalidIdna { span: 0..1 }.into(),
            ),
            (
                "filter_rule.invalid_regex",
                RuleError::InvalidRegex {
                    message: "x".into(),
                    span: 0..1,
                }
                .into(),
            ),
            (
                "filter_rule.regex_too_large",
                RuleError::RegexTooLarge { span: 0..1 }.into(),
            ),
            ("filter_set.unknown", FilterError::UnknownSet("x".into())),
            (
                "filter_engine.build_failed",
                FilterError::BuildFailed {
                    message: "x".into(),
                },
            ),
            ("filter_engine.no_store", FilterError::NoStore),
            ("filter_id.empty", IdError::Empty.into()),
            ("filter_id.too_long", IdError::TooLong { len: 65 }.into()),
            (
                "filter_id.invalid_char",
                IdError::InvalidChar { ch: 'A' }.into(),
            ),
        ];
        let mut seen = std::collections::HashSet::new();
        for (code, err) in &all {
            assert_eq!(err.code(), *code, "{err}");
            assert_code(code, &mut seen);
            assert!(!err.to_string().is_empty());
        }

        let snapshot: Vec<(&str, SnapshotError)> = vec![
            (
                "filter_set.unknown_list",
                SnapshotError::UnknownList {
                    set: SetId::new("s").unwrap(),
                    list: ListId::new("l").unwrap(),
                },
            ),
            (
                "filter_set.duplicate_set",
                SnapshotError::DuplicateSet(SetId::new("s").unwrap()),
            ),
            (
                "filter_set.duplicate_list",
                SnapshotError::DuplicateList(ListId::new("l").unwrap()),
            ),
            (
                "filtering.config.mcp_rule_id_duplicate",
                SnapshotError::DuplicateMcpRuleId {
                    set: SetId::new("s").unwrap(),
                    id: McpRuleId::new("r").unwrap(),
                },
            ),
            (
                "filtering.config.mcp_rule_duplicate",
                SnapshotError::DuplicateMcpRule {
                    set: SetId::new("s").unwrap(),
                    domain: "example.com".parse().unwrap(),
                },
            ),
            (
                "filtering.config.mcp_rule_expiry",
                SnapshotError::InvalidMcpRuleExpiry {
                    set: SetId::new("s").unwrap(),
                    id: McpRuleId::new("r").unwrap(),
                },
            ),
            (
                "filtering.config.mcp_rule_invalid",
                SnapshotError::InvalidMcpRule {
                    set: SetId::new("s").unwrap(),
                    id: McpRuleId::new("r").unwrap(),
                    code: "filter_build.pattern_not_allowed",
                },
            ),
        ];
        for (code, err) in &snapshot {
            assert_eq!(err.code(), *code, "{err}");
            assert_code(code, &mut seen);
            assert!(!err.to_string().is_empty());
        }
    }

    /// Codes are dot-separated lower-case segments; no code may repeat.
    fn assert_code(code: &'static str, seen: &mut std::collections::HashSet<&'static str>) {
        assert!(seen.insert(code), "duplicate code {code}");
        let parts: Vec<&str> = code.split('.').collect();
        assert!(parts.len() >= 2, "{code} is not area.reason");
        for part in parts {
            assert!(
                !part.is_empty() && part.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
                "{code}"
            );
        }
    }
}
