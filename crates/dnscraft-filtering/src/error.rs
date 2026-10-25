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
//!
//! [`FilterError`] delegates to the code of the wrapped error.

/// A domain name was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
#[non_exhaustive]
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

/// Category of rule syntax that is recognised but not supported (yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum UnsupportedKind {
    /// Element hiding, scriptlets and other cosmetic rules (`##`, `#@#`, ...).
    Cosmetic,
    /// Rules that only make sense in a browser (URL paths, `$script`, `$domain=`, ...).
    BrowserOnly,
    /// A rule with a `$` modifier list (implemented in Task F3).
    Modifiers,
    /// A wildcard pattern (implemented in Task F4).
    Pattern,
    /// A `/regex/` rule (implemented in Task F4).
    Regex,
}

impl UnsupportedKind {
    /// Short stable identifier used as the `kind` message parameter.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cosmetic => "cosmetic",
            Self::BrowserOnly => "browser_only",
            Self::Modifiers => "modifiers",
            Self::Pattern => "pattern",
            Self::Regex => "regex",
        }
    }
}

/// A rule line was rejected (strict parsing) or skipped (list parsing).
///
/// Every variant carries the byte span of the offending part, relative to the
/// start of the parsed input.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
            | Self::ReservedHost { span } => span.clone(),
        }
    }

    /// Message parameters for localisation, as `(name, value)` pairs.
    pub fn params(&self) -> Vec<(&'static str, String)> {
        match self {
            Self::TooLong { len, .. } => vec![("len", len.to_string()), ("max", "4096".into())],
            Self::InvalidDomain { source, .. } => vec![("reason", source.code().to_string())],
            Self::Unsupported { kind, .. } => vec![("kind", kind.as_str().to_string())],
            Self::InvalidSyntax { detail, .. } => vec![("detail", (*detail).to_string())],
            _ => Vec::new(),
        }
    }
}

/// Top-level error of the filtering module.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
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
}

impl FilterError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Name(e) => e.code(),
            Self::Id(e) => e.code(),
            Self::Rule(e) => e.code(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
                    kind: UnsupportedKind::Regex,
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
            assert!(seen.insert(*code), "duplicate code {code}");
            let (area, reason) = code.split_once('.').expect("area.reason");
            let ok =
                |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c == '_');
            assert!(ok(reason), "{code}");
            assert!(ok(&area.replace("filter_", "")), "{code}");
            assert!(!err.to_string().is_empty());
        }
    }
}
