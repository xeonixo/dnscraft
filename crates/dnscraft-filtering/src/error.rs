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
}

impl FilterError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Name(e) => e.code(),
            Self::Id(e) => e.code(),
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
