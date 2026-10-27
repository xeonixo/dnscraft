//! Canonical domain name used for rule matching.

use std::fmt;
use std::str::FromStr;

use crate::error::NameError;

const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 253;

/// A domain name in canonical matching form.
///
/// Canonical form: ASCII lower-case, no trailing dot, 1 to 253 octets, every
/// label 1 to 63 octets.
///
/// Allowed characters are ASCII letters, digits, hyphen and underscore
/// (underscore is needed for names such as `_dmarc.example.org`). The check is
/// deliberately lenient about *position*: hyphens at the start or end of a
/// label and all-numeric labels are accepted, because real-world block lists
/// contain such names. It is strict about length and character set. The root
/// name is not representable. Non-ASCII input is rejected; IDNA (punycode)
/// conversion is the parser's job.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String")]
pub struct DomainName(Box<str>);

impl DomainName {
    /// Parses and canonicalises `input`. A single trailing dot is accepted.
    pub fn parse(input: &str) -> Result<Self, NameError> {
        let s = input.strip_suffix('.').unwrap_or(input);
        if s.is_empty() {
            return if input.is_empty() || input == "." {
                Err(NameError::Empty)
            } else {
                Err(NameError::EmptyLabel)
            };
        }
        if let Some(ch) = s.chars().find(|c| !c.is_ascii()) {
            return Err(NameError::NonAscii { ch });
        }
        if s.len() > MAX_NAME {
            return Err(NameError::TooLong { len: s.len() });
        }
        for label in s.split('.') {
            if label.is_empty() {
                return Err(NameError::EmptyLabel);
            }
            if label.len() > MAX_LABEL {
                return Err(NameError::LabelTooLong { len: label.len() });
            }
            if let Some(ch) = label
                .chars()
                .find(|c| !(c.is_ascii_alphanumeric() || *c == '-' || *c == '_'))
            {
                return Err(NameError::InvalidChar { ch });
            }
        }
        Ok(Self(s.to_ascii_lowercase().into_boxed_str()))
    }

    /// The canonical text form (lower-case, no trailing dot).
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Number of labels (at least 1).
    pub fn label_count(&self) -> usize {
        self.0.bytes().filter(|&b| b == b'.').count() + 1
    }

    /// Iterates over the labels, left to right (`a.b.c` yields `a`, `b`, `c`).
    /// Does not allocate.
    pub fn labels(&self) -> Labels<'_> {
        Labels(self.0.split('.'))
    }

    /// Iterates over the name and its parent suffixes, longest first
    /// (`a.b.c` yields `a.b.c`, `b.c`, `c`). Does not allocate.
    pub fn suffixes(&self) -> Suffixes<'_> {
        Suffixes(Some(&self.0))
    }

    /// The labels in reverse order, joined by dots (`a.b.c` becomes `c.b.a`).
    ///
    /// The rule index stores names in this form so that all names under a
    /// suffix share a common byte prefix, which makes suffix lookups prefix
    /// lookups. Allocates one `String`.
    pub fn reversed(&self) -> String {
        let mut out = String::with_capacity(self.0.len());
        for (i, label) in self.0.rsplit('.').enumerate() {
            if i > 0 {
                out.push('.');
            }
            out.push_str(label);
        }
        out
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DomainName({})", self.0)
    }
}

impl FromStr for DomainName {
    type Err = NameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<String> for DomainName {
    type Error = NameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(&value)
    }
}

impl AsRef<str> for DomainName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Iterator over the labels of a [`DomainName`], left to right.
#[derive(Clone, Debug)]
pub struct Labels<'a>(std::str::Split<'a, char>);

impl<'a> Iterator for Labels<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        self.0.next()
    }
}

/// Iterator over a [`DomainName`] and its parent suffixes, longest first.
#[derive(Clone, Debug)]
pub struct Suffixes<'a>(Option<&'a str>);

impl<'a> Iterator for Suffixes<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        let cur = self.0?;
        self.0 = cur.split_once('.').map(|(_, rest)| rest);
        Some(cur)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ok(s: &str) -> DomainName {
        DomainName::parse(s).expect("valid name")
    }

    fn code(s: &str) -> &'static str {
        DomainName::parse(s).expect_err("invalid name").code()
    }

    #[test]
    fn canonicalises_case_and_trailing_dot() {
        assert_eq!(ok("WWW.Example.COM.").as_str(), "www.example.com");
        assert_eq!(ok("example.com").to_string(), "example.com");
        assert_eq!("A.B".parse::<DomainName>().unwrap().as_str(), "a.b");
    }

    #[test]
    fn label_length_limits() {
        let l63 = "a".repeat(63);
        let l64 = "a".repeat(64);
        assert!(DomainName::parse(&format!("{l63}.com")).is_ok());
        assert_eq!(code(&format!("{l64}.com")), "filter_name.label_too_long");
    }

    #[test]
    fn total_length_limits() {
        // 3 x 63 + 1 + 3 x ... build exactly 253 and 254 octets.
        let l = "a".repeat(63);
        let n253 = format!("{l}.{l}.{l}.{}", "a".repeat(61)); // 63*3 + 3 + 61 = 253
        assert_eq!(n253.len(), 253);
        assert!(DomainName::parse(&n253).is_ok());
        assert!(DomainName::parse(&format!("{n253}.")).is_ok());
        let n254 = format!("{l}.{l}.{l}.{}", "a".repeat(62));
        assert_eq!(n254.len(), 254);
        assert_eq!(code(&n254), "filter_name.too_long");
    }

    #[test]
    fn empty_inputs_and_labels() {
        assert_eq!(code(""), "filter_name.empty");
        assert_eq!(code("."), "filter_name.empty");
        assert_eq!(code("a..b"), "filter_name.empty_label");
        assert_eq!(code(".a.b"), "filter_name.empty_label");
        assert_eq!(code("a.b.."), "filter_name.empty_label");
    }

    #[test]
    fn underscore_and_lenient_hyphens() {
        assert_eq!(ok("_dmarc.example.org").as_str(), "_dmarc.example.org");
        assert!(DomainName::parse("-a-.b-.-c").is_ok());
        assert!(DomainName::parse("123.456").is_ok());
    }

    #[test]
    fn invalid_characters() {
        for bad in [
            "a b.com",
            "*.example.com",
            "a/b.com",
            "a@b",
            "a:b",
            "a^b.com",
        ] {
            assert_eq!(code(bad), "filter_name.invalid_char", "{bad}");
        }
    }

    #[test]
    fn non_ascii_is_rejected() {
        assert_eq!(code("münchen.de"), "filter_name.non_ascii");
        assert_eq!(code("例え.jp"), "filter_name.non_ascii");
    }

    #[test]
    fn suffix_iteration() {
        let n = ok("a.b.c");
        assert_eq!(n.suffixes().collect::<Vec<_>>(), ["a.b.c", "b.c", "c"]);
        assert_eq!(ok("com").suffixes().collect::<Vec<_>>(), ["com"]);
    }

    #[test]
    fn label_iteration_and_count() {
        let n = ok("a.b.c");
        assert_eq!(n.labels().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(n.label_count(), 3);
        assert_eq!(ok("x").label_count(), 1);
    }

    #[test]
    fn reversed_form() {
        assert_eq!(ok("a.b.c").reversed(), "c.b.a");
        assert_eq!(ok("Example.com.").reversed(), "com.example");
        assert_eq!(ok("single").reversed(), "single");
    }
}
