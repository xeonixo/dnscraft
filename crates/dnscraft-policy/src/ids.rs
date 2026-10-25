//! Stable identifiers for views, profiles, listeners and DoH/DoT Client IDs.

use std::fmt;
use std::str::FromStr;
use std::sync::Arc;

use crate::error::IdError;

/// Maximum length for [`ViewId`], [`ProfileId`] and [`ListenerId`].
const MAX_ID: usize = 64;
/// Maximum length for a DoH/DoT [`ClientId`] (one DNS label).
const MAX_CLIENT_ID: usize = 63;

fn validate_id(s: &str, max: usize) -> Result<(), IdError> {
    if s.is_empty() {
        return Err(IdError::Empty);
    }
    if s.len() > max {
        return Err(IdError::TooLong { len: s.len(), max });
    }
    match s
        .chars()
        .find(|c| !(c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-'))
    {
        Some(ch) => Err(IdError::InvalidChar { ch }),
        None => Ok(()),
    }
}

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $max:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
        pub struct $name(Arc<str>);

        impl $name {
            /// Validates `s` (`[a-z0-9-]{1,N}`) and wraps it.
            pub fn new(s: &str) -> Result<Self, IdError> {
                validate_id(s, $max)?;
                Ok(Self(Arc::from(s)))
            }

            /// The id as text.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }
    };
}

id_type!(
    /// Identifier of a split-horizon view.
    ///
    /// Matches `[a-z0-9-]{1,64}`.
    ViewId,
    MAX_ID
);
id_type!(
    /// Identifier of a policy profile (filter set, canaries, rebind, …).
    ///
    /// Matches `[a-z0-9-]{1,64}`.
    ProfileId,
    MAX_ID
);
id_type!(
    /// Identifier of a DNS listener that accepted the query.
    ///
    /// Matches `[a-z0-9-]{1,64}`.
    ListenerId,
    MAX_ID
);
id_type!(
    /// DoH path / DoT SNI Client ID.
    ///
    /// Matches `[a-z0-9-]{1,63}` so it is a valid DNS label for the Client-ID
    /// hostname. Distinct from UniFi / directory client records.
    ClientId,
    MAX_CLIENT_ID
);

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn client_id_accepts_valid_labels() {
        assert_eq!(
            ClientId::new("iphone-k7q2x9").unwrap().as_str(),
            "iphone-k7q2x9"
        );
        assert_eq!(ClientId::new("a").unwrap().as_str(), "a");
        assert_eq!(ClientId::new(&"a".repeat(63)).unwrap().as_str().len(), 63);
    }

    #[test]
    fn client_id_rejects_upper_case_underscore_empty_and_64_chars() {
        assert_eq!(
            ClientId::new("iPhone").unwrap_err().code(),
            "policy.id.invalid_char"
        );
        assert_eq!(
            ClientId::new("bad_id").unwrap_err().code(),
            "policy.id.invalid_char"
        );
        assert_eq!(ClientId::new("").unwrap_err().code(), "policy.id.empty");
        assert_eq!(
            ClientId::new(&"a".repeat(64)).unwrap_err().code(),
            "policy.id.too_long"
        );
    }

    #[test]
    fn view_id_allows_64_chars() {
        assert!(ViewId::new(&"v".repeat(64)).is_ok());
        assert_eq!(
            ViewId::new(&"v".repeat(65)).unwrap_err().code(),
            "policy.id.too_long"
        );
    }
}
