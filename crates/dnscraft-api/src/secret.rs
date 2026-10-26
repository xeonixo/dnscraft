//! Zeroizing secret string that never leaks through `Debug` or `Serialize`.

use std::fmt;

use serde::{Serialize, Serializer};
use zeroize::Zeroizing;

/// A secret string that serializes as the literal `"redacted"` and zeroizes its
/// contents on drop, so a secret never reaches a log, a snapshot or a serialized
/// config.
#[derive(Clone, Default)]
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wraps a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrows the secret for use (e.g. an HTTP header); callers must never log
    /// or serialize it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl PartialEq for Secret {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for Secret {}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("redacted")
    }
}
