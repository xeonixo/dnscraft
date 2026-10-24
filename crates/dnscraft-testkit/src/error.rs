use std::net::SocketAddr;

use hickory_proto::ProtoError;

/// Errors produced by the testkit.
#[derive(Debug, thiserror::Error)]
pub enum TestkitError {
    /// Binding a UDP or TCP socket failed.
    #[error("failed to bind {addr}: {source}")]
    Bind {
        /// Address that could not be bound.
        addr: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// A domain name in a zone definition was invalid.
    #[error("invalid domain name {name:?}: {source}")]
    InvalidName {
        /// The offending text.
        name: String,
        /// Underlying parse error.
        source: ProtoError,
    },
    /// No server is configured for the zone the caller asked for.
    #[error("no server for zone {zone}")]
    UnknownZone {
        /// Zone origin that was requested.
        zone: String,
    },
    /// Key generation or zone signing failed.
    #[error("signing failed: {0}")]
    Signing(String),
}

impl TestkitError {
    /// Stable, locale-neutral code for the error.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Bind { .. } => "testkit.bind",
            Self::InvalidName { .. } => "testkit.invalid_name",
            Self::UnknownZone { .. } => "testkit.unknown_zone",
            Self::Signing(_) => "testkit.signing",
        }
    }
}
