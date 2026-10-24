//! Test helpers for DNScraft: in-process fake DNS hierarchy and DNSSEC test zones.
//!
//! The [`Hierarchy`] type starts authoritative servers for `.`, `test.` and
//! `example.test.` on loopback with OS-assigned ports. Zone data is kept as
//! structured records (see [`Zone`]). [`Hierarchy::start_signed`] starts a
//! DNSSEC-signed hierarchy (see [`DnssecScenario`]) with an exported trust anchor.

mod dnssec_zones;
mod error;
mod hierarchy;
mod responder;
mod server;
mod signer;
mod zone;

pub use dnssec_zones::{ChildVariant, DnssecScenario, NSEC3_SALT, TrustAnchor, signed_servers};
pub use error::TestkitError;
pub use hierarchy::{Hierarchy, ServerSpec, default_servers};
pub use server::{ReceivedQuery, ServerHandle, Transport};
pub use signer::{DenialMode, SigAlgorithm, SigningOptions, ZoneKey, sign_zone, unix_now};
pub use zone::{Zone, parse_name};
