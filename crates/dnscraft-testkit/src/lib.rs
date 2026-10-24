//! Test helpers for DNScraft: in-process fake DNS hierarchy and DNSSEC test zones.
//!
//! The [`Hierarchy`] type starts authoritative servers for `.`, `test.` and
//! `example.test.` on loopback with OS-assigned ports. Zone data is kept as
//! structured records (see [`Zone`]) so later DNSSEC signing can extend it.

mod error;
mod hierarchy;
mod responder;
mod server;
mod zone;

pub use error::TestkitError;
pub use hierarchy::{Hierarchy, ServerSpec, default_servers};
pub use server::{ReceivedQuery, ServerHandle, Transport};
pub use zone::{Zone, parse_name};
