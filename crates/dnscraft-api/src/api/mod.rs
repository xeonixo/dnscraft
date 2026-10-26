//! HTTP surface: envelopes, pagination, routing and rate limiting.
//!
//! The router is assembled in [`router`] from the reusable pieces here. The
//! network entry point (bind, TLS) lives in [`crate::server`].

pub(crate) mod pagination;
pub(crate) mod rate_limit;
pub(crate) mod response;
pub(crate) mod router;
