//! HTTP surface: envelopes, pagination, routing and rate limiting.
//!
//! The router is assembled in [`router`] from the reusable pieces here. The
//! network entry point (bind, TLS) lives in [`crate::server`].

pub(crate) mod auth;
pub(crate) mod clients_routes;
pub(crate) mod config_routes;
pub(crate) mod filter_routes;
pub(crate) mod listener_routes;
pub(crate) mod mcp_endpoints;
pub(crate) mod pagination;
pub(crate) mod query_log_routes;
pub(crate) mod rate_limit;
pub(crate) mod response;
pub(crate) mod router;
pub(crate) mod stats_routes;
pub(crate) mod tls_routes;
