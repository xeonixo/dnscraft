//! Client identity index for DNScraft.
//!
//! Turns manual names and UniFi Network data into an [`Arc`] snapshot that
//! answers `by_ip` / `by_name` / `reverse` / `local_domains`. This crate never
//! selects filter profiles or views — that stays in `policy`.
//!
//! So far: [`ClientsConfig`], [`ClientsError`], [`Clock`] / [`ManualClock`],
//! [`read_secret`], label helpers ([`normalise_label`], [`fqdn`], [`suffixed`]),
//! [`ClientLookup`], UniFi [`merge::build`], [`GatewayClient`] with pin/CA/insecure
//! TLS, Integration + classic fetch / [`sync_once`], and the core data types
//! ([`ClientInfo`], [`ClientId`], …).

#![deny(missing_docs)]

mod cache;
mod classic;
mod clock;
mod config;
mod engine;
mod error;
mod gateway;
mod integration;
mod label;
mod lookup;
mod merge;
mod state;
mod status;
mod sync;
mod tls;
mod types;

pub use cache::{
    CACHE_VERSION, CachePayload, MAX_CACHE_BYTES, cache_path, networks_from_value,
    networks_to_value, observations_from_value, observations_to_value,
};
pub use classic::{
    CLASSIC_PREFIX, ClassicFetch, fetch as fetch_classic,
    parse_clients_json as parse_classic_clients_json, resolve_site_key as resolve_classic_site_key,
};
pub use clock::{Clock, ManualClock, SystemClock, wait_until};
pub use config::{
    ClientsConfig, DEFAULT_IPV6_ADDRESS_TTL, DEFAULT_LOCAL_DOMAIN, DEFAULT_OFFLINE_RETAIN,
    DEFAULT_POLL_INTERVAL, DEFAULT_UNIFI_PROFILE_ID, LOCAL_NODE_ID, LocalDomainMode,
    MAX_MANUAL_ENTRIES, ManualEntry, TlsMode, UnifiConfig, UnifiProfile,
};
pub use dnscraft_common::secret::Secret;
pub use engine::{ClientEngine, SyncReport};
pub use error::ClientsError;
pub use gateway::{GatewayClient, MAX_BODY_BYTES};
pub use integration::{
    INTEGRATION_PREFIX, IntegrationFetch, fetch as fetch_integration,
    parse_clients_page_json as parse_integration_clients_json,
};
/// Re-export for constructing [`ManualEntry`] CIDRs without a direct `ipnet` dependency.
pub use ipnet::IpNet;
pub use label::{MAX_LABEL_LEN, fqdn, is_normalised_label, normalise_label, suffixed};
pub use lookup::ClientLookup;
pub use merge::{
    MAX_CLIENT_COUNT, MergeOutput, MergeStats, NetworkInfo, UnifiObservation, WARN_CLIENT_COUNT,
    build, is_link_local,
};
pub use state::{RetainedClient, State};
pub use status::ClientsStatus;
pub use sync::{SyncResult, sync_once};
pub use tls::{INSECURE_WARN_CODE, leaf_sha256};
pub use types::{ClientId, ClientInfo, ClientSource, MacAddr, VlanInfo};

/// Environment variable holding the UniFi Network Integration API key.
pub const UNIFI_API_KEY_ENV: &str = "DNSCRAFT_UNIFI_API_KEY";

/// Reads a secret from `name` or `{name}_FILE`.
///
/// A missing or empty value maps to [`ClientsError::SecretMissing`].
pub fn read_secret(name: &str) -> Result<Secret, ClientsError> {
    dnscraft_common::secret::read_secret(name).map_err(|name| ClientsError::SecretMissing { name })
}
