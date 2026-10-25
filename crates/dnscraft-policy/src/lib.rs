//! Policy pipeline for DNScraft: view/profile selection and the steps between
//! listeners and the resolver / filter engine.
//!
//! This crate owns configuration validation and (in later tasks) the twelve
//! pipeline steps. It depends on [`dnscraft_resolver`] and
//! [`dnscraft_filtering`], and defines the `ClientDirectory` contract
//! for device names without depending on `dnscraft-clients`.
//!
//! Phase 1 (this release): ids, [`PolicyConfig`], [`PolicySnapshot::build`] and
//! [`PolicyError`] codes. Selection and the engine follow in P2+.

mod config;
mod error;
mod ids;
mod snapshot;

pub use config::{
    ClientFlags, DEFAULT_LOCAL_NXDOMAIN_SUFFIXES, DEFAULT_RECORD_TTL, DnsProtocol, PolicyConfig,
    ProfileConfig, RequestContext, SafeSearchConfig, ScheduleConfig, ViewConfig, ViewRecordConfig,
};
pub use error::{ConfigReason, IdError, PolicyError};
pub use ids::{ClientId, ListenerId, ProfileId, ViewId};
pub use snapshot::{
    PolicySnapshot, PrefixTable, ProfileIdx, SnapshotProfile, SnapshotView, ViewIdx, ViewRrSets,
};
