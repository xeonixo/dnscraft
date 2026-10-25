//! Policy pipeline for DNScraft: view/profile selection and the steps between
//! listeners and the resolver / filter engine.
//!
//! This crate owns configuration validation and the twelve pipeline steps. It
//! depends on [`dnscraft_resolver`] and [`dnscraft_filtering`], and defines
//! the [`ClientDirectory`] contract for device names without depending on
//! `dnscraft-clients`.
//!
//! Phase 1–3: ids, config, snapshot build/select, and
//! [`PolicyEngine::handle`] with resolver passthrough (ANY, AD, forward-zone
//! allow-list). Steps 1–6 and 8–11 follow in later tasks.

mod config;
mod decision;
mod directory;
mod engine;
mod error;
mod ids;
mod pipeline;
mod select;
mod snapshot;
mod synth;

pub use config::{
    ClientFlags, DEFAULT_LOCAL_NXDOMAIN_SUFFIXES, DEFAULT_RECORD_TTL, DnsProtocol, PolicyConfig,
    ProfileConfig, RequestContext, SafeSearchConfig, ScheduleConfig, ViewConfig, ViewRecordConfig,
};
pub use decision::{AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, FilterHit};
pub use directory::{ClientDirectory, NoClients};
pub use engine::{PolicyAnswer, PolicyEngine};
pub use error::{ConfigReason, IdError, PolicyError};
pub use ids::{ClientId, ListenerId, ProfileId, ViewId};
pub use pipeline::{Draft, Flow, StepCtx, Synth, clear_ad};
pub use select::{Selection, SelectionCause};
pub use snapshot::{
    PolicySnapshot, PrefixTable, ProfileIdx, SnapshotProfile, SnapshotView, ViewIdx, ViewRrSets,
};
