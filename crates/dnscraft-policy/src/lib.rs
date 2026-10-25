//! Policy pipeline for DNScraft: view/profile selection and the steps between
//! listeners and the resolver / filter engine.
//!
//! This crate owns configuration validation and the twelve pipeline steps. It
//! depends on [`dnscraft_resolver`] and [`dnscraft_filtering`], and defines
//! the [`ClientDirectory`] contract for device names without depending on
//! `dnscraft-clients`.
//!
//! Phase 1–9: ids, config, snapshot build/select, engine through filter
//! (step 4), resolve (step 7), answer-side CNAME/IP filtering (steps 8–9),
//! rebind (step 10), and AAAA suppression (step 11). Steps 5–6 follow later.

mod config;
mod decision;
mod directory;
mod engine;
mod error;
mod ids;
mod pipeline;
mod private;
mod reverse;
mod select;
mod snapshot;
mod steps;
mod synth;

pub use config::{
    ClientFlags, DEFAULT_LOCAL_NXDOMAIN_SUFFIXES, DEFAULT_RECORD_TTL, DnsProtocol, PolicyConfig,
    ProfileConfig, RequestContext, SafeSearchConfig, ScheduleConfig, ViewConfig, ViewRecordConfig,
};
pub use decision::{
    AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, FilterHit, RebindSkipReason,
};
pub use directory::{ClientDirectory, NoClients};
pub use engine::{PolicyAnswer, PolicyEngine};
pub use error::{ConfigReason, IdError, PolicyError};
pub use ids::{ClientId, ListenerId, ProfileId, ViewId};
pub use pipeline::{Draft, Flow, StepCtx, Synth, clear_ad};
pub use select::{Selection, SelectionCause};
pub use snapshot::{
    PolicySnapshot, PrefixTable, ProfileIdx, SnapshotProfile, SnapshotView, ViewIdx, ViewRrSets,
};
