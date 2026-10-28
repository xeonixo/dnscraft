//! Policy pipeline for DNScraft: view/profile selection and the steps between
//! listeners and the resolver / filter engine.
//!
//! This crate owns configuration validation and the twelve pipeline steps. It
//! depends on [`dnscraft_resolver`] and [`dnscraft_filtering`], and defines
//! the [`ClientDirectory`] contract for device names without depending on
//! `dnscraft-clients`.
//!
//! Pipeline through SafeSearch (steps 5–6), resolve, answer-side filtering,
//! rebind, AAAA suppression, pause, and hot reload. Schedule evaluation is P14.

mod config;
mod decision;
mod directory;
mod engine;
mod error;
mod ids;
mod pause;
mod pipeline;
mod private;
mod rdata_text;
mod reverse;
mod safesearch_table;
mod schedule;
mod select;
mod snapshot;
mod stats;
mod status;
mod steps;
mod synth;
mod util;

pub use config::{
    ClientFlags, ClientIdEntry, ClientIdMeta, DEFAULT_LOCAL_NXDOMAIN_SUFFIXES, DEFAULT_RECORD_TTL,
    DnsProtocol, MAX_CLIENT_DEVICE_CHARS, MAX_CLIENT_LABEL_CHARS, PolicyConfig, ProfileConfig,
    RequestContext, SAFESEARCH_PROVIDERS, SCHEDULE_WEEK, SafeSearchConfig, ScheduleConfig,
    ViewConfig, ViewRecordConfig, YoutubeMode, check_client_device, check_client_label,
};
pub use decision::{
    AnswerOrigin, DecisionRecord, DecisionStep, DecisionTimings, FilterHit, ProtectionPauseScope,
    RebindSkipReason,
};
pub use directory::{ClientDirectory, NoClients};
pub use engine::{PolicyAnswer, PolicyEngine};
pub use error::{ConfigReason, IdError, PolicyError};
pub use ids::{ClientId, ListenerId, NodeId, ProfileId, ViewId};
pub use pause::{PauseScope, PauseUntil};
pub use pipeline::{Draft, Flow, StepCtx, Synth, clear_ad};
pub use rdata_text::{format_rdata, parse_rdata, parse_record_type, record_type_text};
pub use schedule::{active_schedule, offset_in_week};
pub use select::{Selection, SelectionCause};
pub use snapshot::{
    PolicySnapshot, PrefixTable, ProfileIdx, RebindException, SnapshotProfile, SnapshotView,
    ViewIdx, ViewRrSets,
};
pub use stats::{PolicyStats, ProfileStats, ViewStats};
pub use status::PolicyStatus;
pub use status::ProfileScheduleStatus;
