//! Domain filtering engine for DNScraft.
//!
//! This crate decides what should happen to a query name: pass it, allow it
//! explicitly, block it, or rewrite the answer. Every non-pass verdict carries
//! a [`Reason`] naming the rule and where it came from.
//!
//! What it is not: it speaks no DNS on the wire, opens no sockets, and has no
//! notion of clients. Callers hand in a name and get a [`Verdict`] back.
//!
//! Currently provided (Task F1): the canonical matching name [`DomainName`],
//! validated ids ([`ListId`], [`SetId`]), verdict types, [`BlockMode`], an
//! injectable [`Clock`], and error types with stable codes.

mod clock;
mod error;
mod name;
mod types;

pub use clock::{Clock, ManualClock, SystemClock};
pub use error::{FilterError, IdError, NameError};
pub use name::{DomainName, Labels, Suffixes};
pub use types::{BlockMode, ListId, Reason, Rewrite, RuleSource, SetId, Verdict};
