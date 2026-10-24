//! DNS wire format for DNScraft: domain names, compression, and (in later
//! modules) records and messages.
//!
//! This crate performs no I/O, never panics on untrusted input, and reports
//! every decode failure as a typed [`ProtoError`].

mod error;
mod name;
mod rdata;
mod record;
mod rtype;

pub use error::ProtoError;
pub use name::{CompressionMap, Labels, Name};
pub use rdata::{RData, SvcbData};
pub use record::Record;
pub use rtype::{Class, RecordType};
