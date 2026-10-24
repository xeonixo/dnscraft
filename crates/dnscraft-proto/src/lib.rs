//! DNS wire format for DNScraft: domain names, compression, records,
//! EDNS(0) and complete messages.
//!
//! This crate performs no I/O, never panics on untrusted input, and reports
//! every decode failure as a typed [`ProtoError`].

mod edns;
mod error;
mod header;
mod message;
mod name;
mod rdata;
mod record;
mod rtype;

pub use edns::{Edns, EdnsOption};
pub use error::ProtoError;
pub use header::{Counts, Header, Opcode, Rcode};
pub use message::{Message, Question};
pub use name::{CompressionMap, Labels, Name};
pub use rdata::{RData, SvcbData};
pub use record::Record;
pub use rtype::{Class, RecordType};
