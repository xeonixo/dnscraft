//! SQLite persistence for control-api (single writer, `spawn_blocking`).
//!
//! ## Design
//!
//! This module wraps a single-writer SQLite connection behind a `Mutex`. Every
//! database call runs via `tokio::task::spawn_blocking` to avoid blocking the
//! async runtime — SQLite I/O is synchronous and must not run on async executor
//! threads.
//!
//! Migrations are idempotent and tracked via `PRAGMA user_version`. Each migration
//! index `i` corresponds to schema version `i + 1`. The migration runner applies
//! missing migrations in order on database open.
//!
//! All SQL statements use bind parameters (never string interpolation) to prevent
//! SQL injection. See `tests/sql_injection_is_treated_as_data` in the integration
//! tests for verification.

mod audit;
mod config_store;
mod db;
mod kv;
mod migrations;

pub use audit::AuditRecord;
pub use config_store::ConfigStore;
pub use db::Db;

/// Maps a `rusqlite` error to the storage invariant code.
pub(crate) fn db_err(err: rusqlite::Error) -> crate::error::ControlApiError {
    crate::error::ControlApiError::Internal {
        message: err.to_string(),
    }
}
