//! SQLite persistence for control-api (single writer, `spawn_blocking`).

mod audit;
mod db;
mod kv;
mod migrations;

pub use audit::AuditRecord;
pub use db::Db;

/// Maps a `rusqlite` error to the storage invariant code.
pub(crate) fn db_err(err: rusqlite::Error) -> crate::error::ControlApiError {
    crate::error::ControlApiError::Internal {
        message: err.to_string(),
    }
}
