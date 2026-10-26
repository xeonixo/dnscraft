//! Pagination parameter parsing (`limit` / `offset`) and cursor helpers.
//!
//! `limit` defaults to 50 and is capped at 500; `offset` defaults to 0. Out of
//! range or non-numeric values are rejected with
//! [`ControlApiError::PaginationInvalid`] (a 400) rather than panicking or
//! silently clamping. Callers fetch `limit + 1` rows and use [`Pagination::has_more`]
//! / [`Pagination::next_offset`] to expose the documented `has_more` /
//! `next_offset` fields.

// Wired to the query-log list endpoint in A12; until then the public API here
// is exercised only by the unit tests below.
#![allow(dead_code)]

use axum::extract::Query;
use serde::Deserialize;

use crate::error::ControlApiError;

/// Default page size.
pub(crate) const DEFAULT_LIMIT: u32 = 50;
/// Maximum page size.
pub(crate) const MAX_LIMIT: u32 = 500;

/// Parsed pagination parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pagination {
    /// Page size, in `1..=MAX_LIMIT`.
    pub(crate) limit: u32,
    /// Number of rows to skip (non-negative).
    pub(crate) offset: u64,
}

impl Pagination {
    /// Parses the raw query values, applying defaults and bounds.
    pub(crate) fn from_query(query: Query<RawPagination>) -> Result<Self, ControlApiError> {
        Self::parse(query.limit.as_deref(), query.offset.as_deref())
    }

    /// Parses already-extracted raw values; shared by endpoints that carry
    /// additional query parameters besides `limit`/`offset`.
    pub(crate) fn parse(
        limit: Option<&str>,
        offset: Option<&str>,
    ) -> Result<Self, ControlApiError> {
        let limit = match limit {
            None => DEFAULT_LIMIT,
            Some(raw) => {
                let n: u32 = raw
                    .trim()
                    .parse()
                    .map_err(|_| invalid("limit", raw, "a non-negative integer"))?;
                if !(1..=MAX_LIMIT).contains(&n) {
                    return Err(ControlApiError::PaginationInvalid {
                        reason: format!("limit must be within 1..={MAX_LIMIT}, got `{raw}`"),
                    });
                }
                n
            }
        };
        let offset = match offset {
            None => 0,
            Some(raw) => raw
                .trim()
                .parse()
                .map_err(|_| invalid("offset", raw, "a non-negative integer"))?,
        };
        Ok(Self { limit, offset })
    }

    /// Whether more rows exist after `fetched` (which must be `limit + 1` when
    /// the caller probed for a following page).
    pub(crate) fn has_more(&self, fetched: usize) -> bool {
        fetched > self.limit as usize
    }

    /// The offset to request for the next page, or `None` when there is none.
    pub(crate) fn next_offset(&self, fetched: usize) -> Option<u64> {
        self.has_more(fetched)
            .then_some(self.offset + self.limit as u64)
    }
}

/// Raw (string) pagination parameters; parsed manually so non-numeric and
/// overflowing values are 4xx errors instead of panics.
#[derive(Debug, Deserialize)]
pub(crate) struct RawPagination {
    limit: Option<String>,
    offset: Option<String>,
}

fn invalid(field: &str, raw: &str, want: &str) -> ControlApiError {
    ControlApiError::PaginationInvalid {
        reason: format!("{field} must be {want}, got `{raw}`"),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn q(limit: Option<&str>, offset: Option<&str>) -> Query<RawPagination> {
        Query(RawPagination {
            limit: limit.map(str::to_owned),
            offset: offset.map(str::to_owned),
        })
    }

    #[test]
    fn defaults_and_valid_values() {
        let p = Pagination::from_query(q(None, None)).unwrap();
        assert_eq!(
            p,
            Pagination {
                limit: 50,
                offset: 0
            }
        );

        let p = Pagination::from_query(q(Some("10"), Some("20"))).unwrap();
        assert_eq!(
            p,
            Pagination {
                limit: 10,
                offset: 20
            }
        );

        let p = Pagination::from_query(q(Some("500"), None)).unwrap();
        assert_eq!(p.limit, 500);
    }

    #[test]
    fn rejects_out_of_range_and_non_numeric_without_panicking() {
        for raw in ["0", "501", "-1", "abc", "99999999999999999999"] {
            let err = Pagination::from_query(q(Some(raw), None)).unwrap_err();
            assert_eq!(
                err.code(),
                "control_api.pagination.invalid",
                "limit `{raw}`"
            );
        }
        for raw in ["-5", "abc", "9999999999999999999999999999"] {
            let err = Pagination::from_query(q(None, Some(raw))).unwrap_err();
            assert_eq!(
                err.code(),
                "control_api.pagination.invalid",
                "offset `{raw}`"
            );
        }
    }

    #[test]
    fn has_more_and_next_offset_follow_limit_plus_one_probe() {
        let p = Pagination {
            limit: 50,
            offset: 0,
        };
        assert!(!p.has_more(50));
        assert_eq!(p.next_offset(50), None);
        assert!(p.has_more(51));
        assert_eq!(p.next_offset(51), Some(50));

        let p = Pagination {
            limit: 50,
            offset: 120,
        };
        assert_eq!(p.next_offset(51), Some(170));
    }
}
