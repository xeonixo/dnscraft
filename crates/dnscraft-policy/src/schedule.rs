//! Profile schedule windows: switch the active filter set by time of week.
//!
//! Windows are offsets within one week from Monday 00:00 UTC (validated at
//! snapshot build). [`active_schedule`] takes an already-converted
//! offset-in-week so a later owner decision for local time zones only changes
//! how [`offset_in_week`] is computed (no tz dependency in v1).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::config::{SCHEDULE_WEEK, ScheduleConfig};

/// Seconds from Monday 00:00 to Thursday 00:00 (Unix epoch weekday).
const EPOCH_OFFSET_FROM_MONDAY: u64 = 3 * 24 * 3600;

/// Converts a wall-clock instant to an offset within the current UTC week
/// starting Monday 00:00.
///
/// Open question (SPEC): local time zones would change only this conversion
/// (and need a tz dependency — not in v1).
pub fn offset_in_week(now: SystemTime) -> Duration {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let week_secs = SCHEDULE_WEEK.as_secs();
    Duration::from_secs((secs + EPOCH_OFFSET_FROM_MONDAY) % week_secs)
}

/// Returns the schedule whose window contains `offset` (`start` inclusive,
/// `end` exclusive), or `None` when no window is active.
///
/// `schedules` must be sorted by `start` ascending (snapshot build order).
/// Overlaps are rejected at validation, so at most one window matches.
pub fn active_schedule(schedules: &[ScheduleConfig], offset: Duration) -> Option<&ScheduleConfig> {
    schedules
        .iter()
        .find(|s| offset >= s.start && offset < s.end)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use dnscraft_filtering::SetId;
    use std::sync::Arc;

    fn sched(id: &str, start_h: u64, end_h: u64) -> ScheduleConfig {
        ScheduleConfig {
            id: Arc::from(id),
            filter_set: SetId::new("evening").unwrap(),
            start: Duration::from_secs(start_h * 3600),
            end: Duration::from_secs(end_h * 3600),
        }
    }

    #[test]
    fn active_schedule_boundaries_inclusive_start_exclusive_end() {
        let windows = [sched("a", 10, 12)];
        assert!(active_schedule(&windows, Duration::from_secs(10 * 3600 - 1)).is_none());
        assert_eq!(
            active_schedule(&windows, Duration::from_secs(10 * 3600))
                .unwrap()
                .id
                .as_ref(),
            "a"
        );
        assert_eq!(
            active_schedule(&windows, Duration::from_secs(12 * 3600 - 1))
                .unwrap()
                .id
                .as_ref(),
            "a"
        );
        assert!(active_schedule(&windows, Duration::from_secs(12 * 3600)).is_none());
    }

    #[test]
    fn offset_in_week_monday_midnight_is_zero() {
        // 1970-01-05 was a Monday (epoch Thursday + 4 days).
        let monday = UNIX_EPOCH + Duration::from_secs(4 * 24 * 3600);
        assert_eq!(offset_in_week(monday), Duration::ZERO);
        let monday_noon = monday + Duration::from_secs(12 * 3600);
        assert_eq!(offset_in_week(monday_noon), Duration::from_secs(12 * 3600));
    }

    #[test]
    fn sunday_and_monday_are_separate_windows() {
        // Sunday 22:00–24:00 and Monday 00:00–02:00 as two windows.
        let sun_start = 6 * 24 * 3600 + 22 * 3600;
        let mon_end = 2 * 3600;
        let windows = [
            ScheduleConfig {
                id: Arc::from("sun"),
                filter_set: SetId::new("evening").unwrap(),
                start: Duration::from_secs(sun_start),
                end: SCHEDULE_WEEK,
            },
            ScheduleConfig {
                id: Arc::from("mon"),
                filter_set: SetId::new("evening").unwrap(),
                start: Duration::ZERO,
                end: Duration::from_secs(mon_end),
            },
        ];
        // Sort as snapshot would.
        let mut sorted = windows.to_vec();
        sorted.sort_by_key(|s| s.start);
        assert_eq!(
            active_schedule(&sorted, Duration::from_secs(sun_start + 60))
                .unwrap()
                .id
                .as_ref(),
            "sun"
        );
        assert_eq!(
            active_schedule(&sorted, Duration::from_secs(3600))
                .unwrap()
                .id
                .as_ref(),
            "mon"
        );
        assert!(active_schedule(&sorted, Duration::from_secs(3 * 3600)).is_none());
    }
}
