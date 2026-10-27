//! Human-readable [`Duration`] parsing, formatting, and serde.
//!
//! Config files use strings like `"10s"`, `"5m"`, `"1d"`, and `"500ms"`.
//! [`parse`] and [`format`] are inverse for durations that are whole
//! milliseconds; sub-millisecond durations have no unit in the grammar and
//! are truncated by [`format`].
//!
//! Use as a serde adapter:
//!
//! ```ignore
//! #[serde(with = "dnscraft_common::duration::serde")]
//! pub timeout: std::time::Duration,
//! ```

use std::time::Duration;

/// Parses a human duration.
///
/// Accepts a bare integer (seconds) or an integer followed by one of `ms`,
/// `s`, `m`/`min`, `h`, `d`, `w` (case-insensitive). Whitespace, signs,
/// fractions, a missing number, and unknown units are rejected.
pub fn parse(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Err("duration is empty".to_owned());
    }
    if s.chars().any(char::is_whitespace) {
        return Err(format!("duration {s:?} contains whitespace"));
    }
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (number, unit) = s.split_at(split);
    if number.is_empty() {
        return Err(format!("duration {s:?} has no number"));
    }
    let value: u64 = number
        .parse()
        .map_err(|_| format!("duration {s:?} has an invalid number"))?;

    let seconds_per_unit: u64 = match unit.to_ascii_lowercase().as_str() {
        "" | "s" => return Ok(Duration::from_secs(value)),
        "ms" => return Ok(Duration::from_millis(value)),
        "m" | "min" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        "w" => 7 * 24 * 60 * 60,
        other => return Err(format!("duration {s:?} has unknown unit {other:?}")),
    };
    let secs = value
        .checked_mul(seconds_per_unit)
        .ok_or_else(|| format!("duration {s:?} is too large"))?;
    Ok(Duration::from_secs(secs))
}

/// Formats `d` as the largest whole unit that divides it exactly.
///
/// Whole units are `w`, `d`, `h`, `m`, `s`; anything else is milliseconds.
/// `parse(format(d)) == d` holds for durations that are whole milliseconds.
pub fn format(d: Duration) -> String {
    let secs = d.as_secs();
    let nanos = d.subsec_nanos();
    if nanos == 0 {
        for (unit, size) in [("w", 604_800), ("d", 86_400), ("h", 3_600), ("m", 60)] {
            if secs > 0 && secs.is_multiple_of(size) {
                return format!("{}{unit}", secs / size);
            }
        }
        return format!("{secs}s");
    }
    format!("{}ms", d.as_millis())
}

/// serde adapter for [`Duration`] as a human-readable string.
pub mod serde {
    use std::time::Duration;

    /// Serializes `d` via [`super::format`].
    pub fn serialize<S: ::serde::Serializer>(
        d: &Duration,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::format(*d))
    }

    /// Deserializes a string via [`super::parse`].
    pub fn deserialize<'de, D: ::serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Duration, D::Error> {
        let text = <String as ::serde::Deserialize>::deserialize(deserializer)?;
        super::parse(&text).map_err(::serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_units_and_bare_seconds() {
        for (text, secs) in [
            ("0", 0),
            ("30", 30),
            ("500ms", 0),
            ("10s", 10),
            ("10S", 10),
            ("5m", 300),
            ("5min", 300),
            ("5MIN", 300),
            ("2h", 7_200),
            ("1d", 86_400),
            ("1w", 604_800),
            ("90s", 90),
        ] {
            assert_eq!(parse(text).unwrap().as_secs(), secs, "{text}");
        }
        assert_eq!(parse("500ms").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn rejects_invalid_durations() {
        for text in [
            "", "-5s", "+5s", "s", "ms", "1x", "1.5s", "1 s", " 1s", "1s ", "1s2", "1_0s",
        ] {
            assert!(parse(text).is_err(), "{text:?} should be rejected");
        }
    }

    #[test]
    fn formats_the_largest_whole_unit() {
        for (d, text) in [
            (Duration::ZERO, "0s"),
            (Duration::from_millis(500), "500ms"),
            (Duration::from_millis(1_500), "1500ms"),
            (Duration::from_secs(5), "5s"),
            (Duration::from_secs(90), "90s"),
            (Duration::from_secs(300), "5m"),
            (Duration::from_secs(7_200), "2h"),
            (Duration::from_secs(86_400), "1d"),
            (Duration::from_secs(604_800), "1w"),
        ] {
            assert_eq!(format(d), text, "{d:?}");
            assert_eq!(parse(&format(d)).unwrap(), d, "{d:?}");
        }
    }
}
