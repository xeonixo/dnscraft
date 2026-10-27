//! Config helper functions.
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Normalises a domain: UTS 46 -> ASCII, lower-case, no trailing dot.
///
/// Returns `Err(msg)` on failure.
pub fn normalise_domain(input: &str) -> Result<String, String> {
    let trimmed = input.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    let ascii = idna::domain_to_ascii_cow(trimmed.as_bytes(), idna::AsciiDenyList::URL)
        .map_err(|_| format!("invalid domain {input:?}"))?;
    let s = ascii.into_owned().to_ascii_lowercase();
    if s.is_empty() || s.starts_with('.') || s.contains("..") || s.ends_with('.') {
        return Err(format!("invalid domain {input:?}"));
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("invalid domain {input:?}"));
        }
    }
    if s.len() > 253 {
        return Err(format!("domain too long ({})", s.len()));
    }
    Ok(s)
}

/// Validates a URL is https (or optionally http for loopback in tests).
pub fn check_https_url(url: &str, allow_http_for_tests: bool, field: &str) -> Result<(), String> {
    use crate::net::is_loopback_host_str;
    let lower = url.trim().to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if allow_http_for_tests {
        if let Some(r) = lower.strip_prefix("http://") {
            if !is_loopback_host_str(r) {
                return Err(format!(
                    "{field} http:// is only allowed for loopback in tests"
                ));
            }
            r
        } else {
            return Err(format!("{field} must be an https:// URL"));
        }
    } else {
        return Err(format!("{field} must be an https:// URL"));
    };
    if rest.is_empty() || rest.starts_with('/') || rest.chars().any(char::is_whitespace) {
        return Err(format!("{field} has no valid host"));
    }
    Ok(())
}

/// Interval +/- 10 %, never below one second (unless base is below one second).
pub fn jittered(base: Duration, salt: SystemTime) -> Duration {
    if base.is_zero() {
        return Duration::from_secs(1);
    }
    let nanos = base.as_nanos().min(u128::from(u64::MAX)) as u64;
    let span = nanos / 10;
    let mix = salt
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let signed = (mix as i64) >> 32;
    let max = span as i64;
    let delta = if max == 0 {
        0
    } else {
        signed.rem_euclid(max.saturating_mul(2).saturating_add(1)) - max
    };
    let floor = if base >= Duration::from_secs(1) {
        1_000_000_000u64
    } else {
        base.as_nanos() as u64
    };
    let adjusted = nanos.saturating_add_signed(delta).max(floor);
    Duration::from_nanos(adjusted)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn normalise_domain_trailing_dot() {
        assert_eq!(normalise_domain("Home.ARPA.").unwrap(), "home.arpa");
    }

    #[test]
    fn normalise_domain_idn() {
        assert_eq!(normalise_domain("münchen.de").unwrap(), "xn--mnchen-3ya.de");
    }

    #[test]
    fn check_https_url_accepts_https() {
        assert!(check_https_url("https://example.com/", false, "url").is_ok());
    }

    #[test]
    fn check_https_url_rejects_http() {
        assert!(check_https_url("http://example.com/", false, "url").is_err());
    }

    #[test]
    fn jitter_stays_within_ten_percent() {
        let base = Duration::from_secs(1000);
        for i in 0..50 {
            let salt = SystemTime::UNIX_EPOCH + Duration::from_secs(i * 17);
            let j = jittered(base, salt);
            assert!(j >= Duration::from_secs(900), "{j:?}");
            assert!(j <= Duration::from_secs(1100), "{j:?}");
        }
    }
}
