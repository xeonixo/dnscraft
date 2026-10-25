//! Renewal planner + scheduler tests (ManualClock; no ACME/Cloudflare).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dnscraft_tls::{
    AcmeDirectoryKind, AriWindow, BACKOFF_CAP, CertMeta, DEFAULT_EXPIRY_WARN, DEFAULT_RENEW_BEFORE,
    IssueState, KeyPem, LoadedCert, ManualClock, RenewFn, RenewScheduler, TlsError, TlsStatus,
    backoff_delay_with_rng, cert_flags, is_transient_renew_error, next_renewal,
    next_renewal_with_rng, parse_retry_after, retry_after_from_error,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

fn t0() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000)
}

fn days(n: u64) -> Duration {
    Duration::from_secs(n * 86_400)
}

#[test]
fn next_renewal_no_cert_is_now() {
    let now = t0();
    assert_eq!(next_renewal(None, DEFAULT_RENEW_BEFORE, None, now), now);
}

#[test]
fn next_renewal_fallback_renew_before() {
    let now = t0();
    let not_after = now + days(90);
    let due = next_renewal(Some(not_after), DEFAULT_RENEW_BEFORE, None, now);
    assert_eq!(due, not_after - DEFAULT_RENEW_BEFORE);
}

#[test]
fn next_renewal_fallback_already_due_is_now() {
    let now = t0();
    let not_after = now + days(10);
    let due = next_renewal(Some(not_after), DEFAULT_RENEW_BEFORE, None, now);
    assert_eq!(due, now);
}

#[test]
fn next_renewal_ari_window_used() {
    let now = t0();
    let window = AriWindow {
        start: now + days(5),
        end: now + days(10),
    };
    let mut rng = StdRng::seed_from_u64(42);
    let due = next_renewal_with_rng(
        Some(now + days(90)),
        DEFAULT_RENEW_BEFORE,
        Some(window),
        now,
        &mut rng,
    );
    assert!(due >= window.start);
    assert!(due <= window.end);
    assert_ne!(due, now + days(90) - DEFAULT_RENEW_BEFORE);
}

#[test]
fn next_renewal_ari_past_window_is_now() {
    let now = t0();
    let window = AriWindow {
        start: now - days(10),
        end: now - days(1),
    };
    let mut rng = StdRng::seed_from_u64(1);
    let due = next_renewal_with_rng(
        Some(now + days(90)),
        DEFAULT_RENEW_BEFORE,
        Some(window),
        now,
        &mut rng,
    );
    assert_eq!(due, now);
}

#[test]
fn backoff_sequence_capped_at_six_hours() {
    let mut rng = StdRng::seed_from_u64(7);
    let early = backoff_delay_with_rng(0, None, &mut rng);
    assert!(
        early.as_secs() < 120,
        "base attempt stays near 30s: {early:?}"
    );
    let mid = backoff_delay_with_rng(4, None, &mut rng);
    assert!(mid > early, "exponential growth: {mid:?} vs {early:?}");
    for attempt in 10..25 {
        let d = backoff_delay_with_rng(attempt, None, &mut rng);
        assert!(d <= BACKOFF_CAP, "attempt {attempt}: {d:?}");
        assert!(
            d.as_secs() >= BACKOFF_CAP.as_secs() * 3 / 4,
            "near cap for attempt {attempt}: {d:?}"
        );
    }
}

#[test]
fn backoff_honours_retry_after() {
    let mut rng = StdRng::seed_from_u64(3);
    let d = backoff_delay_with_rng(0, Some(Duration::from_secs(3600)), &mut rng);
    assert!(d.as_secs() >= 3600);
    assert!(d <= BACKOFF_CAP);
}

#[test]
fn parse_retry_after_from_cloudflare_message() {
    assert_eq!(
        parse_retry_after("HTTP 429: rate limited; Retry-After: 45"),
        Some(Duration::from_secs(45))
    );
    assert_eq!(
        retry_after_from_error(&TlsError::CloudflareHttp {
            message: "HTTP 429; Retry-After: 12".into(),
        }),
        Some(Duration::from_secs(12))
    );
}

#[test]
fn cert_flags_at_expiry_boundaries() {
    let now = t0();
    let warn = DEFAULT_EXPIRY_WARN;

    let (expiring, expired) = cert_flags(now + warn, now, warn);
    assert!(!expiring);
    assert!(!expired);

    let (expiring, expired) = cert_flags(now + warn - Duration::from_secs(1), now, warn);
    assert!(expiring);
    assert!(!expired);

    let (expiring, expired) = cert_flags(now, now, warn);
    assert!(!expiring);
    assert!(expired);

    let (expiring, expired) = cert_flags(now - Duration::from_secs(1), now, warn);
    assert!(!expiring);
    assert!(expired);
}

#[test]
fn transient_error_classification() {
    assert!(is_transient_renew_error(&TlsError::AcmePropagation));
    assert!(is_transient_renew_error(&TlsError::AcmeRateLimited {
        message: "x".into()
    }));
    assert!(is_transient_renew_error(&TlsError::CloudflareHttp {
        message: "429".into()
    }));
    assert!(!is_transient_renew_error(&TlsError::ConfigInvalid {
        reason: "x".into()
    }));
}

#[test]
fn status_from_cert_sets_flags() {
    let now = t0();
    let loaded = LoadedCert {
        chain_pem: b"x".to_vec(),
        key: KeyPem::from_bytes(b"k"),
        not_after: now + days(7),
        identifiers: vec!["dns.example.com".into()],
        meta: CertMeta::default(),
    };
    let status = TlsStatus::from_cert(
        Some(&loaded),
        &IssueState::default(),
        now,
        DEFAULT_EXPIRY_WARN,
        &AcmeDirectoryKind::Staging,
        true,
    );
    assert!(status.cert_expiring);
    assert!(!status.cert_expired);
    assert_eq!(status.days_to_expiry, Some(7));
    assert_eq!(status.identifiers, vec!["dns.example.com"]);
    assert!(status.acme_enabled);
}

#[tokio::test]
async fn scheduler_issues_immediately_when_no_cert() {
    let clock = Arc::new(ManualClock::new(t0()));
    let enabled = Arc::new(AtomicBool::new(true));
    let renews = Arc::new(AtomicU32::new(0));
    let renews2 = renews.clone();

    let schedule =
        Arc::new(move |now: SystemTime| next_renewal(None, DEFAULT_RENEW_BEFORE, None, now));
    let renew: RenewFn = Arc::new(move || {
        let c = renews2.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    });
    let on_status = Arc::new(TlsStatus::default);

    let sched = RenewScheduler::start(clock.clone(), enabled, schedule, renew, on_status);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        renews.load(Ordering::SeqCst) >= 1,
        "no-cert schedule is due immediately"
    );
    sched.stop().await;
}

#[tokio::test]
async fn scheduler_never_orders_when_acme_disabled() {
    let clock = Arc::new(ManualClock::new(t0()));
    let enabled = Arc::new(AtomicBool::new(false));
    let renews = Arc::new(AtomicU32::new(0));
    let renews2 = renews.clone();

    let schedule =
        Arc::new(move |now: SystemTime| next_renewal(None, DEFAULT_RENEW_BEFORE, None, now));
    let renew: RenewFn = Arc::new(move || {
        let c = renews2.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    });
    let status_hits = Arc::new(AtomicU32::new(0));
    let status_hits2 = status_hits.clone();
    let on_status = Arc::new(move || {
        status_hits2.fetch_add(1, Ordering::SeqCst);
        TlsStatus {
            acme_enabled: false,
            ..TlsStatus::default()
        }
    });

    let sched = RenewScheduler::start(clock.clone(), enabled, schedule, renew, on_status);
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        clock.advance(days(1));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(renews.load(Ordering::SeqCst), 0);
    assert!(status_hits.load(Ordering::SeqCst) >= 1);
    sched.stop().await;
}

#[tokio::test]
async fn scheduler_backoff_after_transient_failure() {
    let clock = Arc::new(ManualClock::new(t0()));
    let enabled = Arc::new(AtomicBool::new(true));
    let renews = Arc::new(AtomicU32::new(0));
    let renews2 = renews.clone();

    let schedule = Arc::new(move |now: SystemTime| now);
    let renew: RenewFn = Arc::new(move || {
        let c = renews2.clone();
        Box::pin(async move {
            c.fetch_add(1, Ordering::SeqCst);
            Err(TlsError::CloudflareHttp {
                message: "HTTP 429; Retry-After: 60".into(),
            })
        })
    });
    let on_status = Arc::new(TlsStatus::default);

    let sched = RenewScheduler::start(clock.clone(), enabled, schedule, renew, on_status);
    tokio::time::sleep(Duration::from_millis(40)).await;
    let first = renews.load(Ordering::SeqCst);
    assert!(first >= 1);

    tokio::time::sleep(Duration::from_millis(40)).await;
    let mid = renews.load(Ordering::SeqCst);
    assert_eq!(mid, first, "must wait for backoff / Retry-After");

    clock.advance(Duration::from_secs(90));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        renews.load(Ordering::SeqCst) > first,
        "retry after Retry-After window"
    );
    sched.stop().await;
}
