//! Formatting of status / errors / secrets must never leak PEM or tokens.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::time::{Duration, SystemTime};

use dnscraft_tls::{
    AcmeDirectoryKind, CertMeta, IssueState, KeyPem, LoadedCert, Secret, TlsError, TlsStatus,
};

const TOKEN: &str = "super-secret-cf-token-do-not-leak";
const PEM_MARKER: &str = "BEGIN";

fn assert_clean(label: &str, text: &str) {
    assert!(
        !text.contains(PEM_MARKER),
        "{label} contains PEM marker: {text}"
    );
    assert!(!text.contains(TOKEN), "{label} contains token: {text}");
    assert!(
        !text.contains("-----"),
        "{label} looks like PEM armour: {text}"
    );
}

/// Every public [`TlsError`] variant with realistic log text (no secrets embedded).
fn all_errors() -> Vec<TlsError> {
    vec![
        TlsError::ConfigInvalid {
            reason: "renew_before must be positive".into(),
        },
        TlsError::SecretMissing {
            name: "DNSCRAFT_CLOUDFLARE_API_TOKEN".into(),
        },
        TlsError::AcmeAccount {
            message: "create account failed".into(),
        },
        TlsError::AcmeOrder {
            message: "finalize failed".into(),
        },
        TlsError::AcmeChallenge {
            message: "ready failed".into(),
        },
        TlsError::AcmeRateLimited {
            message: "HTTP 429; Retry-After: 60".into(),
        },
        TlsError::AcmePropagation,
        TlsError::CloudflareHttp {
            message: "HTTP 401: Authentication error".into(),
        },
        TlsError::CloudflareZone {
            message: "no zone named example.com".into(),
        },
        TlsError::StoreIo {
            message: "permission denied".into(),
        },
        TlsError::StoreCorrupt {
            message: "leaf PEM parse error".into(),
        },
        TlsError::DyndnsEcho {
            message: "no ip= line in echo body (ipv4)".into(),
        },
        TlsError::DyndnsUpdate {
            message: "HTTP 500: forced".into(),
        },
        TlsError::DyndnsEntryConflict,
        TlsError::CertExpiring,
        TlsError::CertExpired,
    ]
}

#[test]
fn every_error_display_and_debug_is_clean() {
    for err in all_errors() {
        let code = err.code();
        assert!(code.starts_with("tls."), "{code}");
        assert_clean(&format!("Display/{code}"), &err.to_string());
        assert_clean(&format!("Debug/{code}"), &format!("{err:?}"));
    }
}

#[test]
fn secret_and_key_pem_never_show_material() {
    let secret = Secret::new(TOKEN);
    assert_clean("Secret/Debug", &format!("{secret:?}"));
    assert_eq!(format!("{secret:?}"), "Secret([redacted])");
    // Expose is intentional for HTTP; formatting paths must not call it.
    assert_eq!(secret.expose(), TOKEN);

    let pem = format!("-----BEGIN PRIVATE KEY-----\n{TOKEN}\n-----END PRIVATE KEY-----");
    assert!(pem.contains(PEM_MARKER));
    let key = KeyPem::from_bytes(pem.into_bytes());
    assert_clean("KeyPem/Debug", &format!("{key:?}"));
    assert_clean("KeyPem/Display", &format!("{key}"));
}

#[test]
fn loaded_cert_and_status_debug_have_no_pem_or_token() {
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let chain = format!("-----BEGIN CERTIFICATE-----\n{TOKEN}\n-----END CERTIFICATE-----");
    let key_pem = format!("-----BEGIN PRIVATE KEY-----\n{TOKEN}\n-----END PRIVATE KEY-----");
    let loaded = LoadedCert {
        chain_pem: chain.into_bytes(),
        key: KeyPem::from_bytes(key_pem.into_bytes()),
        not_after: now + Duration::from_secs(30 * 86_400),
        identifiers: vec!["dns.example.com".into()],
        meta: CertMeta::default(),
    };
    assert_clean("LoadedCert/Debug", &format!("{loaded:?}"));

    let state = IssueState {
        last_error: Some("tls.acme.order".into()),
        last_issue_unix: Some(1_700_000_000),
        last_renew_attempt_unix: Some(1_700_000_100),
    };
    let status = TlsStatus::from_cert(
        Some(&loaded),
        &state,
        now,
        Duration::from_secs(14 * 86_400),
        &AcmeDirectoryKind::Staging,
        true,
    );
    assert_clean("TlsStatus/Debug", &format!("{status:?}"));
    assert!(status.identifiers.iter().all(|i| !i.contains(PEM_MARKER)));
}

#[test]
fn every_error_variant_has_unique_code() {
    let mut seen = std::collections::HashSet::new();
    for err in all_errors() {
        assert!(seen.insert(err.code()), "duplicate {}", err.code());
    }
    assert_eq!(seen.len(), 16);
}
