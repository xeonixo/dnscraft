//! rcgen test certificates for TLS listener tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use rcgen::generate_simple_self_signed;

/// Self-signed cert for `dns.example.com` (and SANs used in SNI tests).
pub fn example_dns_cert() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    self_signed(&[
        "dns.example.com",
        "phone.dns.example.com",
        "PHONE.dns.example.com",
        "node1.dns.example.com",
        "unknown.dns.example.com",
        "localhost",
    ])
}

/// Distinct self-signed cert (different leaf DER) for hot-reload tests.
pub fn example_dns_cert_b() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    self_signed(&["dns.example.com", "phone.dns.example.com", "localhost"])
}

/// Returns `(chain_pem, key_pem, leaf_der)`.
pub fn self_signed(sans: &[&str]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let names: Vec<String> = sans.iter().map(|s| (*s).to_owned()).collect();
    let certified = generate_simple_self_signed(names).unwrap();
    let der = certified.cert.der().as_ref().to_vec();
    (
        certified.cert.pem().into_bytes(),
        certified.signing_key.serialize_pem().into_bytes(),
        der,
    )
}
