#![no_main]

//! Fuzzes join-token handling: the `EnrollRequest` JSON decode and protocol
//! check. Only the "never panic" property is checked; a rejected request must
//! still expose a well-formed stable `cluster.*` code.
//!
//! `EnrollRequest` carries the one-time token in a [`Secret`], so the decoded
//! value is never logged here.

use dnscraft_cluster::{ClusterError, EnrollRequest, PROTOCOL_VERSION};
use libfuzzer_sys::fuzz_target;

fn check_code(error: &ClusterError) {
    let code = error.code();
    assert!(
        code.starts_with("cluster."),
        "code {code} is not namespaced"
    );
    assert!(
        code.split('.').all(|segment| !segment.is_empty()),
        "code {code} has an empty segment"
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(request) = serde_json::from_slice::<EnrollRequest>(data) else {
        return;
    };
    match request.check_protocol() {
        Ok(()) => assert_eq!(request.protocol, PROTOCOL_VERSION),
        Err(error) => check_code(&error),
    }
});
