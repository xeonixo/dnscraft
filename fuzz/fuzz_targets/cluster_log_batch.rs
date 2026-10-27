#![no_main]

//! Fuzzes `LogBatch::validate` over arbitrary JSON. Validation is called both
//! with the batch's own `node_id` (the certificate-matched case) and with a
//! fixed other identity (the mismatch case). Only the "never panic" property
//! is checked; errors must expose a well-formed stable `cluster.*` code.

use dnscraft_cluster::{ClusterError, LogBatch};
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
    let Ok(batch) = serde_json::from_slice::<LogBatch>(data) else {
        return;
    };
    for authenticated in [batch.node_id.as_str(), "other-node"] {
        if let Err(error) = batch.validate(authenticated) {
            check_code(&error);
        }
    }
});
