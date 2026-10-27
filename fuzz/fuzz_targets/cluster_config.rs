#![no_main]

//! Fuzzes the `[cluster]` TOML bootstrap config: `ClusterConfig::from_toml`
//! (parse + role consistency) and a re-validation of any accepted config.
//! Only the "never panic" property is checked; parse/validation errors must
//! expose a well-formed stable `cluster.*` code.

use dnscraft_cluster::{ClusterConfig, ClusterError};
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
    let text = String::from_utf8_lossy(data);
    match ClusterConfig::from_toml(&text) {
        Ok(config) => {
            // from_toml validates; an accepted config must validate again.
            assert!(
                config.validate().is_ok(),
                "accepted config failed re-validation"
            );
        }
        Err(error) => check_code(&error),
    }
});
