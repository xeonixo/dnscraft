#![no_main]

//! Fuzzes the `[control_api]` bootstrap config as JSON (the serde shape of
//! `ControlApiConfig`): deserialization plus `validate()`. Only the "never
//! panic" property is checked, and every validation error must expose a
//! namespaced, dotted stable code.

use dnscraft_api::ControlApiConfig;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(config) = serde_json::from_slice::<ControlApiConfig>(data) else {
        return;
    };
    match config.validate() {
        Ok(()) => {}
        Err(error) => {
            let code = error.code();
            assert!(code.contains('.'), "code {code} is not namespaced");
            assert!(
                code.split('.').all(|segment| !segment.is_empty()),
                "code {code} has an empty segment"
            );
        }
    }
});
