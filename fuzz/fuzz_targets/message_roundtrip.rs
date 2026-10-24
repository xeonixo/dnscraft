#![no_main]

use dnscraft_proto::{Message, ProtoError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(m) = Message::decode(data) else {
        return;
    };
    let enc = match m.encode() {
        Ok(enc) => enc,
        // Documented encode errors (e.g. section too large) are acceptable.
        Err(_) => return,
    };
    let m2 = Message::decode(&enc).expect("decode of own encoding");
    let enc2 = m2.encode().expect("re-encode of decoded own encoding");
    assert_eq!(enc, enc2);

    match m.encode_with_limit(512) {
        Ok(limited) => {
            assert!(limited.len() <= 512);
            Message::decode(&limited).expect("limited encoding decodes");
        }
        Err(ProtoError::LimitTooSmall { .. }) => {}
        Err(_) => {}
    }
});
