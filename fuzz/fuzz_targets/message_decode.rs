#![no_main]

use dnscraft_proto::Message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Message::decode(data);
});
