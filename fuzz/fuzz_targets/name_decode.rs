#![no_main]

use dnscraft_proto::Name;
use libfuzzer_sys::fuzz_target;

fn check(data: &[u8], offset: usize) {
    if let Ok((name, _)) = Name::decode(data, offset) {
        let mut buf = Vec::new();
        name.encode(&mut buf, None);
        let (again, end) = Name::decode(&buf, 0).expect("re-decode of encoded name");
        assert_eq!(end, buf.len());
        assert_eq!(name, again);
    }
}

fuzz_target!(|data: &[u8]| {
    check(data, 0);
    if let Some(&first) = data.first() {
        check(data, usize::from(first) % data.len());
    }
});
