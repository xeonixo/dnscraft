//! Oracle tests: compare `Name` against hickory-proto.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use dnscraft_proto::{CompressionMap, Name};
use hickory_proto::rr::Name as HName;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

/// A corpus entry: our presentation text, the hickory name, and whether
/// hickory's `Display` is expected to match ours (it does for plain names).
struct Case {
    text: String,
    theirs: HName,
    same_display: bool,
}

fn plain(text: &str) -> Case {
    Case {
        text: text.into(),
        theirs: HName::from_ascii(text).expect("hickory parses"),
        same_display: true,
    }
}

/// hickory's `from_ascii` is strict about escapes, so build these from raw labels.
fn raw(text: &str, labels: &[&[u8]]) -> Case {
    Case {
        text: text.into(),
        theirs: HName::from_labels(labels.iter().copied()).expect("hickory labels"),
        same_display: false,
    }
}

fn corpus() -> Vec<Case> {
    let l63 = "a".repeat(63);
    vec![
        plain("."),
        plain("example.com."),
        plain("www.Example.COM."),
        plain(&format!("{l63}.example.")),
        plain(&format!("{l63}.{l63}.{l63}.{}.", "a".repeat(61))),
        plain(r"a\.b.example."),
        raw(r"back\\slash.example.", &[b"back\\slash", b"example"]),
        raw(
            r"nul\000.\001x.\255.example.",
            &[b"nul\0", b"\x01x", b"\xff", b"example"],
        ),
        raw(r"sp\032ace.example.", &[b"sp ace", b"example"]),
    ]
}

#[test]
fn encode_matches_hickory() {
    for case in corpus() {
        let ours = Name::from_ascii(&case.text).expect("ours parses");
        let mut buf = Vec::new();
        ours.encode(&mut buf, None);
        let want = case.theirs.to_bytes().expect("hickory encodes");
        assert_eq!(buf, want, "{}", case.text);
        assert_eq!(buf.len(), ours.wire_len());
    }
}

#[test]
fn decode_hickory_bytes() {
    for case in corpus() {
        let bytes = case.theirs.to_bytes().expect("hickory encodes");
        let (ours, end) = Name::decode(&bytes, 0).expect("decodes");
        assert_eq!(end, bytes.len());
        assert_eq!(ours, Name::from_ascii(&case.text).expect("parses"));
        if case.same_display {
            assert_eq!(ours.to_string(), case.theirs.to_string(), "{}", case.text);
        } else {
            assert_eq!(ours.to_string(), case.text);
        }
    }
}

#[test]
fn decode_hickory_compressed_message() {
    let first = HName::from_ascii("www.example.com.").expect("n1");
    let second = HName::from_ascii("mail.example.com.").expect("n2");
    let third = HName::from_ascii("example.com.").expect("n3");
    let mut buf = Vec::new();
    let offsets = {
        let mut enc = BinEncoder::new(&mut buf);
        let mut offsets = Vec::new();
        for n in [&first, &second, &third] {
            offsets.push(enc.offset());
            n.emit(&mut enc).expect("emit");
        }
        offsets
    };
    // Compression really happened.
    assert!(buf.len() < 17 + 18 + 13);
    let mut want = vec!["www.example.com.", "mail.example.com.", "example.com."].into_iter();
    for (i, off) in offsets.iter().enumerate() {
        let (name, next) = Name::decode(&buf, *off).expect("decode");
        assert_eq!(name.to_string(), want.next().expect("expected"));
        let end = offsets.get(i + 1).copied().unwrap_or(buf.len());
        assert_eq!(next, end);
    }
}

#[test]
fn our_compressed_output_decodes_in_hickory() {
    use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
    let mut buf = Vec::new();
    let mut map = CompressionMap::new();
    for t in ["www.example.com.", "mail.example.com.", "example.com."] {
        Name::from_ascii(t)
            .expect("parse")
            .encode(&mut buf, Some(&mut map));
    }
    let mut dec = BinDecoder::new(&buf);
    for t in ["www.example.com.", "mail.example.com.", "example.com."] {
        let n = HName::read(&mut dec).expect("hickory decodes");
        assert_eq!(n.to_string(), t);
    }
}
