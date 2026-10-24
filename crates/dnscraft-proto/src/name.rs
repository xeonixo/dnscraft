//! Domain names: presentation parsing, wire decoding/encoding, ordering.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::fmt;
use std::hash::{Hash, Hasher};

use crate::error::ProtoError;

/// Maximum length of a single label in octets.
const MAX_LABEL: usize = 63;
/// Maximum length of a name in wire form, including the root octet.
const MAX_NAME: usize = 255;
/// Maximum number of compression pointers followed while decoding one name.
const MAX_JUMPS: usize = 128;
/// Compression pointers can only address offsets below this value.
const POINTER_LIMIT: usize = 0x4000;

/// A domain name stored in uncompressed wire form.
///
/// The bytes are the length-prefixed labels followed by the root octet, so the
/// root name is a single zero byte. Equality and hashing ignore ASCII case;
/// ordering is the RFC 4034 section 6.1 canonical order.
#[derive(Clone)]
pub struct Name {
    wire: Box<[u8]>,
}

/// Iterator over the labels of a [`Name`], excluding the root label.
#[derive(Clone, Debug)]
pub struct Labels<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let (&len, tail) = self.rest.split_first()?;
        if len == 0 {
            self.rest = &[];
            return None;
        }
        let (label, rest) = tail.split_at_checked(usize::from(len))?;
        self.rest = rest;
        Some(label)
    }
}

impl Name {
    /// The root name `.`.
    pub fn root() -> Self {
        Self {
            wire: Box::new([0]),
        }
    }

    /// Parses a name from presentation format.
    ///
    /// Names are always treated as absolute: `"www.example.com"` and
    /// `"www.example.com."` yield the same name, and `"."` is the root.
    /// Supported escapes are `\.`, `\\` (any `\X` with non-digit `X` yields
    /// the byte `X`) and `\DDD` (three decimal digits, at most 255). Empty
    /// labels (including the empty string) are rejected, as are labels over
    /// 63 octets and names over 255 wire octets. Non-ASCII characters are
    /// taken as their UTF-8 bytes.
    pub fn from_ascii(text: &str) -> Result<Self, ProtoError> {
        let bytes = text.as_bytes();
        if bytes == b"." {
            return Ok(Self::root());
        }
        if bytes.is_empty() {
            return Err(ProtoError::EmptyLabel);
        }
        let mut wire: Vec<u8> = Vec::with_capacity(bytes.len() + 2);
        let mut label: Vec<u8> = Vec::new();
        let mut iter = bytes.iter().copied();
        while let Some(b) = iter.next() {
            match b {
                b'.' => {
                    push_label(&mut wire, &label)?;
                    label.clear();
                }
                b'\\' => {
                    let first = iter.next().ok_or(ProtoError::InvalidEscape)?;
                    if first.is_ascii_digit() {
                        let d2 = iter.next().ok_or(ProtoError::InvalidEscape)?;
                        let d3 = iter.next().ok_or(ProtoError::InvalidEscape)?;
                        if !d2.is_ascii_digit() || !d3.is_ascii_digit() {
                            return Err(ProtoError::InvalidEscape);
                        }
                        let value = u32::from(first - b'0') * 100
                            + u32::from(d2 - b'0') * 10
                            + u32::from(d3 - b'0');
                        label.push(u8::try_from(value).map_err(|_| ProtoError::InvalidEscape)?);
                    } else {
                        label.push(first);
                    }
                }
                other => label.push(other),
            }
        }
        if !label.is_empty() {
            push_label(&mut wire, &label)?;
        }
        wire.push(0);
        if wire.len() > MAX_NAME {
            return Err(ProtoError::NameTooLong { len: wire.len() });
        }
        Ok(Self { wire: wire.into() })
    }

    /// Decodes a possibly compressed name from `msg` starting at `offset`.
    ///
    /// Returns the name and the offset just after it in the original
    /// position (after the first pointer if one was followed). Pointers must
    /// point strictly backwards; at most 128 are followed.
    pub fn decode(msg: &[u8], offset: usize) -> Result<(Self, usize), ProtoError> {
        if offset > msg.len() {
            return Err(ProtoError::OffsetOutOfBounds {
                offset,
                len: msg.len(),
            });
        }
        let mut pos = offset;
        let mut end: Option<usize> = None;
        let mut jumps = 0usize;
        let mut wire: Vec<u8> = Vec::new();
        loop {
            let byte = *msg.get(pos).ok_or(ProtoError::Truncated { offset: pos })?;
            match byte & 0xC0 {
                0x00 => {
                    let len = usize::from(byte);
                    if len == 0 {
                        wire.push(0);
                        let after = pos + 1;
                        return Ok((Self { wire: wire.into() }, end.unwrap_or(after)));
                    }
                    let start = pos + 1;
                    let label = msg
                        .get(start..start + len)
                        .ok_or(ProtoError::Truncated { offset: msg.len() })?;
                    // This label, its length octet, and the terminating root.
                    if wire.len() + 1 + len + 1 > MAX_NAME {
                        return Err(ProtoError::NameTooLong {
                            len: wire.len() + 1 + len + 1,
                        });
                    }
                    wire.push(byte);
                    wire.extend_from_slice(label);
                    pos = start + len;
                }
                0xC0 => {
                    let low = *msg
                        .get(pos + 1)
                        .ok_or(ProtoError::Truncated { offset: pos + 1 })?;
                    let target = (usize::from(byte & 0x3F) << 8) | usize::from(low);
                    if target == pos {
                        return Err(ProtoError::PointerLoop { offset: pos });
                    }
                    if target > pos {
                        return Err(ProtoError::ForwardPointer {
                            offset: pos,
                            target,
                        });
                    }
                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(ProtoError::TooManyPointers);
                    }
                    end.get_or_insert(pos + 2);
                    pos = target;
                }
                _ => {
                    return Err(ProtoError::ReservedLabelType { byte, offset: pos });
                }
            }
        }
    }

    /// Encodes the name, optionally compressing it against `compression`.
    ///
    /// Offsets recorded in the map are positions within `buf`, so `buf` must
    /// start at the beginning of the message. Without a map the uncompressed
    /// form is appended.
    pub fn encode(&self, buf: &mut Vec<u8>, compression: Option<&mut CompressionMap>) {
        let Some(map) = compression else {
            buf.extend_from_slice(&self.wire);
            return;
        };
        let base = buf.len();
        // Suffix start positions (within self.wire) not yet in the map.
        let mut pending: Vec<(usize, Vec<u8>)> = Vec::new();
        let mut pointer: Option<(usize, u16)> = None;
        let mut pos = 0usize;
        while self.wire.get(pos).is_some_and(|&len| len != 0) {
            let suffix = self.wire.get(pos..).unwrap_or(&[]);
            let key = suffix.to_ascii_lowercase();
            if let Some(&target) = map.offsets.get(&key) {
                pointer = Some((pos, target));
                break;
            }
            if base + pos < POINTER_LIMIT {
                pending.push((pos, key));
            }
            pos += 1 + self.wire.get(pos).map_or(0, |&l| usize::from(l));
        }
        match pointer {
            Some((at, target)) => {
                buf.extend_from_slice(self.wire.get(..at).unwrap_or(&[]));
                buf.extend_from_slice(&(0xC000 | target).to_be_bytes());
            }
            None => buf.extend_from_slice(&self.wire),
        }
        for (at, key) in pending {
            if let Ok(off) = u16::try_from(base + at) {
                map.offsets.entry(key).or_insert(off);
            }
        }
    }

    /// Appends the canonical form (lowercase, uncompressed) of the name.
    pub fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend(self.wire.iter().map(u8::to_ascii_lowercase));
    }

    /// Returns a copy with all ASCII letters lowercased (canonical form).
    pub fn to_lowercase(&self) -> Self {
        Self {
            wire: self.wire.to_ascii_lowercase().into(),
        }
    }

    /// The uncompressed wire form, including the root octet.
    pub fn as_wire(&self) -> &[u8] {
        &self.wire
    }

    /// Length of the uncompressed wire form in octets.
    pub fn wire_len(&self) -> usize {
        self.wire.len()
    }

    /// Iterates over the labels from the leftmost, excluding the root.
    pub fn labels(&self) -> Labels<'_> {
        Labels { rest: &self.wire }
    }

    /// Number of labels, excluding the root (as counted by RFC 4034).
    pub fn label_count(&self) -> usize {
        self.labels().count()
    }

    /// Whether this is the root name.
    pub fn is_root(&self) -> bool {
        self.wire.len() == 1
    }

    /// The name with the leftmost label removed, or `None` for the root.
    pub fn parent(&self) -> Option<Self> {
        let first = usize::from(*self.wire.first()?);
        if first == 0 {
            return None;
        }
        let rest = self.wire.get(first + 1..)?;
        Some(Self { wire: rest.into() })
    }

    /// True if `self` equals `other` or is an ancestor of it (case-insensitive).
    pub fn zone_of(&self, other: &Self) -> bool {
        let (mine, theirs) = (self.label_count(), other.label_count());
        if mine > theirs {
            return false;
        }
        let mut rest: &[u8] = &other.wire;
        for _ in 0..theirs - mine {
            let skip = rest.first().map_or(0, |&l| usize::from(l) + 1);
            rest = rest.get(skip..).unwrap_or(&[]);
        }
        rest.eq_ignore_ascii_case(&self.wire)
    }

    fn reversed_labels(&self) -> Vec<&[u8]> {
        let mut v: Vec<&[u8]> = self.labels().collect();
        v.reverse();
        v
    }
}

fn push_label(wire: &mut Vec<u8>, label: &[u8]) -> Result<(), ProtoError> {
    if label.is_empty() {
        return Err(ProtoError::EmptyLabel);
    }
    let len = u8::try_from(label.len())
        .ok()
        .filter(|&l| usize::from(l) <= MAX_LABEL)
        .ok_or(ProtoError::LabelTooLong { len: label.len() })?;
    wire.push(len);
    wire.extend_from_slice(label);
    if wire.len() + 1 > MAX_NAME {
        return Err(ProtoError::NameTooLong {
            len: wire.len() + 1,
        });
    }
    Ok(())
}

/// Remembers where name suffixes were written, to emit compression pointers.
///
/// Keys are lowercased suffixes, so matching is ASCII case-insensitive. Only
/// offsets below 0x4000 are recorded. Use one map per message, together with
/// a buffer that starts at the message start.
#[derive(Debug, Default, Clone)]
pub struct CompressionMap {
    offsets: HashMap<Vec<u8>, u16>,
}

impl CompressionMap {
    /// Creates an empty map.
    pub fn new() -> Self {
        Self::default()
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str(".");
        }
        for label in self.labels() {
            for &b in label {
                match b {
                    b'.' | b'\\' => write!(f, "\\{}", char::from(b))?,
                    0x21..=0x7E => write!(f, "{}", char::from(b))?,
                    _ => write!(f, "\\{b:03}")?,
                }
            }
            f.write_str(".")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Name({self})")
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.wire.eq_ignore_ascii_case(&other.wire)
    }
}

impl Eq for Name {}

impl Hash for Name {
    fn hash<H: Hasher>(&self, state: &mut H) {
        for b in self.wire.iter() {
            state.write_u8(b.to_ascii_lowercase());
        }
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = self.reversed_labels();
        let b = other.reversed_labels();
        for (x, y) in a.iter().zip(b.iter()) {
            let ord = x
                .iter()
                .map(u8::to_ascii_lowercase)
                .cmp(y.iter().map(u8::to_ascii_lowercase));
            if ord != Ordering::Equal {
                return ord;
            }
        }
        a.len().cmp(&b.len())
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use std::collections::hash_map::DefaultHasher;

    use super::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).expect("valid name")
    }

    fn hash_of(name: &Name) -> u64 {
        let mut h = DefaultHasher::new();
        name.hash(&mut h);
        h.finish()
    }

    #[test]
    fn root_and_basic_parse() {
        assert!(Name::root().is_root());
        assert_eq!(Name::root().as_wire(), &[0]);
        assert_eq!(n(".").to_string(), ".");
        assert_eq!(
            n("www.example.com.").as_wire(),
            b"\x03www\x07example\x03com\x00"
        );
        assert_eq!(n("www.example.com"), n("www.example.com."));
        assert_eq!(n("a.b").label_count(), 2);
        assert_eq!(Name::root().label_count(), 0);
        assert_eq!(n("a.b.").wire_len(), 5);
    }

    #[test]
    fn parse_escapes() {
        let name = n(r"a\.b.c\\d.\000\255.");
        let labels: Vec<&[u8]> = name.labels().collect();
        assert_eq!(labels, vec![&b"a.b"[..], &b"c\\d"[..], &[0u8, 255][..]]);
        assert_eq!(n(r"\065bc.").as_wire(), b"\x03Abc\x00");
        assert_eq!(n(r"a\-b").as_wire(), b"\x03a-b\x00");
    }

    #[test]
    fn parse_errors() {
        assert_eq!(Name::from_ascii(""), Err(ProtoError::EmptyLabel));
        assert_eq!(Name::from_ascii("a..b"), Err(ProtoError::EmptyLabel));
        assert_eq!(Name::from_ascii(".a"), Err(ProtoError::EmptyLabel));
        assert_eq!(Name::from_ascii(".."), Err(ProtoError::EmptyLabel));
        assert_eq!(Name::from_ascii(r"a\"), Err(ProtoError::InvalidEscape));
        assert_eq!(Name::from_ascii(r"a\256"), Err(ProtoError::InvalidEscape));
        assert_eq!(Name::from_ascii(r"a\12"), Err(ProtoError::InvalidEscape));
        assert_eq!(Name::from_ascii(r"a\1x2"), Err(ProtoError::InvalidEscape));
        let long = "a".repeat(64);
        assert_eq!(
            Name::from_ascii(&format!("{long}.com")),
            Err(ProtoError::LabelTooLong { len: 64 })
        );
        assert!(Name::from_ascii(&format!("{}.com", "a".repeat(63))).is_ok());
    }

    #[test]
    fn name_length_limit() {
        let l63 = "a".repeat(63);
        let ok = format!("{l63}.{l63}.{l63}.{}", "a".repeat(61));
        assert_eq!(Name::from_ascii(&ok).map(|x| x.wire_len()), Ok(255));
        let bad = format!("{l63}.{l63}.{l63}.{}", "a".repeat(62));
        assert!(matches!(
            Name::from_ascii(&bad),
            Err(ProtoError::NameTooLong { .. })
        ));
    }

    #[test]
    fn display_round_trip() {
        for s in [
            ".",
            "example.com.",
            r"a\.b.c\\d.",
            r"\000\031\032\127\255.x.",
            "Mixed.CASE.example.",
        ] {
            let name = n(s);
            assert_eq!(name.to_string(), s);
            assert_eq!(n(&name.to_string()).as_wire(), name.as_wire());
        }
        assert_eq!(n("a b").to_string(), r"a\032b.");
    }

    #[test]
    fn case_insensitive_eq_and_hash() {
        let (a, b) = (n("WWW.Example.COM"), n("www.example.com"));
        assert_eq!(a, b);
        assert_eq!(hash_of(&a), hash_of(&b));
        assert_ne!(a, n("www.example.org"));
        assert_eq!(a.to_lowercase().as_wire(), b.as_wire());
        let mut buf = Vec::new();
        a.encode_canonical(&mut buf);
        assert_eq!(buf, b.as_wire());
    }

    #[test]
    fn rfc4034_canonical_order() {
        let ordered = [
            "example.",
            "a.example.",
            "yljkjljk.a.example.",
            "Z.a.example.",
            "zABC.a.EXAMPLE.",
            "z.example.",
            r"\001.z.example.",
            "*.z.example.",
            r"\200.z.example.",
        ];
        let names: Vec<Name> = ordered.iter().map(|s| n(s)).collect();
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                assert_eq!(a.cmp(b), i.cmp(&j), "{a} vs {b}");
            }
        }
        assert!(Name::root() < n("a."));
    }

    #[test]
    fn hierarchy_helpers() {
        let name = n("www.Example.com.");
        assert_eq!(name.parent(), Some(n("example.com.")));
        assert_eq!(n("com.").parent(), Some(Name::root()));
        assert_eq!(Name::root().parent(), None);
        assert_eq!(name.label_count(), 3);
        assert!(n("EXAMPLE.com.").zone_of(&name));
        assert!(name.zone_of(&name));
        assert!(Name::root().zone_of(&name));
        assert!(!name.zone_of(&n("example.com.")));
        assert!(!n("ample.com.").zone_of(&name));
        assert!(!n("example.org.").zone_of(&name));
        assert_eq!(name.labels().next(), Some(&b"www"[..]));
    }

    #[test]
    fn decode_plain_and_pointer() {
        let mut msg = b"\x03www\x07example\x03com\x00".to_vec();
        msg.extend_from_slice(b"\x04mail\xC0\x04");
        msg.extend_from_slice(b"\xC0\x00");
        let (a, next) = Name::decode(&msg, 0).expect("a");
        assert_eq!((a.to_string(), next), ("www.example.com.".into(), 17));
        let (b, next) = Name::decode(&msg, 17).expect("b");
        assert_eq!((b.to_string(), next), ("mail.example.com.".into(), 24));
        let (c, next) = Name::decode(&msg, 24).expect("c");
        assert_eq!((c, next), (a, 26));
        assert_eq!(Name::decode(&[0], 0).expect("root"), (Name::root(), 1));
    }

    #[test]
    fn decode_errors() {
        // Pointer to itself.
        assert_eq!(
            Name::decode(&[0xC0, 0x00], 0),
            Err(ProtoError::PointerLoop { offset: 0 })
        );
        // Forward pointer.
        assert_eq!(
            Name::decode(&[0xC0, 0x02, 0x00], 0),
            Err(ProtoError::ForwardPointer {
                offset: 0,
                target: 2
            })
        );
        // Truncated label.
        assert_eq!(
            Name::decode(b"\x05ab", 0),
            Err(ProtoError::Truncated { offset: 3 })
        );
        // Missing root terminator.
        assert_eq!(
            Name::decode(b"\x01a", 0),
            Err(ProtoError::Truncated { offset: 2 })
        );
        // Truncated pointer.
        assert_eq!(
            Name::decode(&[0xC0], 0),
            Err(ProtoError::Truncated { offset: 1 })
        );
        // Reserved label types.
        assert_eq!(
            Name::decode(&[0x40, 0], 0),
            Err(ProtoError::ReservedLabelType {
                byte: 0x40,
                offset: 0
            })
        );
        assert_eq!(
            Name::decode(&[0x01, b'a', 0x80], 0),
            Err(ProtoError::ReservedLabelType {
                byte: 0x80,
                offset: 2
            })
        );
        // Offset beyond buffer, and empty buffer.
        assert_eq!(
            Name::decode(&[0], 5),
            Err(ProtoError::OffsetOutOfBounds { offset: 5, len: 1 })
        );
        assert_eq!(
            Name::decode(&[], 0),
            Err(ProtoError::Truncated { offset: 0 })
        );
        assert_eq!(
            Name::decode(&[], 1),
            Err(ProtoError::OffsetOutOfBounds { offset: 1, len: 0 })
        );
    }

    #[test]
    fn decode_pointer_chain_limit() {
        // Offset 0: root. Then a chain of pointers, each to the previous one.
        let build = |jumps: usize| {
            let mut msg = vec![0u8];
            let mut prev = 0usize;
            for _ in 0..jumps {
                let here = msg.len();
                msg.extend_from_slice(&[0xC0 | (prev >> 8) as u8, prev as u8]);
                prev = here;
            }
            (msg, prev)
        };
        let (msg, start) = build(128);
        assert_eq!(Name::decode(&msg, start).map(|(n, _)| n), Ok(Name::root()));
        let (msg, start) = build(129);
        assert_eq!(Name::decode(&msg, start), Err(ProtoError::TooManyPointers));
    }

    #[test]
    fn decode_overlong_via_pointers() {
        // Each block is a 63-byte label followed by a pointer to the previous block.
        let mut msg = vec![0u8];
        let mut prev = 0usize;
        for _ in 0..5 {
            let here = msg.len();
            msg.push(63);
            msg.extend(std::iter::repeat_n(b'a', 63));
            msg.extend_from_slice(&[0xC0 | (prev >> 8) as u8, prev as u8]);
            prev = here;
        }
        // Four labels: 4 * 64 + 1 = 257 > 255.
        assert!(matches!(
            Name::decode(&msg, prev),
            Err(ProtoError::NameTooLong { .. })
        ));
        // Three labels still fit (193 octets).
        let three = 1 + 2 * 66;
        assert_eq!(
            Name::decode(&msg, three).map(|(n, _)| n.wire_len()),
            Ok(193)
        );
    }

    #[test]
    fn decode_max_length_plain() {
        let wire = n(&format!("{0}.{0}.{0}.{1}", "a".repeat(63), "b".repeat(61)));
        assert_eq!(Name::decode(wire.as_wire(), 0), Ok((wire.clone(), 255)));
    }

    #[test]
    fn compression_round_trip() {
        let mut buf = Vec::new();
        let mut map = CompressionMap::new();
        n("www.example.com.").encode(&mut buf, Some(&mut map));
        assert_eq!(buf.len(), 17);
        n("mail.EXAMPLE.com.").encode(&mut buf, Some(&mut map));
        assert_eq!(&buf[17..], b"\x04mail\xC0\x04");
        n("www.example.com.").encode(&mut buf, Some(&mut map));
        assert_eq!(&buf[24..], b"\xC0\x00");
        let (a, next) = Name::decode(&buf, 0).expect("a");
        let (b, next) = Name::decode(&buf, next).expect("b");
        let (c, end) = Name::decode(&buf, next).expect("c");
        assert_eq!(a.to_string(), "www.example.com.");
        assert_eq!(b.to_string(), "mail.example.com.");
        assert_eq!(c, a);
        assert_eq!(end, buf.len());
    }

    #[test]
    fn encode_without_map_and_root() {
        let mut buf = Vec::new();
        n("a.b.").encode(&mut buf, None);
        n("a.b.").encode(&mut buf, None);
        assert_eq!(buf, b"\x01a\x01b\x00\x01a\x01b\x00");
        let mut map = CompressionMap::new();
        let mut buf = Vec::new();
        Name::root().encode(&mut buf, Some(&mut map));
        Name::root().encode(&mut buf, Some(&mut map));
        assert_eq!(buf, [0, 0]);
    }

    #[test]
    fn compression_ignores_offsets_past_limit() {
        let mut buf = vec![0u8; POINTER_LIMIT];
        let mut map = CompressionMap::new();
        n("a.example.").encode(&mut buf, Some(&mut map));
        let before = buf.len();
        n("b.example.").encode(&mut buf, Some(&mut map));
        assert_eq!(buf.len() - before, 11);
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(ProtoError::EmptyLabel.code(), "proto.empty_label");
        assert_eq!(
            ProtoError::LabelTooLong { len: 64 }.code(),
            "proto.label_too_long"
        );
        assert_eq!(
            ProtoError::TooManyPointers.code(),
            "proto.too_many_pointers"
        );
    }
}
