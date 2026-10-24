//! SVCB and HTTPS RDATA (RFC 9460). Parameter values stay opaque for now.

use super::{Reader, invalid};
use crate::error::ProtoError;
use crate::name::Name;
use crate::rtype::RecordType;

/// The shared body of SVCB and HTTPS records.
///
/// `params` holds `(key, value)` pairs with strictly increasing keys; values
/// are the raw wire bytes (typed parsing of the known keys comes later).
/// `priority` 0 means AliasMode, in which `params` should be empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SvcbData {
    /// SvcPriority.
    pub priority: u16,
    /// TargetName. Never compressed on encode; a compression pointer is
    /// tolerated on decode.
    pub target: Name,
    /// SvcParams as `(key, opaque value)` in strictly increasing key order.
    pub params: Vec<(u16, Box<[u8]>)>,
}

pub(super) fn decode(r: &mut Reader<'_>, _rtype: RecordType) -> Result<SvcbData, ProtoError> {
    let priority = r.u16()?;
    let target = r.name()?;
    let mut params: Vec<(u16, Box<[u8]>)> = Vec::new();
    while r.remaining() > 0 {
        let key = r.u16()?;
        let len = usize::from(r.u16()?);
        let value = r.bytes(len)?;
        if let Some(&(previous, _)) = params.last() {
            if key <= previous {
                return Err(ProtoError::SvcbKeyOrder { previous, key });
            }
        }
        params.push((key, value.into()));
    }
    Ok(SvcbData {
        priority,
        target,
        params,
    })
}

pub(super) fn encode(
    data: &SvcbData,
    rtype: RecordType,
    buf: &mut Vec<u8>,
) -> Result<(), ProtoError> {
    buf.extend_from_slice(&data.priority.to_be_bytes());
    data.target.encode(buf, None);
    let mut last: Option<u16> = None;
    for (key, value) in &data.params {
        if let Some(previous) = last {
            if *key <= previous {
                return Err(ProtoError::SvcbKeyOrder {
                    previous,
                    key: *key,
                });
            }
        }
        last = Some(*key);
        let len = u16::try_from(value.len())
            .map_err(|_| invalid(rtype, "svcb parameter value longer than 65535 octets"))?;
        buf.extend_from_slice(&key.to_be_bytes());
        buf.extend_from_slice(&len.to_be_bytes());
        buf.extend_from_slice(value);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rdata::RData;

    fn dec(bytes: &[u8]) -> Result<RData, ProtoError> {
        RData::decode(bytes, RecordType::HTTPS, 0, bytes.len())
    }

    #[test]
    fn decodes_params() {
        let bytes = b"\x00\x01\x00\x00\x01\x00\x03\x02h2\x00\x03\x00\x02\x01\xBB";
        let RData::HTTPS(d) = dec(bytes).expect("https") else {
            panic!("variant");
        };
        assert_eq!(d.priority, 1);
        assert!(d.target.is_root());
        assert_eq!(
            d.params,
            vec![
                (1, b"\x02h2".to_vec().into_boxed_slice()),
                (3, vec![1, 187].into_boxed_slice())
            ]
        );
    }

    #[test]
    fn alias_mode_without_params() {
        let bytes = b"\x00\x00\x03foo\x00";
        let RData::HTTPS(d) = dec(bytes).expect("alias") else {
            panic!("variant");
        };
        assert_eq!((d.priority, d.params.len()), (0, 0));
    }

    #[test]
    fn key_order_is_enforced() {
        // Descending and duplicate keys.
        for bytes in [
            &b"\x00\x01\x00\x00\x03\x00\x00\x00\x01\x00\x00"[..],
            b"\x00\x01\x00\x00\x01\x00\x00\x00\x01\x00\x00",
        ] {
            assert!(matches!(dec(bytes), Err(ProtoError::SvcbKeyOrder { .. })));
        }
        let bad = SvcbData {
            priority: 1,
            target: Name::root(),
            params: vec![(3, Box::new([])), (1, Box::new([]))],
        };
        let mut buf = Vec::new();
        assert_eq!(
            RData::SVCB(bad).encode(&mut buf, None),
            Err(ProtoError::SvcbKeyOrder {
                previous: 3,
                key: 1
            })
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn truncated_param() {
        // Value length 4 but only 1 octet left.
        assert!(matches!(
            dec(b"\x00\x01\x00\x00\x01\x00\x04\x00"),
            Err(ProtoError::RdataLengthMismatch { .. })
        ));
        // Missing priority.
        assert!(matches!(
            dec(&[0]),
            Err(ProtoError::RdataLengthMismatch { .. })
        ));
    }

    #[test]
    fn oversize_value_rejected_on_encode() {
        let d = SvcbData {
            priority: 1,
            target: Name::root(),
            params: vec![(1, vec![0u8; 65536].into())],
        };
        assert!(RData::SVCB(d).encode(&mut Vec::new(), None).is_err());
    }
}
