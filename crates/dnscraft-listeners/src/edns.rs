//! EDNS helpers for the message core: ECS strip, OPT echo, EDE, padding.

use dnscraft_proto::{Edns, EdnsOption, Message};
use dnscraft_resolver::ExtendedError;

/// RFC 8467 recommended response padding block length (octets).
pub const PAD_BLOCK: usize = 468;

/// Removes ECS options from `edns` (SPEC.md: never answer or forward ECS).
///
/// Cookies and other options are left alone here; the response OPT is built
/// fresh by [`build_response_edns`].
pub fn strip_ecs(edns: &mut Edns) {
    edns.options
        .retain(|opt| !matches!(opt, EdnsOption::ClientSubnet { .. }));
}

/// Builds the response OPT: payload `min(client, udp_payload_max)`, DO from the
/// client, no ECS/cookies; optional EDE when the client sent OPT.
pub fn build_response_edns(
    client: &Edns,
    udp_payload_max: u16,
    ede: Option<&ExtendedError>,
) -> Edns {
    let mut out = Edns::new(client.udp_payload.min(udp_payload_max));
    out.dnssec_ok = client.dnssec_ok;
    if let Some(ede) = ede {
        out.options.push(EdnsOption::ExtendedError {
            info_code: ede.code,
            extra_text: ede.text.clone().unwrap_or_default().into_boxed_str(),
        });
    }
    out
}

/// Pads `msg` so its encoding is a multiple of [`PAD_BLOCK`] and ≤ `max`.
///
/// Only call when the client sent OPT and the transport requested padding.
/// If the next block boundary does not fit in `max`, pads up to `max` (still
/// with a Padding option when at least 4 octets remain). Returns the encoded
/// bytes. Existing Padding options are replaced.
pub fn encode_padded(msg: &mut Message, max: usize) -> Result<Vec<u8>, dnscraft_proto::ProtoError> {
    if let Some(edns) = msg.edns.as_mut() {
        edns.options
            .retain(|o| !matches!(o, EdnsOption::Padding(_)));
    }

    let base = msg.encode_with_limit(max)?;
    if base.len() % PAD_BLOCK == 0 {
        return Ok(base);
    }

    let Some(edns) = msg.edns.as_mut() else {
        return Ok(base);
    };

    let base_len = base.len();
    let room = max.saturating_sub(base_len);
    if room < 4 {
        return Ok(base);
    }

    // Prefer the next multiple of PAD_BLOCK; otherwise fill remaining room.
    let rem = (base_len + 4) % PAD_BLOCK;
    let ideal_content = if rem == 0 { 0 } else { PAD_BLOCK - rem };
    let content = if base_len + 4 + ideal_content <= max {
        ideal_content
    } else {
        room - 4
    };
    let content = u16::try_from(content).unwrap_or(u16::MAX);
    edns.options.push(EdnsOption::Padding(content));

    match msg.encode_with_limit(max) {
        Ok(out) => Ok(out),
        Err(_) => {
            // Encoding grew unexpectedly; fall back to the unpadded base.
            if let Some(edns) = msg.edns.as_mut() {
                edns.options
                    .retain(|o| !matches!(o, EdnsOption::Padding(_)));
            }
            Ok(base)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use dnscraft_proto::{Message, Name, RecordType};

    #[test]
    fn strip_ecs_removes_only_subnet() {
        let mut edns = Edns::new(1232);
        edns.options.push(EdnsOption::ClientSubnet {
            family: 1,
            source_prefix: 24,
            scope_prefix: 0,
            address: vec![192, 0, 2].into(),
        });
        edns.options.push(EdnsOption::Cookie {
            client: [1; 8],
            server: None,
        });
        strip_ecs(&mut edns);
        assert_eq!(edns.options.len(), 1);
        assert!(matches!(edns.options[0], EdnsOption::Cookie { .. }));
    }

    #[test]
    fn encode_padded_aligns_to_block() {
        let q = Message::query(1, Name::root(), RecordType::A);
        let mut resp = Message::response_to(&q);
        resp.edns = Some(Edns::new(1232));
        let out = encode_padded(&mut resp, 4096).unwrap();
        assert_eq!(out.len() % PAD_BLOCK, 0);
        assert!(out.len() <= 4096);
    }
}
