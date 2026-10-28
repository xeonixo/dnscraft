//! Presentation text for local record data (SPEC-policy.md): the form used in
//! TOML, the control API and the stored policy snapshot.

use std::net::{Ipv4Addr, Ipv6Addr};

use dnscraft_proto::{Name, RData, RecordType};

/// Parses a record type name (`A`, `AAAA`, `CNAME`, `TXT`, `SRV`, `MX`, `PTR`).
///
/// Case-insensitive. Returns `None` for any other type.
pub fn parse_record_type(text: &str) -> Option<RecordType> {
    match text.to_ascii_uppercase().as_str() {
        "A" => Some(RecordType::A),
        "AAAA" => Some(RecordType::AAAA),
        "CNAME" => Some(RecordType::CNAME),
        "TXT" => Some(RecordType::TXT),
        "SRV" => Some(RecordType::SRV),
        "MX" => Some(RecordType::MX),
        "PTR" => Some(RecordType::PTR),
        _ => None,
    }
}

/// Presentation name of a local record type (`UNKNOWN` for other types).
pub fn record_type_text(rtype: RecordType) -> &'static str {
    match rtype {
        RecordType::A => "A",
        RecordType::AAAA => "AAAA",
        RecordType::CNAME => "CNAME",
        RecordType::TXT => "TXT",
        RecordType::SRV => "SRV",
        RecordType::MX => "MX",
        RecordType::PTR => "PTR",
        _ => "UNKNOWN",
    }
}

/// Parses presentation text into record data of type `rtype`.
///
/// Formats: an address for A/AAAA, a name for CNAME/PTR, one string (at most
/// 255 bytes) for TXT, `<preference> <exchange>` for MX and
/// `<priority> <weight> <port> <target>` for SRV. Errors are human-readable.
pub fn parse_rdata(rtype: RecordType, text: &str) -> Result<RData, String> {
    let text = text.trim();
    let fields: Vec<&str> = text.split_whitespace().collect();
    let number = |field: &str| -> Result<u16, String> {
        field
            .parse::<u16>()
            .map_err(|_| format!("invalid number `{field}`"))
    };
    let name = |field: &str| -> Result<Name, String> {
        Name::from_ascii(field).map_err(|err| format!("invalid name `{field}`: {err}"))
    };
    match rtype {
        RecordType::A => text
            .parse::<Ipv4Addr>()
            .map(RData::A)
            .map_err(|_| "invalid IPv4 address".to_owned()),
        RecordType::AAAA => text
            .parse::<Ipv6Addr>()
            .map(RData::AAAA)
            .map_err(|_| "invalid IPv6 address".to_owned()),
        RecordType::CNAME => Ok(RData::CNAME(name(text)?)),
        RecordType::PTR => Ok(RData::PTR(name(text)?)),
        RecordType::TXT => {
            if text.is_empty() || text.len() > 255 {
                return Err("TXT value must be 1 to 255 bytes".to_owned());
            }
            Ok(RData::TXT(vec![Box::from(text.as_bytes())]))
        }
        RecordType::MX => match fields.as_slice() {
            [preference, exchange] => Ok(RData::MX {
                preference: number(preference)?,
                exchange: name(exchange)?,
            }),
            _ => Err("MX value must be `<preference> <exchange>`".to_owned()),
        },
        RecordType::SRV => match fields.as_slice() {
            [priority, weight, port, target] => Ok(RData::SRV {
                priority: number(priority)?,
                weight: number(weight)?,
                port: number(port)?,
                target: name(target)?,
            }),
            _ => Err("SRV value must be `<priority> <weight> <port> <target>`".to_owned()),
        },
        _ => Err("unsupported record type".to_owned()),
    }
}

/// Presentation text of record data (inverse of [`parse_rdata`]).
pub fn format_rdata(rdata: &RData) -> String {
    match rdata {
        RData::A(addr) => addr.to_string(),
        RData::AAAA(addr) => addr.to_string(),
        RData::CNAME(name) | RData::PTR(name) => name.to_string(),
        RData::MX {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        RData::SRV {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RData::TXT(strings) => strings
            .iter()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn presentation_round_trips_every_supported_type() {
        let cases = [
            (RecordType::A, "192.0.2.10"),
            (RecordType::AAAA, "2001:db8::10"),
            (RecordType::CNAME, "nas.lan.example.com."),
            (RecordType::PTR, "nas.lan.example.com."),
            (RecordType::TXT, "hello world"),
            (RecordType::MX, "10 mail.example.com."),
            (RecordType::SRV, "1 5 5060 sip.example.com."),
        ];
        for (rtype, text) in cases {
            let rdata = parse_rdata(rtype, text).unwrap();
            assert_eq!(format_rdata(&rdata), text, "{rtype:?}");
        }
    }

    #[test]
    fn presentation_rejects_malformed_values() {
        assert!(parse_rdata(RecordType::A, "not-an-address").is_err());
        assert!(parse_rdata(RecordType::MX, "mail.example.com.").is_err());
        assert!(parse_rdata(RecordType::SRV, "1 5 5060").is_err());
        assert!(parse_rdata(RecordType::TXT, "").is_err());
        assert_eq!(parse_record_type("ns"), None);
        assert_eq!(parse_record_type("aaaa"), Some(RecordType::AAAA));
    }
}
