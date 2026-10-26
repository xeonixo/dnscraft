//! Discovery of Designated Resolvers (RFC 9462) for local Do53 listeners.
//!
//! Opportunistic discovery only (RFC 9462 §4.3): certificates cover
//! `dns.<domain>` / `*.dns.<domain>`, not IP SANs, so clients must not treat
//! these answers as verified discovery (§4.2).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock, RwLock};

use dnscraft_filtering::SetId;
use dnscraft_policy::{
    AnswerOrigin, DecisionRecord, DecisionTimings, ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType, SvcbData};

use crate::config::{DdrConfig, Protocol};

/// Validated placeholder ids for DDR decision records (logging only).
#[allow(clippy::expect_used)]
static DDR_VIEW: LazyLock<ViewId> = LazyLock::new(|| {
    ViewId::new("default").unwrap_or_else(|_| ViewId::new("ddr").expect("ddr view id"))
});
#[allow(clippy::expect_used)]
static DDR_PROFILE: LazyLock<ProfileId> = LazyLock::new(|| {
    ProfileId::new("default").unwrap_or_else(|_| ProfileId::new("ddr").expect("ddr profile id"))
});
#[allow(clippy::expect_used)]
static DDR_SET: LazyLock<SetId> = LazyLock::new(|| {
    SetId::new("default").unwrap_or_else(|_| SetId::new("ddr").expect("ddr set id"))
});
static RESOLVER_ARPA: LazyLock<Name> =
    LazyLock::new(|| Name::from_ascii("resolver.arpa.").unwrap_or_else(|_| Name::root()));
static HOSTMASTER_RESOLVER_ARPA: LazyLock<Name> = LazyLock::new(|| {
    Name::from_ascii("hostmaster.resolver.arpa.").unwrap_or_else(|_| RESOLVER_ARPA.clone())
});

/// QNAME answered by DDR (`_dns.resolver.arpa.`, RFC 9462 §4).
pub const DDR_QNAME: &str = "_dns.resolver.arpa.";

/// Relative DoH URI template (RFC 9461 §5).
pub const DOH_PATH: &str = "/dns-query{?dns}";

/// SVCB / SOA TTL used in DDR answers.
pub const DDR_TTL: u32 = 7200;

/// SvcParamKey numbers (RFC 9460 / 9461); encoded in increasing order.
const SVCB_ALPN: u16 = 1;
const SVCB_PORT: u16 = 3;
const SVCB_IPV4HINT: u16 = 4;
const SVCB_IPV6HINT: u16 = 6;
const SVCB_DOHPATH: u16 = 7;

/// One local encrypted listener advertised in DDR SVCB answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DdrEndpoint {
    /// Encrypted protocol (`Dot` / `Doh` / `Doq`).
    pub protocol: Protocol,
    /// Bound socket address (may be unspecified for wildcard binds).
    pub address: SocketAddr,
    /// When true, DoH also offers HTTP/3 (N12); ignored until then.
    pub h3: bool,
}

/// Shared DDR advertisement state.
///
/// N11 updates this on `apply_config`; Do53 serve loops hold an
/// [`Arc<RwLock<DdrEndpoints>>`] and pass it into [`crate::core::QueryMeta`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DdrEndpoints {
    /// From [`DdrConfig::enabled`].
    pub enabled: bool,
    /// Target label ([`DdrConfig::target`]).
    pub target: String,
    /// Public DNS domain (e.g. `example.com`) for
    /// `{target}.dns.{public_domain}.`.
    pub public_domain: String,
    /// Bound local encrypted listeners to advertise.
    pub endpoints: Vec<DdrEndpoint>,
}

impl Default for DdrEndpoints {
    fn default() -> Self {
        let d = DdrConfig::default();
        Self {
            enabled: d.enabled,
            target: d.target,
            public_domain: String::new(),
            endpoints: Vec::new(),
        }
    }
}

impl DdrEndpoints {
    /// Builds from config plus the current encrypted listener set.
    pub fn new(
        config: &DdrConfig,
        public_domain: impl Into<String>,
        endpoints: Vec<DdrEndpoint>,
    ) -> Self {
        Self {
            enabled: config.enabled,
            target: config.target.clone(),
            public_domain: public_domain.into(),
            endpoints,
        }
    }

    /// Shared handle for Do53 params / N11.
    pub fn shared(self) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(self))
    }

    /// SVCB TargetName.
    ///
    /// Default `target = "dns"` → `dns.<public_domain>.` (cert apex). Any other
    /// label (node hostname) → `<target>.dns.<public_domain>.`.
    pub fn target_name(&self) -> Result<Name, dnscraft_proto::ProtoError> {
        let domain = self.public_domain.trim_matches('.');
        let target = self.target.trim_matches('.');
        let fqdn = if target.eq_ignore_ascii_case("dns") {
            format!("dns.{domain}.")
        } else {
            format!("{target}.dns.{domain}.")
        };
        Name::from_ascii(&fqdn)
    }
}

/// Whether `name` is exactly `_dns.resolver.arpa.`.
pub fn is_ddr_qname(name: &Name) -> bool {
    Name::from_ascii(DDR_QNAME).is_ok_and(|n| &n == name)
}

/// Builds a DDR response (SVCB answers or NODATA+SOA), or `None` to fall through to policy.
pub fn try_answer_ddr(query: &Message, arrival: IpAddr, state: &DdrEndpoints) -> Option<Message> {
    if !state.enabled {
        return None;
    }
    let question = query.questions.first()?;
    if question.qclass != Class::IN || question.qtype != RecordType::SVCB {
        return None;
    }
    if !is_ddr_qname(&question.name) {
        return None;
    }

    let family_v4 = arrival.is_ipv4();
    let mut matching: Vec<&DdrEndpoint> = state
        .endpoints
        .iter()
        .filter(|ep| is_encrypted(ep.protocol) && ep.address.is_ipv4() == family_v4)
        .collect();
    // Stable order: Dot, Doh, Doq, then by port.
    matching.sort_by_key(|ep| (protocol_rank(ep.protocol), ep.address.port()));

    let mut resp = Message::response_to(query);
    resp.header.ra = true;
    resp.set_rcode(Rcode::NOERROR).ok()?;

    if matching.is_empty() {
        resp.authorities.push(resolver_arpa_soa());
        return Some(resp);
    }

    let target = state.target_name().ok()?;
    for (i, ep) in matching.iter().enumerate() {
        let priority = u16::try_from(i + 1).unwrap_or(u16::MAX);
        let hint = hint_addr(ep.address, arrival)?;
        let params = svcb_params(ep, hint)?;
        resp.answers.push(Record::new(
            question.name.clone(),
            Class::IN,
            DDR_TTL,
            RData::SVCB(SvcbData {
                priority,
                target: target.clone(),
                params,
            }),
        ));
    }
    Some(resp)
}

/// Decision record for a DDR answer (`AnswerOrigin::ListenerDdr`).
pub fn ddr_decision_record(rcode: Rcode) -> DecisionRecord {
    DecisionRecord {
        view_id: DDR_VIEW.clone(),
        profile_id: DDR_PROFILE.clone(),
        selection: SelectionCause::Default,
        client_id: None,
        filter_set: DDR_SET.clone(),
        steps: Vec::new(),
        filter: None,
        forward_zone: None,
        dnssec: None,
        answer_source: AnswerOrigin::ListenerDdr,
        timings: DecisionTimings::default(),
        rcode,
    }
}

fn is_encrypted(p: Protocol) -> bool {
    matches!(p, Protocol::Dot | Protocol::Doh | Protocol::Doq)
}

fn protocol_rank(p: Protocol) -> u8 {
    match p {
        Protocol::Dot => 0,
        Protocol::Doh => 1,
        Protocol::Doq => 2,
        Protocol::Udp53 | Protocol::Tcp53 => 9,
    }
}

fn hint_addr(bound: SocketAddr, arrival: IpAddr) -> Option<IpAddr> {
    let ip = bound.ip();
    let hint = if ip.is_unspecified() {
        arrival.to_canonical()
    } else {
        ip.to_canonical()
    };
    match (hint, arrival.is_ipv4()) {
        (IpAddr::V4(_), true) | (IpAddr::V6(_), false) => Some(hint),
        _ => None,
    }
}

fn svcb_params(ep: &DdrEndpoint, hint: IpAddr) -> Option<Vec<(u16, Box<[u8]>)>> {
    let alpn = match ep.protocol {
        Protocol::Dot => b"dot".as_slice(),
        Protocol::Doh => b"h2".as_slice(), // h3 only once N12 exists
        Protocol::Doq => b"doq".as_slice(),
        Protocol::Udp53 | Protocol::Tcp53 => return None,
    };
    let mut params = Vec::new();
    // alpn = length-prefixed id(s)
    let mut alpn_wire = Vec::with_capacity(1 + alpn.len());
    alpn_wire.push(u8::try_from(alpn.len()).ok()?);
    alpn_wire.extend_from_slice(alpn);
    params.push((SVCB_ALPN, alpn_wire.into_boxed_slice()));

    params.push((
        SVCB_PORT,
        ep.address.port().to_be_bytes().to_vec().into_boxed_slice(),
    ));

    match hint {
        IpAddr::V4(v4) => {
            params.push((SVCB_IPV4HINT, v4.octets().to_vec().into_boxed_slice()));
        }
        IpAddr::V6(v6) => {
            params.push((SVCB_IPV6HINT, v6.octets().to_vec().into_boxed_slice()));
        }
    }

    if ep.protocol == Protocol::Doh {
        params.push((
            SVCB_DOHPATH,
            DOH_PATH.as_bytes().to_vec().into_boxed_slice(),
        ));
    }
    Some(params)
}

/// NODATA authority SOA for the locally served `resolver.arpa` zone (RFC 9462 §4).
fn resolver_arpa_soa() -> Record {
    Record::new(
        RESOLVER_ARPA.clone(),
        Class::IN,
        DDR_TTL,
        RData::SOA {
            mname: RESOLVER_ARPA.clone(),
            rname: HOSTMASTER_RESOLVER_ARPA.clone(),
            serial: 1,
            refresh: 3600,
            retry: 600,
            expire: 86_400,
            minimum: DDR_TTL,
        },
    )
}

/// Convenience: empty endpoints with DDR enabled for tests.
#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn empty_enabled(domain: &str) -> DdrEndpoints {
    DdrEndpoints {
        enabled: true,
        target: "dns".into(),
        public_domain: domain.into(),
        endpoints: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn target_name_shape() {
        let s = DdrEndpoints {
            enabled: true,
            target: "dns".into(),
            public_domain: "example.com".into(),
            endpoints: vec![],
        };
        assert_eq!(s.target_name().unwrap().to_string(), "dns.example.com.");
        let mut node = s;
        node.target = "node1".into();
        assert_eq!(
            node.target_name().unwrap().to_string(),
            "node1.dns.example.com."
        );
    }

    #[test]
    fn hint_uses_arrival_on_wildcard() {
        let bound = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 853));
        let arrival = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(hint_addr(bound, arrival), Some(arrival));
    }

    #[test]
    fn key_order_alpn_port_hint_dohpath() {
        let ep = DdrEndpoint {
            protocol: Protocol::Doh,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            h3: false,
        };
        let params = svcb_params(&ep, IpAddr::V4(Ipv4Addr::LOCALHOST)).unwrap();
        let keys: Vec<u16> = params.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![SVCB_ALPN, SVCB_PORT, SVCB_IPV4HINT, SVCB_DOHPATH]
        );
    }
}
