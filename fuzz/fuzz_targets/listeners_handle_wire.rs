#![no_main]

//! Fuzzes the transport-independent `handle_wire` core with arbitrary wire
//! bytes and a `QueryMeta` derived from the same input. The goal is only
//! "never panic / never hang": every decode, validate, encode and handler path
//! must be total on adversarial input.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock, RwLock};

use dnscraft_filtering::SetId;
use dnscraft_listeners::{
    DdrConfig, DdrEndpoint, DdrEndpoints, Exposure, FakeHandler, Protocol, QueryMeta, handle_wire,
};
use dnscraft_policy::{
    AnswerOrigin, ClientId, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId, PolicyAnswer,
    ProfileId, SelectionCause, ViewId,
};
use dnscraft_proto::{Message, Name, Rcode, RecordType};
use libfuzzer_sys::fuzz_target;

/// A canned NOERROR answer so the handler runs (exercising `finish_response`).
fn answer() -> PolicyAnswer {
    let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
    let resp = Message::response_to(&q);
    PolicyAnswer {
        message: resp,
        ede: None,
        record: DecisionRecord {
            view_id: ViewId::new("fuzz").unwrap(),
            profile_id: ProfileId::new("fuzz").unwrap(),
            selection: SelectionCause::Default,
            client_id: None,
            client_label: None,
            client_device: None,
            filter_set: SetId::new("fuzz").unwrap(),
            steps: Vec::new(),
            filter: None,
            forward_zone: None,
            dnssec: None,
            answer_source: AnswerOrigin::LocalView,
            timings: DecisionTimings::default(),
            rcode: Rcode::NOERROR,
        },
        loggable: true,
    }
}

fn handler() -> Arc<FakeHandler> {
    static H: OnceLock<Arc<FakeHandler>> = OnceLock::new();
    Arc::clone(H.get_or_init(|| Arc::new(FakeHandler::new(answer()))))
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    })
}

/// Builds a `DdrEndpoints` (as the library does for a local Do53 listener) for
/// about half of the inputs, selected by an input byte. Both address families
/// and every encrypted protocol are advertised so `try_answer_ddr`'s SVCB
/// construction, family filtering and NODATA fallback are all reachable.
fn ddr_for(data: &[u8]) -> Option<Arc<RwLock<DdrEndpoints>>> {
    if data.get(23).copied().unwrap_or(0) & 1 != 0 {
        return None;
    }
    let endpoints = vec![
        DdrEndpoint {
            protocol: Protocol::Dot,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 853)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Doh,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 443)),
            h3: true,
        },
        DdrEndpoint {
            protocol: Protocol::Doq,
            address: SocketAddr::from((Ipv4Addr::LOCALHOST, 8853)),
            h3: false,
        },
        DdrEndpoint {
            protocol: Protocol::Doh,
            address: "[::1]:443".parse().unwrap(),
            h3: false,
        },
    ];
    Some(
        DdrEndpoints::new(
            &DdrConfig {
                enabled: true,
                target: "dns".into(),
            },
            "example.com",
            endpoints,
        )
        .shared(),
    )
}

/// Derives a `QueryMeta` from the input bytes. All fields are total: a short
/// input reads as zeros, so no `QueryMeta` construction can panic.
fn meta_from(data: &[u8]) -> QueryMeta {
    let b = |i: usize| data.get(i).copied().unwrap_or(0);
    let protocol = [
        DnsProtocol::Udp53,
        DnsProtocol::Tcp53,
        DnsProtocol::DoT,
        DnsProtocol::DoH,
        DnsProtocol::DoQ,
    ][usize::from(b(0)) % 5];
    let exposure = if b(1) & 1 == 0 {
        Exposure::Local
    } else {
        Exposure::Public
    };
    let source = if b(2) & 1 == 0 {
        IpAddr::V4(Ipv4Addr::new(b(3), b(4), b(5), b(6)))
    } else {
        let mut octets = [0u8; 16];
        for (i, o) in octets.iter_mut().enumerate() {
            *o = b(3 + i);
        }
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    QueryMeta {
        protocol,
        listener_id: ListenerId::new("fuzz").unwrap(),
        exposure,
        source,
        arrival: source,
        client_id: if b(19) & 1 == 0 {
            ClientId::new("fuzz").ok()
        } else {
            None
        },
        node_id: None,
        size_limit: 512 + usize::from(b(20)) * 64,
        pad: b(21) & 1 == 0,
        udp_payload_max: 512 + u16::from(b(22)) * 2,
        ddr: ddr_for(data),
    }
}

fuzz_target!(|data: &[u8]| {
    let meta = meta_from(data);
    let h = handler();
    runtime().block_on(async {
        let _ = handle_wire(data, meta, &h).await;
    });
});
