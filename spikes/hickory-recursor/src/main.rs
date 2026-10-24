//! Throwaway spike: resolve real names with hickory-resolver's `recursor` feature, DNSSEC validation on.
use std::{net::IpAddr, time::Instant};

use hickory_resolver::{
    net::runtime::TokioRuntimeProvider,
    proto::{
        op::Query,
        rr::{Name, RecordType},
    },
    recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
};

const ROOTS: [&str; 4] = ["198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13"];

#[tokio::main]
async fn main() {
    let roots: Vec<IpAddr> = ROOTS.iter().map(|s| s.parse().unwrap()).collect();
    let recursor = Recursor::new(
        &roots,
        DnssecPolicy::ValidateWithStaticKey(DnssecConfig::default()),
        None,
        RecursorOptions::default(),
        TokioRuntimeProvider::default(),
    )
    .expect("recursor");

    let cases = [
        ("example.com.", RecordType::A),
        ("dnssec-failed.org.", RecordType::A),
        ("nonexistent-dnscraft-spike.example.com.", RecordType::A),
        ("nxd-dnscraft-spike.iana.org.", RecordType::A),
        ("nxd-dnscraft-spike.nlnetlabs.nl.", RecordType::A),
        ("www.github.com.", RecordType::A),
        ("example.com.", RecordType::A), // second time: cache
    ];
    for (name, rt) in cases {
        let q = Query::query(name.parse::<Name>().unwrap(), rt);
        let t = Instant::now();
        println!("=== {name} {rt}");
        match recursor.resolve(q, Instant::now(), true).await {
            Ok(m) => {
                println!("  ok rcode={:?} ad={} cd={} elapsed={:?}", m.metadata.response_code, m.metadata.authentic_data, m.metadata.checking_disabled, t.elapsed());
                for r in m.answers.iter().chain(m.authorities.iter()) {
                    println!("  {:?} {} ttl={} proof={:?}", r.record_type(), r.name, r.ttl, r.proof);
                }
            }
            Err(e) => {
                let soa_proof = e.clone().into_soa().map(|s| format!("{:?}", s.proof));
                println!(
                    "  err elapsed={:?}: {e} nxdomain={} nodata={} soa_proof={:?}",
                    t.elapsed(),
                    e.is_nx_domain(),
                    e.is_no_records_found(),
                    soa_proof
                );
            }
        }
    }
}
