//! Minimal Do53 UDP+TCP demo on loopback high ports (Checkpoint B).
//!
//! ```text
//! cargo run -p dnscraft-listeners --example serve
//! dig @127.0.0.1 -p 5353 example.com A +short
//! dig @127.0.0.1 -p 5353 example.com A +tcp +short
//! ```
//!
//! Uses the real resolver from the built-in root hints (no testkit, no config file).
//! Ctrl-C stops the process.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unwrap_used,
    clippy::expect_used
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_listeners::{
    Admission, Exposure, Limits, ListenerConfig, Protocol, PublicConfig, SystemClock,
    TcpServeParams, TcpStats, UdpServeParams, UdpStats, serve_tcp, serve_udp,
};
use dnscraft_policy::{
    ListenerId, NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, SafeSearchConfig,
    ViewConfig, ViewId,
};
use dnscraft_resolver::{Resolver, ResolverConfig};
use std::sync::Mutex;
use tokio::sync::{oneshot, watch};

#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn empty_filter() -> Arc<FilterEngine> {
    let sc = FilterSetConfig::new(SetId::new("default").unwrap(), "default");
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![sc],
        ..FilterConfig::default()
    };
    Arc::new(FilterEngine::from_snapshot(
        SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
            .build(&cfg)
            .unwrap(),
    ))
}

async fn build_engine() -> Arc<PolicyEngine> {
    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            query_timeout: Duration::from_secs(5),
            ..ResolverConfig::default()
        })
        .await
        .expect("resolver"),
    );
    let profile = ProfileConfig {
        id: ProfileId::new("default").unwrap(),
        filter_set: SetId::new("default").unwrap(),
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: Some(true),
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    };
    let view = ViewConfig {
        id: ViewId::new("default").unwrap(),
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: Vec::new(),
        profile: ProfileId::new("default").unwrap(),
    };
    let cfg = PolicyConfig {
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };
    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    Arc::new(
        PolicyEngine::new(cfg, empty_filter(), resolver, Arc::new(NoClients), clock)
            .expect("policy"),
    )
}

#[tokio::main]
async fn main() {
    let engine = build_engine().await;
    // Prefer 5353 (Checkpoint B dig example); fall back if the port is taken.
    let ports = [5353u16, 15353];
    let udp_stats = Arc::new(UdpStats::default());
    let tcp_stats = Arc::new(TcpStats::default());
    let clock: Arc<dyn dnscraft_listeners::Clock> = Arc::new(SystemClock);

    let mut started = None;
    for port in ports {
        let udp_bind = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let tcp_bind = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let (udp_bound_tx, udp_bound_rx) = oneshot::channel();
        let (tcp_bound_tx, tcp_bound_rx) = oneshot::channel();
        let (udp_sd_tx, udp_sd_rx) = watch::channel(false);
        let (tcp_sd_tx, tcp_sd_rx) = watch::channel(false);

        let admission = Arc::new(Mutex::new(Admission::new(
            &Limits::default(),
            &PublicConfig::default(),
        )));
        let mut udp_join = tokio::spawn(serve_udp(UdpServeParams {
            listener: ListenerConfig {
                id: ListenerId::new("demo-udp").unwrap(),
                protocol: Protocol::Udp53,
                address: udp_bind,
                exposure: Exposure::Local,
                h3: false,
                tls_policy: None,
            },
            limits: Limits::default(),
            admission: Arc::clone(&admission),
            handler: Arc::clone(&engine),
            clock: Arc::clone(&clock),
            stats: Arc::clone(&udp_stats),
            ddr: None,
            event_sink: None,
            bound: udp_bound_tx,
            shutdown: udp_sd_rx,
        }));

        let udp_addr = tokio::select! {
            r = udp_bound_rx => match r {
                Ok(a) => a,
                Err(_) => continue,
            },
            r = &mut udp_join => {
                eprintln!("UDP {port}: {r:?}");
                continue;
            }
        };

        let mut tcp_join = tokio::spawn(serve_tcp(TcpServeParams {
            listener: ListenerConfig {
                id: ListenerId::new("demo-tcp").unwrap(),
                protocol: Protocol::Tcp53,
                address: tcp_bind,
                exposure: Exposure::Local,
                h3: false,
                tls_policy: None,
            },
            limits: Limits::default(),
            admission,
            handler: Arc::clone(&engine),
            clock: Arc::clone(&clock),
            stats: Arc::clone(&tcp_stats),
            ddr: None,
            event_sink: None,
            bound: tcp_bound_tx,
            shutdown: tcp_sd_rx,
        }));

        let tcp_addr = tokio::select! {
            r = tcp_bound_rx => match r {
                Ok(a) => a,
                Err(_) => {
                    let _ = udp_sd_tx.send(true);
                    let _ = udp_join.await;
                    continue;
                }
            },
            r = &mut tcp_join => {
                eprintln!("TCP {port}: {r:?}");
                let _ = udp_sd_tx.send(true);
                let _ = udp_join.await;
                continue;
            }
        };

        started = Some((
            port, udp_addr, tcp_addr, udp_sd_tx, tcp_sd_tx, udp_join, tcp_join,
        ));
        break;
    }

    let Some((port, udp_addr, tcp_addr, udp_sd_tx, tcp_sd_tx, udp_join, tcp_join)) = started else {
        eprintln!("could not bind UDP+TCP on 127.0.0.1:5353 or :15353");
        std::process::exit(1);
    };

    if port != 5353 {
        eprintln!("note: 127.0.0.1:5353 busy; using {port}");
    }
    println!("DNScraft listeners demo");
    println!("  UDP {udp_addr}");
    println!("  TCP {tcp_addr}");
    println!("Try: dig @127.0.0.1 -p {port} example.com A +short");
    println!("     dig @127.0.0.1 -p {port} example.com A +tcp +short");
    println!("Ctrl-C to stop.");

    tokio::signal::ctrl_c().await.expect("ctrl-c");
    let _ = udp_sd_tx.send(true);
    let _ = tcp_sd_tx.send(true);
    let _ = udp_join.await;
    let _ = tcp_join.await;
    println!(
        "stopped (udp answered={}, tcp answered={})",
        udp_stats
            .answered
            .load(std::sync::atomic::Ordering::Relaxed),
        tcp_stats
            .answered
            .load(std::sync::atomic::Ordering::Relaxed)
    );
}
