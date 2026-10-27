//! [`ListenerSet`]: bind, reload, status, and graceful shutdown.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use dnscraft_policy::{ListenerId, PolicyEngine};
use dnscraft_tls::{CertResolver, ClientIdRegistry, ReservedLabels};
use tokio::sync::{Mutex as AsyncMutex, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

use crate::admission::{Admission, SourceClassifier, default_classifier};
use crate::clock::Clock;
use crate::config::{Exposure, Limits, ListenerConfig, ListenersConfig, Protocol};
use crate::conn::FramedStats;
use crate::ddr::{DdrEndpoint, DdrEndpoints};
use crate::doh::{DohServeParams, DohStats, serve_doh};
use crate::doh_h3::{DohH3ServeParams, serve_doh_h3};
use crate::doq::{DoqServeParams, DoqStats, serve_doq};
use crate::dot::{DotServeParams, DotStats, serve_dot};
use crate::error::ListenersError;
use crate::events::QueryEventSink;
use crate::handler::QueryHandler;
use crate::status::{ListenerStatus, ListenersStatus};
use crate::tcp::{TcpServeParams, TcpStats, serve_tcp};
use crate::tls::{PolicyClientIds, SniGate, TlsStats};
use crate::udp::{UdpServeParams, UdpStats, serve_udp};

/// Shared runtime for all configured listeners.
pub struct ListenerSet<H: QueryHandler + ?Sized = PolicyEngine> {
    handler: Arc<H>,
    certs: Arc<CertResolver>,
    sni_gate: Arc<SniGate>,
    clock: Arc<dyn Clock>,
    sink: Arc<dyn QueryEventSink>,
    admission: Arc<Mutex<Admission>>,
    ddr: Arc<RwLock<DdrEndpoints>>,
    public_domain: String,
    inner: Mutex<Inner>,
    apply_lock: AsyncMutex<()>,
}

struct Inner {
    config: ListenersConfig,
    running: HashMap<ListenerId, RunningListener>,
}

struct RunningListener {
    config: ListenerConfig,
    bound: Option<SocketAddr>,
    bind_error: Option<ListenersError>,
    shutdown: watch::Sender<bool>,
    join: JoinHandle<Result<(), ListenersError>>,
    kind: ListenerKind,
}

enum ListenerKind {
    Udp {
        stats: Arc<UdpStats>,
    },
    Tcp {
        stats: Arc<TcpStats>,
    },
    Dot {
        stats: Arc<DotStats>,
        tls: Arc<TlsStats>,
    },
    Doh {
        stats: Arc<DohStats>,
        tls: Arc<TlsStats>,
    },
    Doq {
        stats: Arc<DoqStats>,
        tls: Arc<TlsStats>,
    },
}

/// Inputs for [`ListenerSet::start_with`].
pub struct ListenerSetParams<H: QueryHandler + ?Sized = PolicyEngine> {
    /// Validated listener configuration.
    pub config: ListenersConfig,
    /// Policy engine or test [`crate::FakeHandler`].
    pub handler: Arc<H>,
    /// Shared TLS store; `None` → empty resolver (encrypted → `listeners.tls.no_cert`).
    pub certs: Option<Arc<CertResolver>>,
    /// Query-log sink (non-blocking).
    pub sink: Arc<dyn QueryEventSink>,
    /// Wall clock.
    pub clock: Arc<dyn Clock>,
    /// Public DNS domain for SNI / DDR (`dns.<domain>`).
    pub public_domain: String,
    /// Client-ID registry for public SNI / DoH paths.
    pub client_ids: Arc<dyn ClientIdRegistry>,
    /// Source classifier. Production constructors ([`ListenerSet::start`]) pass
    /// [`default_classifier`]; the field exists as a test seam so tests can
    /// classify loopback as public and exercise public admission and bans from
    /// `127.0.0.1` without real public peers.
    pub classify: SourceClassifier,
}

impl ListenerSet<PolicyEngine> {
    /// Starts every listener (SPEC entry point).
    ///
    /// Bind failures are recorded in [`Self::status`]; other listeners keep running.
    pub async fn start(
        cfg: ListenersConfig,
        policy: Arc<PolicyEngine>,
        certs: Option<Arc<CertResolver>>,
        sink: Arc<dyn QueryEventSink>,
        clock: Arc<dyn Clock>,
        public_domain: impl Into<String>,
    ) -> Result<Self, ListenersError> {
        let public_domain = public_domain.into();
        Self::start_with(ListenerSetParams {
            client_ids: Arc::new(PolicyClientIds(Arc::clone(&policy))),
            config: cfg,
            handler: policy,
            certs,
            sink,
            clock,
            public_domain,
            classify: default_classifier(),
        })
        .await
    }
}

impl<H: QueryHandler + 'static> ListenerSet<H> {
    /// Starts listeners with an arbitrary [`QueryHandler`].
    pub async fn start_with(params: ListenerSetParams<H>) -> Result<Self, ListenersError> {
        params.config.validate()?;
        let ListenerSetParams {
            config,
            handler,
            certs,
            sink,
            clock,
            public_domain,
            client_ids,
            classify,
        } = params;

        let certs = certs.unwrap_or_else(|| Arc::new(CertResolver::new()));
        let sni_gate = Arc::new(SniGate {
            public_domain: public_domain.clone(),
            reserved: Arc::new(RwLock::new(reserved_from_ddr(&config.ddr.target))),
            registry: client_ids,
        });

        let admission = Arc::new(Mutex::new(Admission::with_classifier(
            &config.limits,
            &config.public,
            classify,
        )));
        // Endpoints are filled after binding: DDR must advertise the addresses
        // that actually bound, not the configured ones (port 0 / failures).
        let ddr = DdrEndpoints::new(&config.ddr, public_domain.clone(), Vec::new()).shared();

        let set = Self {
            handler,
            certs,
            sni_gate,
            clock,
            sink,
            admission,
            ddr,
            public_domain,
            inner: Mutex::new(Inner {
                config: config.clone(),
                running: HashMap::new(),
            }),
            apply_lock: AsyncMutex::new(()),
        };

        for listener in &config.listeners {
            set.spawn_one(listener.clone(), &config.limits).await;
        }
        set.refresh_ddr(&config);
        Ok(set)
    }

    /// Rebinds only listeners whose [`ListenerConfig`] changed; unchanged keep sockets.
    ///
    /// Serialized so concurrent reloads cannot interleave their stop/start phases.
    pub async fn apply_config(&self, cfg: ListenersConfig) -> Result<(), ListenersError> {
        let _apply = self.apply_lock.lock().await;
        cfg.validate()?;

        let (to_stop, to_start, limits, rebuild_admission, reserved) = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let old = &inner.config;
            let limits_changed = cfg.limits.listener_limits_changed(&old.limits);
            let rebuild_admission =
                old.public != cfg.public || cfg.limits.admission_limits_changed(&old.limits);
            let reserved = if old.ddr.target != cfg.ddr.target {
                Some(reserved_from_ddr(&cfg.ddr.target))
            } else {
                None
            };

            let mut to_stop = Vec::new();
            let mut to_start = Vec::new();

            for (id, running) in &inner.running {
                match cfg.listeners.iter().find(|l| &l.id == id) {
                    None => to_stop.push(id.clone()),
                    Some(new_cfg) if limits_changed || new_cfg != &running.config => {
                        to_stop.push(id.clone());
                        to_start.push(new_cfg.clone());
                    }
                    Some(_) => {}
                }
            }
            for new_cfg in &cfg.listeners {
                if !inner.running.contains_key(&new_cfg.id)
                    && !to_start.iter().any(|l| l.id == new_cfg.id)
                {
                    to_start.push(new_cfg.clone());
                }
            }

            let limits = cfg.limits.clone();
            inner.config = cfg.clone();
            (to_stop, to_start, limits, rebuild_admission, reserved)
        };

        if rebuild_admission {
            let mut adm = self
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            adm.reconfigure(&cfg.limits, &cfg.public);
        }

        if let Some(new_reserved) = reserved {
            let mut guard = self
                .sni_gate
                .reserved
                .write()
                .unwrap_or_else(|e| e.into_inner());
            *guard = new_reserved;
        }

        for id in to_stop {
            self.stop_one(&id).await;
        }
        for listener in to_start {
            self.spawn_one(listener, &limits).await;
        }
        self.refresh_ddr(&cfg);
        Ok(())
    }

    /// Current bind / counter snapshot.
    pub fn status(&self) -> ListenersStatus {
        let inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ban_entries = {
            let adm = self
                .admission
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            adm.ban_entry_count() as u64
        };

        let mut listeners = Vec::with_capacity(inner.running.len());
        for running in inner.running.values() {
            listeners.push(running.to_status());
        }
        listeners.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        ListenersStatus {
            listeners,
            events_dropped: self.sink.events_dropped(),
            ban_entries,
        }
    }

    /// Stops accepting and waits up to `grace` for in-flight work to finish.
    pub async fn shutdown(self, grace: Duration) {
        let running = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::take(&mut inner.running)
        };
        for r in running.values() {
            let _ = r.shutdown.send(true);
        }
        let mut joins: Vec<_> = running.into_values().map(|r| r.join).collect();
        let wait = async {
            for j in &mut joins {
                let _ = j.await;
            }
        };
        if tokio::time::timeout(grace, wait).await.is_err() {
            // Grace expired: stop waiting for a drain that will not finish.
            for j in &mut joins {
                j.abort();
            }
        }
    }

    fn refresh_ddr(&self, cfg: &ListenersConfig) {
        // Advertise successfully bound local encrypted listeners (bound
        // addresses, so port 0 and bind failures are handled correctly).
        let endpoints = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner
                .running
                .values()
                .filter_map(|r| {
                    let bound = r.bound?;
                    if r.config.exposure != Exposure::Local
                        || !matches!(
                            r.config.protocol,
                            Protocol::Dot | Protocol::Doh | Protocol::Doq
                        )
                    {
                        return None;
                    }
                    Some(DdrEndpoint {
                        protocol: r.config.protocol,
                        address: bound,
                        h3: r.config.h3,
                    })
                })
                .collect()
        };
        if let Ok(mut guard) = self.ddr.write() {
            *guard = DdrEndpoints::new(&cfg.ddr, self.public_domain.clone(), endpoints);
        }
    }

    async fn spawn_one(&self, listener: ListenerConfig, limits: &Limits) {
        let (bound_tx, bound_rx) = oneshot::channel();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let id = listener.id.clone();

        let (kind, join) = match listener.protocol {
            Protocol::Udp53 => {
                let stats = Arc::new(UdpStats::default());
                let join = tokio::spawn(serve_udp(UdpServeParams {
                    listener: listener.clone(),
                    limits: limits.clone(),
                    admission: Arc::clone(&self.admission),
                    handler: Arc::clone(&self.handler),
                    clock: Arc::clone(&self.clock),
                    stats: Arc::clone(&stats),
                    ddr: Some(Arc::clone(&self.ddr)),
                    event_sink: Some(Arc::clone(&self.sink)),
                    bound: bound_tx,
                    shutdown: shutdown_rx,
                }));
                (ListenerKind::Udp { stats }, join)
            }
            Protocol::Tcp53 => {
                let stats = Arc::new(TcpStats::default());
                let join = tokio::spawn(serve_tcp(TcpServeParams {
                    listener: listener.clone(),
                    limits: limits.clone(),
                    admission: Arc::clone(&self.admission),
                    handler: Arc::clone(&self.handler),
                    clock: Arc::clone(&self.clock),
                    stats: Arc::clone(&stats),
                    ddr: Some(Arc::clone(&self.ddr)),
                    event_sink: Some(Arc::clone(&self.sink)),
                    bound: bound_tx,
                    shutdown: shutdown_rx,
                }));
                (ListenerKind::Tcp { stats }, join)
            }
            Protocol::Dot => {
                let stats = Arc::new(DotStats::default());
                let tls = Arc::new(TlsStats::default());
                let join = tokio::spawn(serve_dot(DotServeParams {
                    listener: listener.clone(),
                    limits: limits.clone(),
                    admission: Arc::clone(&self.admission),
                    handler: Arc::clone(&self.handler),
                    clock: Arc::clone(&self.clock),
                    stats: Arc::clone(&stats),
                    tls_stats: Arc::clone(&tls),
                    certs: Arc::clone(&self.certs),
                    sni_gate: Arc::clone(&self.sni_gate),
                    event_sink: Some(Arc::clone(&self.sink)),
                    bound: bound_tx,
                    shutdown: shutdown_rx,
                }));
                (ListenerKind::Dot { stats, tls }, join)
            }
            Protocol::Doh => {
                let stats = Arc::new(DohStats::default());
                let tls = Arc::new(TlsStats::default());
                let alt_svc_port = Arc::new(AtomicU16::new(listener.address.port()));
                let join = if listener.h3 {
                    let (tcp_bound_tx, tcp_bound_rx) = oneshot::channel();
                    let (h3_bound_tx, h3_bound_rx) = oneshot::channel();
                    // A JoinSet aborts both halves if the coordinator is
                    // dropped (reload timeout), so neither socket leaks.
                    let mut joins = JoinSet::new();
                    joins.spawn(serve_doh_h3(DohH3ServeParams {
                        listener: listener.clone(),
                        limits: limits.clone(),
                        admission: Arc::clone(&self.admission),
                        handler: Arc::clone(&self.handler),
                        clock: Arc::clone(&self.clock),
                        stats: Arc::clone(&stats),
                        tls_stats: Arc::clone(&tls),
                        certs: Arc::clone(&self.certs),
                        sni_gate: Arc::clone(&self.sni_gate),
                        event_sink: Some(Arc::clone(&self.sink)),
                        alt_svc_port: Arc::clone(&alt_svc_port),
                        bound: h3_bound_tx,
                        shutdown: shutdown_rx.clone(),
                    }));
                    joins.spawn(serve_doh(DohServeParams {
                        listener: listener.clone(),
                        limits: limits.clone(),
                        admission: Arc::clone(&self.admission),
                        handler: Arc::clone(&self.handler),
                        clock: Arc::clone(&self.clock),
                        stats: Arc::clone(&stats),
                        tls_stats: Arc::clone(&tls),
                        certs: Arc::clone(&self.certs),
                        sni_gate: Arc::clone(&self.sni_gate),
                        event_sink: Some(Arc::clone(&self.sink)),
                        alt_svc_port: Arc::clone(&alt_svc_port),
                        bound: tcp_bound_tx,
                        shutdown: shutdown_rx,
                    }));
                    let stop_tx = shutdown_tx.clone();
                    // One listener owns both sockets: report bound only when
                    // both halves bound. On a partial failure stop the half
                    // that did bind so the listener fails as a whole and the
                    // status path reports `listeners.bind`.
                    tokio::spawn(async move {
                        let (tcp_bound, h3_bound) = tokio::join!(tcp_bound_rx, h3_bound_rx);
                        let both_bound = match (tcp_bound, h3_bound) {
                            (Ok(tcp), Ok(_)) => {
                                let _ = bound_tx.send(tcp);
                                true
                            }
                            _ => {
                                let _ = stop_tx.send(true);
                                false
                            }
                        };
                        let mut error = None;
                        while let Some(result) = joins.join_next().await {
                            match result {
                                Ok(Err(e)) => {
                                    error.get_or_insert(e);
                                }
                                Ok(Ok(())) => {}
                                Err(e) => {
                                    error.get_or_insert_with(|| ListenersError::bind("doh+h3", e));
                                }
                            }
                        }
                        match error {
                            Some(e) => Err(e),
                            None if both_bound => Ok(()),
                            None => Err(ListenersError::bind(
                                "doh+h3",
                                "listener exited before bind",
                            )),
                        }
                    })
                } else {
                    tokio::spawn(serve_doh(DohServeParams {
                        listener: listener.clone(),
                        limits: limits.clone(),
                        admission: Arc::clone(&self.admission),
                        handler: Arc::clone(&self.handler),
                        clock: Arc::clone(&self.clock),
                        stats: Arc::clone(&stats),
                        tls_stats: Arc::clone(&tls),
                        certs: Arc::clone(&self.certs),
                        sni_gate: Arc::clone(&self.sni_gate),
                        event_sink: Some(Arc::clone(&self.sink)),
                        alt_svc_port,
                        bound: bound_tx,
                        shutdown: shutdown_rx,
                    }))
                };
                (ListenerKind::Doh { stats, tls }, join)
            }
            Protocol::Doq => {
                let stats = Arc::new(DoqStats::default());
                let tls = Arc::new(TlsStats::default());
                let join = tokio::spawn(serve_doq(DoqServeParams {
                    listener: listener.clone(),
                    limits: limits.clone(),
                    admission: Arc::clone(&self.admission),
                    handler: Arc::clone(&self.handler),
                    clock: Arc::clone(&self.clock),
                    stats: Arc::clone(&stats),
                    tls_stats: Arc::clone(&tls),
                    certs: Arc::clone(&self.certs),
                    sni_gate: Arc::clone(&self.sni_gate),
                    event_sink: Some(Arc::clone(&self.sink)),
                    bound: bound_tx,
                    shutdown: shutdown_rx,
                }));
                (ListenerKind::Doq { stats, tls }, join)
            }
        };

        let (bound, bind_error, join) =
            match tokio::time::timeout(Duration::from_secs(2), bound_rx).await {
                Ok(Ok(addr)) => (Some(addr), None, join),
                Ok(Err(_)) => {
                    let err = match join.await {
                        Ok(Err(e)) => Some(e),
                        Ok(Ok(())) => Some(ListenersError::bind(
                            listener.address,
                            "listener exited before bind",
                        )),
                        Err(e) => Some(ListenersError::bind(listener.address, e)),
                    };
                    (None, err, tokio::spawn(async { Ok(()) }))
                }
                Err(_) => {
                    join.abort();
                    (
                        None,
                        Some(ListenersError::bind(listener.address, "bind timeout")),
                        tokio::spawn(async { Ok(()) }),
                    )
                }
            };

        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.running.insert(
            id,
            RunningListener {
                config: listener,
                bound,
                bind_error,
                shutdown: shutdown_tx,
                join,
                kind,
            },
        );
    }

    async fn stop_one(&self, id: &ListenerId) {
        let running = {
            let mut inner = self
                .inner
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            inner.running.remove(id)
        };
        if let Some(r) = running {
            let _ = r.shutdown.send(true);
            let mut join = r.join;
            if tokio::time::timeout(Duration::from_secs(2), &mut join)
                .await
                .is_err()
            {
                // Draining exceeded the reload budget; abort so the old
                // sockets are released before the replacement binds.
                join.abort();
                let _ = join.await;
            }
        }
    }
}

impl RunningListener {
    fn to_status(&self) -> ListenerStatus {
        let mut status = ListenerStatus {
            id: self.config.id.clone(),
            protocol: self.config.protocol,
            configured_address: self.config.address,
            bound: self.bound,
            error: self.bind_error.clone(),
            connections: 0,
            queries: 0,
            answered: 0,
            dropped: 0,
            rate_limited: 0,
            tls_no_cert: 0,
            tls_handshake_failures: 0,
        };
        match &self.kind {
            ListenerKind::Udp { stats } => {
                status.queries = stats.received.load(Ordering::Relaxed);
                status.answered = stats.answered.load(Ordering::Relaxed);
                status.dropped = stats.dropped_public.load(Ordering::Relaxed)
                    + stats.dropped_admission.load(Ordering::Relaxed)
                    + stats.dropped_inflight.load(Ordering::Relaxed)
                    + stats.dropped_timeout.load(Ordering::Relaxed)
                    + stats.dropped_silent.load(Ordering::Relaxed);
            }
            ListenerKind::Tcp { stats } => fill_framed(&mut status, stats),
            ListenerKind::Dot { stats, tls } => {
                fill_framed(&mut status, stats);
                fill_tls(&mut status, tls);
            }
            ListenerKind::Doh { stats, tls } => {
                status.connections = stats
                    .accepted
                    .load(Ordering::Relaxed)
                    .saturating_sub(stats.closed.load(Ordering::Relaxed));
                status.answered = stats.answered.load(Ordering::Relaxed);
                status.queries = status.answered;
                status.dropped = stats.dropped_banned.load(Ordering::Relaxed)
                    + stats.rejected_conn_cap.load(Ordering::Relaxed)
                    + stats.rejected_per_source.load(Ordering::Relaxed);
                status.rate_limited = stats.http_429.load(Ordering::Relaxed);
                fill_tls(&mut status, tls);
            }
            ListenerKind::Doq { stats, tls } => {
                status.connections = stats
                    .accepted
                    .load(Ordering::Relaxed)
                    .saturating_sub(stats.closed.load(Ordering::Relaxed));
                status.queries = stats.queries.load(Ordering::Relaxed);
                status.answered = stats.answered.load(Ordering::Relaxed);
                status.dropped = stats.dropped_banned.load(Ordering::Relaxed)
                    + stats.rejected_conn_cap.load(Ordering::Relaxed)
                    + stats.rejected_per_source.load(Ordering::Relaxed);
                status.rate_limited = stats.refused.load(Ordering::Relaxed);
                fill_tls(&mut status, tls);
            }
        }
        status
    }
}

fn fill_framed(status: &mut ListenerStatus, stats: &FramedStats) {
    status.connections = stats
        .accepted
        .load(Ordering::Relaxed)
        .saturating_sub(stats.closed.load(Ordering::Relaxed));
    status.queries = stats.queries.load(Ordering::Relaxed);
    status.answered = stats.answered.load(Ordering::Relaxed);
    status.dropped = stats.dropped_public.load(Ordering::Relaxed)
        + stats.dropped_admission.load(Ordering::Relaxed)
        + stats.rejected_conn_cap.load(Ordering::Relaxed)
        + stats.rejected_per_source.load(Ordering::Relaxed);
    status.rate_limited = stats.refused.load(Ordering::Relaxed);
}

fn fill_tls(status: &mut ListenerStatus, tls: &TlsStats) {
    status.tls_no_cert = tls.no_cert.load(Ordering::Relaxed);
    status.tls_handshake_failures =
        tls.handshake_fail.load(Ordering::Relaxed) + tls.handshake_timeouts.load(Ordering::Relaxed);
}

fn reserved_from_ddr(target: &str) -> ReservedLabels {
    let t = target.trim_matches('.');
    if t.is_empty() || t.eq_ignore_ascii_case("dns") {
        ReservedLabels::new(std::iter::empty())
    } else {
        ReservedLabels::new([t.to_ascii_lowercase()])
    }
}

/// Client-ID registry that never matches (Do53-only / FakeHandler tests).
#[derive(Debug, Default)]
pub struct EmptyClientIds;

impl ClientIdRegistry for EmptyClientIds {
    fn is_registered(&self, _client_id: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::clock::SystemClock;
    use crate::events::ChannelSink;
    use crate::handler::FakeHandler;
    use dnscraft_filtering::SetId;
    use dnscraft_policy::{
        AnswerOrigin, DecisionRecord, DecisionTimings, PolicyAnswer, ProfileId, SelectionCause,
        ViewId,
    };
    use dnscraft_proto::{Message, Name, Rcode, RecordType};

    fn dummy_answer() -> PolicyAnswer {
        let q = Message::query(1, Name::from_ascii("example.com.").unwrap(), RecordType::A);
        PolicyAnswer {
            message: Message::response_to(&q),
            ede: None,
            record: DecisionRecord {
                view_id: ViewId::new("default").unwrap(),
                profile_id: ProfileId::new("default").unwrap(),
                selection: SelectionCause::Default,
                client_id: None,
                filter_set: SetId::new("default").unwrap(),
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

    /// GL11: DDR advertises the addresses that actually bound (port 0 resolved),
    /// not the configured ones.
    #[tokio::test]
    async fn ddr_endpoints_use_bound_addresses() {
        let cfg = ListenersConfig {
            listeners: vec![ListenerConfig {
                id: ListenerId::new("lan-dot").unwrap(),
                protocol: Protocol::Dot,
                address: SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0)),
                exposure: Exposure::Local,
                h3: false,
                tls_policy: None,
            }],
            ..Default::default()
        };
        let (sink, _rx) = ChannelSink::new(4);
        let set = ListenerSet::start_with(ListenerSetParams {
            config: cfg,
            handler: Arc::new(FakeHandler::new(dummy_answer())),
            certs: None,
            sink,
            clock: Arc::new(SystemClock),
            public_domain: "example.com".into(),
            client_ids: Arc::new(EmptyClientIds),
            classify: default_classifier(),
        })
        .await
        .unwrap();

        let bound = set.status().listeners[0].bound.unwrap();
        assert_ne!(bound.port(), 0);
        {
            let ddr = set.ddr.read().unwrap_or_else(|e| e.into_inner());
            assert_eq!(ddr.endpoints.len(), 1);
            assert_eq!(ddr.endpoints[0].address, bound);
            assert_eq!(ddr.endpoints[0].address.port(), bound.port());
        }

        set.shutdown(Duration::from_secs(2)).await;
    }

    #[tokio::test]
    async fn apply_config_updates_reserved_from_ddr_target() {
        let cfg = ListenersConfig {
            ddr: crate::config::DdrConfig {
                target: "node1".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let (sink, _rx) = ChannelSink::new(4);
        let set = ListenerSet::start_with(ListenerSetParams {
            config: cfg.clone(),
            handler: Arc::new(FakeHandler::new(dummy_answer())),
            certs: None,
            sink,
            clock: Arc::new(SystemClock),
            public_domain: "example.com".into(),
            client_ids: Arc::new(EmptyClientIds),
            classify: default_classifier(),
        })
        .await
        .unwrap();

        assert!(
            set.sni_gate
                .reserved
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains("node1")
        );

        let mut next = cfg;
        next.ddr.target = "dns".into();
        set.apply_config(next).await.unwrap();

        assert!(
            !set.sni_gate
                .reserved
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .contains("node1")
        );

        set.shutdown(Duration::from_secs(2)).await;
    }
}
