//! Source classification and admission (SPEC-listeners § Source classification).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

use dnscraft_policy::ClientId;

use crate::bans::{BanTable, StrikeReason};
use crate::config::{Exposure, Limits, ListenerConfig, Protocol, PublicConfig, TokenRate};
use crate::ratelimit::{LruMap, TokenBucket};

/// Private vs public client source (after `to_canonical`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SourceClass {
    /// RFC 1918, loopback, link-local, ULA, CGNAT (and IPv4-mapped forms).
    Private,
    /// Everything else.
    Public,
}

impl SourceClass {
    /// Classifies `ip`. IPv4-mapped addresses are classified by their IPv4 part.
    pub fn of(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
        if is_private_source(ip) {
            Self::Private
        } else {
            Self::Public
        }
    }
}

fn is_private_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    v4.is_private() || v4.is_loopback() || v4.is_link_local() || is_cgnat(v4)
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local()
}

fn is_cgnat(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

/// Client-ID presentation state after SNI / DoH path parsing.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClientIdState {
    /// No Client ID on the request.
    Absent,
    /// Registered in the policy snapshot.
    Registered(ClientId),
    /// Present but not registered.
    Unknown,
}

/// Result of [`Admission::check`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AdmitDecision {
    /// Proceed to message handling.
    Admit,
    /// Drop silently (UDP) / close without a DNS answer (TCP).
    Drop {
        /// Stable `listeners.*` code.
        code: &'static str,
    },
    /// Answer with REFUSED / HTTP 429 (transport-specific).
    Refuse {
        /// Stable `listeners.*` code.
        code: &'static str,
    },
}

/// Admission state: rate buckets and ban table.
#[derive(Debug)]
pub struct Admission {
    rate_per_source: TokenRate,
    rate_per_client_id: TokenRate,
    sources: LruMap<IpAddr, TokenBucket>,
    clients: LruMap<ClientId, TokenBucket>,
    bans: BanTable,
}

impl Admission {
    /// Builds empty tables from the validated config slices.
    pub fn new(limits: &Limits, public: &PublicConfig) -> Self {
        let cap = public.max_tracked_sources as usize;
        Self {
            rate_per_source: limits.rate_per_source,
            rate_per_client_id: limits.rate_per_client_id,
            sources: LruMap::new(cap),
            clients: LruMap::new(cap),
            bans: BanTable::new(
                cap,
                public.ban_strikes,
                public.ban_window,
                public.ban_duration,
            ),
        }
    }

    /// Number of tracked source rate buckets (tests / status).
    pub fn source_bucket_count(&self) -> usize {
        self.sources.len()
    }

    /// Number of tracked Client-ID rate buckets.
    pub fn client_bucket_count(&self) -> usize {
        self.clients.len()
    }

    /// Number of tracked ban/strike entries.
    pub fn ban_entry_count(&self) -> usize {
        self.bans.len()
    }

    /// Records a ban strike for a public source (no-op for private sources).
    pub fn strike(&mut self, source: IpAddr, reason: StrikeReason, now: SystemTime) {
        let source = source.to_canonical();
        if SourceClass::of(source) != SourceClass::Public {
            return;
        }
        self.bans.strike(source, reason, now);
    }

    /// Admission check for one query / connection attempt.
    ///
    /// Order: ban → public Do53 → public-listener Client ID → rate (source) →
    /// rate (Client ID for public sources).
    pub fn check(
        &mut self,
        listener: &ListenerConfig,
        source: IpAddr,
        client_id: &ClientIdState,
        now: SystemTime,
    ) -> AdmitDecision {
        let source = source.to_canonical();
        let class = SourceClass::of(source);
        let proto = listener.protocol;

        if class == SourceClass::Public && self.bans.is_banned(source, now) {
            // Spec: close immediately (no DNS answer on any transport).
            return AdmitDecision::Drop {
                code: "listeners.banned",
            };
        }

        if class == SourceClass::Public && matches!(proto, Protocol::Udp53 | Protocol::Tcp53) {
            return AdmitDecision::Drop {
                code: "listeners.admission.public_do53",
            };
        }

        if listener.exposure == Exposure::Public && class == SourceClass::Public {
            match client_id {
                ClientIdState::Registered(_) => {}
                ClientIdState::Absent | ClientIdState::Unknown => {
                    return AdmitDecision::Refuse {
                        code: "listeners.admission.unknown_client_id",
                    };
                }
            }
        }

        if !self.take_source(source, now) {
            return drop_or_refuse(proto, "listeners.rate_limited");
        }

        if class == SourceClass::Public
            && let ClientIdState::Registered(id) = client_id
            && !self.take_client(id, now)
        {
            return drop_or_refuse(proto, "listeners.rate_limited");
        }

        AdmitDecision::Admit
    }

    fn take_source(&mut self, source: IpAddr, now: SystemTime) -> bool {
        if let Some(bucket) = self.sources.get_mut(&source) {
            return bucket.try_take(now);
        }
        let mut bucket = TokenBucket::new(self.rate_per_source, now);
        let ok = bucket.try_take(now);
        self.sources.insert(source, bucket);
        ok
    }

    fn take_client(&mut self, id: &ClientId, now: SystemTime) -> bool {
        if let Some(bucket) = self.clients.get_mut(id) {
            return bucket.try_take(now);
        }
        let mut bucket = TokenBucket::new(self.rate_per_client_id, now);
        let ok = bucket.try_take(now);
        self.clients.insert(id.clone(), bucket);
        ok
    }
}

fn drop_or_refuse(proto: Protocol, code: &'static str) -> AdmitDecision {
    match proto {
        Protocol::Udp53 => AdmitDecision::Drop { code },
        Protocol::Tcp53 | Protocol::Dot | Protocol::Doh | Protocol::Doq => {
            AdmitDecision::Refuse { code }
        }
    }
}
