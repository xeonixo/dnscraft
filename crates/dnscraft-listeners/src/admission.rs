//! Source classification and admission (SPEC-listeners § Source classification).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::SystemTime;

use dnscraft_policy::ClientId;

use crate::bans::{BanTable, StrikeReason};
use crate::config::{Exposure, Limits, ListenerConfig, Protocol, PublicConfig, TokenRate};
use crate::ratelimit::{LruMap, TokenBucket};

/// Private vs public client source (after `to_canonical`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

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

/// Injectable source classifier (`Admission` and SNI/path gates).
///
/// Tests may treat selected loopback addresses (e.g. `127.0.0.2`) as
/// [`SourceClass::Public`] so public-admission paths can be exercised locally.
pub type SourceClassifier = Arc<dyn Fn(IpAddr) -> SourceClass + Send + Sync>;

/// Default classifier: [`SourceClass::of`].
pub fn default_classifier() -> SourceClassifier {
    Arc::new(SourceClass::of)
}

fn is_private_source(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: Ipv4Addr) -> bool {
    // The shared helper also covers `0.0.0.0/8` and broadcast, which are not
    // private source ranges here (RFC 1918, loopback, link-local, CGNAT).
    v4.octets()[0] != 0 && !v4.is_broadcast() && dnscraft_common::net::is_private_v4(v4)
}

fn is_private_v6(v6: Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local()
}

/// Client-ID presentation state after SNI / DoH path parsing.
#[derive(Clone, Debug, PartialEq, Eq)]

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

/// Whether a public Client-ID gate (SNI / DoH path) applies.
///
/// Only `(exposure Public, source Public)` requires a registered id. A private
/// source on a public listener behaves like local (id optional, unknown ignored).
pub fn public_client_id_required(exposure: Exposure, class: SourceClass) -> bool {
    exposure == Exposure::Public && class == SourceClass::Public
}

/// Admission state: rate buckets and ban table.
pub struct Admission {
    rate_per_source: TokenRate,
    rate_per_client_id: TokenRate,
    sources: LruMap<IpAddr, TokenBucket>,
    clients: LruMap<ClientId, TokenBucket>,
    bans: BanTable,
    classify: SourceClassifier,
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Admission")
            .field("source_buckets", &self.sources.len())
            .field("client_buckets", &self.clients.len())
            .field("ban_entries", &self.bans.len())
            .finish_non_exhaustive()
    }
}

impl Admission {
    /// Builds empty tables from the validated config slices (default classifier).
    pub fn new(limits: &Limits, public: &PublicConfig) -> Self {
        Self::with_classifier(limits, public, default_classifier())
    }

    /// Like [`Self::new`] with an injectable source classifier.
    pub fn with_classifier(
        limits: &Limits,
        public: &PublicConfig,
        classify: SourceClassifier,
    ) -> Self {
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
            classify,
        }
    }

    /// Classifies `ip` with the installed classifier (after `to_canonical`).
    pub fn classify(&self, ip: IpAddr) -> SourceClass {
        (self.classify)(ip.to_canonical())
    }

    /// Applies a new limits/public config slice in place.
    ///
    /// Rate buckets are rebuilt empty (their transient token state belongs to the
    /// old rate), but the ban table is carried over: bans already in force keep
    /// their expiry, and the new ban params apply to new strikes only.
    pub fn reconfigure(&mut self, limits: &Limits, public: &PublicConfig) {
        self.rate_per_source = limits.rate_per_source;
        self.rate_per_client_id = limits.rate_per_client_id;
        let cap = public.max_tracked_sources as usize;
        self.sources = LruMap::new(cap);
        self.clients = LruMap::new(cap);
        self.bans.reconfigure(
            cap,
            public.ban_strikes,
            public.ban_window,
            public.ban_duration,
        );
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

    /// Whether a **public** source is currently banned (private → false).
    pub fn is_banned(&mut self, source: IpAddr, now: SystemTime) -> bool {
        let source = source.to_canonical();
        if self.classify(source) != SourceClass::Public {
            return false;
        }
        self.bans.is_banned(source, now)
    }

    /// Currently banned sources with their ban expiry.
    pub fn banned_sources(&self, now: SystemTime) -> Vec<(IpAddr, SystemTime)> {
        self.bans.banned(now)
    }

    /// Lifts the ban on `source`; `true` when it was banned.
    pub fn unban(&mut self, source: IpAddr, now: SystemTime) -> bool {
        self.bans.unban(source.to_canonical(), now)
    }

    /// Records a ban strike for a public source (no-op for private sources).
    pub fn strike(&mut self, source: IpAddr, reason: StrikeReason, now: SystemTime) {
        let source = source.to_canonical();
        if self.classify(source) != SourceClass::Public {
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
        let class = self.classify(source);
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

        if public_client_id_required(listener.exposure, class) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn public_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))
    }

    #[test]
    fn reconfigure_preserves_ban_table_and_applies_new_params_to_new_strikes() {
        let limits = Limits::default();
        let public = PublicConfig {
            ban_strikes: 1,
            ban_window: Duration::from_secs(60),
            ban_duration: Duration::from_secs(900),
            ..PublicConfig::default()
        };
        let mut adm = Admission::new(&limits, &public);
        let now = SystemTime::UNIX_EPOCH;
        let src = public_ip();

        adm.strike(src, StrikeReason::UnknownClientId, now);
        assert!(adm.is_banned(src, now), "single strike should ban");

        // Reconfigure with different ban params and admission rates.
        let limits2 = {
            let mut l = limits.clone();
            l.rate_per_source.per_second = 9999;
            l.rate_per_source.burst = 19998;
            l
        };
        let public2 = PublicConfig {
            ban_strikes: 5,
            ban_window: Duration::from_secs(120),
            ban_duration: Duration::from_secs(1800),
            ..PublicConfig::default()
        };
        adm.reconfigure(&limits2, &public2);

        // The existing ban survives with its expiry.
        assert!(adm.is_banned(src, now), "ban must survive reconfigure");
        assert_eq!(adm.ban_entry_count(), 1);

        // New ban params apply to new strikes: a fresh source needs 5, not 1.
        let src2 = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
        adm.strike(src2, StrikeReason::UnknownClientId, now);
        assert!(
            !adm.is_banned(src2, now),
            "new ban_strikes=5 must apply to new strikes"
        );
    }
}
