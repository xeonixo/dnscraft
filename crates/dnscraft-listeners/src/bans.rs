//! Temporary ban table for public source IPs (strikes → ban).

use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::ratelimit::LruMap;

/// Why a strike was recorded (for logs / future metrics).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub enum StrikeReason {
    /// Unknown or missing Client ID on a public listener.
    UnknownClientId,
    /// Failed TLS handshake (public).
    TlsHandshake,
    /// Malformed DoH or DoQ framing.
    MalformedFraming,
}

#[derive(Clone, Debug)]
struct BanEntry {
    /// Strike timestamps still inside the window.
    strikes: Vec<SystemTime>,
    /// When set and `now < banned_until`, the source is banned.
    banned_until: Option<SystemTime>,
}

/// LRU-capped ban / strike table for public sources.
#[derive(Debug)]
pub struct BanTable {
    entries: LruMap<IpAddr, BanEntry>,
    strikes_needed: u32,
    window: Duration,
    duration: Duration,
}

impl BanTable {
    /// Creates an empty table.
    pub fn new(cap: usize, strikes_needed: u32, window: Duration, duration: Duration) -> Self {
        Self {
            entries: LruMap::new(cap),
            strikes_needed: strikes_needed.max(1),
            window,
            duration,
        }
    }

    /// Number of tracked sources.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Applies new ban parameters and LRU cap without dropping existing entries.
    ///
    /// Bans already in force keep their `banned_until`; the new strike threshold,
    /// window and duration apply to strikes recorded after this call.
    pub fn reconfigure(
        &mut self,
        cap: usize,
        strikes_needed: u32,
        window: Duration,
        duration: Duration,
    ) {
        self.strikes_needed = strikes_needed.max(1);
        self.window = window;
        self.duration = duration;
        self.entries.set_cap(cap);
    }

    /// Whether `source` is currently banned at `now`.
    pub fn is_banned(&mut self, source: IpAddr, now: SystemTime) -> bool {
        let Some(entry) = self.entries.get_mut(&source) else {
            return false;
        };
        match entry.banned_until {
            Some(until) if now < until => true,
            Some(_) => {
                entry.banned_until = None;
                false
            }
            None => false,
        }
    }

    /// Records a strike for a **public** source. May start a ban.
    pub fn strike(&mut self, source: IpAddr, _reason: StrikeReason, now: SystemTime) {
        let window = self.window;
        let needed = self.strikes_needed;
        let duration = self.duration;

        let mut entry = self.entries.take(&source).unwrap_or(BanEntry {
            strikes: Vec::new(),
            banned_until: None,
        });
        if let Some(until) = entry.banned_until
            && now < until
        {
            self.entries.insert(source, entry);
            return;
        }
        entry.banned_until = None;
        entry.strikes.push(now);
        entry
            .strikes
            .retain(|t| now.duration_since(*t).map(|d| d <= window).unwrap_or(false));
        if entry.strikes.len() as u32 >= needed {
            entry.banned_until = now.checked_add(duration);
            entry.strikes.clear();
        }
        self.entries.insert(source, entry);
    }
}
