//! Positive and negative answer cache (RFC 2308).
//!
//! The key is the question: owner name, type and class. The client's DO bit
//! is not part of the key. The stored message keeps its DNSSEC records, and
//! the resolver strips them on the way out when DO is clear (RFC 4035
//! section 3.2.1), the same as a fresh answer.
//!
//! Resolutions made with the CD bit are not stored. Those skip validation,
//! and caching them would let a later validating lookup replay unchecked
//! data. A CD lookup may still be answered from an entry stored by a
//! validating lookup: that data was checked. `Bogus` results, which the
//! resolver serves as `SERVFAIL`, are not cached.
//!
//! A negative answer (NXDOMAIN, or NODATA as NOERROR without a final RRset
//! for the query type — including a CNAME/DNAME chain that ends that way) is
//! kept for the minimum of the SOA record's TTL and its MINIMUM field
//! (RFC 2308 section 3), then further limited by any TTLs in the answer
//! chain, then clamped. A positive answer uses the lowest TTL in the answer
//! section. The result is clamped to `[ttl_min, ttl_max]`. A clamped TTL of
//! zero is not stored.
//!
//! Expiry uses the resolver's monotonic clock. An expired entry is a miss.
//! It stays in the map so serve-stale (Task 13) can still find it, until a
//! flush or eviction removes it. Looking up an expired entry does not mark
//! it recently used.
//!
//! Each entry is charged the compressed wire length of the stored message
//! plus [`ENTRY_OVERHEAD`] bytes for the key, DNSSEC status and bookkeeping.
//! That estimates retained memory; it is not an allocator measurement.
//! Least-recently-used entries are dropped until the total fits the budget.
//! An entry larger than the budget is not kept.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use dnscraft_proto::{Class, Message, Name, RData, Rcode, Record, RecordType};

use crate::config::ResolverConfig;
use crate::types::{Answer, AnswerSource, DnssecStatus, ExtendedError, FlushScope, Query};

/// Bytes added to the wire length for the key, status and map node.
///
/// Over-counting evicts early, which keeps the cache inside its budget.
const ENTRY_OVERHEAD: usize = 256;

/// One mebibyte, the unit of [`ResolverConfig::cache_size_mb`].
const MIB: u64 = 1024 * 1024;

/// Question that identifies a cache entry. Name equality ignores case.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Key {
    name: Name,
    qtype: RecordType,
    qclass: Class,
}

impl From<&Query> for Key {
    fn from(query: &Query) -> Self {
        Self {
            name: query.name.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
        }
    }
}

/// A stored answer. Record TTLs inside `message` are the originals; a hit
/// rewrites them to the time left on `expires_at`.
#[derive(Debug)]
struct Entry {
    message: Message,
    dnssec: DnssecStatus,
    ede: Option<ExtendedError>,
    /// Clamped lifetime, in seconds.
    ttl: u32,
    expires_at: Instant,
    /// Bytes charged against the budget.
    size: usize,
    /// Bumps on use. Higher means more recently used.
    last_used: u64,
}

#[derive(Debug)]
struct Inner {
    map: HashMap<Key, Entry>,
    /// Next [`Entry::last_used`] stamp. Stamps are unique.
    clock: u64,
    used: usize,
    budget: usize,
}

/// Inclusive TTL clamp, in seconds, applied when an answer is stored.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TtlClamp {
    /// Lowest stored TTL. Shorter values are raised to this.
    pub min: u32,
    /// Highest stored TTL. Longer values are lowered to this.
    pub max: u32,
}

/// In-memory answer cache. Shared by concurrent lookups; the lock is not
/// held across recursion.
#[derive(Debug)]
pub(crate) struct Cache {
    inner: Mutex<Inner>,
}

impl Cache {
    pub(crate) fn new(budget: usize) -> Self {
        Self {
            inner: Mutex::new(Inner {
                map: HashMap::new(),
                clock: 0,
                used: 0,
                budget,
            }),
        }
    }

    /// Fresh hit, with record TTLs rewritten to the remaining lifetime.
    /// `None` when the question is absent or expired.
    pub(crate) fn lookup(&self, query: &Query, now: Instant) -> Option<Answer> {
        let mut inner = lock(&self.inner);
        let key = Key::from(query);
        let (mut message, dnssec, ede, ttl) = {
            let entry = inner.map.get(&key)?;
            if now >= entry.expires_at {
                return None;
            }
            let ttl = remaining_ttl(entry.expires_at, now, entry.ttl);
            (entry.message.clone(), entry.dnssec, entry.ede.clone(), ttl)
        };
        inner.clock = inner.clock.saturating_add(1);
        let stamp = inner.clock;
        if let Some(entry) = inner.map.get_mut(&key) {
            entry.last_used = stamp;
        }
        drop(inner);
        set_ttls(&mut message, ttl);
        message.header.ad = dnssec == DnssecStatus::Secure;
        Some(Answer {
            message,
            dnssec,
            source: AnswerSource::Cache,
            ede,
        })
    }

    /// Stores `message` when it is a cacheable positive or negative answer.
    ///
    /// Returns the clamped TTL, including when the new entry was immediately
    /// evicted for being over budget, so the caller can publish that TTL.
    /// `None` means the answer is not cached and its TTLs should be left
    /// alone.
    pub(crate) fn store(
        &self,
        query: &Query,
        message: &Message,
        dnssec: DnssecStatus,
        ede: Option<ExtendedError>,
        now: Instant,
        clamp: TtlClamp,
    ) -> Option<u32> {
        let ttl = cache_ttl(query, message, clamp.min, clamp.max)?;
        let expires_at = now.checked_add(Duration::from_secs(u64::from(ttl)))?;
        let stored = message.clone();
        let size = entry_size(&stored);
        tracing::debug!(
            qname = %query.name,
            qtype = %query.qtype,
            ttl,
            size,
            "caching answer"
        );
        let key = Key::from(query);
        let mut inner = lock(&self.inner);
        if let Some(old) = inner.map.remove(&key) {
            inner.used = inner.used.saturating_sub(old.size);
        }
        inner.clock = inner.clock.saturating_add(1);
        let last_used = inner.clock;
        inner.used = inner.used.saturating_add(size);
        inner.map.insert(
            key,
            Entry {
                message: stored,
                dnssec,
                ede,
                ttl,
                expires_at,
                size,
                last_used,
            },
        );
        evict(&mut inner);
        Some(ttl)
    }

    pub(crate) fn flush(&self, scope: &FlushScope) {
        let mut inner = lock(&self.inner);
        match scope {
            FlushScope::All => {
                inner.map.clear();
                inner.used = 0;
            }
            FlushScope::Domain(name) => {
                let keys: Vec<Key> = inner
                    .map
                    .keys()
                    .filter(|key| name.zone_of(&key.name))
                    .cloned()
                    .collect();
                for key in keys {
                    if let Some(entry) = inner.map.remove(&key) {
                        inner.used = inner.used.saturating_sub(entry.size);
                    }
                }
            }
        }
    }

    pub(crate) fn bytes_used(&self) -> usize {
        lock(&self.inner).used
    }
}

/// Cache budget in bytes. [`ResolverConfig::cache_capacity_bytes`] wins over
/// the mebibyte setting so tests can force eviction.
pub(crate) fn budget_bytes(config: &ResolverConfig) -> usize {
    let bytes = match config.cache_capacity_bytes {
        Some(exact) => exact,
        None => config.cache_size_mb.saturating_mul(MIB),
    };
    usize::try_from(bytes).unwrap_or(usize::MAX)
}

/// Writes `ttl` into every record of `message`.
pub(crate) fn set_ttls(message: &mut Message, ttl: u32) {
    for section in [
        &mut message.answers,
        &mut message.authorities,
        &mut message.additionals,
    ] {
        for record in section {
            record.ttl = ttl;
        }
    }
}

fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    inner.lock().unwrap_or_else(PoisonError::into_inner)
}

fn evict(inner: &mut Inner) {
    let before = inner.map.len();
    while inner.used > inner.budget && !inner.map.is_empty() {
        let Some(victim) = inner
            .map
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        else {
            break;
        };
        match inner.map.remove(&victim) {
            Some(entry) => inner.used = inner.used.saturating_sub(entry.size),
            None => break,
        }
    }
    if inner.map.is_empty() {
        inner.used = 0;
    }
    let removed = before.saturating_sub(inner.map.len());
    if removed > 0 {
        tracing::debug!(
            removed,
            bytes = inner.used,
            budget = inner.budget,
            "cache eviction"
        );
    }
}

fn entry_size(message: &Message) -> usize {
    message_wire_len(message)
        .saturating_add(ENTRY_OVERHEAD)
        .max(1)
}

fn message_wire_len(message: &Message) -> usize {
    match message.encode() {
        Ok(bytes) => bytes.len(),
        Err(_) => {
            let records =
                message.answers.len() + message.authorities.len() + message.additionals.len();
            12 + message.questions.len().saturating_mul(64) + records.saturating_mul(128)
        }
    }
}

/// Clamped cache lifetime, or `None` when the answer must not be stored.
fn cache_ttl(query: &Query, message: &Message, ttl_min: u32, ttl_max: u32) -> Option<u32> {
    let negative = match message.rcode() {
        Rcode::NXDOMAIN => true,
        Rcode::NOERROR => is_nodata(query, message),
        _ => return None,
    };
    let raw = if negative {
        let soa = soa_negative_ttl(message)?;
        match min_ttl(&message.answers) {
            Some(answer) => soa.min(answer),
            None => soa,
        }
    } else {
        min_ttl(&message.answers)?
    };
    let ttl = clamp_ttl(raw, ttl_min, ttl_max);
    (ttl > 0).then_some(ttl)
}

/// NODATA: empty answers, or a CNAME/DNAME chain that ends without an RRset
/// for the query type (iterate keeps the links and the final SOA).
fn is_nodata(query: &Query, message: &Message) -> bool {
    if message.answers.is_empty() {
        return true;
    }
    let has_final = message
        .answers
        .iter()
        .any(|r| matches_qtype(query.qtype, r));
    !has_final && soa_negative_ttl(message).is_some()
}

fn matches_qtype(qtype: RecordType, record: &Record) -> bool {
    if record.rtype == RecordType::RRSIG {
        return false;
    }
    match qtype {
        RecordType::ANY => !matches!(record.rtype, RecordType::CNAME | RecordType::DNAME),
        _ => record.rtype == qtype,
    }
}

/// `min(SOA TTL, SOA MINIMUM)` (RFC 2308 section 3).
fn soa_negative_ttl(message: &Message) -> Option<u32> {
    message
        .authorities
        .iter()
        .chain(message.answers.iter())
        .find_map(|record| match &record.rdata {
            RData::SOA { minimum, .. } => Some(record.ttl.min(*minimum)),
            _ => None,
        })
}

fn min_ttl(records: &[Record]) -> Option<u32> {
    records.iter().map(|record| record.ttl).min()
}

/// Clamps into the closed interval between `min` and `max`.
///
/// The bounds are ordered so a swapped configuration cannot panic.
fn clamp_ttl(ttl: u32, min: u32, max: u32) -> u32 {
    let (lo, hi) = if min <= max { (min, max) } else { (max, min) };
    ttl.clamp(lo, hi)
}

fn remaining_ttl(expires_at: Instant, now: Instant, clamped: u32) -> u32 {
    let secs = expires_at.saturating_duration_since(now).as_secs();
    u32::try_from(secs).unwrap_or(u32::MAX).min(clamped)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dnscraft_proto::{Header, Question};

    use super::*;

    fn name(text: &str) -> Name {
        Name::from_ascii(text).unwrap()
    }

    fn query(owner: &str, qtype: RecordType) -> Query {
        Query {
            name: name(owner),
            qtype,
            qclass: Class::IN,
        }
    }

    fn message(
        owner: &str,
        rcode: Rcode,
        answers: Vec<Record>,
        authorities: Vec<Record>,
    ) -> Message {
        Message {
            header: Header {
                qr: true,
                ra: true,
                rcode_low: rcode.low(),
                ..Header::default()
            },
            questions: vec![Question {
                name: name(owner),
                qtype: RecordType::A,
                qclass: Class::IN,
            }],
            answers,
            authorities,
            additionals: Vec::new(),
            edns: None,
        }
    }

    fn a_record(owner: &str, ttl: u32) -> Record {
        Record {
            name: name(owner),
            rtype: RecordType::A,
            class: Class::IN,
            ttl,
            rdata: RData::A(Ipv4Addr::new(192, 0, 2, 1)),
        }
    }

    fn cname_record(owner: &str, target: &str, ttl: u32) -> Record {
        Record {
            name: name(owner),
            rtype: RecordType::CNAME,
            class: Class::IN,
            ttl,
            rdata: RData::CNAME(name(target)),
        }
    }

    fn soa(ttl: u32, minimum: u32) -> Record {
        let apex = name("example.test.");
        Record {
            name: apex.clone(),
            rtype: RecordType::SOA,
            class: Class::IN,
            ttl,
            rdata: RData::SOA {
                mname: apex,
                rname: name("hostmaster.example.test."),
                serial: 1,
                refresh: 3600,
                retry: 600,
                expire: 86_400,
                minimum,
            },
        }
    }

    fn put(
        cache: &Cache,
        query: &Query,
        message: &Message,
        now: Instant,
        ttl_min: u32,
        ttl_max: u32,
    ) -> Option<u32> {
        cache.store(
            query,
            message,
            DnssecStatus::Indeterminate,
            None,
            now,
            TtlClamp {
                min: ttl_min,
                max: ttl_max,
            },
        )
    }

    #[test]
    fn positive_ttl_is_the_minimum_answer_ttl_then_clamped() {
        let now = Instant::now();
        let owner = "www.example.test.";
        let mut msg = message(
            owner,
            Rcode::NOERROR,
            vec![a_record(owner, 300), a_record(owner, 100)],
            vec![soa(5, 5)],
        );
        msg.additionals.push(a_record("ns.example.test.", 1));
        let q = query(owner, RecordType::A);
        let cache = Cache::new(usize::MAX);

        assert_eq!(put(&cache, &q, &msg, now, 0, 86_400), Some(100));
        assert_eq!(put(&cache, &q, &msg, now, 0, 30), Some(30));
        assert_eq!(put(&cache, &q, &msg, now, 150, 86_400), Some(150));

        let hit = cache.lookup(&q, now).unwrap();
        assert_eq!(hit.source, AnswerSource::Cache);
        assert_eq!(hit.message.answers[0].ttl, 150);
        let later = cache.lookup(&q, now + Duration::from_secs(40)).unwrap();
        assert_eq!(later.message.answers[0].ttl, 110);
    }

    #[test]
    fn negative_ttl_is_min_of_soa_ttl_and_minimum() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let q = query("nope.example.test.", RecordType::A);
        let from_minimum = message(
            "nope.example.test.",
            Rcode::NXDOMAIN,
            vec![],
            vec![soa(300, 60)],
        );
        assert_eq!(put(&cache, &q, &from_minimum, now, 0, 86_400), Some(60));

        let from_record = message(
            "gone.example.test.",
            Rcode::NXDOMAIN,
            vec![],
            vec![soa(30, 60)],
        );
        let q2 = query("gone.example.test.", RecordType::A);
        assert_eq!(put(&cache, &q2, &from_record, now, 0, 86_400), Some(30));

        let nodata = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![],
            vec![soa(300, 60)],
        );
        let q3 = query("www.example.test.", RecordType::MX);
        assert_eq!(put(&cache, &q3, &nodata, now, 0, 86_400), Some(60));

        let chained_nx = message(
            "alias.example.test.",
            Rcode::NXDOMAIN,
            vec![cname_record(
                "alias.example.test.",
                "nope.example.test.",
                40,
            )],
            vec![soa(300, 60)],
        );
        let q4 = query("alias.example.test.", RecordType::A);
        assert_eq!(put(&cache, &q4, &chained_nx, now, 0, 86_400), Some(40));

        // CNAME → NODATA: answers hold only the link; SOA MINIMUM still wins.
        let chained_nodata = message(
            "alias.example.test.",
            Rcode::NOERROR,
            vec![cname_record("alias.example.test.", "www.example.test.", 40)],
            vec![soa(300, 60)],
        );
        assert_eq!(put(&cache, &q4, &chained_nodata, now, 0, 86_400), Some(40));
        let short_cname = message(
            "alias.example.test.",
            Rcode::NOERROR,
            vec![cname_record(
                "alias.example.test.",
                "www.example.test.",
                120,
            )],
            vec![soa(300, 60)],
        );
        assert_eq!(put(&cache, &q4, &short_cname, now, 0, 86_400), Some(60));

        let no_soa = message("missing.example.test.", Rcode::NXDOMAIN, vec![], vec![]);
        let q5 = query("missing.example.test.", RecordType::A);
        assert_eq!(put(&cache, &q5, &no_soa, now, 0, 86_400), None);
    }

    #[test]
    fn servfail_and_zero_ttl_are_not_stored() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let q = query("www.example.test.", RecordType::A);
        let servfail = message(
            "www.example.test.",
            Rcode::SERVFAIL,
            vec![a_record("www.example.test.", 30)],
            vec![],
        );
        assert_eq!(put(&cache, &q, &servfail, now, 0, 86_400), None);
        let zero = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![a_record("www.example.test.", 0)],
            vec![],
        );
        assert_eq!(put(&cache, &q, &zero, now, 0, 86_400), None);
        assert_eq!(cache.bytes_used(), 0);
        assert_eq!(put(&cache, &q, &zero, now, 5, 86_400), Some(5));
    }

    #[test]
    fn expired_entry_is_a_miss_and_still_occupies_the_budget() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let q = query("www.example.test.", RecordType::A);
        let msg = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![a_record("www.example.test.", 30)],
            vec![],
        );
        assert_eq!(put(&cache, &q, &msg, now, 0, 86_400), Some(30));
        let used = cache.bytes_used();
        assert!(cache.lookup(&q, now + Duration::from_secs(29)).is_some());
        assert!(cache.lookup(&q, now + Duration::from_secs(30)).is_none());
        assert_eq!(cache.bytes_used(), used);
    }

    #[test]
    fn lru_evicts_the_entry_that_was_not_used() {
        let now = Instant::now();
        let names = ["a.example.", "b.example.", "c.example."];
        let items: Vec<(Query, Message)> = names
            .iter()
            .map(|owner| {
                (
                    query(owner, RecordType::A),
                    message(owner, Rcode::NOERROR, vec![a_record(owner, 30)], vec![]),
                )
            })
            .collect();
        let big = Cache::new(usize::MAX);
        put(&big, &items[0].0, &items[0].1, now, 0, 86_400);
        let one = big.bytes_used();
        let cache = Cache::new(one * 2);
        put(&cache, &items[0].0, &items[0].1, now, 0, 86_400);
        put(&cache, &items[1].0, &items[1].1, now, 0, 86_400);
        assert!(cache.lookup(&items[0].0, now).is_some());
        put(&cache, &items[2].0, &items[2].1, now, 0, 86_400);
        assert!(cache.lookup(&items[1].0, now).is_none());
        assert!(cache.lookup(&items[0].0, now).is_some());
        assert!(cache.lookup(&items[2].0, now).is_some());
        assert_eq!(cache.bytes_used(), one * 2);

        let tiny = Cache::new(one - 1);
        assert!(put(&tiny, &items[0].0, &items[0].1, now, 0, 86_400).is_some());
        assert_eq!(tiny.bytes_used(), 0);
        assert!(tiny.lookup(&items[0].0, now).is_none());
    }

    #[test]
    fn flush_domain_removes_the_name_and_names_below_it() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        for owner in [
            "www.example.test.",
            "sub.www.example.test.",
            "mail.example.test.",
        ] {
            let q = query(owner, RecordType::A);
            let msg = message(owner, Rcode::NOERROR, vec![a_record(owner, 30)], vec![]);
            put(&cache, &q, &msg, now, 0, 86_400);
        }
        cache.flush(&FlushScope::Domain(name("WWW.EXAMPLE.TEST.")));
        assert!(
            cache
                .lookup(&query("www.example.test.", RecordType::A), now)
                .is_none()
        );
        assert!(
            cache
                .lookup(&query("sub.www.example.test.", RecordType::A), now)
                .is_none()
        );
        assert!(
            cache
                .lookup(&query("mail.example.test.", RecordType::A), now)
                .is_some()
        );

        cache.flush(&FlushScope::All);
        assert_eq!(cache.bytes_used(), 0);
        assert!(
            cache
                .lookup(&query("mail.example.test.", RecordType::A), now)
                .is_none()
        );
    }

    #[test]
    fn key_ignores_case_and_includes_qtype() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let msg = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![a_record("www.example.test.", 30)],
            vec![],
        );
        put(
            &cache,
            &query("www.example.test.", RecordType::A),
            &msg,
            now,
            0,
            86_400,
        );
        assert!(
            cache
                .lookup(&query("WWW.EXAMPLE.TEST.", RecordType::A), now)
                .is_some()
        );
        assert!(
            cache
                .lookup(&query("www.example.test.", RecordType::AAAA), now)
                .is_none()
        );
    }

    #[test]
    fn lookup_returns_the_cached_dnssec_status() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let q = query("www.example.test.", RecordType::A);
        let msg = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![a_record("www.example.test.", 30)],
            vec![],
        );
        let ede = ExtendedError {
            code: 27,
            text: Some("dnssec.nsec3_iterations".to_owned()),
        };
        cache.store(
            &q,
            &msg,
            DnssecStatus::Insecure,
            Some(ede.clone()),
            now,
            TtlClamp {
                min: 0,
                max: 86_400,
            },
        );
        let hit = cache.lookup(&q, now).unwrap();
        assert_eq!(hit.dnssec, DnssecStatus::Insecure);
        assert_eq!(hit.ede, Some(ede));
        assert!(!hit.message.header.ad);

        cache.store(
            &q,
            &msg,
            DnssecStatus::Secure,
            None,
            now,
            TtlClamp {
                min: 0,
                max: 86_400,
            },
        );
        let secure = cache.lookup(&q, now).unwrap();
        assert_eq!(secure.dnssec, DnssecStatus::Secure);
        assert!(secure.message.header.ad);
        assert_eq!(secure.ede, None);
    }

    #[test]
    fn replacing_an_entry_does_not_double_charge() {
        let now = Instant::now();
        let cache = Cache::new(usize::MAX);
        let q = query("www.example.test.", RecordType::A);
        let msg = message(
            "www.example.test.",
            Rcode::NOERROR,
            vec![a_record("www.example.test.", 30)],
            vec![],
        );
        put(&cache, &q, &msg, now, 0, 86_400);
        let once = cache.bytes_used();
        put(&cache, &q, &msg, now, 0, 86_400);
        assert_eq!(cache.bytes_used(), once);
    }
}
