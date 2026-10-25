//! Coalescing of identical in-flight resolutions.
//!
//! A cache miss joins a resolution that is already running for the same
//! question instead of starting another one. The key is the cache key
//! (name, type, class) plus the CD bit. CD skips validation, so a CD lookup
//! must not satisfy a waiter that asked to be validated, and a validated
//! answer must not be thrown away for a CD caller that shares its flight.
//! The DO bit is not part of the key: every waiter receives the full answer
//! and strips DNSSEC records itself when its own DO bit is clear.
//!
//! The resolution runs in its own spawned task, not inline in the first
//! caller's future. Every caller, the first included, waits for the published
//! outcome like a follower, so cancelling any one caller (a client that gave
//! up) never disturbs the others and never fabricates an error for them.
//!
//! The entry is removed when the resolution finishes, so a later miss starts
//! a new one. Waiters all observe that same outcome. If the spawned task
//! itself is lost (panic, runtime shutdown), dropping its [`Leader`] still
//! unblocks the waiters and frees the key.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dnscraft_proto::{Class, Name, RecordType};
use tokio::sync::{Notify, oneshot};

use crate::error::ResolveError;
use crate::types::{Answer, Query};

/// Question plus CD, the unit of coalescing.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    name: Name,
    qtype: RecordType,
    qclass: Class,
    checking_disabled: bool,
}

impl Key {
    pub(crate) fn new(query: &Query, checking_disabled: bool) -> Self {
        Self {
            name: query.name.clone(),
            qtype: query.qtype,
            qclass: query.qclass,
            checking_disabled,
        }
    }
}

/// Shared table of resolutions that have not finished yet.
#[derive(Clone, Debug)]
pub(crate) struct Inflight {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    flights: Mutex<HashMap<Key, Arc<Flight>>>,
    /// Flights currently in the map.
    active: AtomicUsize,
    /// Signalled with `notify_waiters` when `active` drops to zero. Waiters
    /// must enable their `notified()` future before checking the counter.
    idle: Notify,
}

#[derive(Debug)]
struct Flight {
    state: Mutex<FlightState>,
}

#[derive(Debug)]
struct FlightState {
    result: Option<Result<Answer, ResolveError>>,
    waiters: Vec<oneshot::Sender<Result<Answer, ResolveError>>>,
}

/// The task that runs the resolution. Completing or dropping it publishes
/// the outcome and removes the flight.
pub(crate) struct Leader {
    inflight: Inflight,
    key: Key,
    flight: Arc<Flight>,
    done: bool,
}

enum Admission {
    Lead(Leader),
    Follow(Arc<Flight>),
}

impl Inflight {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                flights: Mutex::new(HashMap::new()),
                active: AtomicUsize::new(0),
                idle: Notify::new(),
            }),
        }
    }

    /// Spawns `fut` when `key` is not already in flight, and waits for the
    /// outcome of the resolution for `key` either way.
    ///
    /// The spawned task owns the [`Leader`] and always publishes the real
    /// result, even when the caller that started it is dropped.
    pub(crate) async fn dedup<Fut>(&self, key: Key, fut: Fut) -> Result<Answer, ResolveError>
    where
        Fut: Future<Output = Result<Answer, ResolveError>> + Send + 'static,
    {
        let name = key.name.clone();
        let flight = match self.admit(key) {
            Admission::Lead(leader) => {
                let flight = Arc::clone(&leader.flight);
                let task = tokio::spawn(async move {
                    let result = fut.await;
                    leader.complete(result);
                });
                drop(task);
                flight
            }
            Admission::Follow(flight) => {
                tracing::debug!(qname = %name, "joining in-flight resolution");
                flight
            }
        };
        flight.recv(name).await
    }

    /// Starts a flight for `key` when none exists.
    ///
    /// `None` means a resolution for `key` is already running. The caller
    /// does not join it: prefetch uses this so a cache hit is never blocked
    /// on a refresh that some other task already started.
    pub(crate) fn try_lead(&self, key: Key) -> Option<Leader> {
        match self.admit(key) {
            Admission::Lead(leader) => Some(leader),
            Admission::Follow(_) => None,
        }
    }

    /// Resolves once no flight is left. Returns immediately when already idle.
    pub(crate) async fn wait_idle(&self) {
        loop {
            // Register for the wake-up before re-checking the counter, so a
            // flight that finishes between the check and the await still
            // wakes this task (`notify_waiters` stores no permit).
            let notified = self.inner.idle.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.active.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    fn admit(&self, key: Key) -> Admission {
        let mut flights = lock(&self.inner.flights);
        if let Some(flight) = flights.get(&key) {
            return Admission::Follow(Arc::clone(flight));
        }
        let flight = Arc::new(Flight::new());
        flights.insert(key.clone(), Arc::clone(&flight));
        self.inner.active.fetch_add(1, Ordering::Release);
        drop(flights);
        Admission::Lead(Leader {
            inflight: self.clone(),
            key,
            flight,
            done: false,
        })
    }

    fn remove(&self, key: &Key, flight: &Arc<Flight>) {
        let mut flights = lock(&self.inner.flights);
        let same = flights
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight));
        if same {
            flights.remove(key);
        }
        drop(flights);
        if !same {
            return;
        }
        // The previous value was 1, so the map is empty of this flight and
        // the counter is now zero when no other flight remains.
        if self.inner.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.idle.notify_waiters();
        }
    }
}

impl Leader {
    pub(crate) fn complete(mut self, result: Result<Answer, ResolveError>) {
        self.finish(result);
    }

    fn finish(&mut self, result: Result<Answer, ResolveError>) {
        if self.done {
            return;
        }
        self.done = true;
        self.flight.publish(result);
        self.inflight.remove(&self.key, &self.flight);
    }
}

impl Drop for Leader {
    fn drop(&mut self) {
        if self.done {
            return;
        }
        // The leader task was cancelled before it published. Waiters must
        // not stay parked, and the key must be free for the next miss.
        tracing::debug!(qname = %self.key.name, "in-flight resolution dropped");
        let name = self.key.name.clone();
        self.finish(Err(ResolveError::Unreachable { zone: name }));
    }
}

impl Flight {
    fn new() -> Self {
        Self {
            state: Mutex::new(FlightState {
                result: None,
                waiters: Vec::new(),
            }),
        }
    }

    fn publish(&self, result: Result<Answer, ResolveError>) {
        let waiters = {
            let mut state = lock(&self.state);
            if state.result.is_some() {
                return;
            }
            let waiters = std::mem::take(&mut state.waiters);
            state.result = Some(result.clone());
            waiters
        };
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }

    async fn recv(&self, name: Name) -> Result<Answer, ResolveError> {
        let rx = {
            let mut state = lock(&self.state);
            if let Some(result) = state.result.clone() {
                return result;
            }
            let (tx, rx) = oneshot::channel();
            state.waiters.push(tx);
            rx
        };
        match rx.await {
            Ok(result) => result,
            // The flight was dropped without `publish`. Same outcome as a
            // leader that disappeared: the caller can try again later.
            Err(_closed) => Err(ResolveError::Unreachable { zone: name }),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    use dnscraft_proto::{Header, Message, Rcode};
    use tokio::sync::oneshot;

    use super::*;
    use crate::types::{AnswerSource, DnssecStatus};

    fn key(checking_disabled: bool) -> Key {
        Key::new(
            &Query {
                name: Name::from_ascii("www.example.test.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            checking_disabled,
        )
    }

    fn sample(code: u16) -> Answer {
        Answer {
            message: Message {
                header: Header {
                    rcode_low: Rcode::NOERROR.low(),
                    ..Header::default()
                },
                questions: Vec::new(),
                answers: Vec::new(),
                authorities: Vec::new(),
                additionals: Vec::new(),
                edns: None,
            },
            dnssec: DnssecStatus::Indeterminate,
            source: AnswerSource::Recursion,
            ede: Some(crate::types::ExtendedError { code, text: None }),
        }
    }

    #[tokio::test]
    async fn fifty_waiters_share_one_resolution() {
        let inflight = Inflight::new();
        let flight_key = key(false);
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::with_capacity(50);
        for _ in 0..50 {
            let inflight = inflight.clone();
            let flight_key = flight_key.clone();
            let calls = Arc::clone(&calls);
            let started = Arc::clone(&started);
            joins.push(tokio::spawn(async move {
                started.fetch_add(1, Ordering::SeqCst);
                inflight
                    .dedup(flight_key, async move {
                        while started.load(Ordering::SeqCst) < 50 {
                            tokio::task::yield_now().await;
                        }
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(sample(1))
                    })
                    .await
                    .unwrap()
            }));
        }
        let answers = tokio::time::timeout(Duration::from_secs(2), async {
            let mut answers = Vec::with_capacity(joins.len());
            for join in joins {
                answers.push(join.await.unwrap());
            }
            answers
        })
        .await
        .expect("waiters should observe the single resolution");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(answers.len(), 50);
        for answer in &answers {
            assert_eq!(answer.ede.as_ref().unwrap().code, 1);
        }

        // The finished flight is gone, so the next miss runs again.
        let again = Arc::clone(&calls);
        inflight
            .dedup(flight_key, async move {
                again.fetch_add(1, Ordering::SeqCst);
                Ok(sample(2))
            })
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn waiters_receive_the_leader_error() {
        let inflight = Inflight::new();
        let flight_key = key(false);
        let started = Arc::new(AtomicUsize::new(0));
        let mut joins = Vec::new();
        for _ in 0..8 {
            let inflight = inflight.clone();
            let flight_key = flight_key.clone();
            let started = Arc::clone(&started);
            joins.push(tokio::spawn(async move {
                started.fetch_add(1, Ordering::SeqCst);
                inflight
                    .dedup(flight_key, async move {
                        while started.load(Ordering::SeqCst) < 8 {
                            tokio::task::yield_now().await;
                        }
                        Err(ResolveError::CnameLoop { name: Name::root() })
                    })
                    .await
            }));
        }
        for join in joins {
            let result = tokio::time::timeout(Duration::from_secs(2), join)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(result, Err(ResolveError::CnameLoop { .. })));
        }
    }

    #[tokio::test]
    async fn cd_does_not_share_a_flight_with_a_validating_query() {
        let inflight = Inflight::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let mut joins = Vec::new();
        for checking_disabled in [false, true] {
            let inflight = inflight.clone();
            let calls = Arc::clone(&calls);
            let barrier = Arc::clone(&barrier);
            joins.push(tokio::spawn(async move {
                inflight
                    .dedup(key(checking_disabled), async move {
                        calls.fetch_add(1, Ordering::SeqCst);
                        barrier.wait().await;
                        Ok(sample(1))
                    })
                    .await
                    .unwrap()
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            for join in joins {
                join.await.unwrap();
            }
        })
        .await
        .expect("CD and non-CD queries must each run");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wait_idle_blocks_until_the_flight_finishes() {
        let inflight = Inflight::new();
        let (tx, rx) = oneshot::channel();
        let worker = inflight.clone();
        let leader = tokio::spawn(async move {
            worker
                .dedup(key(false), async move {
                    rx.await.unwrap();
                    Ok(sample(1))
                })
                .await
                .unwrap();
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while inflight.inner.active.load(Ordering::Acquire) == 0 {
            if tokio::time::Instant::now() > deadline {
                panic!("leader did not register");
            }
            tokio::task::yield_now().await;
        }
        let waiting = inflight.clone();
        let idle = tokio::spawn(async move {
            waiting.wait_idle().await;
        });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !idle.is_finished(),
            "wait_idle returned while a resolution was still running"
        );
        tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            idle.await.unwrap();
            leader.await.unwrap();
        })
        .await
        .expect("wait_idle should return after the flight finishes");
        assert_eq!(inflight.inner.active.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn cancelling_the_first_caller_does_not_fail_the_followers() {
        let inflight = Inflight::new();
        let (tx, rx) = oneshot::channel::<()>();
        let first = {
            let inflight = inflight.clone();
            tokio::spawn(async move {
                inflight
                    .dedup(key(false), async move {
                        rx.await.unwrap();
                        Ok(sample(7))
                    })
                    .await
            })
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while inflight.inner.active.load(Ordering::Acquire) == 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "leader did not register"
            );
            tokio::task::yield_now().await;
        }
        let mut followers = Vec::new();
        for _ in 0..4 {
            let inflight = inflight.clone();
            followers.push(tokio::spawn(async move {
                inflight
                    .dedup(key(false), async {
                        Err(ResolveError::CnameLoop { name: Name::root() })
                    })
                    .await
            }));
        }
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        // The client behind the first caller gives up.
        first.abort();
        let _ = first.await;
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert!(
            followers.iter().all(|f| !f.is_finished()),
            "followers must keep waiting for the real result"
        );
        tx.send(()).unwrap();
        for follower in followers {
            let answer = tokio::time::timeout(Duration::from_secs(2), follower)
                .await
                .unwrap()
                .unwrap()
                .expect("followers get the real answer, not a fabricated error");
            assert_eq!(answer.ede.as_ref().unwrap().code, 7);
        }
        tokio::time::timeout(Duration::from_secs(2), inflight.wait_idle())
            .await
            .unwrap();
    }
}
