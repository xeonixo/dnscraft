//! Non-blocking query-event sink (query log feed for control-api).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use tokio::sync::mpsc;

use crate::clock::Clock;
use crate::core::QueryEvent;

/// Receives structured query-log events without blocking the answer path.
pub trait QueryEventSink: Send + Sync {
    /// Tries to enqueue `event`. Returns `false` when the sink is full or closed.
    fn try_send(&self, event: QueryEvent) -> bool;

    /// Events dropped because the sink was full or closed (default 0).
    fn events_dropped(&self) -> u64 {
        0
    }
}

/// Bounded channel sink: full → drop + [`Self::events_dropped`].
#[derive(Debug)]
pub struct ChannelSink {
    tx: mpsc::Sender<QueryEvent>,
    dropped: AtomicU64,
}

impl ChannelSink {
    /// Creates a sink with `capacity` slots and a receiver for the consumer.
    pub fn new(capacity: usize) -> (Arc<Self>, mpsc::Receiver<QueryEvent>) {
        let (tx, rx) = mpsc::channel(capacity.max(1));
        (
            Arc::new(Self {
                tx,
                dropped: AtomicU64::new(0),
            }),
            rx,
        )
    }

    /// Number of events dropped because the channel was full or closed.
    pub fn events_dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl QueryEventSink for ChannelSink {
    fn try_send(&self, event: QueryEvent) -> bool {
        match self.tx.try_send(event) {
            Ok(()) => true,
            Err(_) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    fn events_dropped(&self) -> u64 {
        ChannelSink::events_dropped(self)
    }
}

/// Emits `event` when `loggable`, stamping [`QueryEvent::time`] from `clock`.
///
/// Never blocks; a full sink drops the event (counted by [`ChannelSink`]).
pub fn emit_event(sink: &dyn QueryEventSink, clock: &dyn Clock, mut event: QueryEvent) {
    if !event.loggable {
        return;
    }
    event.time = clock.now();
    let _ = sink.try_send(event);
}

/// Optional sink + event from [`crate::handle_wire`].
pub(crate) fn emit_optional(
    sink: &Option<Arc<dyn QueryEventSink>>,
    clock: &dyn Clock,
    event: Option<QueryEvent>,
) {
    let (Some(sink), Some(event)) = (sink, event) else {
        return;
    };
    emit_event(sink.as_ref(), clock, event);
}

/// Sink that discards every event.
#[derive(Debug, Default)]
pub struct NullSink;

impl QueryEventSink for NullSink {
    fn try_send(&self, _event: QueryEvent) -> bool {
        true
    }
}

/// Placeholder time before [`emit_event`] stamps the clock.
pub(crate) fn placeholder_time() -> SystemTime {
    SystemTime::UNIX_EPOCH
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use dnscraft_filtering::SetId;
    use dnscraft_policy::{
        AnswerOrigin, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId, ProfileId,
        SelectionCause, ViewId,
    };
    use dnscraft_proto::{Class, Name, Rcode, RecordType};
    use dnscraft_resolver::Query;

    use super::*;
    use crate::clock::ManualClock;

    fn sample_event(loggable: bool) -> QueryEvent {
        QueryEvent {
            time: placeholder_time(),
            protocol: DnsProtocol::Udp53,
            listener_id: ListenerId::new("lan-udp").unwrap(),
            source: Ipv4Addr::new(192, 0, 2, 10).into(),
            client_id: None,
            query: Query {
                name: Name::from_ascii("example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            rcode: Rcode::NOERROR,
            answer_size: 42,
            duration: Duration::from_millis(1),
            decision: DecisionRecord {
                view_id: ViewId::new("default").unwrap(),
                profile_id: ProfileId::new("default").unwrap(),
                selection: SelectionCause::Default,
                client_id: None,
                client_label: None,
                filter_set: SetId::new("default").unwrap(),
                steps: Vec::new(),
                filter: None,
                forward_zone: None,
                dnssec: None,
                answer_source: AnswerOrigin::LocalView,
                timings: DecisionTimings::default(),
                rcode: Rcode::NOERROR,
            },
            loggable,
        }
    }

    #[test]
    fn channel_sink_drops_when_full() {
        let (sink, mut rx) = ChannelSink::new(1);
        assert!(sink.try_send(sample_event(true)));
        assert!(!sink.try_send(sample_event(true)));
        assert_eq!(sink.events_dropped(), 1);
        let _ = rx.try_recv();
    }

    #[test]
    fn emit_skips_non_loggable() {
        let (sink, mut rx) = ChannelSink::new(4);
        let clock = ManualClock::new(SystemTime::UNIX_EPOCH + Duration::from_secs(100));
        emit_event(sink.as_ref(), &clock, sample_event(false));
        assert!(rx.try_recv().is_err());
        assert_eq!(sink.events_dropped(), 0);
    }

    #[test]
    fn emit_stamps_clock_time() {
        let (sink, mut rx) = ChannelSink::new(4);
        let t = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let clock = ManualClock::new(t);
        emit_event(sink.as_ref(), &clock, sample_event(true));
        let ev = rx.try_recv().unwrap();
        assert_eq!(ev.time, t);
    }
}
