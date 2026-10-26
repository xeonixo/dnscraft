//! JSON-lines query-event output.

use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use dnscraft_listeners::QueryEvent;
use dnscraft_policy::DnsProtocol;
use serde_json::Value;
use tokio::sync::mpsc;

/// Writes each received event as one JSON object per line on stdout.
///
/// A dedicated task owns the blocking stdout handle so the answer path never
/// blocks; `serde_json` handles all string escaping.
pub async fn write_events(mut rx: mpsc::Receiver<QueryEvent>) {
    while let Some(event) = rx.recv().await {
        if let Ok(line) = serde_json::to_string(&event_json(&event)) {
            // Lock stdout only for the duration of the write so the guard
            // (`StdoutLock` is `!Send`) never lives across an `.await`.
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }
}

fn event_json(event: &QueryEvent) -> Value {
    serde_json::json!({
        "time": unix_seconds(event.time),
        "protocol": protocol_str(event.protocol),
        "listener_id": event.listener_id.as_str(),
        "source": event.source.to_string(),
        "client_id": event.client_id.as_ref().map(|c| c.as_str()),
        "qname": event.query.name.to_string(),
        "qtype": event.query.qtype.to_string(),
        "qclass": event.query.qclass.to_string(),
        "rcode": event.rcode.to_string(),
        "answer_size": event.answer_size,
        "duration_ms": event.duration.as_millis() as u64,
        "view_id": event.decision.view_id.as_str(),
        "profile_id": event.decision.profile_id.as_str(),
    })
}

fn protocol_str(protocol: DnsProtocol) -> &'static str {
    match protocol {
        DnsProtocol::Udp53 => "udp53",
        DnsProtocol::Tcp53 => "tcp53",
        DnsProtocol::DoT => "dot",
        DnsProtocol::DoH => "doh",
        DnsProtocol::DoQ => "doq",
        _ => "unknown",
    }
}

fn unix_seconds(time: SystemTime) -> f64 {
    time.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    use dnscraft_filtering::SetId;
    use dnscraft_policy::{
        AnswerOrigin, DecisionRecord, DecisionTimings, DnsProtocol, ListenerId, ProfileId,
        SelectionCause, ViewId,
    };
    use dnscraft_proto::{Class, Name, Rcode, RecordType};
    use dnscraft_resolver::Query;

    use super::*;

    fn event() -> QueryEvent {
        QueryEvent {
            time: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            protocol: DnsProtocol::Udp53,
            listener_id: ListenerId::new("lan-udp").unwrap(),
            source: Ipv4Addr::new(192, 0, 2, 10).into(),
            client_id: None,
            query: Query {
                name: Name::from_ascii("a\"b.example.com.").unwrap(),
                qtype: RecordType::A,
                qclass: Class::IN,
            },
            rcode: Rcode::NOERROR,
            answer_size: 42,
            duration: Duration::from_millis(7),
            decision: DecisionRecord {
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

    #[test]
    fn json_line_escapes_qname() {
        let json = serde_json::to_string(&event_json(&event())).unwrap();
        // The `"` in `a"b.example.com.` must come out escaped as `\"`.
        assert!(
            json.contains("a\\\"b"),
            "qname must be JSON-escaped: {json}"
        );
        // And the whole line must still be valid JSON.
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["qname"], "a\"b.example.com.");
    }
}
