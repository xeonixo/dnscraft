//! Resolves one question against the real internet from the root hints.
//!
//! Usage: `cargo run -p dnscraft-resolver --example query -- <name> [TYPE]`
//!
//! Exit status: 0 on NOERROR or NXDOMAIN, 1 on any other outcome, 2 on bad usage.

use std::fmt::Write as _;
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use dnscraft_proto::{Class, Name, Rcode, Record, RecordType};
use dnscraft_resolver::{Answer, Query, RequestFlags, Resolver, ResolverConfig};

const MNEMONICS: &[(&str, RecordType)] = &[
    ("A", RecordType::A),
    ("AAAA", RecordType::AAAA),
    ("NS", RecordType::NS),
    ("CNAME", RecordType::CNAME),
    ("MX", RecordType::MX),
    ("TXT", RecordType::TXT),
    ("SOA", RecordType::SOA),
    ("PTR", RecordType::PTR),
    ("SRV", RecordType::SRV),
    ("DS", RecordType::DS),
    ("DNSKEY", RecordType::DNSKEY),
    ("HTTPS", RecordType::HTTPS),
];

fn parse_type(text: &str) -> Option<RecordType> {
    let upper = text.to_ascii_uppercase();
    if let Some((_, t)) = MNEMONICS.iter().find(|(m, _)| *m == upper) {
        return Some(*t);
    }
    let digits = upper.strip_prefix("TYPE").unwrap_or(&upper);
    digits.parse::<u16>().ok().map(RecordType::from)
}

fn print_records(title: &str, records: &[Record]) {
    if records.is_empty() {
        return;
    }
    println!("{title}:");
    for r in records {
        println!(
            "  {} {} {} {} {:?}",
            r.name, r.ttl, r.class, r.rtype, r.rdata
        );
    }
}

fn print_answer(answer: &Answer, elapsed: std::time::Duration) {
    let msg = &answer.message;
    println!("rcode: {}", msg.rcode());
    println!("ad: {}", msg.header.ad);
    println!("dnssec: {:?}", answer.dnssec);
    println!("source: {:?}", answer.source);
    println!("elapsed: {:.1} ms", elapsed.as_secs_f64() * 1000.0);
    if let Some(ede) = &answer.ede {
        println!("ede: {} {}", ede.code, ede.text.as_deref().unwrap_or(""));
    }
    print_records("answer", &msg.answers);
    print_records("authority", &msg.authorities);
}

/// Minimal stderr subscriber, enabled with `DNSCRAFT_TRACE=1` (DEBUG and up).
struct StderrSubscriber(AtomicU64);

struct Fields(String);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, " {}={:?}", field.name(), value);
    }
}

impl tracing::Subscriber for StderrSubscriber {
    fn enabled(&self, meta: &tracing::Metadata<'_>) -> bool {
        *meta.level() <= tracing::Level::DEBUG
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(self.0.fetch_add(1, Ordering::Relaxed) + 1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, event: &tracing::Event<'_>) {
        let mut f = Fields(String::new());
        event.record(&mut f);
        eprintln!(
            "{} {}{}",
            event.metadata().level(),
            event.metadata().target(),
            f.0
        );
    }
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (name_arg, type_arg) = match args.as_slice() {
        [name] => (name, None),
        [name, qtype] => (name, Some(qtype)),
        _ => {
            eprintln!("usage: query <name> [TYPE]");
            return ExitCode::from(2);
        }
    };

    let name = if name_arg.ends_with('.') {
        Name::from_ascii(name_arg)
    } else {
        Name::from_ascii(&format!("{name_arg}."))
    };
    let Ok(name) = name else {
        eprintln!("invalid name: {name_arg}");
        return ExitCode::from(2);
    };
    let qtype = match type_arg {
        None => RecordType::A,
        Some(text) => match parse_type(text) {
            Some(t) => t,
            None => {
                eprintln!("unknown record type: {text}");
                return ExitCode::from(2);
            }
        },
    };

    if std::env::var_os("DNSCRAFT_TRACE").is_some() {
        let _ = tracing::subscriber::set_global_default(StderrSubscriber(AtomicU64::new(0)));
    }
    let resolver = match Resolver::new(ResolverConfig::default()).await {
        Ok(r) => r,
        Err(err) => {
            eprintln!("error [{}]: {err}", err.code());
            return ExitCode::from(1);
        }
    };
    let query = Query {
        name,
        qtype,
        qclass: Class::IN,
    };

    let start = Instant::now();
    let result = resolver.resolve(&query, RequestFlags::default()).await;
    let elapsed = start.elapsed();
    println!(
        "outgoing queries (incl. priming): {}",
        resolver.stats().outgoing_queries
    );
    match result {
        Ok(answer) => {
            print_answer(&answer, elapsed);
            let rcode = answer.message.rcode();
            let ok = rcode == Rcode::NOERROR || rcode == Rcode::NXDOMAIN;
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(err) => {
            println!("elapsed: {:.1} ms", elapsed.as_secs_f64() * 1000.0);
            eprintln!("error [{}]: {err}", err.code());
            ExitCode::from(1)
        }
    }
}
