//! Resolves one question against the real internet from the root hints.
//!
//! Usage: `cargo run -p dnscraft-resolver --example query -- <name> [TYPE]`
//!
//! Exit status: 0 on NOERROR or NXDOMAIN, 1 on any other outcome, 2 on bad usage.

use std::process::ExitCode;
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
