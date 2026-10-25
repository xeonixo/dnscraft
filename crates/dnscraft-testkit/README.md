# dnscraft-testkit

Test helpers for DNScraft: an in-process fake DNS hierarchy and DNSSEC-signed
test zones. It is a development-only crate (`publish = false`) that the resolver
uses as a dev-dependency. Nothing here ships in the resolver binary.

- Authoritative servers for `.`, `test.` and `example.test.` run as tokio tasks
  on loopback, on OS-assigned ports, over UDP and TCP.
- Zone data is built as structured records; the servers answer from them.
- Signing uses `hickory-proto`, an implementation independent of
  `dnscraft-proto`, so the resolver's validator is checked against a second
  implementation.
- `start_signed` and `start_scenario` add DNSSEC-signed child zones (see
  `ChildVariant`) with an exported trust anchor.

## Main API

| Item | Purpose |
|------|---------|
| `Hierarchy::start()` | Default hierarchy: `.`, `test.`, `example.test.` |
| `Hierarchy::start_with(Vec<ServerSpec>)` | Custom zones; servers whose origin is `.` become root hints |
| `Hierarchy::start_signed(&[ChildVariant])` | Signed hierarchy (ECDSA P-256) with the given child zones |
| `Hierarchy::start_scenario(&DnssecScenario)` | Signed hierarchy with algorithm, time and validity set explicitly |
| `ServerSpec::new(ns_name, zone)` | One server: name server host and the `Zone` it serves |
| `Zone::new(origin)` and `with_soa`, `with_ns`, `with_a`, `with_aaaa`, `with_record` | Builder for zone data |
| `ChildVariant::ALL` | Child zones of `test.`: `secure`, `nsec3`, `nsec3-optout`, `insecure`, and the `bogus-*` variants |
| `ServerHandle` | `stop()`, `start()`, `queries()` (received queries, in order), `clear_queries()`, `addr()` |
| `Hierarchy::root_hints()`, `nameserver_addrs()`, `trust_anchor()` | Values for `ResolverConfig` and for trust anchors |

Use `Hierarchy::server(origin)` to get the `ServerHandle` for one zone.

## Example

Adapted from `crates/dnscraft-resolver/tests/recursion.rs`:

```rust
use std::time::Duration;

use dnscraft_proto::{Class, Name, RecordType};
use dnscraft_resolver::dnssec::TrustAnchors;
use dnscraft_resolver::{Query, RequestFlags, Resolver, ResolverConfig};
use dnscraft_testkit::Hierarchy;

#[tokio::test]
async fn resolves_through_the_fake_hierarchy() {
    let h = Hierarchy::start().await.unwrap();
    let config = ResolverConfig {
        root_hints: h.root_hints(),
        query_timeout: Duration::from_millis(300),
        nameserver_addr_overrides: h
            .nameserver_addrs()
            .iter()
            .map(|(n, a)| (Name::from_ascii(&n.to_string()).unwrap(), *a))
            .collect(),
        trust_anchors: TrustAnchors::empty(),
        ..ResolverConfig::default()
    };
    let resolver = Resolver::new(config).await.unwrap();
    let query = Query {
        name: Name::from_ascii("www.example.test.").unwrap(),
        qtype: RecordType::A,
        qclass: Class::IN,
    };
    let answer = resolver.resolve(&query, RequestFlags::default()).await.unwrap();
    assert_eq!(answer.message.answers.len(), 1);
}
```

`nameserver_addr_overrides` is needed because every fake server listens on
127.0.0.1 with its own port, so the resolver cannot find them by name.

## Test keys

The RSA keys under `src/keys/` are fixed test keys embedded with `include_bytes!`
(ring cannot generate RSA keys). They are for tests only and must never be used
for real zones. ECDSA and Ed25519 keys are generated per run.

## Running

```bash
cargo test -p dnscraft-testkit
```

The resolver's integration tests depend on this crate, so
`cargo test -p dnscraft-resolver` exercises it too.
