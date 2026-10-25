# dnscraft-proto

In-house DNS wire format for DNScraft: domain names, compression, records,
EDNS(0), complete messages, and the DNSSEC record types and helpers that the
resolver needs.

The crate performs no I/O and uses no async runtime. Its only dependencies are
`thiserror` and `ring` (for digests and the NSEC3 hash). Everything is
synchronous and pure, so it can be fuzzed and tested without sockets.

The design decision is recorded in [ADR-0001](../../docs/adr/0001-recursion-engine.md).

## Hardening rules

Input from the network is untrusted. Decoding follows these rules:

- Compression pointers must point strictly backwards (`ProtoError::ForwardPointer`
  otherwise); a pointer to itself is `PointerLoop`.
- At most 128 compression pointers are followed per name (`TooManyPointers`).
- Names are at most 255 octets on the wire and labels at most 63 octets.
- Section counts are checked against the remaining data before anything is
  allocated (`CountsExceedData`), so a header cannot force a large allocation.
- No panics on untrusted input. Every decode failure is a typed `ProtoError`
  with a stable `code()` string such as `proto.too_many_pointers`.
- The decoders are fuzzed (see [fuzz/README.md](../../fuzz/README.md)) and
  property-tested.

## Modules

| Module | Contents |
|--------|----------|
| `name` | `Name` (wire form, case-insensitive equality), presentation parsing, compression |
| `header` | Header, `Counts`, `Opcode`, `Rcode` |
| `message` | `Message` and `Question`; section decoding and encoding, size limits |
| `record` | `Record` with owner, class, TTL and `RData` (wire type derived from `RData`) |
| `rtype` | `RecordType` and `Class` |
| `rdata` | `RData` variants: `basic` (A, AAAA, names, SOA, MX, TXT, ...), `dnssec` (DNSKEY, DS, RRSIG, NSEC, NSEC3, ...), `svcb` |
| `edns` | OPT pseudo-record and EDNS options |
| `dnssec` | Helpers without I/O: `keytag`, `digest` (DS digests), `nsec3hash`, `canonical` (RRSIG signing input) |
| `error` | `ProtoError` |

Signature verification is not in this crate. `dnssec::canonical` only produces
the exact octets a signature covers; the resolver verifies them.

## Tests

```bash
cargo test -p dnscraft-proto
```

The suite includes property-based round-trip tests (`tests/props.rs`) and
oracle tests (`tests/name_oracle.rs`, `tests/message_oracle.rs`,
`tests/rdata_oracle.rs`, `tests/dnssec_oracle.rs`) that compare the output with
`hickory-proto`, a dev-dependency used only as an independent reference.
`tests/dnssec_vectors.rs` checks known DNSSEC vectors.

Fuzz targets (`name_decode`, `message_decode`, `message_roundtrip`) live in
`fuzz/` and need a nightly toolchain; see [fuzz/README.md](../../fuzz/README.md).
