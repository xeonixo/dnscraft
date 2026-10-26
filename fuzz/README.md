# Fuzzing

Coverage-guided fuzz targets for the wire decoders in
[`dnscraft-proto`](../crates/dnscraft-proto/README.md), the filter-list
parser in `dnscraft-filtering`, and the listener core / DoH request parser in
`dnscraft-listeners`, built with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer. The fuzz
crate (`dnscraft-proto-fuzz`) is separate from the workspace and has its own
`Cargo.lock`.

## Targets

Defined in `fuzz/Cargo.toml`, sources in `fuzz/fuzz_targets/`:

| Target | Source | What it checks |
|--------|--------|----------------|
| `name_decode` | `name_decode.rs` | `Name::decode` at offset 0 and at an offset taken from the input; a decoded name re-encodes and decodes to itself |
| `message_decode` | `message_decode.rs` | `Message::decode` never panics on arbitrary bytes |
| `message_roundtrip` | `message_roundtrip.rs` | Encode, decode and encode again gives identical bytes; the encoding with a 512-octet limit decodes again |
| `rule_parse` | `rule_parse.rs` | `parse_list` (both sources) and `parse_rule` never panic; every parsed rule has source text; a described rule builds with `build_rule` and parses again |
| `listeners_handle_wire` | `listeners_handle_wire.rs` | `handle_wire` never panics or hangs on arbitrary wire bytes with a `QueryMeta` derived from the input (async, on a current-thread tokio runtime) |
| `listeners_doh_request` | `listeners_doh_request.rs` | `parse_doh_path`, `extract_wire` and `content_type_of` never panic on arbitrary method/path/query/headers/body |

## Prerequisites

- A nightly Rust toolchain: `rustup toolchain install nightly`. The root
  `rust-toolchain.toml` pins stable, so select nightly explicitly (see below).
- cargo-fuzz: `cargo install cargo-fuzz`.
- A C++ compiler (for example `g++` or `clang++`). libFuzzer is built from C++
  sources through `libfuzzer-sys`.

## Running one target

From the `fuzz` directory, for 60 seconds:

```bash
cd fuzz
cargo +nightly fuzz run name_decode --target x86_64-unknown-linux-gnu -- -max_total_time=60
```

Replace `name_decode` with `message_decode`, `message_roundtrip`, `rule_parse`,
`listeners_handle_wire` or `listeners_doh_request`. Use the `gnu` target: the
`musl` default enables static linking, which does not work with the sanitizers
that cargo-fuzz uses.

## Corpora and artifacts

- Named seed inputs live in `fuzz/corpus/<target>/` and are committed. libFuzzer
  adds new interesting inputs as hex-named files in the same directory; those
  generated units are git-ignored (see `.gitignore`).
- Crashes and timeouts are written to `fuzz/artifacts/<target>/`. This
  directory is git-ignored. Reproduce a crash with
  `cargo +nightly fuzz run <target> <artifact-file>`.
- `fuzz/target/` (build output) and `fuzz/coverage/` are git-ignored.

## CI

The `fuzz` job in `.github/workflows/ci.yml` runs on every push and pull
request, plus a Monday schedule for a longer run:

- Matrix over `name_decode`, `message_decode`, `message_roundtrip`, `rule_parse`,
  `listeners_handle_wire` and `listeners_doh_request`, with `fail-fast: false`.
- `RUSTUP_TOOLCHAIN=nightly` overrides the stable pin for this job only.
- `cargo-fuzz` via `taiki-e/install-action`.
- Duration: **60 s** on push/PR (smoke); **600 s** on the weekly schedule.
- Concurrency cancels superseded PR runs, but not pushes to `main`.

The separate `coverage` job fails if line coverage of `dnscraft-proto`,
`dnscraft-resolver`, `dnscraft-filtering` or `dnscraft-policy` drops under
**80 %** (`--fail-under-lines 80`).
