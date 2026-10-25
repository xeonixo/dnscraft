# Fuzzing

Coverage-guided fuzz targets for the wire decoders in
[`dnscraft-proto`](../crates/dnscraft-proto/README.md), built with
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

Replace `name_decode` with `message_decode` or `message_roundtrip`. Use the
`gnu` target: the `musl` default enables static linking, which does not work
with the sanitizers that cargo-fuzz uses.

## Corpora and artifacts

- Seed inputs live in `fuzz/corpus/<target>/` and are committed. libFuzzer adds
  new interesting inputs to the same directory while it runs.
- Crashes and timeouts are written to `fuzz/artifacts/<target>/`. This
  directory is git-ignored. Reproduce a crash with
  `cargo +nightly fuzz run <target> <artifact-file>`.
- `fuzz/target/` (build output) and `fuzz/coverage/` are git-ignored.

## CI

The `fuzz` job in `.github/workflows/ci.yml` runs on every push and pull
request:

- It is a matrix over `name_decode`, `message_decode` and `message_roundtrip`,
  with `fail-fast: false`, so one failing target does not cancel the others.
- It sets `RUSTUP_TOOLCHAIN=nightly` for the job, overriding the stable pin.
- It installs cargo-fuzz with `taiki-e/install-action`.
- It runs `cargo fuzz run <target> --target x86_64-unknown-linux-gnu -- -max_total_time=60`
  in the `fuzz` directory, so each target gets 60 seconds per run.
