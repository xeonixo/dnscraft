# dnscraft-clients

Client identity index for DNScraft: manual names plus UniFi Network inventory
become an `Arc` snapshot that answers `by_ip` / `by_name` / `reverse` /
`local_domains`.

This crate never selects filter profiles or views (`policy`) and never blocks
the DNS hot path on UniFi I/O (background sync only).

Formal requirements: [`SPEC-clients.md`](../../SPEC-clients.md).

## UniFi API key

| Item | Value |
|------|--------|
| Env | `DNSCRAFT_UNIFI_API_KEY` |
| File secret | `DNSCRAFT_UNIFI_API_KEY_FILE` (Docker / systemd credentials) |
| Header | `X-API-KEY` (Integration **and** classic feeds on UniFi OS) |

Prefer `*_FILE`. The key never appears in `Debug` (`Secret([redacted])`) or
error messages. Create a key in the console under **Settings → Control Plane →
Integrations / API Keys**.

Automated tests never call a real gateway — only the in-crate HTTPS mock.

## TLS bootstrap (pin)

Gateways usually present a self-signed cert. Default trust is **not** “accept
any certificate”.

1. Fetch the leaf once (browser, or `openssl s_client -connect GATEWAY:443 -showcerts`).
2. SHA-256 of the **leaf DER** (32 bytes), configured as
   `tls_pin_sha256 = "sha256:"` + 64 hex digits (colons optional).
3. Helper: [`leaf_sha256`](src/tls.rs) on the DER bytes.

| Mode | When |
|------|------|
| `TlsMode::Pin([u8; 32])` | Preferred for self-signed |
| `TlsMode::CaFile(path)` | Admin-installed CA bundle |
| `TlsMode::Secure` | Default; verify against the OS CA bundle |
| `TlsMode::Insecure` | Opt-in escape hatch only; logs `clients.tls.insecure` |

Pin mismatch → `clients.tls.untrusted` (fail closed).

## Configuration (Rust / TOML sketch)

| Field | Default | Notes |
|-------|---------|--------|
| `local_domain` | `home.arpa` | Fallback parent domain (RFC 8375) |
| `local_domain_mode` | `unifi_then_config` | Or `config` to force the fallback |
| `offline_retain` | 7 d | Keep disappeared UniFi clients offline |
| `ipv6_address_ttl` | 24 h | Drop stale UniFi IPv6 after last sighting |
| `unifi.enabled` | false | Manuals-only when off |
| `unifi.base_url` | — | HTTPS gateway origin |
| `unifi.site_id` | auto | Required when more than one site |
| `unifi.poll_interval` | 60 s | ±10 % jitter in the engine |
| `unifi.classic_clients` | true | Full IPv6 via `stat/sta` (+ `rest/user`) |
| `manual[]` | — | Exact IP **or** CIDR per entry (≤ 1000) |

Integration API supplies sites / networks; classic supplies multi-address client
rows. They are merged by MAC (preferred) or client id.

## Failure behaviour

| Situation | Lookup | Status |
|-----------|--------|--------|
| Gateway down / TLS / 401 / bad body | Last good `Arc` kept | `stale = true`, `last_error` = stable `code()` |
| Classic down, Integration up | Integration-only snapshot | `classic_error` on sync report; not whole-sync stale |
| 429 / 5xx | Last good kept | Exponential backoff 5 s … 5 min |
| `classic_clients = false` | Integration singular `ipAddress` only | No classic HTTP |

Lookups never `await`.

## On-disk last-good cache

Under `<data_dir>/clients/` (directory **0700**):

| File | Mode | Contents |
|------|------|----------|
| `state.json` | 0600 | Format version, merge `State`, last observations + networks |

Atomic write (temp + fsync + rename). Loaded as untrusted input (16 MiB cap);
corrupt / wrong-version / oversized → ignored with a warning; next sync starts
fresh. On start the engine serves the cache before the first successful poll
(`stale` until a live sync confirms).

## Library usage

```rust
use std::path::PathBuf;
use std::sync::Arc;

use dnscraft_clients::{
    ClientEngine, ClientsConfig, Clock, ManualClock, Secret, SystemClock,
};

fn boot(config: ClientsConfig, data_dir: PathBuf) -> Result<Arc<ClientEngine>, dnscraft_clients::ClientsError> {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock);
    // Production: API key from DNSCRAFT_UNIFI_API_KEY / _FILE via ClientsConfig::validate.
    ClientEngine::new(config, data_dir, clock)
}
```

- `lookup()` → cheap `Arc<ClientLookup>` clone.
- `sync_now()` / background poll rebuild only when the observation hash changes.
- `apply_config` rebuilds from cached UniFi rows (manual edits need no gateway round-trip).
  When `unifi.enabled` is false, UniFi contribution is empty (manuals only); first-seen
  labels in state are kept, observations / retain inventory are cleared.
- Gateway fetch runs **outside** the sync lock; under the lock a fetch is **discarded**
  (`SyncReport.superseded = true`, no install / no stale) when UniFi was disabled, the
  `UnifiConfig` changed mid-flight, or a newer fetch/apply already installed.
- Tests: `ClientEngine::new_with_secret` + `ManualClock` (no process env mutation).

## Error codes

Stable `area.reason` via [`ClientsError::code`](src/error.rs):
`clients.config.invalid`, `clients.secret.missing`, `clients.tls.untrusted`,
`clients.tls.handshake`, `clients.connect`, `clients.http.status`,
`clients.http.body`, `clients.sync.partial`, `clients.sync.backoff`,
`clients.too_many`, `clients.ip.conflict`, `clients.name.collision`.

A superseded mid-flight fetch is **not** an error code — it returns `Ok(SyncReport)`
with `superseded: true` and `rebuilt: false`.

## Coverage

```bash
cargo llvm-cov -p dnscraft-clients --summary-only
```

Target ≥ 80 % lines on non-HTTP modules (label, lookup, merge, state, cache,
config, parsers). Gateway / Integration / classic HTTP paths are exercised via
the mock; real UniFi is never hit in CI.
