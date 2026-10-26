# dnscraft

Minimal DNScraft server binary: a TOML bootstrap that wires the policy engine
into the listener set and streams query-log events as JSON lines.

The heavier crates ([`dnscraft-listeners`](../dnscraft-listeners),
[`dnscraft-policy`](../dnscraft-policy), [`dnscraft-resolver`](../dnscraft-resolver))
do the DNS work; this crate is a thin-but-complete bootstrap around them.

## Build and run

```bash
cargo build -p dnscraft
cargo run -p dnscraft -- deploy/dnscraft.example.toml
```

The only argument is a TOML config path. A runnable loopback sample is
[`deploy/dnscraft.example.toml`](../../deploy/dnscraft.example.toml) (UDP + TCP
on `127.0.0.1:5300`); the public encrypted listeners are commented out.

## Configuration

```toml
public_domain = "example.com"

[log]
queries = true             # default true: JSON lines on stdout
# ip_truncate = "none"     # none | last_octet | last_group (default none)

[[listeners]]
id = "lan-udp"
protocol = "udp53"          # udp53 | tcp53 | dot | doh | doq
address = "127.0.0.1:5300"  # host:port; port 0 = ephemeral
# exposure = "local"        # default "local"; "public" only for dot/doh/doq
# h3 = false                # doh only: also serve HTTP/3 on the same UDP port
```

- `public_domain` (required) — the domain used for SNI/DDR (`dns.<domain>`).
- `listeners` — one `[[listeners]]` table each; `id` must match `[a-z0-9-]{1,64}`.
- `[log]` — `queries` (default true) and optional `ip_truncate`
  (`none` | `last_octet` | `last_group`).
- Shared limits and public settings use the crate defaults; public exposure is
  enabled only when a listener sets `exposure = "public"` (encrypted transports
  only, and then validated against `public_domain`).

## Secrets

TLS certificate material never goes in the TOML file. For each secret set
**exactly one** of the PEM-in-env or the file-path variable (both set is an
error) to install a certificate for `dot`/`doh`/`doq` listeners:

| Variable | Value |
|---|---|
| `DNSCRAFT_TLS_CERT` | PEM certificate chain |
| `DNSCRAFT_TLS_CERT_FILE` | path to a file holding the PEM certificate chain |
| `DNSCRAFT_TLS_KEY` | PEM private key |
| `DNSCRAFT_TLS_KEY_FILE` | path to a file holding the PEM private key |

Setting only one secret of the pair is a configuration error (exit 2,
`dnscraft.config.tls_env_incomplete`); setting both sources for one secret is
`dnscraft.config.tls_env_conflict`. A key file that is group/other readable
produces a warning. With neither set, encrypted listeners stay bound but fail
each handshake with `listeners.tls.no_cert`.

## Query log

Each answered query is written to **stdout** as one JSON object per line
(`serde_json` escaping, so names containing quotes/backslashes stay valid JSON):

```json
{"answer_size":42,"client_id":null,"duration_ms":7,"listener_id":"lan-udp","profile_id":"default","protocol":"udp53","qclass":"IN","qname":"example.com.","qtype":"A","rcode":"NoError","source":"192.0.2.10","time":1700000000.0,"view_id":"default"}
```

Startup notices go to stderr, so stdout stays a clean JSON-lines stream.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | graceful shutdown after SIGTERM/SIGINT |
| `2` | config/usage error, TLS bootstrap error, or startup failure |

## Manual interop (not run)

> **Not run** — exercising these requires a real certificate and a public
> domain, which CI does not provision. This is the recipe once the binary runs
> with `DNSCRAFT_TLS_CERT`/`DNSCRAFT_TLS_KEY` set and a listener on
> `dns.example.com` with `public_domain = example.com`.

```bash
# Do53
dig @dns.example.com example.com A +short

# DoT
kdig @dns.example.com +tls +tls-hostname=dns.example.com example.com A

# DoH
curl --http2 --doh-url https://dns.example.com/dns-query https://example.com/ -o /dev/null -w '%{http_code}\n'
```
