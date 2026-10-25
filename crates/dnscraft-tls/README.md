# dnscraft-tls

ACME DNS-01 certificates (Cloudflare), hot-reloadable `CertResolver`, DynDNS, and
SNI helpers for DNScraft encrypted DNS listeners.

## Secrets

| Env | Purpose |
|---|---|
| `DNSCRAFT_CLOUDFLARE_API_TOKEN` | Zone → DNS → Edit token (or `DNSCRAFT_CLOUDFLARE_API_TOKEN_FILE`) |

Never commit real tokens. Prefer Docker secrets / `*_FILE`.

## ACME directories

Configured via `AcmeDirectoryKind`: `Production`, `Staging`, or a custom HTTPS URL.
Use **staging** for manual acceptance before production.

## Local Pebble (ignored test)

The account-wiring spike includes an ignored integration test that talks to a
local [Pebble](https://github.com/letsencrypt/pebble) server. CI does **not**
run it; the lead runs it at Checkpoint A.

```bash
# Terminal 1 — Pebble with challenges always valid (no real DNS needed for account tests)
docker run --rm -it -p 14000:14000 -p 15000:15000 \
  -e PEBBLE_VA_ALWAYS_VALID=1 \
  --name pebble \
  ghcr.io/letsencrypt/pebble:latest

# Copy the test CA out of the image (path may vary by tag; adjust if needed)
docker cp pebble:/test/certs/pebble.minica.pem /tmp/pebble.minica.pem

# Terminal 2 — run the ignored test
PEBBLE_ROOT_CA=/tmp/pebble.minica.pem \
PEBBLE_DIRECTORY_URL=https://localhost:14000/dir \
  cargo test -p dnscraft-tls -- --ignored pebble
```

The test builds an HTTP client that trusts `PEBBLE_ROOT_CA` (no global
insecure-TLS switch). Account credentials are written to `<data>/tls/account.json`
mode `0600` and reloaded on a second `ensure_account` call.

## Crypto / HTTP stack (L4)

`instant-acme` is depended on with `default-features = false` and
`features = ["ring", "rcgen", "time", "x509-parser"]` — **no** `aws-lc-rs`,
**no** `hyper-rustls`. ACME HTTP uses the workspace `reqwest` client via
`ReqwestHttpClient` (single TLS stack + webpki roots). Gate:
`cargo tree -i aws-lc-rs` and `cargo tree -i openssl-sys` must print nothing.
