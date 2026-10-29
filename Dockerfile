# syntax=docker/dockerfile:1
#
# Production image (glibc / Debian bookworm-slim).
#
# The workspace does not ship a musl cross-toolchain in CI; this is the
# supported default. For a statically linked musl binary on scratch, see
# Dockerfile.musl and deploy/README.md.

ARG RUST_VERSION=1.88

FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS web
WORKDIR /web
RUN corepack enable && corepack prepare pnpm@9 --activate
COPY web .
RUN pnpm install --frozen-lockfile
RUN pnpm run build

FROM rust:${RUST_VERSION}-bookworm AS builder
WORKDIR /build

COPY Cargo.toml Cargo.lock deny.toml rust-toolchain.toml ./
COPY crates ./crates
COPY --from=web /web/build ./crates/dnscraft-api/embed-web-ui

RUN cargo build --release -p dnscraft --features web-ui --locked

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 -s /usr/sbin/nologin dnscraft \
    && mkdir -p /var/lib/dnscraft /etc/dnscraft \
    && chown -R dnscraft:dnscraft /var/lib/dnscraft

COPY --from=builder /build/target/release/dnscraft /usr/local/bin/dnscraft
COPY deploy/dnscraft.docker.toml /etc/dnscraft/config.toml

USER dnscraft

EXPOSE 5300/udp 5300/tcp 80/tcp 443/tcp

HEALTHCHECK --interval=10s --timeout=3s --start-period=45s --retries=3 \
    CMD curl -fsS http://127.0.0.1:80/healthz || exit 1

ENTRYPOINT ["/usr/local/bin/dnscraft"]
CMD ["/etc/dnscraft/config.toml"]
