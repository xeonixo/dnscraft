//! TOML bootstrap and environment secrets.

use std::env;
use std::net::SocketAddr;

use serde::Deserialize;

use dnscraft_listeners::{
    DdrConfig, Exposure, Limits, ListenerConfig, ListenersConfig, Protocol, PublicConfig,
};
use dnscraft_policy::ListenerId;
use dnscraft_tls::Secret;

use crate::Error;

/// TLS secret material loaded from the environment (never the TOML file).
///
/// The PEM fields are wrapped in [`Secret`] so they never appear in `Debug`
/// output and are zeroized on drop.
#[derive(Debug)]
pub struct TlsSecrets {
    /// PEM certificate chain.
    pub chain_pem: Secret,
    /// PEM private key.
    pub key_pem: Secret,
}

/// Environment variable holding the PEM certificate chain.
pub const TLS_CERT_ENV: &str = "DNSCRAFT_TLS_CERT";
/// Environment variable holding the PEM private key.
pub const TLS_KEY_ENV: &str = "DNSCRAFT_TLS_KEY";

/// Reads the TLS PEM pair from the environment.
///
/// Returns `None` when neither variable is set and an error when exactly one
/// is set (a half-configured TLS bootstrap must fail loudly).
pub fn tls_secrets_from_env() -> Result<Option<TlsSecrets>, Error> {
    match (env::var(TLS_CERT_ENV).ok(), env::var(TLS_KEY_ENV).ok()) {
        (None, None) => Ok(None),
        (Some(chain), Some(key)) => Ok(Some(TlsSecrets {
            chain_pem: Secret::new(chain),
            key_pem: Secret::new(key),
        })),
        _ => Err(Error::config(
            "dnscraft.config.tls_env_incomplete",
            format!("{TLS_CERT_ENV} and {TLS_KEY_ENV} must be set together"),
        )),
    }
}

/// Top-level configuration loaded from a TOML file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Public DNS domain for SNI / DDR (`dns.<domain>`).
    pub public_domain: String,
    /// Listeners to serve (at least one in practice).
    #[serde(default)]
    pub listeners: Vec<ListenerToml>,
    /// Keep the listener-set partial-bind behaviour (report bind failures in
    /// status and keep the other listeners). Default `false`: any bind failure
    /// is fatal (`dnscraft.startup.bind`).
    #[serde(default)]
    pub allow_partial_bind: bool,
}

/// One listener entry in the TOML file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerToml {
    /// Unique listener id (`[a-z0-9-]{1,64}`).
    pub id: String,
    /// Transport: `udp53`, `tcp53`, `dot`, `doh`, `doq`.
    pub protocol: String,
    /// Bind address (`host:port`; port `0` picks an ephemeral port).
    pub address: SocketAddr,
    /// `local` (default) or `public` (encrypted transports only).
    #[serde(default = "default_exposure")]
    pub exposure: String,
    /// DoH only: also serve HTTP/3 on the same UDP port.
    #[serde(default)]
    pub h3: bool,
}

fn default_exposure() -> String {
    "local".to_owned()
}

impl Config {
    /// Maps this TOML config onto a [`ListenersConfig`] with security defaults
    /// (shared [`Limits::default`], public exposure enabled only when a
    /// listener explicitly opts in, DDR discovery on).
    pub fn listeners_config(&self) -> Result<ListenersConfig, Error> {
        let mut listeners = Vec::with_capacity(self.listeners.len());
        let mut public = false;
        for listener in &self.listeners {
            let id = ListenerId::new(&listener.id).map_err(|_| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!("invalid listener id `{}`", listener.id),
                )
            })?;
            let protocol = parse_protocol(&listener.protocol).ok_or_else(|| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!(
                        "unknown protocol `{}` for listener `{}`",
                        listener.protocol, listener.id
                    ),
                )
            })?;
            let exposure = parse_exposure(&listener.exposure).ok_or_else(|| {
                Error::config(
                    "dnscraft.config.invalid_listener",
                    format!(
                        "unknown exposure `{}` for listener `{}`",
                        listener.exposure, listener.id
                    ),
                )
            })?;
            if exposure == Exposure::Public {
                public = true;
            }
            listeners.push(ListenerConfig {
                id,
                protocol,
                address: listener.address,
                exposure,
                h3: listener.h3,
            });
        }
        Ok(ListenersConfig {
            listeners,
            limits: Limits::default(),
            public: PublicConfig {
                enabled: public,
                ..PublicConfig::default()
            },
            ddr: DdrConfig::default(),
        })
    }
}

fn parse_protocol(s: &str) -> Option<Protocol> {
    match s {
        "udp53" => Some(Protocol::Udp53),
        "tcp53" => Some(Protocol::Tcp53),
        "dot" => Some(Protocol::Dot),
        "doh" => Some(Protocol::Doh),
        "doq" => Some(Protocol::Doq),
        _ => None,
    }
}

fn parse_exposure(s: &str) -> Option<Exposure> {
    match s {
        "local" => Some(Exposure::Local),
        "public" => Some(Exposure::Public),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn tls_secrets_debug_is_redacted() {
        let secrets = TlsSecrets {
            chain_pem: Secret::new(
                "-----BEGIN CERTIFICATE-----\nchain-material\n-----END CERTIFICATE-----",
            ),
            key_pem: Secret::new(
                "-----BEGIN PRIVATE KEY-----\nsuper-secret-key\n-----END PRIVATE KEY-----",
            ),
        };
        let shown = format!("{secrets:?}");
        assert!(!shown.contains("super-secret-key"), "key leaked: {shown}");
        assert!(
            !shown.contains("BEGIN PRIVATE KEY"),
            "key PEM leaked: {shown}"
        );
        assert!(
            shown.contains("Secret([redacted])"),
            "missing marker: {shown}"
        );
    }
}
