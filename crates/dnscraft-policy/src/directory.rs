//! Client directory contract for local name and PTR answers.
//!
//! Defined here so `policy` does not depend on `dnscraft-clients`. `control-api`
//! adapts the clients crate to this trait.

use std::net::IpAddr;
use std::sync::Arc;

use dnscraft_proto::Name;

/// Read-only view of known client names and addresses for policy steps.
pub trait ClientDirectory: Send + Sync {
    /// Addresses for an FQDN, if the directory knows the name.
    ///
    /// `None` means unknown (fall through the pipeline). `Some` empty means
    /// known without addresses of any family (NODATA for A/AAAA).
    fn addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>>;

    /// Reverse name for `ip`, if known.
    fn reverse(&self, ip: IpAddr) -> Option<Arc<str>>;

    /// Local domain suffixes the directory owns (snapshot; cheap to clone).
    fn local_domains(&self) -> Arc<[String]>;
}

/// Directory that knows no clients (every lookup returns [`None`]).
#[derive(Clone, Copy, Debug, Default)]
pub struct NoClients;

impl ClientDirectory for NoClients {
    fn addresses(&self, _fqdn: &Name) -> Option<Arc<[IpAddr]>> {
        None
    }

    fn reverse(&self, _ip: IpAddr) -> Option<Arc<str>> {
        None
    }

    fn local_domains(&self) -> Arc<[String]> {
        Arc::from([])
    }
}
