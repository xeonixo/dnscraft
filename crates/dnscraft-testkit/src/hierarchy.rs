use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto::rr::Name;

use crate::TestkitError;
use crate::server::ServerHandle;
use crate::zone::{Zone, parse_name};

/// Definition of one fake server: the name of its name server host and the
/// zone it serves.
#[derive(Clone, Debug)]
pub struct ServerSpec {
    /// Name of the name server host (for example `ns1.test.`). Used as the key
    /// in [`Hierarchy::nameserver_addrs`].
    pub ns_name: Name,
    /// The zone served.
    pub zone: Zone,
}

impl ServerSpec {
    /// Creates a spec from a name server host name and its zone.
    pub fn new(ns_name: &str, zone: Zone) -> Result<Self, TestkitError> {
        Ok(Self {
            ns_name: parse_name(ns_name)?,
            zone,
        })
    }
}

/// The default zone set: `.`, `test.` and `example.test.`.
///
/// Extend it by pushing more [`ServerSpec`]s (or replacing a zone) and passing
/// the list to [`Hierarchy::start_with`].
pub fn default_servers() -> Result<Vec<ServerSpec>, TestkitError> {
    let lo = Ipv4Addr::LOCALHOST;
    let root = Zone::new(".")?
        .with_soa("a.root-servers.net.", "hostmaster.root-servers.net.")?
        .with_ns(".", "a.root-servers.net.")?
        .with_a("a.root-servers.net.", lo)?
        .with_ns("test.", "ns1.test.")?
        .with_a("ns1.test.", lo)?;
    let test = Zone::new("test.")?
        .with_soa("ns1.test.", "hostmaster.test.")?
        .with_ns("test.", "ns1.test.")?
        .with_a("ns1.test.", lo)?
        .with_ns("example.test.", "ns1.example.test.")?
        .with_a("ns1.example.test.", lo)?;
    let example = Zone::new("example.test.")?
        .with_soa("ns1.example.test.", "hostmaster.example.test.")?
        .with_ns("example.test.", "ns1.example.test.")?
        .with_a("ns1.example.test.", lo)?
        .with_a("www.example.test.", Ipv4Addr::new(192, 0, 2, 1))?
        .with_aaaa(
            "www.example.test.",
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        )?;
    Ok(vec![
        ServerSpec::new("a.root-servers.net.", root)?,
        ServerSpec::new("ns1.test.", test)?,
        ServerSpec::new("ns1.example.test.", example)?,
    ])
}

/// An in-process fake DNS hierarchy on loopback.
///
/// # Test-only constraint: ports
///
/// Every server listens on `127.0.0.1` but on its own OS-assigned port (UDP
/// and TCP share the port). DNS glue records cannot carry a port, so all glue
/// and in-zone address records for name servers contain plain `127.0.0.1`.
/// A resolver under test therefore must NOT connect to port 53 at the glue
/// address; it must use [`nameserver_addrs`](Self::nameserver_addrs) (name
/// server name to `ip:port`) or an equivalent port override, and start from
/// [`root_hints`](Self::root_hints).
///
/// Servers run as tasks in the tokio runtime that called [`Hierarchy::start`].
#[derive(Debug)]
pub struct Hierarchy {
    servers: Vec<(Name, ServerHandle)>,
    ns_addrs: HashMap<Name, SocketAddr>,
    root_hints: Vec<SocketAddr>,
}

impl Hierarchy {
    /// Starts the default hierarchy (`.`, `test.`, `example.test.`).
    pub async fn start() -> Result<Self, TestkitError> {
        Self::start_with(default_servers()?).await
    }

    /// Starts a hierarchy from custom server specs. Servers whose zone origin
    /// is the root become root hints.
    pub async fn start_with(specs: Vec<ServerSpec>) -> Result<Self, TestkitError> {
        let mut servers = Vec::with_capacity(specs.len());
        let mut ns_addrs = HashMap::new();
        let mut root_hints = Vec::new();
        for spec in specs {
            let origin = spec.zone.origin().clone();
            let handle = ServerHandle::spawn(spec.zone).await?;
            if origin.is_root() {
                root_hints.push(handle.addr());
            }
            ns_addrs.insert(spec.ns_name, handle.addr());
            servers.push((origin, handle));
        }
        Ok(Self {
            servers,
            ns_addrs,
            root_hints,
        })
    }

    /// Addresses (`127.0.0.1:port`) of the root servers.
    pub fn root_hints(&self) -> Vec<SocketAddr> {
        self.root_hints.clone()
    }

    /// Mapping from name server host name to the real `ip:port` of its server.
    pub fn nameserver_addrs(&self) -> &HashMap<Name, SocketAddr> {
        &self.ns_addrs
    }

    /// The handle of the server for zone `origin` (for example `"test."`).
    pub fn server(&self, origin: &str) -> Result<&ServerHandle, TestkitError> {
        let name = parse_name(origin)?;
        self.servers
            .iter()
            .find(|(zone, _)| *zone == name)
            .map(|(_, handle)| handle)
            .ok_or_else(|| TestkitError::UnknownZone {
                zone: origin.to_owned(),
            })
    }
}
