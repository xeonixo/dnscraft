//! Core client identity types.
//!
//! [`ClientId`] here is a UniFi / manual device id (typically a UUID), **not**
//! the DoH/DoT Client-ID label owned by `policy`.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::SystemTime;

/// Stable identifier for a client (manual uuid or UniFi client uuid).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(Arc<str>);

impl ClientId {
    /// Creates a client id from a non-empty string.
    pub fn new(id: impl AsRef<str>) -> Result<Self, crate::ClientsError> {
        let trimmed = id.as_ref().trim();
        if trimmed.is_empty() {
            return Err(crate::ClientsError::config("client id is empty"));
        }
        Ok(Self(Arc::from(trimmed)))
    }

    /// The id as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ClientId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Ethernet / Wi-Fi MAC address (6 octets).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    /// Creates a MAC from six octets.
    pub const fn from_octets(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    /// The six octets.
    pub const fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// Parses common MAC forms (`aa:bb:…`, `aa-bb-…`, `aabbcc…`).
    pub fn parse(input: &str) -> Result<Self, crate::ClientsError> {
        let hex: String = input
            .chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if hex.len() != 12 {
            return Err(crate::ClientsError::config(format!(
                "invalid MAC address {input:?}"
            )));
        }
        let mut octets = [0u8; 6];
        for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
            let s = std::str::from_utf8(chunk).map_err(|_| {
                crate::ClientsError::config(format!("invalid MAC address {input:?}"))
            })?;
            octets[i] = u8::from_str_radix(s, 16).map_err(|_| {
                crate::ClientsError::config(format!("invalid MAC address {input:?}"))
            })?;
        }
        Ok(Self(octets))
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

/// Where a [`ClientInfo`] came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ClientSource {
    /// Admin-configured manual IP or CIDR entry.
    Manual,
    /// Observed via the UniFi Integration / classic client feeds.
    Unifi,
}

/// VLAN / network metadata attached to a client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VlanInfo {
    /// 802.1Q VLAN id from UniFi networks.
    pub id: u16,
    /// Network name, e.g. `"IoT"`.
    pub name: String,
    /// Per-network DHCP domain, if UniFi publishes one (source unverified).
    pub domain_name: Option<String>,
}

impl VlanInfo {
    /// Display form used in logs/UI: `name (id)`.
    pub fn display(&self) -> String {
        format!("{} ({})", self.name, self.id)
    }
}

/// One client in a snapshot (manual or UniFi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientInfo {
    /// Stable id (manual uuid or UniFi client uuid).
    pub id: ClientId,
    /// Raw display string for UI / log.
    pub display_name: String,
    /// Normalised single DNS label.
    pub dns_label: String,
    /// Parent domain used for this client's FQDN.
    pub local_domain: String,
    /// Provenance.
    pub source: ClientSource,
    /// Zero or more MACs (UniFi wired/wireless usually one).
    pub macs: Vec<MacAddr>,
    /// All known IPs for this client in the snapshot (`Arc` so adapters clone cheaply).
    pub addresses: Arc<[IpAddr]>,
    /// VLAN when known.
    pub vlan: Option<VlanInfo>,
    /// UniFi `connectedAt`; manuals: `None` or an `updated_at`.
    pub last_seen: Option<SystemTime>,
    /// `false` when retained offline after disappearing from a successful sync.
    pub online: bool,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn client_id_rejects_empty() {
        assert_eq!(
            ClientId::new("  ").unwrap_err().code(),
            "clients.config.invalid"
        );
        assert_eq!(ClientId::new("abc-123").unwrap().as_str(), "abc-123");
    }

    #[test]
    fn mac_parses_common_forms() {
        let a = MacAddr::parse("AA:BB:CC:DD:EE:FF").unwrap();
        let b = MacAddr::parse("aa-bb-cc-dd-ee-ff").unwrap();
        let c = MacAddr::parse("aabbccddeeff").unwrap();
        assert_eq!(a, b);
        assert_eq!(b, c);
        assert_eq!(a.to_string(), "aa:bb:cc:dd:ee:ff");
        assert!(MacAddr::parse("aa:bb").is_err());
    }

    #[test]
    fn vlan_display_format() {
        let v = VlanInfo {
            id: 40,
            name: "IoT".into(),
            domain_name: None,
        };
        assert_eq!(v.display(), "IoT (40)");
    }
}
