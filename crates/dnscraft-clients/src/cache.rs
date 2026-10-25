//! Last-good disk cache under `<data>/clients/state.json`.
//!
//! Atomic write (temp + `create_new` 0600 + fsync + rename). Loaded as
//! untrusted input: 16 MiB size cap, format version check, caps re-validated
//! by the caller via [`merge::build`].

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::merge::{NetworkInfo, UnifiObservation};
use crate::state::{RetainedClient, State};
use crate::types::{ClientId, MacAddr};

/// On-disk format version. Bump when the schema changes incompatibly.
pub const CACHE_VERSION: u32 = 1;
/// Maximum accepted cache file size (SPEC-clients.md).
pub const MAX_CACHE_BYTES: u64 = 16 * 1024 * 1024;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Payload restored from / written to the last-good cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachePayload {
    /// Merge state (labels, retain, IPv6 TTL inventory).
    pub state: State,
    /// Last successful UniFi observations.
    pub observations: Vec<UnifiObservation>,
    /// Last successful network metadata.
    pub networks: Vec<NetworkInfo>,
}

/// Path to the cache file: `<data_dir>/clients/state.json`.
pub fn cache_path(data_dir: &Path) -> PathBuf {
    data_dir.join("clients").join("state.json")
}

/// Loads the cache. Corrupt / oversized / wrong-version → `Ok(None)` + warn.
pub fn load(data_dir: &Path) -> io::Result<Option<CachePayload>> {
    let path = cache_path(data_dir);
    match fs::metadata(&path) {
        Ok(meta) => {
            if meta.len() > MAX_CACHE_BYTES {
                warn!(
                    code = "clients.cache.oversized",
                    path = %path.display(),
                    len = meta.len(),
                    "clients cache ignored (oversized)"
                );
                return Ok(None);
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            warn!(
                code = "clients.cache.io",
                path = %path.display(),
                error = %e,
                "clients cache ignored (stat failed)"
            );
            return Ok(None);
        }
    }

    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                code = "clients.cache.io",
                path = %path.display(),
                error = %e,
                "clients cache ignored (read failed)"
            );
            return Ok(None);
        }
    };

    let wire: DiskCache = match serde_json::from_slice(&bytes) {
        Ok(w) => w,
        Err(e) => {
            warn!(
                code = "clients.cache.corrupt",
                path = %path.display(),
                error = %e,
                "clients cache ignored (JSON)"
            );
            return Ok(None);
        }
    };

    if wire.version != CACHE_VERSION {
        warn!(
            code = "clients.cache.version",
            path = %path.display(),
            version = wire.version,
            expected = CACHE_VERSION,
            "clients cache ignored (version)"
        );
        return Ok(None);
    }

    match wire.into_payload() {
        Ok(p) => Ok(Some(p)),
        Err(e) => {
            warn!(
                code = "clients.cache.corrupt",
                path = %path.display(),
                error = %e,
                "clients cache ignored (decode)"
            );
            Ok(None)
        }
    }
}

/// Ensures `<data_dir>/clients` exists (mode 0700 on unix) and atomically
/// writes the cache file (mode 0600).
///
/// Callers should treat write failures as non-fatal (warn + keep serving).
pub fn save(data_dir: &Path, payload: &CachePayload) -> io::Result<()> {
    let dir = data_dir.join("clients");
    create_dir_private(&dir)?;
    let path = cache_path(data_dir);
    let wire = DiskCache::from_payload(payload);
    let bytes =
        serde_json::to_vec(&wire).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    atomic_write(&path, &bytes)
}

fn create_dir_private(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(dir)?.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

fn tmp_path(path: &Path) -> PathBuf {
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut name = std::ffi::OsString::from(".");
    name.push(path.file_name().unwrap_or_default());
    name.push(format!(".{}.{n}.tmp", std::process::id()));
    path.with_file_name(name)
}

fn create_private_new(path: &Path) -> io::Result<fs::File> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = tmp_path(path);
    let result = (|| {
        let mut file = create_private_new(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, path)
    })();
    match result {
        Ok(()) => {
            if let Some(dir) = path.parent() {
                #[cfg(unix)]
                if let Ok(d) = fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
            Ok(())
        }
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

// --- wire format ----------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct DiskCache {
    version: u32,
    state: DiskState,
    observations: Vec<DiskObs>,
    networks: Vec<DiskNet>,
}

#[derive(Serialize, Deserialize)]
struct DiskState {
    labels: Vec<(String, String)>,
    retained: Vec<DiskRetained>,
    ipv6_last_seen: Vec<(String, Vec<(String, u64)>)>,
    last_unifi: Vec<DiskRetained>,
}

#[derive(Serialize, Deserialize)]
struct DiskRetained {
    id: String,
    display_name: String,
    macs: Vec<String>,
    addresses: Vec<String>,
    network_id: Option<String>,
    last_seen: Option<u64>,
    missing_since: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct DiskObs {
    id: String,
    display_name: String,
    macs: Vec<String>,
    addresses: Vec<String>,
    network_id: Option<String>,
    last_seen: Option<u64>,
    online: bool,
}

#[derive(Serialize, Deserialize)]
struct DiskNet {
    id: String,
    name: String,
    vlan_id: Option<u16>,
    ipv4_prefix: Option<String>,
    ipv6_prefix: Option<String>,
    domain_name: Option<String>,
}

impl DiskCache {
    fn from_payload(p: &CachePayload) -> Self {
        Self {
            version: CACHE_VERSION,
            state: DiskState::from_state(&p.state),
            observations: p.observations.iter().map(DiskObs::from_obs).collect(),
            networks: p.networks.iter().map(DiskNet::from_net).collect(),
        }
    }

    fn into_payload(self) -> Result<CachePayload, String> {
        Ok(CachePayload {
            state: self.state.into_state()?,
            observations: self
                .observations
                .into_iter()
                .map(DiskObs::into_obs)
                .collect::<Result<_, _>>()?,
            networks: self
                .networks
                .into_iter()
                .map(DiskNet::into_net)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl DiskState {
    fn from_state(s: &State) -> Self {
        Self {
            labels: s
                .labels
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.clone()))
                .collect(),
            retained: s
                .retained
                .iter()
                .map(|(id, r)| DiskRetained::from_retained(id, r))
                .collect(),
            ipv6_last_seen: s
                .ipv6_last_seen
                .iter()
                .map(|(id, map)| {
                    (
                        id.as_str().to_owned(),
                        map.iter()
                            .map(|(ip, t)| (ip.to_string(), system_time_secs(*t)))
                            .collect(),
                    )
                })
                .collect(),
            last_unifi: s
                .last_unifi
                .iter()
                .map(|(id, r)| DiskRetained::from_retained(id, r))
                .collect(),
        }
    }

    fn into_state(self) -> Result<State, String> {
        let mut labels = HashMap::new();
        for (id, lab) in self.labels {
            let id = ClientId::new(&id).map_err(|e| e.to_string())?;
            labels.insert(id, lab);
        }
        let mut retained = HashMap::new();
        for r in self.retained {
            let (id, client) = r.into_retained()?;
            retained.insert(id, client);
        }
        let mut ipv6_last_seen = HashMap::new();
        for (id, entries) in self.ipv6_last_seen {
            let id = ClientId::new(&id).map_err(|e| e.to_string())?;
            let mut map = HashMap::new();
            for (ip, secs) in entries {
                let ip = IpAddr::from_str(&ip).map_err(|e| e.to_string())?;
                map.insert(ip, secs_to_system_time(secs));
            }
            ipv6_last_seen.insert(id, map);
        }
        let mut last_unifi = HashMap::new();
        for r in self.last_unifi {
            let (id, client) = r.into_retained()?;
            last_unifi.insert(id, client);
        }
        Ok(State {
            labels,
            retained,
            ipv6_last_seen,
            last_unifi,
        })
    }
}

impl DiskRetained {
    fn from_retained(id: &ClientId, r: &RetainedClient) -> Self {
        Self {
            id: id.as_str().to_owned(),
            display_name: r.display_name.clone(),
            macs: r.macs.iter().map(ToString::to_string).collect(),
            addresses: r.addresses.iter().map(ToString::to_string).collect(),
            network_id: r.network_id.clone(),
            last_seen: r.last_seen.map(system_time_secs),
            missing_since: r.missing_since.map(system_time_secs),
        }
    }

    fn into_retained(self) -> Result<(ClientId, RetainedClient), String> {
        let id = ClientId::new(&self.id).map_err(|e| e.to_string())?;
        let macs = self
            .macs
            .iter()
            .map(|m| MacAddr::parse(m).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let addresses = self
            .addresses
            .iter()
            .map(|a| IpAddr::from_str(a).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            id,
            RetainedClient {
                display_name: self.display_name,
                macs,
                addresses,
                network_id: self.network_id,
                last_seen: self.last_seen.map(secs_to_system_time),
                missing_since: self.missing_since.map(secs_to_system_time),
            },
        ))
    }
}

impl DiskObs {
    fn from_obs(o: &UnifiObservation) -> Self {
        Self {
            id: o.id.as_str().to_owned(),
            display_name: o.display_name.clone(),
            macs: o.macs.iter().map(ToString::to_string).collect(),
            addresses: o.addresses.iter().map(ToString::to_string).collect(),
            network_id: o.network_id.clone(),
            last_seen: o.last_seen.map(system_time_secs),
            online: o.online,
        }
    }

    fn into_obs(self) -> Result<UnifiObservation, String> {
        let id = ClientId::new(&self.id).map_err(|e| e.to_string())?;
        let macs = self
            .macs
            .iter()
            .map(|m| MacAddr::parse(m).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let addresses = self
            .addresses
            .iter()
            .map(|a| IpAddr::from_str(a).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(UnifiObservation {
            id,
            display_name: self.display_name,
            macs,
            addresses,
            network_id: self.network_id,
            last_seen: self.last_seen.map(secs_to_system_time),
            online: self.online,
        })
    }
}

impl DiskNet {
    fn from_net(n: &NetworkInfo) -> Self {
        Self {
            id: n.id.clone(),
            name: n.name.clone(),
            vlan_id: n.vlan_id,
            ipv4_prefix: n.ipv4_prefix.map(|p| p.to_string()),
            ipv6_prefix: n.ipv6_prefix.map(|p| p.to_string()),
            domain_name: n.domain_name.clone(),
        }
    }

    fn into_net(self) -> Result<NetworkInfo, String> {
        Ok(NetworkInfo {
            id: self.id,
            name: self.name,
            vlan_id: self.vlan_id,
            ipv4_prefix: self
                .ipv4_prefix
                .as_deref()
                .map(IpNet::from_str)
                .transpose()
                .map_err(|e| e.to_string())?,
            ipv6_prefix: self
                .ipv6_prefix
                .as_deref()
                .map(IpNet::from_str)
                .transpose()
                .map_err(|e| e.to_string())?,
            domain_name: self.domain_name,
        })
    }
}

fn system_time_secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn secs_to_system_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::ClientId;

    #[test]
    fn round_trip_empty() {
        let dir =
            std::env::temp_dir().join(format!("dnscraft-clients-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let payload = CachePayload {
            state: State::default(),
            observations: vec![],
            networks: vec![],
        };
        save(&dir, &payload).unwrap();
        let loaded = load(&dir).unwrap().unwrap();
        assert_eq!(loaded, payload);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(cache_path(&dir)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_wrong_version_ignored() {
        let dir =
            std::env::temp_dir().join(format!("dnscraft-clients-cache-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("clients")).unwrap();
        fs::write(cache_path(&dir), b"{not json").unwrap();
        assert!(load(&dir).unwrap().is_none());

        fs::write(
            cache_path(&dir),
            br#"{"version":99,"state":{"labels":[],"retained":[],"ipv6_last_seen":[],"last_unifi":[]},"observations":[],"networks":[]}"#,
        )
        .unwrap();
        assert!(load(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_survive_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "dnscraft-clients-cache-labels-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        let mut state = State::default();
        state
            .labels
            .insert(ClientId::new("abc").unwrap(), "phone".into());
        let payload = CachePayload {
            state,
            observations: vec![UnifiObservation {
                id: ClientId::new("abc").unwrap(),
                display_name: "Phone".into(),
                macs: vec![MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap()],
                addresses: vec![IpAddr::from_str("198.51.100.10").unwrap()],
                network_id: Some("net1".into()),
                last_seen: Some(SystemTime::UNIX_EPOCH + Duration::from_secs(100)),
                online: true,
            }],
            networks: vec![NetworkInfo {
                id: "net1".into(),
                name: "IoT".into(),
                vlan_id: Some(40),
                ipv4_prefix: Some(IpNet::from_str("198.51.100.0/24").unwrap()),
                ipv6_prefix: None,
                domain_name: Some("iot.home.arpa".into()),
            }],
        };
        save(&dir, &payload).unwrap();
        let loaded = load(&dir).unwrap().unwrap();
        assert_eq!(
            loaded
                .state
                .labels
                .get(&ClientId::new("abc").unwrap())
                .map(String::as_str),
            Some("phone")
        );
        assert_eq!(loaded.observations.len(), 1);
        assert_eq!(
            loaded.networks[0].domain_name.as_deref(),
            Some("iot.home.arpa")
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
