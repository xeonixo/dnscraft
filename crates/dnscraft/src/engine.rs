//! Builds the runtime engines (resolver, filtering, clients, policy, TLS) for
//! the binary from the parsed TOML config.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_clients::{ClientEngine, ClientLookup};
use dnscraft_filtering::{
    Clock, FilterConfig, FilterEngine, FilterSetConfig, ListStore, SetId, StoreConfig,
};
use dnscraft_policy::{
    ClientDirectory, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, SafeSearchConfig,
    ViewConfig, ViewId,
};
use dnscraft_proto::Name;
use dnscraft_resolver::{Resolver, ResolverConfig};
use dnscraft_tls::TlsEngine;

use crate::{Config, Error};

/// Query timeout kept for configs that leave [`ResolverConfig::query_timeout`]
/// at its default (the binary used 5 s before the resolver was configurable).
const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Runtime engines assembled from config.
///
/// Kept public so later phases (control-api assembly) can reach the live
/// engines; the config-apply adapters use the same handles.
pub struct Engines {
    /// Filtering engine (inherited by the policy engine and the list scheduler).
    pub filtering: Arc<FilterEngine>,
    /// Client directory engine.
    pub clients: Arc<ClientEngine>,
    /// Policy engine wiring the resolver, filter, and client directory.
    pub policy: Arc<PolicyEngine>,
    /// TLS engine when `[tls]` is configured; its background renewal/DynDNS
    /// tasks live as long as this value is kept.
    pub tls: Option<Arc<TlsEngine>>,
}

/// [`ClientDirectory`] over the live [`ClientEngine`] snapshot.
///
/// Lives in the binary because it needs both the clients and policy crates.
#[derive(Debug)]
struct EngineClients {
    engine: Arc<ClientEngine>,
}

impl ClientDirectory for EngineClients {
    fn addresses(&self, fqdn: &Name) -> Option<Arc<[IpAddr]>> {
        let lookup: Arc<ClientLookup> = self.engine.lookup();
        lookup
            .by_name(&fqdn.to_string())
            .map(|c| c.addresses.clone())
    }

    fn reverse(&self, ip: IpAddr) -> Option<Arc<str>> {
        self.engine.lookup().reverse(ip).map(Arc::from)
    }

    fn local_domains(&self) -> Arc<[String]> {
        self.engine.lookup().local_domains()
    }
}

/// Builds the policy engine from the default module configs.
///
/// Convenience for callers (and tests) that need only the policy engine; the
/// binary uses [`build_engines`] with the parsed TOML config.
pub async fn build_engine(clock: Arc<dyn Clock>) -> Result<Arc<PolicyEngine>, Error> {
    Ok(build_engines(&Config::default(), clock).await?.policy)
}

/// Builds every engine from `config`.
///
/// Each construction failure maps to a distinct stable
/// `dnscraft.startup.<module>` code. The TLS engine is built only when
/// `[tls]` names a public domain; otherwise the caller may fall back to the
/// environment PEM bootstrap.
pub(crate) async fn build_engines(
    config: &Config,
    clock: Arc<dyn Clock>,
) -> Result<Engines, Error> {
    // AS3: real resolver. A config that leaves `query_timeout` at the module
    // default keeps the binary's historical 5 s; an explicit value wins.
    let resolver = Arc::new(
        Resolver::new(resolver_config(&config.resolver))
            .await
            .map_err(|e| Error::startup("dnscraft.startup.resolver", format!("resolver: {e}")))?,
    );

    let data_dir = engine_data_dir(config);

    // AS4 + AS6 fallback: a minimal config (no sets/views) still gets one
    // default set, profile, and view, as the binary always had.
    let (filtering, policy_config) =
        default_filter_and_policy(config.filtering.clone(), config.policy.clone())?;
    let store = ListStore::open_with(
        &data_dir,
        StoreConfig {
            max_body_bytes: filtering.max_list_size_bytes(),
            ..StoreConfig::default()
        },
        Arc::clone(&clock),
    )
    .map_err(|e| Error::startup("dnscraft.startup.filtering", format!("filter store: {e}")))?;
    let filter = FilterEngine::new(filtering, store, Arc::clone(&clock))
        .map_err(|e| Error::startup("dnscraft.startup.filtering", format!("filtering: {e}")))?;

    // AS5: real client directory, adapted to the policy trait.
    let clients_engine =
        ClientEngine::new(config.clients.clone(), data_dir.clone(), Arc::clone(&clock))
            .map_err(|e| Error::startup("dnscraft.startup.clients", format!("clients: {e}")))?;
    let clients: Arc<dyn ClientDirectory> = Arc::new(EngineClients {
        engine: Arc::clone(&clients_engine),
    });

    // AS6: real policy over the resolver, filter, and client directory.
    let policy = PolicyEngine::new(
        policy_config,
        Arc::clone(&filter),
        resolver,
        clients,
        Arc::clone(&clock),
    )
    .map_err(|e| Error::startup("dnscraft.startup.policy", format!("policy: {e}")))?;

    // AS7: real TLS engine. An empty `[tls]` public domain means the section
    // is not configured (its type default enables ACME/DynDNS with no domain).
    let tls = if config.tls.public_domain.trim().is_empty() {
        None
    } else {
        Some(Arc::new(
            TlsEngine::open(config.tls.clone(), &data_dir, clock)
                .map_err(|e| Error::startup("dnscraft.startup.tls", format!("tls: {e}")))?,
        ))
    };

    Ok(Engines {
        filtering: filter,
        clients: clients_engine,
        policy: Arc::new(policy),
        tls,
    })
}

/// Applies the binary's query-timeout rule: a value equal to the module
/// default is treated as "not configured" and keeps the historical 5 s.
fn resolver_config(config: &ResolverConfig) -> ResolverConfig {
    let mut config = config.clone();
    if config.query_timeout == ResolverConfig::default().query_timeout {
        config.query_timeout = DEFAULT_QUERY_TIMEOUT;
    }
    config
}

/// Persistent engine directory: `data_dir` when configured, otherwise a
/// per-process directory under the system temp dir so a minimal config still
/// boots and two instances never fight over the same SQLite file.
pub(crate) fn engine_data_dir(config: &Config) -> PathBuf {
    if let Some(dir) = config.data_dir() {
        return dir.to_path_buf();
    }
    // ponytail: no data_dir configured — keep state in a per-process temp path.
    // Set `data_dir` for real deployments (SQLite, TLS, filter bodies).
    let dir = std::env::temp_dir().join(format!("dnscraft-{}", std::process::id()));
    tracing::warn!(
        "data_dir is not configured; engine state will be kept in {} (not persisted)",
        dir.display()
    );
    dir
}

/// Adds one default set/profile/view when the config omits views entirely.
///
/// A configured policy is left untouched (and validated by the policy engine).
fn default_filter_and_policy(
    mut filtering: FilterConfig,
    mut policy: PolicyConfig,
) -> Result<(FilterConfig, PolicyConfig), Error> {
    if !policy.views.is_empty() {
        return Ok((filtering, policy));
    }
    if filtering.sets.is_empty() {
        let id = SetId::new("default")
            .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in filter set id"))?;
        filtering.sets.push(FilterSetConfig::new(id, "default"));
    }
    let profile_id = match policy.profiles.first() {
        Some(profile) => profile.id.clone(),
        None => {
            let filter_set = filtering
                .sets
                .first()
                .map(|set| set.id.clone())
                .ok_or_else(|| Error::startup("dnscraft.startup.policy", "no filter set"))?;
            let id = ProfileId::new("default")
                .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in profile id"))?;
            policy.profiles.push(ProfileConfig {
                id: id.clone(),
                filter_set,
                suppress_aaaa: false,
                firefox_canary: false,
                icloud_private_relay: false,
                rebind: None,
                rebind_exceptions: Vec::new(),
                forward_zones: None,
                safesearch: SafeSearchConfig::default(),
                schedules: Vec::new(),
            });
            id
        }
    };
    let view_id = ViewId::new("default")
        .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in view id"))?;
    policy.views.push(ViewConfig {
        id: view_id,
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: Vec::new(),
        profile: profile_id,
    });
    Ok((filtering, policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolver_timeout_keeps_five_seconds_only_at_the_module_default() {
        let default = ResolverConfig::default();
        assert_eq!(
            resolver_config(&default).query_timeout,
            DEFAULT_QUERY_TIMEOUT
        );

        let explicit = ResolverConfig {
            query_timeout: Duration::from_secs(2),
            ..ResolverConfig::default()
        };
        assert_eq!(
            resolver_config(&explicit).query_timeout,
            Duration::from_secs(2)
        );
    }
}
