//! Builds the runtime engines (resolver, filtering, clients, policy, TLS) for
//! the binary from the parsed TOML config.

use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use dnscraft_api::{
    ClientEnricher, ClientView, ControlApiError, DirectoryClient, DirectoryExport, SyncSummary,
};
use dnscraft_clients::{
    ClientEngine, ClientLookup, ClientSource, Secret, networks_from_value, networks_to_value,
    observations_from_value, observations_to_value,
};
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
    /// Recursive resolver, shared with the policy engine. Read by the
    /// control API for upstream health and cache flush.
    pub resolver: Arc<Resolver>,
    /// Policy engine wiring the resolver, filter, and client directory.
    pub policy: Arc<PolicyEngine>,
    /// TLS engine when `[tls]` is configured; its background renewal/DynDNS
    /// tasks live as long as this value is kept.
    pub tls: Option<Arc<TlsEngine>>,
}

/// [`ClientDirectory`] over the live [`ClientEngine`] snapshot.
///
/// Lives in the binary because it needs both the clients and policy crates.
/// It also implements the query-log [`ClientEnricher`] over the same snapshot.
#[derive(Debug)]
pub(crate) struct EngineClients {
    pub(crate) engine: Arc<ClientEngine>,
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

/// Query-log view of a directory client: names, MACs, VLAN and parent domain.
impl ClientEnricher for EngineClients {
    fn by_ip(&self, ip: IpAddr) -> Option<ClientView> {
        let client = self.engine.lookup().by_ip(ip)?;
        Some(ClientView {
            id: client.id.as_str().to_owned(),
            display_name: client.display_name.clone(),
            source: source_name(client.source).to_owned(),
            macs: client.macs.iter().map(ToString::to_string).collect(),
            vlan_id: client.vlan.as_ref().map(|vlan| vlan.id),
            vlan_name: client.vlan.as_ref().map(|vlan| vlan.name.clone()),
            local_domain: (!client.local_domain.is_empty()).then(|| client.local_domain.clone()),
        })
    }
}

/// The public `source` string of a client (`"unifi"` or `"manual"`).
fn source_name(source: ClientSource) -> &'static str {
    match source {
        ClientSource::Manual => "manual",
        ClientSource::Unifi => "unifi",
    }
}

/// [`dnscraft_api::ClientDirectory`] over the live [`ClientEngine`] (GA6, GM3).
///
/// Serves `GET /api/v1/clients`, `POST /api/v1/clients/sync` and the MCP
/// `list_clients` tool from the same snapshot.
pub(crate) struct EngineDirectory {
    pub(crate) engine: Arc<ClientEngine>,
}

impl dnscraft_api::ClientDirectory for EngineDirectory {
    fn clients(&self) -> Vec<DirectoryClient> {
        self.engine
            .lookup()
            .clients()
            .iter()
            .map(|client| DirectoryClient {
                id: client.id.as_str().to_owned(),
                name: client.display_name.clone(),
                dns_label: client.dns_label.clone(),
                local_domain: client.local_domain.clone(),
                source: source_name(client.source),
                ips: client.addresses.to_vec(),
                macs: client.macs.iter().map(ToString::to_string).collect(),
                vlan: client.vlan.as_ref().map(|vlan| vlan.id),
                online: client.online,
                // ponytail: last_seen stays null; dnscraft-api keeps its RFC 3339
                // helper crate-private. Add it when that helper is exported.
                last_seen: None,
            })
            .collect()
    }

    // Same shape as the `async_trait` expansion of the trait method.
    fn sync<'life0, 'async_trait>(
        &'life0 self,
    ) -> Pin<Box<dyn Future<Output = Result<SyncSummary, ControlApiError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async move {
            let report = self
                .engine
                .sync_now()
                .await
                .map_err(|error| ControlApiError::Module {
                    code: error.code(),
                    params: None,
                })?;
            Ok(SyncSummary {
                generation: report.generation,
                rebuilt: report.rebuilt,
                client_count: report.client_count,
                ip_conflicts: report.ip_conflicts,
            })
        })
    }

    fn set_api_key(&self, key: Option<String>) {
        self.engine.set_api_key(key.map(Secret::new));
    }

    fn is_sync_owner(&self) -> bool {
        self.engine.is_sync_owner()
    }

    fn directory_export(&self) -> Option<DirectoryExport> {
        let profile_id = self.engine.bound_profile_id()?;
        let (obs, nets, generation) = self.engine.export_unifi_directory();
        Some(DirectoryExport {
            profile_id,
            generation,
            observations: observations_to_value(&obs),
            networks: networks_to_value(&nets),
        })
    }

    fn apply_directory_push<'life0, 'life1, 'async_trait>(
        &'life0 self,
        profile_id: &'life1 str,
        observations: serde_json::Value,
        networks: serde_json::Value,
    ) -> Pin<Box<dyn Future<Output = Result<(), ControlApiError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        let profile_id = profile_id.to_owned();
        Box::pin(async move {
            let obs = observations_from_value(&observations).map_err(|message| {
                ControlApiError::Module {
                    code: "clients.config.invalid",
                    params: Some(serde_json::json!({ "reason": message })),
                }
            })?;
            let nets =
                networks_from_value(&networks).map_err(|message| ControlApiError::Module {
                    code: "clients.config.invalid",
                    params: Some(serde_json::json!({ "reason": message })),
                })?;
            self.engine
                .apply_directory_push(&profile_id, obs, nets)
                .await
                .map_err(|error| ControlApiError::Module {
                    code: error.code(),
                    params: None,
                })?;
            Ok(())
        })
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
    // The node id decides which UniFi profile this node syncs as sync owner.
    let node_id = config
        .node_id()
        .map_err(|e| Error::startup("dnscraft.startup.node_id", format!("node_id: {e}")))?;
    let clients_engine = ClientEngine::new_with_secret_and_node(
        config.clients.clone(),
        data_dir.clone(),
        Arc::clone(&clock),
        None,
        node_id.as_str(),
    )
    .map_err(|e| Error::startup("dnscraft.startup.clients", format!("clients: {e}")))?;
    let clients: Arc<dyn ClientDirectory> = Arc::new(EngineClients {
        engine: Arc::clone(&clients_engine),
    });

    // AS6: real policy over the resolver, filter, and client directory.
    let policy = PolicyEngine::new(
        policy_config,
        Arc::clone(&filter),
        Arc::clone(&resolver),
        clients,
        Arc::clone(&clock),
    )
    .map_err(|e| Error::startup("dnscraft.startup.policy", format!("policy: {e}")))?;

    // AS7: real TLS engine. An empty `[tls]` public domain means the section
    // is not configured (its type default enables ACME/DynDNS with no domain).
    let tls = if config.tls.public_domain.trim().is_empty() {
        None
    } else {
        // A sub-node gets its certificate pushed by the master and never
        // orders one: the role is part of construction, so not even the
        // startup renewal can race a later `set_node_context`.
        let sub_node = config
            .cluster
            .as_ref()
            .is_some_and(|c| matches!(c.role, dnscraft_cluster::Role::SubNode));
        let engine = TlsEngine::open_for_role(config.tls.clone(), &data_dir, clock, sub_node)
            .map_err(|e| Error::startup("dnscraft.startup.tls", format!("tls: {e}")))?;
        engine.set_node_context(Some(node_id.as_str().to_owned()), !sub_node);
        Some(Arc::new(engine))
    };

    Ok(Engines {
        filtering: filter,
        clients: clients_engine,
        resolver,
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
pub(crate) fn default_filter_and_policy(
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
        nodes: Vec::new(),
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
