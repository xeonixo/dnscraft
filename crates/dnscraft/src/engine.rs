//! Builds the policy engine (resolver + filtering + policy) for the binary.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterSetConfig, ListBodies, ListId, ManualClock, SetId,
    SnapshotBuilder,
};
use dnscraft_policy::{
    NoClients, PolicyConfig, PolicyEngine, ProfileConfig, ProfileId, SafeSearchConfig, ViewConfig,
    ViewId,
};
use dnscraft_resolver::{Resolver, ResolverConfig};

use crate::Error;

/// Filter store with no list bodies (filtering is effectively disabled).
#[derive(Debug, Default)]
struct EmptyBodies;

impl ListBodies for EmptyBodies {
    fn body(&self, _id: &ListId) -> Option<Arc<str>> {
        None
    }
}

fn empty_filter() -> Result<Arc<FilterEngine>, Error> {
    let set_id = SetId::new("default")
        .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in filter set id"))?;
    let cfg = FilterConfig {
        lists: Vec::new(),
        sets: vec![FilterSetConfig::new(set_id, "default")],
        ..FilterConfig::default()
    };
    let snapshot = SnapshotBuilder::new(Arc::new(EmptyBodies) as Arc<dyn ListBodies>)
        .build(&cfg)
        .map_err(|_| Error::startup("dnscraft.startup.policy", "empty filter snapshot"))?;
    Ok(Arc::new(FilterEngine::from_snapshot(snapshot)))
}

/// Builds a policy engine from the built-in root hints and a single default
/// profile/view (no filter lists, no client directory, DNSSEC per resolver).
pub async fn build_engine() -> Result<Arc<PolicyEngine>, Error> {
    let resolver = Arc::new(
        Resolver::new(ResolverConfig {
            query_timeout: Duration::from_secs(5),
            ..ResolverConfig::default()
        })
        .await
        .map_err(|e| Error::startup("dnscraft.startup.resolver", format!("resolver: {e}")))?,
    );

    let default = SetId::new("default")
        .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in set id"))?;
    let profile_id = ProfileId::new("default")
        .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in profile id"))?;
    let view_id = ViewId::new("default")
        .map_err(|_| Error::startup("dnscraft.startup.policy", "built-in view id"))?;

    let profile = ProfileConfig {
        id: profile_id.clone(),
        filter_set: default,
        suppress_aaaa: false,
        firefox_canary: false,
        icloud_private_relay: false,
        rebind: Some(true),
        rebind_exceptions: Vec::new(),
        forward_zones: None,
        safesearch: SafeSearchConfig::default(),
        schedules: Vec::new(),
    };
    let view = ViewConfig {
        id: view_id,
        is_default: true,
        subnets: Vec::new(),
        client_ids: Vec::new(),
        records: Vec::new(),
        profile: profile_id,
    };
    let cfg = PolicyConfig {
        views: vec![view],
        profiles: vec![profile],
        ..PolicyConfig::default()
    };

    let clock = Arc::new(ManualClock::new(SystemTime::now()));
    let engine = PolicyEngine::new(cfg, empty_filter()?, resolver, Arc::new(NoClients), clock)
        .map_err(|e| Error::startup("dnscraft.startup.policy", format!("policy: {e}")))?;
    Ok(Arc::new(engine))
}
