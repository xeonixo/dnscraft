//! Known-tracker database (name and category per domain).
//!
//! Enrichment only: it labels a domain for the query log and never blocks
//! anything. The file is the `trackers.json` that AdGuard Home ships (derived
//! from whotracks.me, CC BY-NC-SA 4.0). It is **downloaded at runtime** like a
//! filter list and cached under the services directory; it is never committed
//! or embedded.
//!
//! Without a cached copy every lookup returns `None`. A malformed update keeps
//! the previous good copy.

use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;

use crate::fetch::{FetchOutcome, Fetcher};
use crate::store::ListStore;

/// Default URL of the tracker database (not bundled).
pub const TRACKERS_URL: &str = "https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/client/src/helpers/trackers/trackers.json";

/// On-disk stem of the cached body (`trackers.json` in the services dir).
pub const TRACKERS_STEM: &str = "trackers";

/// Maximum accepted size of the tracker database.
pub const MAX_TRACKERS_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// One tracker as shown next to a domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackerInfo {
    /// Tracker name (for example `Google Analytics`).
    pub name: String,
    /// Category id (for example `advertising`, `site_analytics`, `cdn`).
    pub category: String,
    /// Tracker home page, when known.
    pub url: Option<String>,
}

/// Parsed tracker database.
#[derive(Clone, Debug, Default)]
pub struct TrackerDb {
    trackers: Vec<Arc<TrackerInfo>>,
    /// Lowercase registered or sub-domain → index into `trackers`.
    domains: HashMap<String, usize>,
}

impl TrackerDb {
    /// Parses `trackers.json`; domains pointing at an unknown tracker are skipped.
    pub fn parse(json: &str) -> Result<Self, String> {
        if json.len() as u64 > MAX_TRACKERS_BODY_BYTES {
            return Err(format!(
                "trackers.json exceeds {MAX_TRACKERS_BODY_BYTES} bytes"
            ));
        }
        let raw: RawFile = serde_json::from_str(json).map_err(|e| format!("trackers.json: {e}"))?;
        let mut trackers = Vec::new();
        let mut by_id = HashMap::new();
        for (id, t) in raw.trackers {
            let name = t.name.trim();
            if name.is_empty() {
                continue;
            }
            let category = t
                .category_id
                .and_then(|c| raw.categories.get(&c.to_string()))
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned());
            by_id.insert(id, trackers.len());
            trackers.push(Arc::new(TrackerInfo {
                name: name.to_owned(),
                category,
                url: t.url.filter(|u| u.starts_with("http")),
            }));
        }
        let domains = raw
            .tracker_domains
            .into_iter()
            .filter_map(|(d, id)| Some((d.trim().to_ascii_lowercase(), *by_id.get(&id)?)))
            .collect::<HashMap<_, _>>();
        if domains.is_empty() {
            return Err("trackers.json: no tracker domains".to_owned());
        }
        Ok(Self { trackers, domains })
    }

    /// Loads the cached body (no network). `None` when absent or unusable.
    pub fn load_cached(store: &ListStore) -> Option<Self> {
        let body = store.read_services_body(TRACKERS_STEM).ok()??;
        Self::parse(&body)
            .inspect_err(|e| tracing::warn!(error = %e, "cached tracker database unusable"))
            .ok()
    }

    /// Looks `name` up by its longest known suffix (never a bare TLD).
    pub fn lookup(&self, name: &str) -> Option<&TrackerInfo> {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        let mut rest = name.as_str();
        while rest.contains('.') {
            if let Some(&i) = self.domains.get(rest) {
                return Some(&self.trackers[i]);
            }
            rest = rest.split_once('.')?.1;
        }
        None
    }

    /// Number of known tracker domains.
    pub fn len(&self) -> usize {
        self.domains.len()
    }

    /// Whether no tracker domain is known.
    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }
}

/// Downloads the database. `Some` only when a new, valid body was stored.
pub(crate) async fn update_trackers(
    fetcher: &Fetcher,
    store: &ListStore,
    url: &str,
) -> Option<TrackerDb> {
    let outcome = fetcher
        .fetch_and_store_services(
            store,
            TRACKERS_STEM,
            url,
            MAX_TRACKERS_BODY_BYTES,
            &|body| TrackerDb::parse(body).map(|_| ()),
        )
        .await;
    match outcome {
        FetchOutcome::Updated { body, .. } => TrackerDb::parse(&body).ok(),
        FetchOutcome::NotModified { .. } => None,
        FetchOutcome::Failed { error, .. } => {
            tracing::warn!(%error, "tracker database update failed; keeping the cached copy");
            None
        }
    }
}

#[derive(Deserialize)]
struct RawFile {
    #[serde(default)]
    categories: HashMap<String, String>,
    #[serde(default)]
    trackers: HashMap<String, RawTracker>,
    #[serde(default, rename = "trackerDomains")]
    tracker_domains: HashMap<String, String>,
}

#[derive(Deserialize)]
struct RawTracker {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "categoryId")]
    category_id: Option<i64>,
    #[serde(default)]
    url: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
        "categories": {"4": "advertising", "9": "cdn"},
        "trackers": {
            "ga": {"name": "Google Analytics", "categoryId": 4, "url": "https://analytics.google.com"},
            "cf": {"name": "Cloudflare", "categoryId": 9},
            "noname": {"name": " ", "categoryId": 4}
        },
        "trackerDomains": {
            "google-analytics.com": "ga",
            "static.cf.example": "cf",
            "x.example": "missing"
        }
    }"#;

    #[test]
    fn lookup_matches_longest_suffix_and_never_a_tld() {
        let db = TrackerDb::parse(SAMPLE).unwrap();
        let hit = db.lookup("WWW.Google-Analytics.com.").unwrap();
        assert_eq!(hit.name, "Google Analytics");
        assert_eq!(hit.category, "advertising");
        assert_eq!(hit.url.as_deref(), Some("https://analytics.google.com"));
        assert_eq!(db.lookup("a.static.cf.example").unwrap().category, "cdn");
        assert!(db.lookup("cf.example").is_none());
        assert!(db.lookup("com").is_none());
        assert!(db.lookup("x.example").is_none());
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn parse_rejects_garbage_and_empty_databases() {
        assert!(TrackerDb::parse("not json").is_err());
        assert!(TrackerDb::parse(r#"{"trackerDomains": {}}"#).is_err());
    }
}
