//! Blocked-services catalog from AdGuard HostlistsRegistry.
//!
//! The catalog (`services.json` + `services_i18n.json`) is **downloaded at
//! runtime** like a filter list and cached under
//! [`ListStore::services_dir`](crate::ListStore::services_dir). The data is
//! GPL-3.0: it is never committed or embedded in this crate.
//!
//! Without a cached catalog the feature is unavailable
//! ([`FilterEngine::services`](crate::FilterEngine::services) returns `None`).
//! A malformed update keeps the previous good catalog and reports
//! [`ServiceError::Malformed`].
//!
//! ## Error codes
//!
//! | Variant | Code |
//! |---|---|
//! | [`ServiceError::Malformed`] | `filter_services.malformed` |
//! | [`ServiceError::Io`] | `filter_services.io` |

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;

use crate::fetch::{FetchOutcome, Fetcher, MALFORMED_SERVICES_CODE};
use crate::store::{ListMeta, ListStore, StoreError};

/// Default URL of the HostlistsRegistry services catalog (not bundled).
pub const SERVICES_JSON_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/services.json";

/// Default URL of the HostlistsRegistry services i18n file (not bundled).
pub const SERVICES_I18N_URL: &str =
    "https://adguardteam.github.io/HostlistsRegistry/assets/services_i18n.json";

/// On-disk stem for the main catalog body (`services.json`).
pub const SERVICES_STEM: &str = "services";

/// On-disk stem for the i18n body (`services_i18n.json`).
pub const SERVICES_I18N_STEM: &str = "services_i18n";

/// A catalog parse or update failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ServiceError {
    /// The JSON is not a usable catalog (keep the previous good one).
    #[error("services catalog is malformed: {detail}")]
    Malformed {
        /// Short human detail for logs.
        detail: String,
    },
    /// Reading or writing the cached catalog failed.
    #[error("services catalog I/O: {0}")]
    Io(String),
}

impl ServiceError {
    /// Stable, locale-neutral code exposed through the API.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Malformed { .. } => "filter_services.malformed",
            Self::Io(_) => "filter_services.io",
        }
    }
}

impl From<StoreError> for ServiceError {
    fn from(e: StoreError) -> Self {
        Self::Io(e.to_string())
    }
}

/// One blocked service as exposed to the UI and to snapshot building.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Stable id (for example `tiktok`).
    pub id: Arc<str>,
    /// Default display name from `services.json` (English in the upstream file).
    pub name: String,
    /// Group id (for example `social_network`).
    pub group: String,
    /// Icon SVG string as provided by the catalog; empty when absent or when
    /// larger than [`MAX_ICON_BYTES`] (dropped).
    ///
    /// **Untrusted remote content.** Consumers must render it only through
    /// `<img src="data:image/svg+xml,…">` (percent-encoded), never inline in
    /// the DOM, and must HTML-escape [`Self::name`] and [`Self::group`].
    pub icon: String,
    /// Adblock-syntax rules, one per line (joined for parsing).
    pub(crate) rules_body: Arc<str>,
}

impl ServiceInfo {
    /// The joined rule text used when this service is enabled in a set.
    pub fn rules_body(&self) -> &str {
        &self.rules_body
    }
}

/// Counts from a lenient catalog parse.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceParseStats {
    /// Entries accepted into the catalog.
    pub accepted: usize,
    /// Entries skipped because required fields were missing or empty.
    pub skipped_malformed: usize,
    /// Services skipped because the catalog holds more than [`MAX_SERVICES`].
    pub skipped_over_limit: usize,
    /// Rules dropped because a service has more than [`MAX_RULES_PER_SERVICE`].
    pub skipped_rules: usize,
    /// Icons dropped because they exceed [`MAX_ICON_BYTES`].
    pub dropped_icons: usize,
}

/// Maximum accepted size of `services.json` and `services_i18n.json`.
pub const MAX_SERVICES_BODY_BYTES: u64 = 4 * 1024 * 1024;

/// Maximum number of services taken from one catalog (excess is skipped).
pub const MAX_SERVICES: usize = 2_000;

/// Maximum number of rules taken from one service (excess is skipped).
pub const MAX_RULES_PER_SERVICE: usize = 1_000;

/// Maximum size of one `icon_svg` in bytes (a larger icon is dropped).
pub const MAX_ICON_BYTES: usize = 16 * 1024;

/// Parsed blocked-services catalog.
///
/// Clone is cheap (`Arc` internals). Translations come from `services_i18n.json`
/// when present; missing locales fall back to English (`en`), then to the
/// default `name` / group id from `services.json`.
#[derive(Clone, Debug)]
pub struct ServiceCatalog {
    services: Vec<ServiceInfo>,
    by_id: HashMap<Arc<str>, usize>,
    /// `service_id → locale → name`
    service_names: HashMap<String, HashMap<String, String>>,
    /// `group_id → locale → name`
    group_names: HashMap<String, HashMap<String, String>>,
    /// Group ids in catalog order (from `groups` when present).
    groups: Vec<String>,
    stats: ServiceParseStats,
}

impl ServiceCatalog {
    /// Parses `services.json` (+ optional `services_i18n.json`).
    ///
    /// Unknown JSON fields are ignored. Individual service objects that lack a
    /// non-empty `id` or that are not objects are skipped and counted. A
    /// completely unusable top-level document returns [`ServiceError::Malformed`].
    pub fn parse(services_json: &str, i18n_json: Option<&str>) -> Result<Self, ServiceError> {
        if services_json.len() as u64 > MAX_SERVICES_BODY_BYTES {
            return Err(ServiceError::Malformed {
                detail: format!("services.json exceeds {MAX_SERVICES_BODY_BYTES} bytes"),
            });
        }
        let raw: RawServicesFile =
            serde_json::from_str(services_json).map_err(|e| ServiceError::Malformed {
                detail: format!("services.json: {e}"),
            })?;
        let Some(entries) = raw.blocked_services else {
            return Err(ServiceError::Malformed {
                detail: "services.json: missing blocked_services".into(),
            });
        };

        let mut services = Vec::new();
        let mut by_id = HashMap::new();
        let mut stats = ServiceParseStats::default();

        for value in entries {
            if services.len() >= MAX_SERVICES {
                stats.skipped_over_limit += 1;
                continue;
            }
            match parse_service_entry(value, &mut stats) {
                Some(info) => {
                    let id = Arc::clone(&info.id);
                    if by_id.contains_key(&id) {
                        stats.skipped_malformed += 1;
                        continue;
                    }
                    by_id.insert(id, services.len());
                    services.push(info);
                    stats.accepted += 1;
                }
                None => stats.skipped_malformed += 1,
            }
        }

        let mut group_names = HashMap::new();
        let mut service_names = HashMap::new();
        let mut groups: Vec<String> = raw
            .groups
            .unwrap_or_default()
            .into_iter()
            .filter_map(|g| {
                let id = g.id?.trim().to_owned();
                (!id.is_empty()).then_some(id)
            })
            .collect();

        let i18n_json = i18n_json.filter(|s| {
            let ok = s.len() as u64 <= MAX_SERVICES_BODY_BYTES;
            if !ok {
                tracing::warn!(
                    code = "filter_services.malformed",
                    "services_i18n.json too large; using English names only"
                );
            }
            ok
        });
        if let Some(i18n) = i18n_json {
            match serde_json::from_str::<RawI18nFile>(i18n) {
                Ok(raw_i18n) => {
                    if let Some(g) = raw_i18n.groups {
                        group_names = flatten_locale_names(g);
                    }
                    if let Some(s) = raw_i18n.services {
                        service_names = flatten_locale_names(s);
                    }
                }
                Err(e) => {
                    // i18n is optional enrichment; a bad file does not discard services.
                    tracing::warn!(
                        error = %e,
                        code = "filter_services.malformed",
                        "services_i18n.json malformed; using English names only"
                    );
                }
            }
        }

        // Ensure every service group appears in `groups` even if omitted upstream.
        for s in &services {
            if !s.group.is_empty() && !groups.iter().any(|g| g == &s.group) {
                groups.push(s.group.clone());
            }
        }

        Ok(Self {
            services,
            by_id,
            service_names,
            group_names,
            groups,
            stats,
        })
    }

    /// Loads the catalog from the store cache (no network).
    ///
    /// Returns `Ok(None)` when `services.json` is absent. A present but
    /// unusable body yields [`ServiceError::Malformed`].
    pub fn load_cached(store: &ListStore) -> Result<Option<Self>, ServiceError> {
        let Some(body) = store.read_services_body(SERVICES_STEM)? else {
            return Ok(None);
        };
        let i18n = store.read_services_body(SERVICES_I18N_STEM)?;
        Self::parse(&body, i18n.as_deref()).map(Some)
    }

    /// All services in catalog order.
    pub fn services(&self) -> &[ServiceInfo] {
        &self.services
    }

    /// Group ids known to the catalog.
    pub fn groups(&self) -> &[String] {
        &self.groups
    }

    /// Parse statistics for the last successful parse.
    pub fn stats(&self) -> &ServiceParseStats {
        &self.stats
    }

    /// Looks up a service by id.
    pub fn get(&self, id: &str) -> Option<&ServiceInfo> {
        self.by_id.get(id).map(|&i| &self.services[i])
    }

    /// Display name for `id` in `locale`, falling back to `en`, then the
    /// default name from `services.json`.
    pub fn translated_name(&self, id: &str, locale: &str) -> Option<&str> {
        let info = self.get(id)?;
        Some(pick_translation(
            self.service_names.get(id),
            locale,
            &info.name,
        ))
    }

    /// Display name for `group` in `locale`, falling back to `en`, then the
    /// group id itself.
    pub fn translated_group<'a>(&'a self, group: &'a str, locale: &str) -> &'a str {
        if let Some(map) = self.group_names.get(group) {
            if let Some(n) = map.get(locale)
                && !n.is_empty()
            {
                return n.as_str();
            }
            if locale != "en"
                && let Some(n) = map.get("en")
                && !n.is_empty()
            {
                return n.as_str();
            }
        }
        group
    }
}

fn pick_translation<'a>(
    map: Option<&'a HashMap<String, String>>,
    locale: &str,
    fallback: &'a str,
) -> &'a str {
    let Some(map) = map else {
        return fallback;
    };
    if let Some(n) = map.get(locale) {
        if !n.is_empty() {
            return n;
        }
    }
    if locale != "en"
        && let Some(n) = map.get("en")
        && !n.is_empty()
    {
        return n;
    }
    fallback
}

fn flatten_locale_names(
    raw: HashMap<String, HashMap<String, RawLocaleName>>,
) -> HashMap<String, HashMap<String, String>> {
    let mut out = HashMap::new();
    for (id, locales) in raw {
        let mut m = HashMap::new();
        for (locale, entry) in locales {
            if let Some(name) = entry.name {
                let name = name.trim();
                if !name.is_empty() {
                    m.insert(locale, name.to_owned());
                }
            }
        }
        if !m.is_empty() {
            out.insert(id, m);
        }
    }
    out
}

/// Service ids use the [`ListId`](crate::ListId) charset plus `_` (real
/// catalog ids such as `amazon_streaming` contain underscores).
fn valid_service_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn parse_service_entry(
    value: serde_json::Value,
    stats: &mut ServiceParseStats,
) -> Option<ServiceInfo> {
    let obj = match value {
        serde_json::Value::Object(m) => m,
        _ => return None,
    };
    let id = obj.get("id")?.as_str()?.trim();
    if !valid_service_id(id) {
        return None;
    }
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or(id)
        .trim()
        .to_owned();
    let group = obj
        .get("group")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .trim()
        .to_owned();
    let mut icon = obj
        .get("icon_svg")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    if icon.len() > MAX_ICON_BYTES {
        icon.clear();
        stats.dropped_icons += 1;
    }
    let mut rules = match obj.get("rules") {
        Some(serde_json::Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>(),
        // Missing rules → empty (UI-only entry). Wrong type → malformed.
        None => Vec::new(),
        Some(_) => return None,
    };
    if rules.len() > MAX_RULES_PER_SERVICE {
        stats.skipped_rules += rules.len() - MAX_RULES_PER_SERVICE;
        rules.truncate(MAX_RULES_PER_SERVICE);
    }
    // A service with no rules is still listed (UI) but contributes nothing.
    let rules_body: Arc<str> = Arc::from(rules.join("\n"));
    Some(ServiceInfo {
        id: Arc::from(id),
        name,
        group,
        icon,
        rules_body,
    })
}

#[derive(Debug, Deserialize)]
struct RawServicesFile {
    blocked_services: Option<Vec<serde_json::Value>>,
    groups: Option<Vec<RawGroup>>,
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawI18nFile {
    groups: Option<HashMap<String, HashMap<String, RawLocaleName>>>,
    /// Optional; upstream currently ships group translations only.
    services: Option<HashMap<String, HashMap<String, RawLocaleName>>>,
}

#[derive(Debug, Deserialize)]
struct RawLocaleName {
    name: Option<String>,
}

/// Result of refreshing the services catalog from the network (or test URLs).
#[derive(Debug)]
pub struct ServicesUpdateReport {
    /// The newly parsed catalog when both files were usable.
    pub catalog: Option<ServiceCatalog>,
    /// Stable error code when the update did not produce a new catalog.
    pub error_code: Option<&'static str>,
    /// Fetch outcome for `services.json`.
    pub services_fetch: FetchOutcomeKind,
    /// Fetch outcome for `services_i18n.json`.
    pub i18n_fetch: FetchOutcomeKind,
    /// A new, valid body was stored for `services.json` or
    /// `services_i18n.json` (so dependents need a rebuild).
    pub changed: bool,
}

/// Coarse fetch result for reporting (body not retained).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FetchOutcomeKind {
    /// New body stored.
    Updated,
    /// Conditional GET / unchanged file.
    NotModified,
    /// Failed; last good body kept.
    Failed,
}

impl From<&FetchOutcome> for FetchOutcomeKind {
    fn from(o: &FetchOutcome) -> Self {
        match o {
            FetchOutcome::Updated { .. } => Self::Updated,
            FetchOutcome::NotModified { .. } => Self::NotModified,
            FetchOutcome::Failed { .. } => Self::Failed,
        }
    }
}

/// Default HostlistsRegistry URLs.
#[derive(Clone, Debug)]
pub struct ServicesUrls {
    /// `services.json`.
    pub services: String,
    /// `services_i18n.json`.
    pub i18n: String,
}

impl Default for ServicesUrls {
    fn default() -> Self {
        Self {
            services: SERVICES_JSON_URL.to_owned(),
            i18n: SERVICES_I18N_URL.to_owned(),
        }
    }
}

/// Downloads and caches the catalog via [`Fetcher`], then parses it.
///
/// On fetch failure the last good bodies stay. On parse failure the previous
/// in-memory catalog (caller-owned) should be kept; this returns
/// `catalog: None` and `error_code: Some("filter_services.malformed")`.
///
/// A downloaded body is validated **before** it is persisted: a malformed
/// `services.json` (or `services_i18n.json`) never replaces the cached copy
/// or its ETag, so the last good catalog survives a restart. Both files are
/// capped at [`MAX_SERVICES_BODY_BYTES`].
pub async fn update_services_catalog(
    fetcher: &Fetcher,
    store: &ListStore,
    urls: &ServicesUrls,
) -> ServicesUpdateReport {
    let services_fetch = fetcher
        .fetch_and_store_services(
            store,
            SERVICES_STEM,
            &urls.services,
            MAX_SERVICES_BODY_BYTES,
            &|body| {
                ServiceCatalog::parse(body, None)
                    .map(|_| ())
                    .map_err(|e| e.to_string())
            },
        )
        .await;
    let i18n_fetch = fetcher
        .fetch_and_store_services(
            store,
            SERVICES_I18N_STEM,
            &urls.i18n,
            MAX_SERVICES_BODY_BYTES,
            &|body| {
                serde_json::from_str::<RawI18nFile>(body)
                    .map(|_| ())
                    .map_err(|e| format!("services_i18n.json: {e}"))
            },
        )
        .await;

    let services_kind = FetchOutcomeKind::from(&services_fetch);
    let i18n_kind = FetchOutcomeKind::from(&i18n_fetch);
    let changed =
        services_kind == FetchOutcomeKind::Updated || i18n_kind == FetchOutcomeKind::Updated;
    let report = |catalog, error_code| ServicesUpdateReport {
        catalog,
        error_code,
        services_fetch: services_kind,
        i18n_fetch: i18n_kind,
        changed,
    };

    // A rejected download keeps the old files; say so even though they parse.
    if let FetchOutcome::Failed { meta, .. } = &services_fetch
        && meta
            .last_error
            .as_ref()
            .is_some_and(|e| e.code == MALFORMED_SERVICES_CODE)
    {
        return report(None, Some("filter_services.malformed"));
    }

    // Prefer freshly downloaded bodies; else whatever is still on disk.
    let body = match &services_fetch {
        FetchOutcome::Updated { body, .. } => Some(body.clone()),
        _ => match store.read_services_body(SERVICES_STEM) {
            Ok(b) => b,
            Err(e) => return report(None, Some(ServiceError::from(e).code())),
        },
    };

    let Some(body) = body else {
        return report(
            None,
            Some(
                ServiceError::Malformed {
                    detail: "no services.json cached".into(),
                }
                .code(),
            ),
        );
    };

    let i18n = match &i18n_fetch {
        FetchOutcome::Updated { body, .. } => Some(body.clone()),
        _ => store.read_services_body(SERVICES_I18N_STEM).ok().flatten(),
    };

    match ServiceCatalog::parse(&body, i18n.as_deref()) {
        Ok(catalog) => report(Some(catalog), None),
        Err(e) => report(None, Some(e.code())),
    }
}

/// Writes a catalog body into the services cache (tests / offline seeding).
pub fn seed_services_cache(store: &ListStore, stem: &str, body: &str) -> Result<(), ServiceError> {
    let now = store.now_unix();
    let meta = ListMeta {
        last_success: Some(now),
        last_attempt: Some(now),
        ..ListMeta::default()
    };
    store.write_services_body(stem, body, &meta)?;
    Ok(())
}

/// Ensures `stem` is a safe relative file name (no path separators).
pub(crate) fn validate_stem(stem: &str) -> Result<(), StoreError> {
    if stem.is_empty()
        || stem.contains('/')
        || stem.contains('\\')
        || stem.contains("..")
        || Path::new(stem).components().count() != 1
    {
        return Err(StoreError::InvalidSource {
            reason: "invalid services cache file name",
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn service_error_codes_are_unique() {
        let errs = [
            ServiceError::Malformed { detail: "x".into() },
            ServiceError::Io("x".into()),
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &errs {
            assert!(e.code().starts_with("filter_services."));
            assert!(seen.insert(e.code()));
        }
    }

    #[test]
    fn parse_skips_bad_entries() {
        let json = r#"{
            "blocked_services": [
                {"id": "ok", "name": "OK", "group": "g", "icon_svg": "<svg/>", "rules": ["||ok.example^"]},
                null,
                {"name": "no-id", "rules": ["||x.example^"]},
                {"id": "", "rules": ["||y.example^"]},
                {"id": "ok", "rules": ["||dup.example^"]},
                42
            ],
            "groups": [{"id": "g"}]
        }"#;
        let cat = ServiceCatalog::parse(json, None).unwrap();
        assert_eq!(cat.services().len(), 1);
        assert_eq!(cat.stats().accepted, 1);
        assert_eq!(cat.stats().skipped_malformed, 5);
        assert_eq!(cat.get("ok").unwrap().icon, "<svg/>");
    }
}
