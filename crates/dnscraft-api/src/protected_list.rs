//! Derivation of the MCP protected-domain list from the module config.
//!
//! `SPEC-mcp.md` § Derived list requires the protected set to be derived from
//! the stored config, not only from `control_api.mcp.protected_domains`:
//!
//! 1. deployment hostnames (`tls.public_domain`, `dns.<public_domain>`,
//!    `tls.dyndns.hostname`, reserved labels and `listeners_ddr.target`),
//! 2. the OIDC issuer host,
//! 3. TLS infrastructure hosts (ACME directory, `api.cloudflare.com`,
//!    `tls.dyndns.echo_url`),
//! 4. filter-list download hosts, and
//! 5. forward-zone apex names.
//!
//! The derived entries are canonicalised and checked by
//! [`dnscraft_mcp::ProtectedDomains`]; this module only supplies the names.
//! Derivations run per request against the current stored snapshot, so a config
//! apply is visible without a restart.

use std::net::IpAddr;

use serde_json::Value;

use dnscraft_mcp::{McpConfig, McpError, ProtectedDomains};

use crate::error::ControlApiError;

/// Derives the protected domains from `snapshot`, the OIDC issuer URL (only
/// when OIDC is enabled) and the owner's additional entries.
///
/// `snapshot` is the current stored config-level JSON; a missing section simply
/// contributes no names. URL hosts that are IP literals are ignored because the
/// coverage rule only applies to domain names.
///
/// # Errors
///
/// Returns [`McpError::ConfigProtectedDomain`] when a derived or configured
/// entry is not a valid domain name.
pub fn derive_protected_domains(
    snapshot: Option<&Value>,
    oidc_issuer: Option<&str>,
    extra: impl IntoIterator<Item = String>,
) -> Result<ProtectedDomains, McpError> {
    let mut entries = Vec::new();
    let root = snapshot.unwrap_or(&Value::Null);
    let tls = root.get("tls");

    let public_domain = tls
        .and_then(|tls| tls.get("public_domain"))
        .and_then(Value::as_str);
    if let Some(public_domain) = public_domain {
        push(&mut entries, public_domain);
        push(&mut entries, format!("dns.{public_domain}"));
        if let Some(labels) = tls
            .and_then(|tls| tls.get("dyndns"))
            .and_then(|dyndns| dyndns.get("reserved_labels"))
            .and_then(Value::as_array)
        {
            for label in labels.iter().filter_map(Value::as_str) {
                push(&mut entries, format!("{label}.dns.{public_domain}"));
            }
        }
    }
    if let Some(hostname) = tls
        .and_then(|tls| tls.get("dyndns"))
        .and_then(|dyndns| dyndns.get("hostname"))
        .and_then(Value::as_str)
    {
        push(&mut entries, hostname);
    }
    if let Some(public_domain) = public_domain
        && let Some(target) = ddr_target(root)
    {
        if target == "dns" {
            push(&mut entries, format!("dns.{public_domain}"));
        } else if target.contains('.') {
            push(&mut entries, target);
        } else {
            push(&mut entries, format!("{target}.dns.{public_domain}"));
        }
    }

    if let Some(host) = tls
        .and_then(|tls| tls.get("acme"))
        .and_then(|acme| acme.get("directory"))
        .and_then(acme_directory_host)
    {
        push(&mut entries, host);
    }
    // The fixed Cloudflare API host is always protected.
    push(&mut entries, "api.cloudflare.com");
    if let Some(host) = tls
        .and_then(|tls| tls.get("dyndns"))
        .and_then(|dyndns| dyndns.get("echo_url"))
        .and_then(Value::as_str)
        .and_then(url_host)
    {
        push(&mut entries, host);
    }

    if let Some(host) = oidc_issuer.and_then(url_host) {
        push(&mut entries, host);
    }

    if let Some(lists) = root
        .get("filtering")
        .and_then(|filtering| filtering.get("lists"))
        .and_then(Value::as_array)
    {
        for url in lists.iter().filter_map(list_url).filter_map(url_host) {
            push(&mut entries, url);
        }
    }

    if let Some(zones) = root
        .get("resolver")
        .and_then(|resolver| resolver.get("forward_zones"))
        .and_then(Value::as_array)
    {
        for zone in zones.iter().filter_map(forward_zone) {
            push(&mut entries, zone);
        }
    }

    for entry in extra {
        push(&mut entries, entry);
    }

    ProtectedDomains::new(entries)
}

/// Returns `config` with its `protected_domains` replaced by the full derived
/// list (the auto-derived infrastructure hosts plus the configured additions).
///
/// The mounted MCP service builds its pre-backend protected list once, at
/// mount time. The list is derived here from that moment's snapshot; the MCP
/// backend re-derives it per request, so a config apply stays visible without
/// a restart.
///
/// # Errors
///
/// Returns a module error carrying [`McpError::ConfigProtectedDomain`] when a
/// derived or configured entry is not a valid domain name.
pub fn populate_mcp_protected_domains(
    mut config: McpConfig,
    snapshot: Option<&Value>,
    oidc_issuer: Option<&str>,
) -> Result<McpConfig, ControlApiError> {
    let derived = derive_protected_domains(
        snapshot,
        oidc_issuer,
        config.protected_domains.iter().cloned(),
    )
    .map_err(|err| ControlApiError::Module {
        code: err.code(),
        params: err.params(),
    })?;
    let mut entries = derived.entries().to_vec();
    entries.sort_unstable();
    entries.dedup();
    config.protected_domains = entries;
    Ok(config)
}

fn push(entries: &mut Vec<String>, value: impl Into<String>) {
    let value = value.into();
    if !value.is_empty() && !entries.contains(&value) {
        entries.push(value);
    }
}

/// `listeners_ddr.target` (TOML table) or `listeners.ddr.target` (section JSON).
fn ddr_target(root: &Value) -> Option<&str> {
    root.get("listeners_ddr")
        .and_then(|ddr| ddr.get("target"))
        .or_else(|| {
            root.get("listeners")
                .and_then(|listeners| listeners.get("ddr"))
                .and_then(|ddr| ddr.get("target"))
        })
        .and_then(Value::as_str)
}

/// Host of the ACME directory: `production`/`staging` or a custom URL.
fn acme_directory_host(value: &Value) -> Option<String> {
    match value {
        Value::String(directory) => match directory.as_str() {
            "production" => Some("acme-v02.api.letsencrypt.org".to_owned()),
            "staging" => Some("acme-staging-v02.api.letsencrypt.org".to_owned()),
            url => url_host(url),
        },
        Value::Object(map) => map.get("url").and_then(Value::as_str).and_then(url_host),
        _ => None,
    }
}

/// URL of a filter list: `source.url`, a direct `url`, or a string `source`.
fn list_url(list: &Value) -> Option<&str> {
    list.get("source")
        .and_then(|source| source.get("url"))
        .and_then(Value::as_str)
        .or_else(|| list.get("url").and_then(Value::as_str))
        .or_else(|| list.get("source").and_then(Value::as_str))
}

/// Forward-zone apex: `{ "zone": "..." }` or a bare string.
fn forward_zone(zone: &Value) -> Option<&str> {
    zone.get("zone")
        .and_then(Value::as_str)
        .or_else(|| zone.as_str())
}

/// Host of `raw`, ignoring IP literals (they are not domain names).
fn url_host(raw: &str) -> Option<String> {
    let host = url::Url::parse(raw).ok()?.host_str()?.to_owned();
    host.parse::<IpAddr>().is_err().then_some(host)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use dnscraft_filtering::{RecordTypeSel, RuleAction, RuleSpec};

    use super::*;

    fn entries(snapshot: &Value, issuer: Option<&str>, extra: &[&str]) -> Vec<String> {
        let mut list = derive_protected_domains(
            Some(snapshot),
            issuer,
            extra.iter().map(|entry| (*entry).to_owned()),
        )
        .unwrap()
        .entries()
        .to_vec();
        list.sort();
        list
    }

    #[test]
    fn derivation_covers_all_five_sources_and_additions() {
        let snapshot = json!({
            "filtering": {
                "lists": [
                    { "id": "ads", "source": { "url": "https://lists.example.com/ads.txt" } },
                    { "id": "local", "source": { "file": "blocklist.txt" } }
                ],
                "sets": []
            },
            "listeners": { "ddr": { "target": "node1" } },
            "tls": {
                "public_domain": "example.net",
                "acme": { "directory": "staging" },
                "dyndns": {
                    "hostname": "node1.dns.example.net",
                    "reserved_labels": ["node1", "node2"],
                    "echo_url": "https://echo.example.net/cdn-cgi/trace"
                }
            },
            "resolver": {
                "forward_zones": [
                    { "zone": "site-b.internal", "targets": ["192.0.2.1"] },
                    "internal.example.net"
                ]
            }
        });
        let list = entries(
            &snapshot,
            Some("https://auth.example.org/realms/main"),
            &["protected.example.com"],
        );
        for expected in [
            "example.net",
            "dns.example.net",
            "node1.dns.example.net",
            "node2.dns.example.net",
            "auth.example.org",
            "acme-staging-v02.api.letsencrypt.org",
            "api.cloudflare.com",
            "echo.example.net",
            "lists.example.com",
            "site-b.internal",
            "internal.example.net",
            "protected.example.com",
        ] {
            assert!(
                list.contains(&expected.to_owned()),
                "missing {expected}: {list:?}"
            );
        }
        assert!(!list.iter().any(|entry| entry.contains("blocklist.txt")));
    }

    #[test]
    fn derivation_follows_the_current_snapshot() {
        let before = json!({ "tls": { "public_domain": "example.net" } });
        let after = json!({ "tls": { "public_domain": "example.org" } });
        let old = entries(&before, None, &[]);
        let new = entries(&after, None, &[]);
        assert!(old.contains(&"example.net".to_owned()));
        assert!(!old.contains(&"example.org".to_owned()));
        assert!(new.contains(&"example.org".to_owned()));
        assert!(!new.contains(&"example.net".to_owned()));
    }

    #[test]
    fn canonicalisation_matches_filtering_build_rule() {
        let corpus = [
            "Example.COM.",
            "XN--BCHER-KVA.EXAMPLE.",
            "bücher.example",
            "_dmarc.Example.COM.",
        ];
        for input in corpus {
            let protected = ProtectedDomains::new([input.to_owned()]).unwrap();
            let canonical_protected = protected.entries()[0].clone();
            let canonical_filtering = RuleSpec {
                action: RuleAction::Allow,
                domain: input.to_owned(),
                include_subdomains: false,
                record_types: RecordTypeSel::default(),
                important: false,
                rewrite: None,
            }
            .normalized()
            .unwrap()
            .domain;
            assert_eq!(canonical_protected, canonical_filtering, "{input}");
        }
        // ASCII inputs also go through `DomainName::parse` unchanged.
        for input in ["Example.COM.", "_dmarc.Example.COM."] {
            assert_eq!(
                ProtectedDomains::new([input.to_owned()]).unwrap().entries()[0],
                dnscraft_filtering::DomainName::parse(input)
                    .unwrap()
                    .as_str()
            );
        }
    }

    #[test]
    fn malformed_explicit_entry_is_rejected() {
        let error =
            derive_protected_domains(Some(&json!({})), None, ["https://example.com".to_owned()])
                .unwrap_err();
        assert_eq!(error.code(), "mcp.config.protected_domain");
    }

    #[test]
    fn populated_mcp_config_contains_derived_and_configured_hosts() {
        let snapshot = json!({
            "tls": { "public_domain": "example.net" },
            "filtering": {
                "lists": [
                    { "id": "ads", "source": { "url": "https://lists.example.com/ads.txt" } }
                ]
            },
            "resolver": {
                "forward_zones": [ { "zone": "site-b.internal" } ]
            }
        });
        let config = McpConfig {
            // `Example.NET.` canonicalises to the same entry as the derived
            // `tls.public_domain`; the result must not contain it twice.
            protected_domains: vec!["Example.NET.".to_owned(), "extra.example.org".to_owned()],
            ..McpConfig::default()
        };

        let config = populate_mcp_protected_domains(config, Some(&snapshot), None).unwrap();

        for expected in [
            "example.net",
            "dns.example.net",
            "lists.example.com",
            "site-b.internal",
            "api.cloudflare.com",
            "extra.example.org",
        ] {
            assert!(
                config
                    .protected_domains
                    .iter()
                    .any(|entry| entry == expected),
                "missing {expected}: {:?}",
                config.protected_domains
            );
        }
        assert_eq!(
            config
                .protected_domains
                .iter()
                .filter(|entry| entry.as_str() == "example.net")
                .count(),
            1,
            "canonical duplicates are removed: {:?}",
            config.protected_domains
        );
        ProtectedDomains::new(config.protected_domains).unwrap();
    }
}
