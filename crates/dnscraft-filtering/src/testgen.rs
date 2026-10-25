//! Deterministic reference-shaped rule set for benchmarks (feature `testgen` only).
//!
//! Not part of the public API: enabled only for criterion benches. Shape mirrors
//! the Checkpoint A real-list set (~2.25 M rules across lists, mostly subdomain
//! blocks, ~85 k exact hosts, hundreds of globs, tens of regexes, ~15 %
//! cross-list duplicates).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use crate::index::{Index, IndexBuilder, IndexError, SourceKind};
use crate::name::DomainName;
use crate::parser::parse_rule;
use crate::rule::{MatchKind, Rule, RuleAction};
use crate::types::ListId;

/// Unique subdomain (`||…^`) rules on the primary list.
pub const SUBDOMAIN_UNIQUE: usize = 1_870_000;
/// Exact hosts-style (`|…^`) rules on the primary list.
pub const EXACT_HOSTS: usize = 85_000;
/// Glob (`*`) rules.
pub const GLOBS: usize = 500;
/// Regex (`/…/`) rules.
pub const REGEXES: usize = 30;
/// Answer-IP rules.
pub const IP_RULES: usize = 100;
/// Cross-list duplicates as a fraction of subdomain + exact (numerator).
pub const DUPLICATE_PCT: usize = 15;

/// Total rules fed into the builder across both lists (including duplicates).
pub fn total_rules_across_lists() -> usize {
    let unique = SUBDOMAIN_UNIQUE + EXACT_HOSTS + GLOBS + REGEXES + IP_RULES;
    let dups = (SUBDOMAIN_UNIQUE + EXACT_HOSTS) * DUPLICATE_PCT / 100;
    unique + dups
}

/// Probe names and addresses that exercise the match paths against a set built
/// by [`build_reference_index`].
#[derive(Clone, Debug)]
pub struct Probes {
    /// A name that matches a subdomain block on the primary list.
    pub hit: DomainName,
    /// A name that matches nothing.
    pub miss: DomainName,
    /// Ten labels; blocked via a subdomain suffix rule.
    pub deep: DomainName,
    /// CNAME-shaped chain: pass, pass, then block.
    pub chain: [DomainName; 3],
    /// An IP that matches an IP block rule.
    pub ip_hit: IpAddr,
    /// An IP that matches nothing.
    pub ip_miss: IpAddr,
}

/// Builds the reference-shaped index and the probe names for the match benches.
///
/// Deterministic: same constants → same rules and probes.
pub fn build_reference_index() -> Result<(Index, Probes), IndexError> {
    let mut b = IndexBuilder::new();
    let probes = feed_reference_set(&mut b)?;
    Ok((b.build_in_memory(), probes))
}

/// Streams the reference-shaped rules into `builder` (two list sources).
pub fn feed_reference_set(builder: &mut IndexBuilder) -> Result<Probes, IndexError> {
    let primary = builder.add_source(SourceKind::List(
        ListId::new("ref-a").expect("valid list id"),
    ))?;
    let secondary = builder.add_source(SourceKind::List(
        ListId::new("ref-b").expect("valid list id"),
    ))?;

    for i in 0..SUBDOMAIN_UNIQUE {
        let d = subdomain_name(i);
        builder.add_rule(
            Rule::new(RuleAction::Block, MatchKind::Subdomains, d),
            primary,
        )?;
    }
    for i in 0..EXACT_HOSTS {
        let d = exact_name(i);
        builder.add_rule(Rule::new(RuleAction::Block, MatchKind::Exact, d), primary)?;
    }
    for i in 0..GLOBS {
        let line = format!("||ad*.g{i}.bench^");
        let rule = parse_rule(&line).expect("glob rule");
        builder.add_rule(rule, primary)?;
    }
    for i in 0..REGEXES {
        let line = format!("/^rx{i}[0-9]+\\.bench$/");
        let rule = parse_rule(&line).expect("regex rule");
        builder.add_rule(rule, primary)?;
    }
    for i in 0..IP_RULES {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 64, (i / 256) as u8, (i % 256) as u8));
        builder.add_rule(Rule::new_ip(RuleAction::Block, ip), primary)?;
    }

    // 15 % of subdomain + exact rules re-emitted on the second list.
    let dup_n = (SUBDOMAIN_UNIQUE + EXACT_HOSTS) * DUPLICATE_PCT / 100;
    for i in 0..dup_n {
        if i < SUBDOMAIN_UNIQUE {
            let d = subdomain_name(i);
            builder.add_rule(
                Rule::new(RuleAction::Block, MatchKind::Subdomains, d),
                secondary,
            )?;
        } else {
            let d = exact_name(i - SUBDOMAIN_UNIQUE);
            builder.add_rule(Rule::new(RuleAction::Block, MatchKind::Exact, d), secondary)?;
        }
    }

    Ok(Probes {
        hit: subdomain_name(0),
        miss: DomainName::parse("never-listed.example.invalid").expect("miss name"),
        // 10 labels: seven prefixes + h0.z0.bench (3).
        deep: DomainName::parse("a.b.c.d.e.f.g.h0.z0.bench").expect("deep name"),
        chain: [
            DomainName::parse("page.chain.bench").expect("chain[0]"),
            DomainName::parse("mid.chain.bench").expect("chain[1]"),
            subdomain_name(0),
        ],
        ip_hit: IpAddr::V4(Ipv4Addr::new(10, 64, 0, 0)),
        ip_miss: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
    })
}

fn subdomain_name(i: usize) -> DomainName {
    // h{i}.z{i%997}.bench — short, unique, valid labels.
    let s = format!("h{i}.z{}.bench", i % 997);
    DomainName::parse(&s).expect("subdomain name")
}

fn exact_name(i: usize) -> DomainName {
    let s = format!("host{i}.exact.bench");
    DomainName::parse(&s).expect("exact name")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shape_counts() {
        let total = total_rules_across_lists();
        assert!(
            (2_200_000..2_300_000).contains(&total),
            "total {total} not ~2.25 M"
        );
        let dups = (SUBDOMAIN_UNIQUE + EXACT_HOSTS) * DUPLICATE_PCT / 100;
        assert_eq!(dups, 293_250);
    }

    #[test]
    fn probes_label_counts() {
        let p = Probes {
            hit: subdomain_name(0),
            miss: DomainName::parse("never-listed.example.invalid").unwrap(),
            deep: DomainName::parse("a.b.c.d.e.f.g.h0.z0.bench").unwrap(),
            chain: [
                DomainName::parse("page.chain.bench").unwrap(),
                DomainName::parse("mid.chain.bench").unwrap(),
                subdomain_name(0),
            ],
            ip_hit: IpAddr::V4(Ipv4Addr::new(10, 64, 0, 0)),
            ip_miss: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
        };
        assert_eq!(p.deep.label_count(), 10);
        assert_eq!(p.hit.as_str(), "h0.z0.bench");
    }
}
