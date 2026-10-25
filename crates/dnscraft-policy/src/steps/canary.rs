//! Step 3: profile bypass / canary answers (Firefox DoH, iCloud Private Relay).

use dnscraft_proto::{Class, Name};

use crate::config::RequestContext;
use crate::decision::DecisionStep;
use crate::pipeline::{Draft, Flow, StepCtx};
use crate::synth::bypass_nxdomain;

/// Which profile flag gates a canary name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CanaryKind {
    /// [`ProfileConfig::firefox_canary`](crate::config::ProfileConfig::firefox_canary).
    Firefox,
    /// [`ProfileConfig::icloud_private_relay`](crate::config::ProfileConfig::icloud_private_relay).
    IcloudPrivateRelay,
}

/// One canary hostname and the docs that define its blocking answer.
///
/// Doc URLs were checked on 2026-10-25. Entries marked `unverified` could not
/// be confirmed from the official page in this session (e.g. JS challenge);
/// the cited URL is still the intended source.
struct CanaryEntry {
    /// Exact owner name (ASCII presentation, no trailing dot required).
    name: &'static str,
    kind: CanaryKind,
    /// Human-readable source note (URLs + verification status).
    #[allow(dead_code)] // documented for reviewers / grep; not read at runtime
    docs: &'static str,
}

/// Canary table. Exact-name match only; answers are always NXDOMAIN (no EDE).
///
/// Firefox DoH canary:
/// <https://support.mozilla.org/kb/canary-domain-use-application-dnsnet>
/// and <https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https>
/// — network resolvers must return NXDOMAIN for A/AAAA of
/// `use-application-dns.net` so Firefox does not enable DoH by default.
/// **unverified** (official support pages returned a client challenge; wording
/// is widely cited, e.g. ISC KB quoting the same Mozilla page).
///
/// Apple Private Relay:
/// <https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/>
/// — return NXDOMAIN or “no error no answer” (NODATA) for `mask.icloud.com`
/// and `mask-h2.icloud.com`. **verified** (page fetched 2026-10-25). We use
/// NXDOMAIN for both names.
const CANARIES: &[CanaryEntry] = &[
    CanaryEntry {
        name: "use-application-dns.net",
        kind: CanaryKind::Firefox,
        docs: "https://support.mozilla.org/kb/canary-domain-use-application-dnsnet \
               https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https \
               (unverified 2026-10-25: JS challenge on support.mozilla.org)",
    },
    CanaryEntry {
        name: "mask.icloud.com",
        kind: CanaryKind::IcloudPrivateRelay,
        docs: "https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/ \
               (verified 2026-10-25: NXDOMAIN or NODATA; we answer NXDOMAIN)",
    },
    CanaryEntry {
        name: "mask-h2.icloud.com",
        kind: CanaryKind::IcloudPrivateRelay,
        docs: "https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/ \
               (verified 2026-10-25: NXDOMAIN or NODATA; we answer NXDOMAIN)",
    },
];

/// Runs step 3. Continues when no canary matches or the profile flag is off.
pub(crate) fn run(ctx: &RequestContext, step: StepCtx<'_>, draft: &mut Draft) -> Flow {
    if ctx.query.qclass != Class::IN {
        return Flow::Continue;
    }
    let profile = step.snapshot.profile_for_view(draft.selection.view_idx);
    let Some(entry) = match_canary(&ctx.query.name) else {
        return Flow::Continue;
    };
    let enabled = match entry.kind {
        CanaryKind::Firefox => profile.config.firefox_canary,
        CanaryKind::IcloudPrivateRelay => profile.config.icloud_private_relay,
    };
    if !enabled {
        return Flow::Continue;
    }
    draft.steps.push(DecisionStep::Bypass);
    draft.synthetic = true;
    Flow::Answer(bypass_nxdomain(&ctx.query, ctx.flags.recursion_desired))
}

fn match_canary(qname: &Name) -> Option<&'static CanaryEntry> {
    CANARIES.iter().find(|e| {
        Name::from_ascii(e.name)
            .map(|n| n == *qname)
            .unwrap_or(false)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod unit {
    use super::*;

    #[test]
    fn canary_table_has_exact_names_only() {
        assert_eq!(CANARIES.len(), 3);
        for e in CANARIES {
            assert!(Name::from_ascii(e.name).is_ok(), "{}", e.name);
        }
        assert!(match_canary(&Name::from_ascii("use-application-dns.net").unwrap()).is_some());
        assert!(match_canary(&Name::from_ascii("USE-APPLICATION-DNS.NET.").unwrap()).is_some());
        assert!(match_canary(&Name::from_ascii("sub.use-application-dns.net").unwrap()).is_none());
        assert!(match_canary(&Name::from_ascii("mask.icloud.com").unwrap()).is_some());
        assert!(match_canary(&Name::from_ascii("mask-h2.icloud.com").unwrap()).is_some());
        assert!(match_canary(&Name::from_ascii("mask-api.icloud.com").unwrap()).is_none());
    }
}
