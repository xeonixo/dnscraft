//! SafeSearch provider hostname table (pipeline steps 5–6).
//!
//! Every rewrite hostname is checked against the provider's official
//! documentation at implement time (2026-10-25). Citations sit next to the
//! constants; hosts that could not be confirmed from the official page are
//! marked `// unverified` and listed in `tasks/progress.md`.

use dnscraft_proto::Name;

use crate::config::YoutubeMode;

/// Safe target for Google Search SafeSearch VIP.
///
/// Source: <https://support.google.com/websearch/answer/186669> (verified
/// 2026-10-25) — CNAME `www.google.com` (and country/region domains) to
/// `forcesafesearch.google.com`.
pub const GOOGLE_SAFE_HOST: &str = "forcesafesearch.google.com";

/// Strict YouTube Restricted Mode target.
///
/// Source: <https://support.google.com/a/answer/6214622> (verified 2026-10-25).
pub const YOUTUBE_STRICT_HOST: &str = "restrict.youtube.com";

/// Moderate YouTube Restricted Mode target.
///
/// Source: <https://support.google.com/a/answer/6214622> (verified 2026-10-25).
pub const YOUTUBE_MODERATE_HOST: &str = "restrictmoderate.youtube.com";

/// Bing Strict SafeSearch target.
///
/// Source: <https://support.microsoft.com/en-us/bing/blocking-explicit-content-with-safesearch>
/// (verified 2026-10-25).
pub const BING_SAFE_HOST: &str = "strict.bing.com";

/// DuckDuckGo network-level Safe Search target.
///
/// Source: <https://duckduckgo.com/duckduckgo-help-pages/features/safe-search>
/// (verified 2026-10-25).
pub const DUCKDUCKGO_SAFE_HOST: &str = "safe.duckduckgo.com";

/// Provider id string used in config / decision records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SafeSearchProvider {
    /// `google`
    Google,
    /// `bing`
    Bing,
    /// `youtube`
    Youtube,
    /// `duckduckgo`
    DuckDuckGo,
}

impl SafeSearchProvider {
    /// Config / decision id (`google`, `bing`, …).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Bing => "bing",
            Self::Youtube => "youtube",
            Self::DuckDuckGo => "duckduckgo",
        }
    }
}

/// Result of matching a query name against the provider table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SafeSearchHit {
    /// Provider that owns the matched hostname.
    pub provider: SafeSearchProvider,
    /// Safe endpoint hostname (no trailing dot).
    pub target: &'static str,
}

/// Google country / region search hosts rewritten to [`GOOGLE_SAFE_HOST`].
///
/// Built from <https://www.google.com/supported_domains> fetched 2026-10-25:
/// each list entry `.example` becomes `www.example`. Google's network guidance
/// (<https://support.google.com/websearch/answer/186669>) says to CNAME
/// `www.google.com` and the corresponding country/region domains.
const GOOGLE_HOSTS: &[&str] = &[
    "www.google.ad",
    "www.google.ae",
    "www.google.al",
    "www.google.am",
    "www.google.as",
    "www.google.at",
    "www.google.az",
    "www.google.ba",
    "www.google.be",
    "www.google.bf",
    "www.google.bg",
    "www.google.bi",
    "www.google.bj",
    "www.google.bs",
    "www.google.bt",
    "www.google.by",
    "www.google.ca",
    "www.google.cat",
    "www.google.cd",
    "www.google.cf",
    "www.google.cg",
    "www.google.ch",
    "www.google.ci",
    "www.google.cl",
    "www.google.cm",
    "www.google.cn",
    "www.google.co.ao",
    "www.google.co.bw",
    "www.google.co.ck",
    "www.google.co.cr",
    "www.google.co.id",
    "www.google.co.il",
    "www.google.co.in",
    "www.google.co.jp",
    "www.google.co.ke",
    "www.google.co.kr",
    "www.google.co.ls",
    "www.google.co.ma",
    "www.google.co.mz",
    "www.google.co.nz",
    "www.google.co.th",
    "www.google.co.tz",
    "www.google.co.ug",
    "www.google.co.uk",
    "www.google.co.uz",
    "www.google.co.ve",
    "www.google.co.vi",
    "www.google.co.za",
    "www.google.co.zm",
    "www.google.co.zw",
    "www.google.com",
    "www.google.com.af",
    "www.google.com.ag",
    "www.google.com.ar",
    "www.google.com.au",
    "www.google.com.bd",
    "www.google.com.bh",
    "www.google.com.bn",
    "www.google.com.bo",
    "www.google.com.br",
    "www.google.com.bz",
    "www.google.com.co",
    "www.google.com.cu",
    "www.google.com.cy",
    "www.google.com.do",
    "www.google.com.ec",
    "www.google.com.eg",
    "www.google.com.et",
    "www.google.com.fj",
    "www.google.com.gh",
    "www.google.com.gi",
    "www.google.com.gt",
    "www.google.com.hk",
    "www.google.com.jm",
    "www.google.com.kh",
    "www.google.com.kw",
    "www.google.com.lb",
    "www.google.com.ly",
    "www.google.com.mm",
    "www.google.com.mt",
    "www.google.com.mx",
    "www.google.com.my",
    "www.google.com.na",
    "www.google.com.ng",
    "www.google.com.ni",
    "www.google.com.np",
    "www.google.com.om",
    "www.google.com.pa",
    "www.google.com.pe",
    "www.google.com.pg",
    "www.google.com.ph",
    "www.google.com.pk",
    "www.google.com.pr",
    "www.google.com.py",
    "www.google.com.qa",
    "www.google.com.sa",
    "www.google.com.sb",
    "www.google.com.sg",
    "www.google.com.sl",
    "www.google.com.sv",
    "www.google.com.tj",
    "www.google.com.tr",
    "www.google.com.tw",
    "www.google.com.ua",
    "www.google.com.uy",
    "www.google.com.vc",
    "www.google.com.vn",
    "www.google.cv",
    "www.google.cz",
    "www.google.de",
    "www.google.dj",
    "www.google.dk",
    "www.google.dm",
    "www.google.dz",
    "www.google.ee",
    "www.google.es",
    "www.google.fi",
    "www.google.fm",
    "www.google.fr",
    "www.google.ga",
    "www.google.ge",
    "www.google.gg",
    "www.google.gl",
    "www.google.gm",
    "www.google.gr",
    "www.google.gy",
    "www.google.hn",
    "www.google.hr",
    "www.google.ht",
    "www.google.hu",
    "www.google.ie",
    "www.google.im",
    "www.google.iq",
    "www.google.is",
    "www.google.it",
    "www.google.je",
    "www.google.jo",
    "www.google.kg",
    "www.google.ki",
    "www.google.kz",
    "www.google.la",
    "www.google.li",
    "www.google.lk",
    "www.google.lt",
    "www.google.lu",
    "www.google.lv",
    "www.google.md",
    "www.google.me",
    "www.google.mg",
    "www.google.mk",
    "www.google.ml",
    "www.google.mn",
    "www.google.mu",
    "www.google.mv",
    "www.google.mw",
    "www.google.ne",
    "www.google.nl",
    "www.google.no",
    "www.google.nr",
    "www.google.nu",
    "www.google.pl",
    "www.google.pn",
    "www.google.ps",
    "www.google.pt",
    "www.google.ro",
    "www.google.rs",
    "www.google.ru",
    "www.google.rw",
    "www.google.sc",
    "www.google.se",
    "www.google.sh",
    "www.google.si",
    "www.google.sk",
    "www.google.sm",
    "www.google.sn",
    "www.google.so",
    "www.google.sr",
    "www.google.st",
    "www.google.td",
    "www.google.tg",
    "www.google.tl",
    "www.google.tm",
    "www.google.tn",
    "www.google.to",
    "www.google.tt",
    "www.google.vu",
    "www.google.ws",
];

/// YouTube hosts rewritten to Restricted Mode (strict or moderate).
///
/// Source: <https://support.google.com/a/answer/6214622> (verified 2026-10-25).
/// Do **not** rewrite bare `youtube.com`, `youtu.be`, `s.ytimg.com`, or
/// `googleapis.com` — Google documents that those break YouTube.
const YOUTUBE_HOSTS: &[&str] = &[
    "www.youtube.com",
    "m.youtube.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "www.youtube-nocookie.com",
];

/// Bing hosts rewritten to [`BING_SAFE_HOST`].
///
/// `www.bing.com` and `edgeservices.bing.com` (Edge sidebar) are both
/// documented at
/// <https://support.microsoft.com/en-us/bing/blocking-explicit-content-with-safesearch>
/// (verified 2026-10-25).
const BING_HOSTS: &[&str] = &["www.bing.com", "edgeservices.bing.com"];

/// DuckDuckGo hosts rewritten to [`DUCKDUCKGO_SAFE_HOST`].
///
/// `duckduckgo.com` is verified from
/// <https://duckduckgo.com/duckduckgo-help-pages/features/safe-search>
/// (2026-10-25). `www.duckduckgo.com` and `start.duckduckgo.com` are common
/// companion names used by other DNS SafeSearch lists but are **not** named
/// on that official page — marked unverified.
const DUCKDUCKGO_HOSTS: &[&str] = &[
    "duckduckgo.com",
    // unverified — not listed on DuckDuckGo's official Safe Search help page
    "www.duckduckgo.com",
    // unverified — not listed on DuckDuckGo's official Safe Search help page
    "start.duckduckgo.com",
];

/// Looks up `qname` in the provider table.
///
/// Returns [`None`] when the name is not a known SafeSearch host. The caller
/// still checks that the profile has SafeSearch enabled and that the provider
/// is in the profile's provider list.
pub fn lookup(qname: &Name, youtube_mode: YoutubeMode) -> Option<SafeSearchHit> {
    let ascii = qname.to_string();
    let host = ascii.trim_end_matches('.').to_ascii_lowercase();
    if GOOGLE_HOSTS.binary_search(&host.as_str()).is_ok() {
        return Some(SafeSearchHit {
            provider: SafeSearchProvider::Google,
            target: GOOGLE_SAFE_HOST,
        });
    }
    if YOUTUBE_HOSTS.iter().any(|h| *h == host) {
        let target = match youtube_mode {
            YoutubeMode::Strict => YOUTUBE_STRICT_HOST,
            YoutubeMode::Moderate => YOUTUBE_MODERATE_HOST,
        };
        return Some(SafeSearchHit {
            provider: SafeSearchProvider::Youtube,
            target,
        });
    }
    if BING_HOSTS.iter().any(|h| *h == host) {
        return Some(SafeSearchHit {
            provider: SafeSearchProvider::Bing,
            target: BING_SAFE_HOST,
        });
    }
    if DUCKDUCKGO_HOSTS.iter().any(|h| *h == host) {
        return Some(SafeSearchHit {
            provider: SafeSearchProvider::DuckDuckGo,
            target: DUCKDUCKGO_SAFE_HOST,
        });
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn google_hosts_are_sorted_for_binary_search() {
        let mut sorted = GOOGLE_HOSTS.to_vec();
        sorted.sort_unstable();
        assert_eq!(GOOGLE_HOSTS, sorted.as_slice());
    }

    #[test]
    fn lookup_google_www_and_country() {
        let www = Name::from_ascii("www.google.com.").unwrap();
        let hit = lookup(&www, YoutubeMode::Strict).unwrap();
        assert_eq!(hit.provider, SafeSearchProvider::Google);
        assert_eq!(hit.target, GOOGLE_SAFE_HOST);

        let uk = Name::from_ascii("WWW.GOOGLE.CO.UK").unwrap();
        let hit = lookup(&uk, YoutubeMode::Strict).unwrap();
        assert_eq!(hit.provider, SafeSearchProvider::Google);
    }

    #[test]
    fn lookup_youtube_strict_vs_moderate() {
        let name = Name::from_ascii("www.youtube.com").unwrap();
        assert_eq!(
            lookup(&name, YoutubeMode::Strict).unwrap().target,
            YOUTUBE_STRICT_HOST
        );
        assert_eq!(
            lookup(&name, YoutubeMode::Moderate).unwrap().target,
            YOUTUBE_MODERATE_HOST
        );
    }

    #[test]
    fn lookup_bing_and_duckduckgo() {
        assert_eq!(
            lookup(
                &Name::from_ascii("www.bing.com").unwrap(),
                YoutubeMode::Strict
            )
            .unwrap()
            .target,
            BING_SAFE_HOST
        );
        assert_eq!(
            lookup(
                &Name::from_ascii("edgeservices.bing.com").unwrap(),
                YoutubeMode::Strict
            )
            .unwrap()
            .target,
            BING_SAFE_HOST
        );
        assert_eq!(
            lookup(
                &Name::from_ascii("duckduckgo.com").unwrap(),
                YoutubeMode::Strict
            )
            .unwrap()
            .target,
            DUCKDUCKGO_SAFE_HOST
        );
    }

    #[test]
    fn lookup_ignores_non_provider_hosts() {
        assert!(
            lookup(
                &Name::from_ascii("youtube.com").unwrap(),
                YoutubeMode::Strict
            )
            .is_none()
        );
        assert!(
            lookup(
                &Name::from_ascii("example.com").unwrap(),
                YoutubeMode::Strict
            )
            .is_none()
        );
    }
}
