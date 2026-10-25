//! Manual acceptance tool for Checkpoint A.
//!
//! Downloads the 19 reference filter lists from SPEC.md ("Reference filter set"),
//! parses each with `parse_list`, and prints a report: per-list counts, skip
//! breakdown, parse time, unique domains, sample skipped lines, regex examples
//! and peak RSS.
//!
//! Lists are cached in `target/reference-lists/` (or `--cache DIR`); cached files
//! are reused so reruns do not contact the providers. Automated tests never run this.
//!
//! Usage:
//!   cargo run --release -p dnscraft-filtering --example parse_lists -- [--cache DIR]

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use dnscraft_filtering::{ListSource, MatchKind, ParsedList, SkipReason, SkippedLine, parse_list};

const SAMPLES_PER_REASON: usize = 5;
const SAMPLE_TEXT_MAX: usize = 120;
const REGEX_EXAMPLES: usize = 10;
const DEFAULT_CACHE: &str = "target/reference-lists";

struct RefList {
    name: &'static str,
    file: &'static str,
    url: &'static str,
    /// Print regex rule examples for this list.
    regex_probe: bool,
}

const LISTS: [RefList; 19] = [
    RefList {
        name: "AdGuard DNS filter",
        file: "filter_1.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
        regex_probe: false,
    },
    RefList {
        name: "AdAway Default Blocklist",
        file: "filter_2.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_2.txt",
        regex_probe: false,
    },
    RefList {
        name: "AdAway",
        file: "adaway_hosts.txt",
        url: "https://adaway.org/hosts.txt",
        regex_probe: false,
    },
    RefList {
        name: "EasyList Germany",
        file: "easylistgermany.txt",
        url: "https://easylist.to/easylistgermany/easylistgermany.txt",
        regex_probe: true,
    },
    RefList {
        name: "StevenBlack",
        file: "stevenblack_hosts.txt",
        url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        regex_probe: false,
    },
    RefList {
        name: "Perflyst and Dandelion Sprout's Smart-TV Blocklist",
        file: "filter_7.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_7.txt",
        regex_probe: false,
    },
    RefList {
        name: "NoCoin Filter List",
        file: "filter_8.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_8.txt",
        regex_probe: false,
    },
    RefList {
        name: "Phishing URL Blocklist (PhishTank and OpenPhish)",
        file: "filter_30.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
        regex_probe: false,
    },
    RefList {
        name: "Scam Blocklist by DurableNapkin",
        file: "filter_10.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_10.txt",
        regex_probe: false,
    },
    RefList {
        name: "Dandelion Sprout's Game Console Adblock List",
        file: "filter_6.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_6.txt",
        regex_probe: false,
    },
    RefList {
        name: "WindowsSpyBlocker - Hosts spy rules",
        file: "filter_23.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_23.txt",
        regex_probe: false,
    },
    RefList {
        name: "EasyPrivacy",
        file: "easyprivacy.txt",
        url: "https://easylist.to/easylist/easyprivacy.txt",
        regex_probe: true,
    },
    RefList {
        name: "1Hosts (Xtra)",
        file: "filter_70.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_70.txt",
        regex_probe: false,
    },
    RefList {
        name: "OISD Blocklist Big",
        file: "filter_27.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_27.txt",
        regex_probe: false,
    },
    RefList {
        name: "HaGeZi's Ultimate Blocklist",
        file: "filter_49.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_49.txt",
        regex_probe: false,
    },
    RefList {
        name: "HaGeZi's Gambling Blocklist",
        file: "filter_47.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
        regex_probe: false,
    },
    RefList {
        name: "HaGeZi's Windows/Office Tracker Blocklist",
        file: "filter_63.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_63.txt",
        regex_probe: false,
    },
    RefList {
        name: "HaGeZi's DNS Rebind Protection",
        file: "filter_71.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_71.txt",
        regex_probe: false,
    },
    RefList {
        name: "HaGeZi's Encrypted DNS/VPN/TOR/Proxy Bypass",
        file: "filter_52.txt",
        url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_52.txt",
        regex_probe: false,
    },
];

fn fail(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(2);
}

fn parse_args() -> PathBuf {
    let mut args = std::env::args().skip(1);
    let mut cache = PathBuf::from(DEFAULT_CACHE);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--cache" => match args.next() {
                Some(dir) => cache = PathBuf::from(dir),
                None => fail("--cache needs a directory"),
            },
            "-h" | "--help" => {
                println!("usage: parse_lists [--cache DIR]");
                std::process::exit(0);
            }
            other => fail(&format!("unknown argument: {other}")),
        }
    }
    cache
}

/// Returns the list body and whether it came from the cache.
async fn load(
    client: &reqwest::Client,
    list: &RefList,
    cache: &Path,
) -> Result<(Vec<u8>, bool), String> {
    let path = cache.join(list.file);
    if let Ok(bytes) = std::fs::read(&path) {
        return Ok((bytes, true));
    }
    let resp = client
        .get(list.url)
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| format!("body read failed: {e}"))?
        .to_vec();
    let tmp = path.with_extension("part");
    std::fs::write(&tmp, &bytes).map_err(|e| format!("cache write failed: {e}"))?;
    std::fs::rename(&tmp, &path).map_err(|e| format!("cache rename failed: {e}"))?;
    Ok((bytes, false))
}

/// Single-line text, cut to `SAMPLE_TEXT_MAX` characters.
fn clip(s: &str) -> String {
    let mut out: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(SAMPLE_TEXT_MAX)
        .collect();
    if s.chars().count() > SAMPLE_TEXT_MAX {
        out.push_str("...");
    }
    out
}

fn peak_rss() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("VmHWM:") {
                    let kb: f64 = rest
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse()
                        .unwrap_or(0.0);
                    return format!("{kb:.0} kB ({:.1} MiB)", kb / 1024.0);
                }
            }
        }
        "n/a".to_owned()
    }
    #[cfg(not(target_os = "linux"))]
    {
        "n/a".to_owned()
    }
}

#[derive(Default)]
struct Totals {
    bytes: u64,
    lines: usize,
    rules: usize,
    subdomains: usize,
    exact: usize,
    pattern: usize,
    regex: usize,
    comments: usize,
    blank: usize,
    skipped: usize,
    parse_ms: f64,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let started = Instant::now();
    let cache = parse_args();
    if let Err(e) = std::fs::create_dir_all(&cache) {
        fail(&format!("cannot create cache dir {}: {e}", cache.display()));
    }
    let client = reqwest::Client::builder()
        .user_agent("dnscraft-parse-lists/0.1")
        .timeout(Duration::from_secs(900))
        .build()
        .unwrap_or_else(|e| fail(&format!("http client: {e}")));

    println!("Cache dir: {}", cache.display());
    println!();
    println!(
        "{:<3} {:<50} {:<8} {:>12} {:>10} {:>10} {:>12} {:>10} {:>9} {:>9} {:>9} {:>9} {:>10} {:>10}",
        "#",
        "List",
        "Source",
        "Bytes",
        "Lines",
        "Rules",
        "Subdomains",
        "Exact",
        "Pattern",
        "Regex",
        "Comments",
        "Blank",
        "Skipped",
        "Parse ms"
    );

    let mut totals = Totals::default();
    let mut domains: HashSet<String> = HashSet::new();
    let mut samples: HashMap<SkipReason, Vec<(&str, SkippedLine)>> = HashMap::new();
    let mut regex_examples: Vec<(&str, Vec<String>)> = Vec::new();
    let mut per_list_skips: Vec<(&str, Vec<(SkipReason, usize)>)> = Vec::new();
    let mut failures: Vec<(&str, String)> = Vec::new();

    for (idx, list) in LISTS.iter().enumerate() {
        let (bytes, cached) = match load(&client, list, &cache).await {
            Ok(v) => v,
            Err(e) => {
                println!("{:<3} {:<50} FAILED: {e}", idx + 1, list.name);
                failures.push((list.name, e));
                continue;
            }
        };
        let body = String::from_utf8_lossy(&bytes);
        let t = Instant::now();
        let parsed: ParsedList = parse_list(&body, ListSource::List);
        let parse_ms = t.elapsed().as_secs_f64() * 1000.0;

        let mut counts = [0usize; 4];
        for rule in &parsed.rules {
            let slot = match rule.kind() {
                MatchKind::Subdomains => 0,
                MatchKind::Exact => 1,
                MatchKind::Pattern => 2,
                MatchKind::Regex => 3,
                _ => 3,
            };
            counts[slot] += 1;
            if let Some(d) = rule.domain() {
                domains.insert(d.as_str().to_owned());
            }
        }
        if list.regex_probe {
            let texts: Vec<String> = parsed
                .rules
                .iter()
                .filter(|r| r.kind() == MatchKind::Regex)
                .take(REGEX_EXAMPLES)
                .filter_map(|r| r.text(&body).map(clip))
                .collect();
            regex_examples.push((list.name, texts));
        }

        let skipped = parsed.skipped.total();
        println!(
            "{:<3} {:<50} {:<8} {:>12} {:>10} {:>10} {:>12} {:>10} {:>9} {:>9} {:>9} {:>9} {:>10} {:>10.1}",
            idx + 1,
            list.name,
            if cached { "cached" } else { "fetched" },
            bytes.len(),
            parsed.total_lines,
            parsed.rules.len(),
            counts[0],
            counts[1],
            counts[2],
            counts[3],
            parsed.comment_lines,
            parsed.blank_lines,
            skipped,
            parse_ms
        );

        totals.bytes += bytes.len() as u64;
        totals.lines += parsed.total_lines;
        totals.rules += parsed.rules.len();
        totals.subdomains += counts[0];
        totals.exact += counts[1];
        totals.pattern += counts[2];
        totals.regex += counts[3];
        totals.comments += parsed.comment_lines;
        totals.blank += parsed.blank_lines;
        totals.skipped += skipped;
        totals.parse_ms += parse_ms;

        let reasons: Vec<(SkipReason, usize)> =
            parsed.skipped.iter().filter(|(_, n)| *n > 0).collect();
        per_list_skips.push((list.name, reasons));

        for s in &parsed.samples {
            let bucket = samples.entry(s.reason).or_default();
            if bucket.len() < SAMPLES_PER_REASON {
                bucket.push((list.name, s.clone()));
            }
        }
        // `parsed` and `body` drop here, before the next list is parsed.
    }

    println!(
        "{:<3} {:<50} {:<8} {:>12} {:>10} {:>10} {:>12} {:>10} {:>9} {:>9} {:>9} {:>9} {:>10} {:>10.1}",
        "",
        "TOTAL",
        "",
        totals.bytes,
        totals.lines,
        totals.rules,
        totals.subdomains,
        totals.exact,
        totals.pattern,
        totals.regex,
        totals.comments,
        totals.blank,
        totals.skipped,
        totals.parse_ms
    );
    println!();
    println!(
        "Unique domains across all lists (Subdomains + Exact rules): {}",
        domains.len()
    );
    println!("Lists failed: {}", failures.len());
    for (name, err) in &failures {
        println!("  {name}: {err}");
    }

    println!();
    println!("Skipped items per list (non-zero reasons only):");
    for (name, reasons) in &per_list_skips {
        if reasons.is_empty() {
            println!("  {name}: none");
            continue;
        }
        let parts: Vec<String> = reasons
            .iter()
            .map(|(r, n)| format!("{}={n}", r.as_str()))
            .collect();
        println!("  {name}: {}", parts.join(", "));
    }

    println!();
    println!(
        "Skipped reasons, total over all lists (all {} reasons):",
        SkipReason::ALL.len()
    );
    for reason in SkipReason::ALL {
        let total: usize = per_list_skips
            .iter()
            .flat_map(|(_, rs)| rs.iter())
            .filter(|(r, _)| *r == reason)
            .map(|(_, n)| *n)
            .sum();
        println!("  {:<20} {total}", reason.as_str());
    }

    println!();
    println!(
        "Sample skipped lines (up to {SAMPLES_PER_REASON} per reason, first {} per list):",
        dnscraft_filtering::SKIP_SAMPLE_LIMIT
    );
    for reason in SkipReason::ALL {
        let Some(bucket) = samples.get(&reason) else {
            continue;
        };
        println!("  [{}]", reason.as_str());
        for (list_name, s) in bucket {
            println!(
                "    {list_name} line {} ({}): {}",
                s.line,
                s.code,
                clip(&s.text)
            );
        }
    }

    println!();
    for (name, texts) in &regex_examples {
        println!("Regex rule examples, {name} (up to {REGEX_EXAMPLES}):");
        if texts.is_empty() {
            println!("  (none)");
        }
        for t in texts {
            println!("  {t}");
        }
    }

    println!();
    println!("Peak RSS (VmHWM): {}", peak_rss());
    println!("Total runtime: {:.2} s", started.elapsed().as_secs_f64());
}
