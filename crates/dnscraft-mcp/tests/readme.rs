//! The README tool table must match what `tools/list` returns.
//!
//! The table is parsed from the `## Tools` section of the crate README and
//! compared, name by name and in order, with the write-enabled catalog.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use dnscraft_mcp::McpConfig;
use support::harness::{self, TestServer};

const README: &str = include_str!("../README.md");

/// Tool names in the README table, in document order.
fn documented_tools() -> Vec<String> {
    README
        .lines()
        .skip_while(|line| line.trim() != "## Tools")
        .skip(1)
        .take_while(|line| !line.starts_with("## "))
        .filter_map(|line| {
            let name = line.strip_prefix("| `")?.split('`').next()?;
            Some(name.to_owned())
        })
        .collect()
}

#[tokio::test]
async fn readme_tool_table_matches_tools_list() {
    let config = McpConfig {
        write_tools_enabled: true,
        ..McpConfig::default()
    };
    let server: TestServer = harness::spawn_with(config, support::write_token()).await;
    let client = reqwest::Client::new();
    let body = harness::list_tools(&client, &server).await;
    let listed: Vec<String> = body["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tool| tool["name"].as_str().unwrap().to_owned())
        .collect();

    let documented = documented_tools();
    assert_eq!(documented.len(), 13, "README must document all 13 tools");
    assert_eq!(
        documented, listed,
        "README tool table must match tools/list exactly, in order"
    );
}
