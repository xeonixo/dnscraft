#![no_main]

//! Fuzzes the pure MCP request pre-checks (`validate_mcp_request`) with
//! arbitrary method, headers and body bytes.
//!
//! Input layout: byte 0 selects the request method, the rest is an
//! HTTP-like header block terminated by a blank line, followed by the body.
//! Invalid header names or values are skipped. Only the "never panic"
//! property is checked; the validator never copies the body, so a body above
//! the cap is rejected by length before any JSON work.
//!
//! `Mcp-Method` / `Mcp-Name` versus the JSON-RPC body are checked by rmcp's
//! tower layer, not by `transport.rs`, so they are outside this target.

use dnscraft_mcp::{RequestLimits, validate_mcp_request};
use http::{HeaderMap, HeaderName, HeaderValue};
use libfuzzer_sys::fuzz_target;

/// Biggest body this target accepts; a fixed cap makes over-cap seeds stable.
const MAX_BODY_BYTES: usize = 1024;

fn split_head(data: &[u8]) -> (&[u8], &[u8]) {
    if let Some(position) = data.windows(4).position(|window| window == b"\r\n\r\n") {
        return (&data[..position], &data[position + 4..]);
    }
    if let Some(position) = data.windows(2).position(|window| window == b"\n\n") {
        return (&data[..position], &data[position + 2..]);
    }
    (data, &[])
}

fn parse_headers(head: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for line in head.split(|byte| *byte == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let name = &line[..colon];
        let value = line[colon + 1..]
            .strip_prefix(b" ")
            .unwrap_or(&line[colon + 1..]);
        let Ok(name) = HeaderName::from_bytes(name) else {
            continue;
        };
        let Ok(value) = HeaderValue::from_bytes(value) else {
            continue;
        };
        headers.append(name, value);
    }
    headers
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, rest)) = data.split_first() else {
        return;
    };
    let method = match selector % 5 {
        0 => "POST",
        1 => "GET",
        2 => "PUT",
        3 => "DELETE",
        _ => "PATCH",
    };
    let (head, body) = split_head(rest);
    let headers = parse_headers(head);

    let allowed_origins = [String::from("https://ui.example.com")];
    let supported_versions = [String::from("2026-07-28")];

    // Legacy mode is the only bypass of the version header; it is not fuzzed here.
    let limits = RequestLimits {
        max_body_bytes: MAX_BODY_BYTES,
        allowed_origins: &allowed_origins,
        supported_versions: &supported_versions,
        version_header_optional: false,
    };
    let _ = validate_mcp_request(method, &headers, body.len(), &limits);
});
