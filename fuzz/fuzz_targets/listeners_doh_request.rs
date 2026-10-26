#![no_main]

//! Fuzzes the DoH request parsing surface (`parse_doh_path`, `extract_wire`,
//! `content_type_of`) with arbitrary method / path / query / headers / body.
//! Only the "never panic" property is checked — no specific outcome is asserted.

use dnscraft_listeners::{content_type_of, extract_wire, parse_doh_path};
use http::{HeaderMap, HeaderValue, Method, Uri};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Byte 0 picks the method; the rest is path + query + body material.
    let method = match data[0] % 4 {
        0 => Method::GET,
        1 => Method::POST,
        2 => Method::PUT,
        _ => Method::DELETE,
    };
    let text = String::from_utf8_lossy(&data[1..]);

    // `parse_doh_path` sees only the path (up to the first `?`).
    let path = text.split('?').next().unwrap_or("");
    let _ = parse_doh_path(path);

    // `extract_wire` sees a URI built from the full text; an unrepresentable
    // URI is skipped (the path parser above must still never panic).
    let uri = format!("https://dns.example.com{text}");
    let Ok(uri) = Uri::try_from(uri) else {
        return;
    };

    let ct = match data[0] % 3 {
        0 => Some("application/dns-message"),
        1 => Some("text/plain"),
        _ => None,
    };

    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_bytes(&data[1..]) {
        headers.insert("x-data", v);
    }
    if let Some(c) = ct {
        headers.insert("content-type", HeaderValue::from_static(c));
    }

    let _ = extract_wire(&method, &uri, ct, &data[1..]);
    let _ = content_type_of(&headers);
});
