//! DoH request parsing: path routing, GET `dns=`, POST body (RFC 8484).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::{Method, Uri, header};

use crate::framing::MAX_MESSAGE_LEN;

/// MIME type for DNS wire messages on DoH.
pub const DNS_MESSAGE_TYPE: &str = "application/dns-message";

/// Maximum POST body / decoded GET payload (one DNS message).
pub const MAX_DOH_PAYLOAD: usize = MAX_MESSAGE_LEN;

/// Maximum accepted `dns=` query-string length (base64url of ≤ 65 535 octets).
pub const MAX_DNS_PARAM_CHARS: usize = (MAX_DOH_PAYLOAD * 4).div_ceil(3) + 8;

/// Maximum HTTP header-list / field-section size accepted by the DoH listener.
///
/// Shared by both transports: hyper's HTTP/2 `max_header_list_size` and h3's
/// `max_field_section_size` are pinned to the same bound so the two listeners
/// reject oversized header sections identically (RFC 9113 §10.5.1 / RFC 9114
/// §4.2.2). 16 KiB matches hyper's historical HTTP/2 default.
pub const MAX_DOH_HEADER_LIST_SIZE: u64 = 16 * 1024;

/// Path classification for DoH routing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DohPath {
    /// `/dns-query` — allowed on local listeners only.
    Bare,
    /// `/dns-query/<id>` with `id` lower-cased.
    ClientId(String),
    /// Anything else (404, no strike on public).
    Other,
}

/// Wire-extraction failure mapped to an HTTP status by the server.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DohWireError {
    /// Malformed query / body / base64.
    BadRequest,
    /// Method other than GET/POST.
    MethodNotAllowed,
    /// POST with wrong or missing Content-Type.
    UnsupportedMediaType,
    /// Body or decoded GET payload too large.
    PayloadTooLarge,
}

impl DohWireError {
    /// HTTP status code for this error.
    pub fn status(self) -> u16 {
        match self {
            Self::BadRequest => 400,
            Self::MethodNotAllowed => 405,
            Self::UnsupportedMediaType => 415,
            Self::PayloadTooLarge => 413,
        }
    }
}

/// Parses the request path (`/dns-query` or `/dns-query/<id>`).
///
/// `<id>` is lower-cased. Trailing slashes beyond the id are [`DohPath::Other`].
pub fn parse_doh_path(path: &str) -> DohPath {
    let path = path.trim_end_matches('/');
    if path == "/dns-query" {
        return DohPath::Bare;
    }
    let Some(rest) = path.strip_prefix("/dns-query/") else {
        return DohPath::Other;
    };
    if rest.is_empty() || rest.contains('/') {
        return DohPath::Other;
    }
    DohPath::ClientId(rest.to_ascii_lowercase())
}

/// Extracts the DNS wire message from a DoH GET or POST.
pub fn extract_wire(
    method: &Method,
    uri: &Uri,
    content_type: Option<&str>,
    body: &[u8],
) -> Result<Vec<u8>, DohWireError> {
    match *method {
        Method::GET => decode_get_dns(uri),
        Method::POST => decode_post(content_type, body),
        _ => Err(DohWireError::MethodNotAllowed),
    }
}

fn decode_get_dns(uri: &Uri) -> Result<Vec<u8>, DohWireError> {
    let query = uri.query().ok_or(DohWireError::BadRequest)?;
    let mut dns_val: Option<&str> = None;
    for pair in query.split('&') {
        let mut parts = pair.splitn(2, '=');
        let key = parts.next().unwrap_or("");
        let val = parts.next().unwrap_or("");
        if key == "dns" {
            if dns_val.is_some() {
                return Err(DohWireError::BadRequest);
            }
            dns_val = Some(val);
        }
    }
    let encoded = dns_val.ok_or(DohWireError::BadRequest)?;
    if encoded.is_empty() || encoded.len() > MAX_DNS_PARAM_CHARS {
        return Err(DohWireError::BadRequest);
    }
    // RFC 8484: base64url, no padding — reject `=`.
    if encoded.as_bytes().contains(&b'=') {
        return Err(DohWireError::BadRequest);
    }
    let wire = URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| DohWireError::BadRequest)?;
    if wire.is_empty() {
        return Err(DohWireError::BadRequest);
    }
    if wire.len() > MAX_DOH_PAYLOAD {
        return Err(DohWireError::PayloadTooLarge);
    }
    Ok(wire)
}

fn decode_post(content_type: Option<&str>, body: &[u8]) -> Result<Vec<u8>, DohWireError> {
    let ct = content_type.ok_or(DohWireError::UnsupportedMediaType)?;
    // Allow optional parameters after the type (e.g. charset — still require the DNS type).
    let media = ct.split(';').next().unwrap_or(ct).trim();
    if !media.eq_ignore_ascii_case(DNS_MESSAGE_TYPE) {
        return Err(DohWireError::UnsupportedMediaType);
    }
    if body.len() > MAX_DOH_PAYLOAD {
        return Err(DohWireError::PayloadTooLarge);
    }
    if body.is_empty() {
        return Err(DohWireError::BadRequest);
    }
    Ok(body.to_vec())
}

/// Reads `Content-Type` from request headers.
pub fn content_type_of(headers: &http::HeaderMap) -> Option<&str> {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use http::Uri;

    #[test]
    fn path_bare_id_other() {
        assert_eq!(parse_doh_path("/dns-query"), DohPath::Bare);
        assert_eq!(parse_doh_path("/dns-query/"), DohPath::Bare);
        assert_eq!(
            parse_doh_path("/dns-query/Phone"),
            DohPath::ClientId("phone".into())
        );
        assert_eq!(parse_doh_path("/dns-query/a/b"), DohPath::Other);
        assert_eq!(parse_doh_path("/other"), DohPath::Other);
        assert_eq!(parse_doh_path("/"), DohPath::Other);
    }

    #[test]
    fn get_rejects_padding_and_accepts_urlsafe() {
        // Wire: minimal header-ish bytes that round-trip.
        let raw = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let enc = URL_SAFE_NO_PAD.encode(raw);
        let uri: Uri = format!("/dns-query?dns={enc}").parse().unwrap();
        assert_eq!(extract_wire(&Method::GET, &uri, None, b"").unwrap(), raw);

        let padded = format!("{enc}=");
        let uri_pad: Uri = format!("/dns-query?dns={padded}").parse().unwrap();
        assert_eq!(
            extract_wire(&Method::GET, &uri_pad, None, b""),
            Err(DohWireError::BadRequest)
        );
    }

    #[test]
    fn post_type_and_size() {
        let body = vec![0u8; 12];
        assert!(
            extract_wire(
                &Method::POST,
                &"/dns-query".parse().unwrap(),
                Some(DNS_MESSAGE_TYPE),
                &body
            )
            .is_ok()
        );
        assert_eq!(
            extract_wire(
                &Method::POST,
                &"/dns-query".parse().unwrap(),
                Some("text/plain"),
                &body
            ),
            Err(DohWireError::UnsupportedMediaType)
        );
        let big = vec![0u8; MAX_DOH_PAYLOAD + 1];
        assert_eq!(
            extract_wire(
                &Method::POST,
                &"/dns-query".parse().unwrap(),
                Some(DNS_MESSAGE_TYPE),
                &big
            ),
            Err(DohWireError::PayloadTooLarge)
        );
    }

    #[test]
    fn method_not_allowed() {
        assert_eq!(
            extract_wire(&Method::PUT, &"/dns-query".parse().unwrap(), None, b""),
            Err(DohWireError::MethodNotAllowed)
        );
    }
}
