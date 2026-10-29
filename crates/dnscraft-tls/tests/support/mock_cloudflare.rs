//! Hand-written mock Cloudflare DNS API (plain HTTP on loopback).
//!
//! Speaks enough of `/client/v4` for zone lookup and DNS record CRUD.
//! Records live in memory; every request is logged for assertions.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// One request as seen by the mock.
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

/// In-memory DNS record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockRecord {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
}

/// Zone fixture.
#[derive(Clone, Debug)]
pub struct MockZone {
    pub id: String,
    pub name: String,
    pub status: String,
    pub name_servers: Vec<String>,
}

/// Misbehaving response bodies for the client's size-cap tests.
///
/// Both variants keep the connection open for a while after writing, so a
/// client that waits for EOF before checking the size would stall.
#[derive(Clone, Copy, Debug)]
pub enum OversizeBody {
    /// `Content-Length` claims 2 MiB; only a few bytes follow.
    DeclaredOnly,
    /// 2 MiB of body with no `Content-Length`.
    Streamed,
}

struct State {
    token: String,
    zones: Vec<MockZone>,
    records: Vec<MockRecord>,
    next_id: AtomicU64,
    /// When set, the next matching response is forced (status, optional Retry-After).
    force_http: Option<(u16, Option<String>)>,
    /// When set, the response at this 1-based request ordinal is forced.
    force_at: Option<(usize, u16, Option<String>)>,
    /// When set, the next response is an oversized body.
    force_oversize: Option<OversizeBody>,
}

/// Loopback Cloudflare API mock.
#[derive(Clone)]
pub struct MockCloudflare {
    addr: SocketAddr,
    state: Arc<Mutex<State>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl MockCloudflare {
    /// Starts a mock with one zone and the given bearer token.
    pub async fn start(token: &str, zone: MockZone) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(Mutex::new(State {
            token: token.to_owned(),
            zones: vec![zone],
            records: Vec::new(),
            next_id: AtomicU64::new(1),
            force_http: None,
            force_at: None,
            force_oversize: None,
        }));
        let log = Arc::new(Mutex::new(Vec::new()));
        let (s, l) = (state.clone(), log.clone());
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(sock, s.clone(), l.clone()));
            }
        });
        Self { addr, state, log }
    }

    /// Base URL including `/client/v4` (same shape as production).
    pub fn base_url(&self) -> String {
        format!("http://{}/client/v4", self.addr)
    }

    pub async fn records(&self) -> Vec<MockRecord> {
        self.state.lock().await.records.clone()
    }

    /// Zones currently visible to the token.
    pub async fn zones(&self) -> Vec<MockZone> {
        self.state.lock().await.zones.clone()
    }

    /// Appends another zone visible to the token (for inventory tests).
    pub async fn add_zone(&self, zone: MockZone) {
        self.state.lock().await.zones.push(zone);
    }

    /// Inserts a DNS record directly (skips the HTTP create path).
    pub async fn insert_record(&self, record: MockRecord) {
        self.state.lock().await.records.push(record);
    }

    /// TXT RDATA currently stored for `name`.
    pub async fn txt_contents(&self, name: &str) -> Vec<String> {
        self.state
            .lock()
            .await
            .records
            .iter()
            .filter(|r| r.record_type == "TXT" && r.name == name)
            .map(|r| r.content.clone())
            .collect()
    }

    pub async fn requests(&self) -> Vec<RecordedRequest> {
        self.log.lock().await.clone()
    }

    /// Make the next API response an oversized body of the given shape.
    pub async fn force_next_oversize(&self, kind: OversizeBody) {
        self.state.lock().await.force_oversize = Some(kind);
    }

    /// Force the next API response to this HTTP status (and optional Retry-After).
    pub async fn force_next_status(&self, status: u16, retry_after: Option<&str>) {
        self.state.lock().await.force_http = Some((status, retry_after.map(str::to_owned)));
    }

    /// Force the response to the request with this 1-based ordinal (across all
    /// routes) to `status`. Used to fail midway through a multi-write pass.
    pub async fn force_status_on_request(
        &self,
        ordinal: usize,
        status: u16,
        retry_after: Option<&str>,
    ) {
        self.state.lock().await.force_at = Some((ordinal, status, retry_after.map(str::to_owned)));
    }
}

async fn serve(
    mut sock: TcpStream,
    state: Arc<Mutex<State>>,
    log: Arc<Mutex<Vec<RecordedRequest>>>,
) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 2048];
    // headers
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 64 * 1024 {
            return;
        }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let head = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_owned();
    let target = parts.next().unwrap_or("/").to_owned();
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), q.to_owned()),
        None => (target, String::new()),
    };
    let headers: HashMap<String, String> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let content_len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    while buf.len() < header_end + content_len {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 2 * 1024 * 1024 {
            return;
        }
    }
    let body = String::from_utf8_lossy(&buf[header_end..header_end + content_len]).into_owned();

    log.lock().await.push(RecordedRequest {
        method: method.clone(),
        path: path.clone(),
        query: query.clone(),
        headers: headers.clone(),
        body: body.clone(),
    });
    let ordinal = log.lock().await.len();

    let mut st = state.lock().await;

    if let Some(kind) = st.force_oversize.take() {
        drop(st);
        let head = match kind {
            OversizeBody::DeclaredOnly => {
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: 2097152\r\n\r\n"
            }
            OversizeBody::Streamed => {
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n"
            }
        };
        let _ = sock.write_all(head.as_bytes()).await;
        match kind {
            OversizeBody::DeclaredOnly => {
                let _ = sock.write_all(b"{\"success\":").await;
            }
            OversizeBody::Streamed => {
                let chunk = vec![b' '; 64 * 1024];
                for _ in 0..32 {
                    if sock.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
            }
        }
        let _ = sock.flush().await;
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        return;
    }

    if let Some((at, status, retry)) = st.force_at.clone()
        && ordinal == at
    {
        st.force_at = None;
        let body = format!(
            r#"{{"success":false,"errors":[{{"code":{status},"message":"forced"}}],"messages":[],"result":null}}"#
        );
        drop(st);
        write_response(&mut sock, status, retry.as_deref(), &body).await;
        return;
    }

    if let Some((status, retry)) = st.force_http.take() {
        let body = format!(
            r#"{{"success":false,"errors":[{{"code":{status},"message":"forced"}}],"messages":[],"result":null}}"#
        );
        drop(st);
        write_response(&mut sock, status, retry.as_deref(), &body).await;
        return;
    }

    let auth = headers.get("authorization").cloned().unwrap_or_default();
    let expected = format!("Bearer {}", st.token);
    if auth != expected {
        let body = r#"{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}"#;
        drop(st);
        write_response(&mut sock, 401, None, body).await;
        return;
    }

    let response = handle(&mut st, &method, &path, &query, &body);
    drop(st);
    write_response(&mut sock, response.0, response.1.as_deref(), &response.2).await;
}

fn handle(
    st: &mut State,
    method: &str,
    path: &str,
    query: &str,
    body: &str,
) -> (u16, Option<String>, String) {
    let q = parse_query(query);

    // GET /client/v4/zones[?name=&page=&per_page=]
    if method == "GET" && path == "/client/v4/zones" {
        let name = q.get("name").map(String::as_str).unwrap_or("");
        let matched: Vec<&MockZone> = if name.is_empty() {
            st.zones.iter().collect()
        } else {
            st.zones.iter().filter(|z| z.name == name).collect()
        };
        let page = parse_u32(q.get("page"), 1).max(1);
        let per_page = parse_u32(q.get("per_page"), 50).max(1);
        let total_count = matched.len() as u32;
        let start = ((page - 1) * per_page) as usize;
        let page_zones: Vec<&MockZone> = matched
            .into_iter()
            .skip(start)
            .take(per_page as usize)
            .collect();
        let result: Vec<serde_json::Value> = page_zones.iter().map(|z| zone_json(z)).collect();
        return ok_json_paginated(
            serde_json::Value::Array(result),
            page,
            per_page,
            total_count,
        );
    }

    // GET /client/v4/zones/{id}
    if method == "GET"
        && let Some(id) = path.strip_prefix("/client/v4/zones/")
        && !id.contains('/')
    {
        return match st.zones.iter().find(|z| z.id == id) {
            Some(z) => ok_json(zone_json(z)),
            None => fail_json(404, 1001, "Zone not found"),
        };
    }

    // /client/v4/zones/{zid}/dns_records[/{rid}]
    if let Some(rest) = path.strip_prefix("/client/v4/zones/")
        && let Some((zid, after)) = rest.split_once("/dns_records")
    {
        if !st.zones.iter().any(|z| z.id == zid) {
            return fail_json(404, 1001, "Zone not found");
        }

        // collection
        if after.is_empty() || after == "/" {
            match method {
                "GET" => {
                    let name = q.get("name").cloned();
                    let rtype = q.get("type").cloned();
                    let name_substr = q.get("name_substr").cloned();
                    let filtered: Vec<&MockRecord> = st
                        .records
                        .iter()
                        .filter(|r| r.zone_id == zid)
                        .filter(|r| name.as_ref().is_none_or(|n| &r.name == n))
                        .filter(|r| rtype.as_ref().is_none_or(|t| &r.record_type == t))
                        .filter(|r| {
                            name_substr.as_ref().is_none_or(|s| {
                                r.name
                                    .to_ascii_lowercase()
                                    .contains(&s.to_ascii_lowercase())
                            })
                        })
                        .collect();
                    // Paginate only when the caller asks for a page (inventory /
                    // Domain-Zonen). Filtered ACME helpers omit page and get all.
                    if q.contains_key("page") || q.contains_key("per_page") {
                        let page = parse_u32(q.get("page"), 1).max(1);
                        let per_page = parse_u32(q.get("per_page"), 100).max(1);
                        let total_count = filtered.len() as u32;
                        let start = ((page - 1) * per_page) as usize;
                        let list: Vec<serde_json::Value> = filtered
                            .into_iter()
                            .skip(start)
                            .take(per_page as usize)
                            .map(record_json)
                            .collect();
                        return ok_json_paginated(
                            serde_json::Value::Array(list),
                            page,
                            per_page,
                            total_count,
                        );
                    }
                    let list: Vec<serde_json::Value> =
                        filtered.into_iter().map(record_json).collect();
                    return ok_json(serde_json::Value::Array(list));
                }
                "POST" => {
                    let v: serde_json::Value = match serde_json::from_str(body) {
                        Ok(v) => v,
                        Err(_) => return fail_json(400, 9000, "bad json"),
                    };
                    let id = format!("rec-{}", st.next_id.fetch_add(1, Ordering::SeqCst));
                    let rec = MockRecord {
                        id: id.clone(),
                        zone_id: zid.to_owned(),
                        name: v["name"].as_str().unwrap_or("").to_owned(),
                        record_type: v["type"].as_str().unwrap_or("").to_owned(),
                        content: v["content"].as_str().unwrap_or("").to_owned(),
                        ttl: v["ttl"].as_u64().unwrap_or(1) as u32,
                        proxied: v["proxied"].as_bool().unwrap_or(false),
                    };
                    st.records.push(rec.clone());
                    return ok_json(record_json(&rec));
                }
                _ => return fail_json(405, 9001, "method not allowed"),
            }
        }

        // item /{id}
        if let Some(rid) = after.strip_prefix('/') {
            let rid = rid.trim_end_matches('/');
            match method {
                "PUT" | "PATCH" => {
                    let v: serde_json::Value = match serde_json::from_str(body) {
                        Ok(v) => v,
                        Err(_) => return fail_json(400, 9000, "bad json"),
                    };
                    let Some(rec) = st
                        .records
                        .iter_mut()
                        .find(|r| r.id == rid && r.zone_id == zid)
                    else {
                        return fail_json(404, 81044, "Record not found");
                    };
                    if let Some(n) = v["name"].as_str() {
                        rec.name = n.to_owned();
                    }
                    if let Some(t) = v["type"].as_str() {
                        rec.record_type = t.to_owned();
                    }
                    if let Some(c) = v["content"].as_str() {
                        rec.content = c.to_owned();
                    } else if let Some(target) = v.pointer("/data/target").and_then(|x| x.as_str())
                    {
                        let priority = v
                            .pointer("/data/priority")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        let weight = v
                            .pointer("/data/weight")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        let port = v
                            .pointer("/data/port")
                            .and_then(|x| x.as_u64())
                            .unwrap_or(0);
                        rec.content = format!("{priority} {weight} {port} {target}");
                    }
                    if let Some(t) = v["ttl"].as_u64() {
                        rec.ttl = t as u32;
                    }
                    if let Some(p) = v["proxied"].as_bool() {
                        rec.proxied = p;
                    }
                    let out = rec.clone();
                    return ok_json(record_json(&out));
                }
                "DELETE" => {
                    let before = st.records.len();
                    st.records.retain(|r| !(r.id == rid && r.zone_id == zid));
                    if st.records.len() == before {
                        return fail_json(404, 81044, "Record not found");
                    }
                    return ok_json(serde_json::json!({ "id": rid }));
                }
                _ => return fail_json(405, 9001, "method not allowed"),
            }
        }
    }

    fail_json(404, 7000, "not found")
}

fn zone_json(z: &MockZone) -> serde_json::Value {
    serde_json::json!({
        "id": z.id,
        "name": z.name,
        "status": z.status,
        "name_servers": z.name_servers,
    })
}

fn record_json(r: &MockRecord) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "zone_id": r.zone_id,
        "name": r.name,
        "type": r.record_type,
        "content": r.content,
        "ttl": r.ttl,
        "proxied": r.proxied,
    })
}

fn ok_json(result: serde_json::Value) -> (u16, Option<String>, String) {
    let body = serde_json::json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
    })
    .to_string();
    (200, None, body)
}

fn ok_json_paginated(
    result: serde_json::Value,
    page: u32,
    per_page: u32,
    total_count: u32,
) -> (u16, Option<String>, String) {
    let count = result.as_array().map(|a| a.len() as u32).unwrap_or(0);
    let total_pages = if per_page == 0 || total_count == 0 {
        0
    } else {
        total_count.div_ceil(per_page)
    };
    let body = serde_json::json!({
        "success": true,
        "errors": [],
        "messages": [],
        "result": result,
        "result_info": {
            "page": page,
            "per_page": per_page,
            "count": count,
            "total_count": total_count,
            "total_pages": total_pages,
        },
    })
    .to_string();
    (200, None, body)
}

fn parse_u32(v: Option<&String>, default: u32) -> u32 {
    v.and_then(|s| s.parse().ok()).unwrap_or(default)
}

fn fail_json(http: u16, code: u32, message: &str) -> (u16, Option<String>, String) {
    let body = serde_json::json!({
        "success": false,
        "errors": [{ "code": code, "message": message }],
        "messages": [],
        "result": null,
    })
    .to_string();
    (http, None, body)
}

fn parse_query(q: &str) -> HashMap<String, String> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .filter_map(|p| {
            let (k, v) = p.split_once('=')?;
            Some((urlencoding_decode(k), urlencoding_decode(v)))
        })
        .collect()
}

fn urlencoding_decode(s: &str) -> String {
    // Enough for our tests (no unicode escapes).
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let h = |c: u8| -> Option<u8> {
                    match c {
                        b'0'..=b'9' => Some(c - b'0'),
                        b'a'..=b'f' => Some(c - b'a' + 10),
                        b'A'..=b'F' => Some(c - b'A' + 10),
                        _ => None,
                    }
                };
                if let (Some(a), Some(b)) = (h(bytes[i + 1]), h(bytes[i + 2])) {
                    out.push((a << 4) | b);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn write_response(sock: &mut TcpStream, status: u16, retry_after: Option<&str>, body: &str) {
    let reason = match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        _ => "Status",
    };
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(ra) = retry_after {
        head.push_str(&format!("Retry-After: {ra}\r\n"));
    }
    head.push_str("\r\n");
    let _ = sock.write_all(head.as_bytes()).await;
    let _ = sock.write_all(body.as_bytes()).await;
}
