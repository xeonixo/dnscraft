//! Minimal scripted HTTP/1.1 server for fetcher tests. Loopback only.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// What the server answers for one path.
#[derive(Clone, Debug)]
pub struct Route {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Send with `Transfer-Encoding: chunked` in pieces of this size.
    pub chunk_size: Option<usize>,
    /// Pause between chunks.
    pub chunk_delay: Duration,
    /// Pause before the first byte of the response.
    pub delay_before: Duration,
    /// If set, answer 304 when `If-None-Match` equals this value, else 200
    /// with `ETag` set to it.
    pub etag: Option<String>,
    /// If set, ignore `body` and stream this many `x` bytes chunked.
    pub stream_total: Option<usize>,
}

impl Route {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            chunk_size: None,
            chunk_delay: Duration::ZERO,
            delay_before: Duration::ZERO,
            etag: None,
            stream_total: None,
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::ok(Vec::new())
        }
    }

    pub fn redirect(location: &str) -> Self {
        Self::status(302).header("Location", location)
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn etag(mut self, etag: &str) -> Self {
        self.etag = Some(etag.to_owned());
        self
    }

    pub fn chunked(mut self, size: usize, delay: Duration) -> Self {
        self.chunk_size = Some(size);
        self.chunk_delay = delay;
        self
    }

    pub fn delayed(mut self, delay: Duration) -> Self {
        self.delay_before = delay;
        self
    }

    pub fn stream(mut self, total: usize, chunk: usize, delay: Duration) -> Self {
        self.stream_total = Some(total);
        self.chunk_size = Some(chunk);
        self.chunk_delay = delay;
        self
    }
}

/// One request as seen by the server.
#[derive(Clone, Debug)]
pub struct Recorded {
    pub path: String,
    /// Header names lower-cased.
    pub headers: HashMap<String, String>,
}

pub struct TestServer {
    pub addr: SocketAddr,
    log: Arc<Mutex<Vec<Recorded>>>,
    bytes_sent: Arc<AtomicU64>,
}

impl TestServer {
    pub async fn start(routes: Vec<(&str, Route)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let routes: Arc<HashMap<String, Route>> =
            Arc::new(routes.into_iter().map(|(p, r)| (p.to_owned(), r)).collect());
        let log = Arc::new(Mutex::new(Vec::new()));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let (l, b) = (log.clone(), bytes_sent.clone());
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(sock, routes.clone(), l.clone(), b.clone()));
            }
        });
        Self {
            addr,
            log,
            bytes_sent,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    pub fn requests(&self) -> Vec<Recorded> {
        self.log.lock().unwrap().clone()
    }

    /// Body bytes successfully handed to the socket so far.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::SeqCst)
    }
}

async fn serve(
    mut sock: TcpStream,
    routes: Arc<HashMap<String, Route>>,
    log: Arc<Mutex<Vec<Recorded>>>,
    sent: Arc<AtomicU64>,
) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 64 * 1024 {
            return;
        }
    }
    let text = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_owned();
    let headers: HashMap<String, String> = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    log.lock().unwrap().push(Recorded {
        path: path.clone(),
        headers: headers.clone(),
    });

    let Some(route) = routes.get(&path) else {
        let _ = sock
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await;
        return;
    };
    if !route.delay_before.is_zero() {
        tokio::time::sleep(route.delay_before).await;
    }
    let mut status = route.status;
    let mut extra: Vec<(String, String)> = route.headers.clone();
    if let Some(etag) = &route.etag {
        if headers.get("if-none-match") == Some(etag) {
            status = 304;
        }
        extra.push(("ETag".into(), etag.clone()));
    }
    let reason = match status {
        200 => "OK",
        302 => "Found",
        304 => "Not Modified",
        404 => "Not Found",
        _ => "Status",
    };
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
    for (k, v) in &extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    let chunked = route.chunk_size.is_some() && status != 304;
    if status == 304 {
        head.push_str("\r\n");
        let _ = sock.write_all(head.as_bytes()).await;
        return;
    }
    if chunked {
        head.push_str("Transfer-Encoding: chunked\r\n\r\n");
    } else {
        head.push_str(&format!("Content-Length: {}\r\n\r\n", route.body.len()));
    }
    if sock.write_all(head.as_bytes()).await.is_err() {
        return;
    }
    if !chunked {
        if sock.write_all(&route.body).await.is_ok() {
            sent.fetch_add(route.body.len() as u64, Ordering::SeqCst);
        }
        return;
    }
    let size = route.chunk_size.unwrap_or(1).max(1);
    let total = route.stream_total.unwrap_or(route.body.len());
    let mut offset = 0;
    while offset < total {
        let n = size.min(total - offset);
        let piece: Vec<u8> = match route.stream_total {
            Some(_) => vec![b'x'; n],
            None => route.body[offset..offset + n].to_vec(),
        };
        let mut frame = format!("{n:x}\r\n").into_bytes();
        frame.extend_from_slice(&piece);
        frame.extend_from_slice(b"\r\n");
        if sock.write_all(&frame).await.is_err() {
            return;
        }
        sent.fetch_add(n as u64, Ordering::SeqCst);
        offset += n;
        if !route.chunk_delay.is_zero() {
            tokio::time::sleep(route.chunk_delay).await;
        }
    }
    let _ = sock.write_all(b"0\r\n\r\n").await;
}
