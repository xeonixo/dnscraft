//! Loopback mock for Cloudflare `cdn-cgi/trace`-style IP echo.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// Serves a queue of response bodies (FIFO), one per GET.
#[derive(Clone)]
pub struct MockEcho {
    addr: SocketAddr,
    bodies: Arc<Mutex<VecDeque<String>>>,
    force_status: Arc<Mutex<Option<u16>>>,
}

impl MockEcho {
    pub async fn start(initial_bodies: impl IntoIterator<Item = String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(initial_bodies.into_iter().collect()));
        let force_status = Arc::new(Mutex::new(None));
        let (b, f) = (bodies.clone(), force_status.clone());
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    return;
                };
                tokio::spawn(serve(sock, b.clone(), f.clone()));
            }
        });
        Self {
            addr,
            bodies,
            force_status,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/cdn-cgi/trace", self.addr)
    }

    /// Replace the FIFO of bodies (next GETs pop from the front).
    pub async fn set_bodies(&self, bodies: impl IntoIterator<Item = String>) {
        *self.bodies.lock().await = bodies.into_iter().collect();
    }

    /// Force the next response status (then clear).
    pub async fn force_next_status(&self, status: u16) {
        *self.force_status.lock().await = Some(status);
    }
}

pub fn trace_body(ip: &str) -> String {
    format!("fl=1\nh=example.com\nip={ip}\nts=1\nvisit_scheme=http\n")
}

async fn serve(
    mut sock: TcpStream,
    bodies: Arc<Mutex<VecDeque<String>>>,
    force_status: Arc<Mutex<Option<u16>>>,
) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        match sock.read(&mut tmp).await {
            Ok(0) | Err(_) => return,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
        if buf.len() > 16 * 1024 {
            return;
        }
    }

    let status = force_status.lock().await.take().unwrap_or(200);
    let body = if status == 200 {
        bodies
            .lock()
            .await
            .pop_front()
            .unwrap_or_else(|| "ip=missing\n".into())
    } else {
        String::new()
    };

    let resp = format!(
        "HTTP/1.1 {status} OK\r\nConnection: close\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    let _ = sock.write_all(resp.as_bytes()).await;
    let _ = sock.flush().await;
}
