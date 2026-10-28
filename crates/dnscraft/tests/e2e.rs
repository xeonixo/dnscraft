//! End-to-end: spawn the binary on an ephemeral port, send one hostile UDP
//! query, check one valid escaped JSON stdout line, then SIGTERM → exit 0.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnscraft_proto::{Message, Name, RecordType};
use serde_json::Value;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_dnscraft")
}

fn temp_config(tag: &str, toml: &str) -> PathBuf {
    static NONCE: AtomicU64 = AtomicU64::new(0);
    let nonce = NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "dnscraft-{tag}-{}-{nanos}-{nonce}.toml",
        std::process::id()
    ));
    std::fs::write(&path, toml).unwrap();
    path
}

/// Reads stderr until the `listening on 127.0.0.1:<port>` info line and
/// returns the port.
fn wait_for_port(child: &mut Child, timeout: Duration) -> u16 {
    let stderr = child.stderr.take().expect("stderr must be piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        // Keep draining after the match: a closed pipe would make the
        // binary's later log writes fail.
        let reader = BufReader::new(stderr);
        let mut sent = false;
        for line in reader.lines().map_while(Result::ok) {
            if sent {
                continue;
            }
            if let Some(port) = line
                .split_once("listening on 127.0.0.1:")
                .map(|(_, rest)| rest)
                .and_then(|rest| rest.split_whitespace().next())
                .and_then(|port| port.parse::<u16>().ok())
            {
                let _ = tx.send(port);
                sent = true;
            }
        }
    });
    rx.recv_timeout(timeout)
        .expect("binary must report the bound 127.0.0.1 port")
}

/// Reads one line from stdout within `timeout`.
fn read_stdout_line(stdout: impl std::io::Read + Send + 'static, timeout: Duration) -> String {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        if let Some(line) = reader.lines().map_while(Result::ok).next() {
            let _ = tx.send(line);
        }
    });
    rx.recv_timeout(timeout).expect("one JSON stdout line")
}

#[test]
fn udp_query_logs_one_escaped_json_line() {
    let cfg = temp_config(
        "e2e",
        r#"public_domain = "example.com"

[log]
queries = true

[[listeners]]
id = "udp"
protocol = "udp53"
address = "127.0.0.1:0"
"#,
    );
    let mut child = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let port = wait_for_port(&mut child, Duration::from_secs(20));
    let stdout = child.stdout.take().expect("stdout must be piped");

    // A label with a quote, a backslash, a control byte and an embedded newline,
    // under `local.` (answered locally as special-use NXDOMAIN — no internet).
    let name = Name::from_ascii(r#"a"b\\c\001d\010.local."#).unwrap();
    let query = Message::query(0x1234, name.clone(), RecordType::A)
        .encode()
        .unwrap();

    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&query, ("127.0.0.1", port)).unwrap();

    let mut buf = [0u8; 4096];
    let (n, _src) = socket.recv_from(&mut buf).expect("one DNS answer");
    assert!(n > 0, "expected a non-empty DNS answer");

    // One valid JSON line; no raw control byte leaks into it.
    let line = read_stdout_line(stdout, Duration::from_secs(5));
    assert!(
        !line.as_bytes().contains(&0x01),
        "raw control byte in JSON line: {line:?}"
    );
    assert!(
        !line.as_bytes().contains(&0x0A),
        "raw newline in JSON line: {line:?}"
    );
    let json: Value = serde_json::from_str(&line).expect("stdout line is valid JSON");
    assert_eq!(json["qname"], name.to_string());

    // SIGTERM → graceful exit 0.
    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(kill.success(), "kill -TERM must succeed");
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0), "graceful SIGTERM must exit 0");

    let _ = std::fs::remove_file(&cfg);
}
