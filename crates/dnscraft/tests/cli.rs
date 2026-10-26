//! Spawns the compiled binary and checks startup, SIGTERM shutdown, and exit codes.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn spawn(config: &Path) -> Child {
    Command::new(binary())
        .arg(config)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Reads stderr until a line contains `needle`, or `timeout` elapses.
fn wait_for_stderr_line(child: &mut Child, needle: &str, timeout: Duration) -> bool {
    let stderr = child.stderr.take().expect("stderr must be piped");
    let needle = needle.to_owned();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains(&needle) {
                let _ = tx.send(());
                return;
            }
        }
    });
    rx.recv_timeout(timeout).is_ok()
}

/// Reads stderr until the `dnscraft: listening on …` line appears and returns it.
fn wait_for_listening_line(child: &mut Child, timeout: Duration) -> String {
    let stderr = child.stderr.take().expect("stderr must be piped");
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines().map_while(Result::ok) {
            if line.contains("listening on") {
                let _ = tx.send(line);
                return;
            }
        }
    });
    rx.recv_timeout(timeout)
        .expect("binary must report the bound address")
}

#[test]
fn exits_zero_on_sigterm() {
    let cfg = temp_config(
        "sigterm",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "udp53"
address = "127.0.0.1:0"
"#,
    );
    let mut child = spawn(&cfg);

    assert!(
        wait_for_stderr_line(&mut child, "listening", Duration::from_secs(20)),
        "binary must report it is listening"
    );

    // SIGTERM (not SIGKILL) so the graceful path runs.
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

#[test]
fn exits_two_on_bad_config() {
    let cfg = temp_config(
        "bad-config",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "bogus"
address = "127.0.0.1:0"
"#,
    );
    let out = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "invalid config must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.config.invalid_listener"),
        "stderr must carry the stable code: {stderr}"
    );

    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn exits_two_on_missing_file() {
    let out = Command::new(binary())
        .arg("/nonexistent/dnscraft.toml")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "missing config must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.config.read"),
        "stderr must carry the stable code: {stderr}"
    );
}

#[test]
fn exits_two_on_half_configured_tls_env() {
    let cfg = temp_config(
        "half-tls",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "udp53"
address = "127.0.0.1:0"
"#,
    );
    let out = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove("DNSCRAFT_TLS_CERT")
        .env_remove("DNSCRAFT_TLS_CERT_FILE")
        .env_remove("DNSCRAFT_TLS_KEY")
        .env_remove("DNSCRAFT_TLS_KEY_FILE")
        .env("DNSCRAFT_TLS_CERT", "-----BEGIN CERTIFICATE-----")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "half TLS env must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.config.tls_env_incomplete"),
        "stderr must carry the stable code: {stderr}"
    );

    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn exits_two_on_public_plaintext_listener() {
    let cfg = temp_config(
        "public-plaintext",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "udp53"
address = "127.0.0.1:0"
exposure = "public"
"#,
    );
    let out = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "public plaintext must exit 2");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.config.invalid_listener"),
        "stderr must carry the stable code: {stderr}"
    );

    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn exits_two_on_unknown_field() {
    let cfg = temp_config(
        "unknown-field",
        r#"public_domain = "example.com"
exposur = "public"
"#,
    );
    let out = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "unknown field must exit 2");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.config.unknown_field"),
        "stderr must carry the stable code: {stderr}"
    );
    assert!(
        stderr.contains("unknown field"),
        "stderr must name the unknown field: {stderr}"
    );

    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn exits_two_on_bind_failure() {
    let cfg = temp_config(
        "bind-failure",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "udp53"
address = "192.0.2.1:5300"
"#,
    );
    let out = Command::new(binary())
        .arg(&cfg)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "unbindable listener must exit 2"
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("dnscraft.startup.bind"),
        "stderr must carry the stable code: {stderr}"
    );
    assert!(
        stderr.contains("192.0.2.1:5300"),
        "stderr must name the failing address: {stderr}"
    );

    let _ = std::fs::remove_file(&cfg);
}

#[test]
fn prints_bound_address_for_ephemeral_port() {
    let cfg = temp_config(
        "ephemeral",
        r#"public_domain = "example.com"

[[listeners]]
id = "udp"
protocol = "udp53"
address = "127.0.0.1:0"
"#,
    );
    let mut child = spawn(&cfg);
    let line = wait_for_listening_line(&mut child, Duration::from_secs(20));
    assert!(
        line.contains("dnscraft: listening on 127.0.0.1:"),
        "stderr must print the real bound address: {line}"
    );

    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(kill.success());
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(0));

    let _ = std::fs::remove_file(&cfg);
}
