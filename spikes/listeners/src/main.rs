//! Throw-away N0 spike: pktinfo, quinn ring-only, HTTP/3, HTTP/2.
//!
//! Run from this directory: `cargo run`. Prints PASS/FAIL per check.
//! Does not touch the internet. Loopback and documentation names only.

mod cert;
mod h2;
mod h3_check;
mod pktinfo;
mod quic_ring;

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    println!("=== spike-listeners N0 (aarch64 Linux expected) ===\n");

    let mut failed = 0u32;

    match pktinfo::run() {
        Ok(report) => {
            println!("[1] quinn-udp pktinfo: PASS");
            for line in report {
                println!("    {line}");
            }
        }
        Err(e) => {
            println!("[1] quinn-udp pktinfo: FAIL — {e}");
            failed += 1;
        }
    }
    println!();

    match quic_ring::run().await {
        Ok(report) => {
            println!("[2] quinn rustls-ring + ResolvesServerCert: PASS");
            for line in report {
                println!("    {line}");
            }
        }
        Err(e) => {
            println!("[2] quinn rustls-ring + ResolvesServerCert: FAIL — {e}");
            failed += 1;
        }
    }
    println!();

    match h3_check::run().await {
        Ok(report) => {
            println!("[3] h3 + h3-quinn HTTP/3 GET: PASS");
            for line in report {
                println!("    {line}");
            }
        }
        Err(e) => {
            println!("[3] h3 + h3-quinn HTTP/3 GET: FAIL — {e}");
            failed += 1;
        }
    }
    println!();

    match h2::run().await {
        Ok(report) => {
            println!("[4] hyper 1 + hyper-util HTTP/2: PASS");
            for line in report {
                println!("    {line}");
            }
        }
        Err(e) => {
            println!("[4] hyper 1 + hyper-util HTTP/2: FAIL — {e}");
            failed += 1;
        }
    }
    println!();

    println!("=== crypto tree (run from this spike dir) ===");
    println!("    cargo tree -i aws-lc-rs");
    println!("    cargo tree -i aws-lc-sys");
    println!("    cargo tree -i openssl-sys");
    println!("    (must all be empty / 'did not match any packages')");
    println!();

    if failed == 0 {
        println!("All checks passed.");
        ExitCode::SUCCESS
    } else {
        println!("{failed} check(s) failed.");
        ExitCode::FAILURE
    }
}
