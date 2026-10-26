//! Thin entry point: maps [`dnscraft::run`]'s result to a process exit code.

#![allow(clippy::print_stderr)]

#[tokio::main]
async fn main() {
    dnscraft::init_tracing();
    let mut args = std::env::args();
    let _program = args.next();
    let config_path = args.next();

    let code = match dnscraft::run(config_path.as_deref()).await {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("dnscraft: {error}");
            error.exit_code()
        }
    };
    std::process::exit(code);
}
