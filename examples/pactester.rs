/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! pactester-style CLI: evaluate a PAC file against URLs.
//!
//! ```text
//! cargo run --example pactester -- <pac-file> <url> [<url>...]
//! ```
//!
//! Not available on Windows, where PAC evaluation is WinHTTP's job — use
//! `examples/resolve.rs` there.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 {
        eprintln!("usage: pactester <pac-file> <url> [<url>...]");
        std::process::exit(2);
    }
    run(&args[0], &args[1..]);
}

#[cfg(windows)]
fn run(_pac_file: &str, _urls: &[String]) {
    eprintln!("pactester is not available on Windows (PAC evaluation is delegated to WinHTTP)");
    std::process::exit(1);
}

#[cfg(not(windows))]
fn run(pac_file: &str, urls: &[String]) {
    let script = match std::fs::read_to_string(pac_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read {pac_file}: {e}");
            std::process::exit(1);
        }
    };
    let resolver = os_proxy_resolver::ProxyResolver::new();
    let mut failed = false;
    for raw in urls {
        match url::Url::parse(raw) {
            Ok(url) => match resolver.evaluate_pac(&script, &url) {
                Ok(list) => {
                    let rendered: Vec<String> = list.iter().map(|p| p.to_string()).collect();
                    println!("{raw} -> {}", rendered.join("; "));
                }
                Err(e) => {
                    eprintln!("{raw} -> error: {e}");
                    failed = true;
                }
            },
            Err(e) => {
                eprintln!("{raw} -> invalid URL: {e}");
                failed = true;
            }
        }
    }
    if failed {
        std::process::exit(1);
    }
}
