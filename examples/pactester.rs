/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Resolve the proxy for URLs the way the OS would — reading the OS proxy
//! config, WPAD, and any configured PAC script — and print the ordered proxy
//! list per URL. Works on every platform.
//!
//! ```text
//! cargo run --example pactester -- <url> [<url>...]
//! cargo run --example pactester -- --pac-script <path-or-url> <url> [<url>...]
//! ```
//!
//! With `--pac-script`, the given PAC file is evaluated instead of the OS
//! configuration. It may be a local path, a `file://` URL, or an `http(s)://`
//! URL. On Windows PAC evaluation is WinHTTP's, and WinHTTP only loads PAC over
//! http(s), so a local file is served from an ephemeral `127.0.0.1` URL.

use os_proxy_resolver::ProxyResolver;

fn main() {
    let mut pac_script: Option<String> = None;
    let mut urls: Vec<String> = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--pac-script" {
            pac_script = Some(
                args.next()
                    .unwrap_or_else(|| usage_error("--pac-script requires a value")),
            );
        } else if let Some(value) = arg.strip_prefix("--pac-script=") {
            pac_script = Some(value.to_string());
        } else if arg == "-h" || arg == "--help" {
            print_usage();
            return;
        } else if arg.starts_with('-') && arg != "-" {
            usage_error(&format!("unknown option: {arg}"));
        } else {
            urls.push(arg);
        }
    }

    if urls.is_empty() {
        usage_error("no URLs given");
    }

    let resolver = ProxyResolver::new();
    // Resolve the PAC override to something the library can load on this
    // platform (on Windows this may spin up a localhost server for a file).
    let source = pac_script.as_deref().map(effective_pac_source);

    let mut failed = false;
    for raw in &urls {
        let parsed = match url::Url::parse(raw) {
            Ok(u) => u,
            Err(e) => {
                eprintln!("{raw} -> invalid URL: {e}");
                failed = true;
                continue;
            }
        };
        let result = match &source {
            Some(src) => resolver.evaluate_pac_source(src, &parsed),
            None => resolver.resolve_proxy(&parsed),
        };
        match result {
            Ok(list) => {
                let rendered: Vec<String> = list.iter().map(ToString::to_string).collect();
                println!("{raw} -> {}", rendered.join("; "));
            }
            Err(e) => {
                eprintln!("{raw} -> error: {e}");
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "usage: pactester [--pac-script <path-or-url>] <url> [<url>...]\n\
         \n\
         Without --pac-script, resolves each URL via the OS proxy config, WPAD,\n\
         and any configured PAC script. With --pac-script, evaluates the given\n\
         PAC file/URL (local path, file://, or http(s)://) instead."
    );
}

fn usage_error(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_usage();
    std::process::exit(2);
}

/// Off Windows the library loads local paths, `file://`, and `http(s)` PAC
/// sources directly, so the value passes through unchanged.
#[cfg(not(windows))]
fn effective_pac_source(source: &str) -> String {
    source.to_string()
}

/// On Windows WinHTTP only loads PAC over http(s). An `http(s)` source passes
/// through; a local path / `file://` URL is served from an ephemeral
/// `127.0.0.1` URL backed by a detached thread that lives for the process.
#[cfg(windows)]
fn effective_pac_source(source: &str) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    if url::Url::parse(source)
        .map(|u| matches!(u.scheme(), "http" | "https"))
        .unwrap_or(false)
    {
        return source.to_string();
    }

    let path = url::Url::parse(source)
        .ok()
        .filter(|u| u.scheme() == "file")
        .and_then(|u| u.to_file_path().ok())
        .unwrap_or_else(|| std::path::PathBuf::from(source));
    let body = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("error: cannot read PAC file {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("error: cannot start local PAC server: {e}");
            std::process::exit(1);
        }
    };
    let addr = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        let head = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/x-ns-proxy-autoconfig\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n",
            body.len()
        );
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    });
    format!("http://{addr}/proxy.pac")
}
