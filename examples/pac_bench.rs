/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Benchmark the two PAC evaluation paths against each other:
//!
//! * **system** — [`ProxyResolver::evaluate_pac_source`], which on Windows is
//!   WinHTTP (`WinHttpGetProxyForUrl`) and off Windows is the embedded engine
//!   fed by an HTTP fetch.
//! * **quickjs** — [`ProxyResolver::evaluate_pac`], the embedded QuickJS
//!   engine evaluated directly from the script text.
//!
//! The interesting comparison is **on Windows**, where the two paths are two
//! genuinely different engines (WinHTTP vs QuickJS). That is why this example
//! only builds the QuickJS side on Windows behind `--features pac-engine`
//! (off Windows the engine is always built). Off Windows both paths are the
//! same QuickJS engine, so the numbers only exercise the harness.
//!
//! ```text
//! cargo run --release --example pac_bench --features pac-engine
//! cargo run --release --example pac_bench --features pac-engine -- \
//!     --iterations 5000 --pac-script my.pac https://a.example/ http://b.corp/
//! ```
//!
//! The same PAC script is served from an ephemeral `127.0.0.1` HTTP endpoint
//! (WinHTTP only loads PAC over http(s)) and also handed to the QuickJS engine
//! as text, so both evaluate identical input.

use os_proxy_resolver::{ProxyKind, ProxyResolver};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use url::Url;

/// A small but non-trivial PAC script: a few helper calls and branches so the
/// measurement reflects real evaluation cost rather than a bare `return`.
const DEFAULT_PAC: &str = r#"
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        isInNet(host, "127.0.0.0", "255.0.0.0")) {
        return "DIRECT";
    }
    if (dnsDomainIs(host, ".corp.example.com") ||
        shExpMatch(url, "http://intra.example.com/*")) {
        return "PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080; DIRECT";
    }
    if (shExpMatch(host, "*.example.net")) {
        return "SOCKS5 socks.example.com:1080; DIRECT";
    }
    return "PROXY edge.example.com:3128; DIRECT";
}
"#;

const DEFAULT_URLS: &[&str] = &[
    "http://plainhost/",
    "https://db.corp.example.com/",
    "http://intra.example.com/dashboard",
    "https://cdn.example.net/asset.js",
    "https://www.example.org/",
    "http://127.0.0.1/",
];

struct Args {
    iterations: usize,
    pac_script: Option<String>,
    urls: Vec<String>,
}

fn parse_args() -> Args {
    let mut iterations = 2000usize;
    let mut pac_script = None;
    let mut urls = Vec::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--iterations" => {
                iterations = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage_error("--iterations requires a positive integer"));
            }
            "--pac-script" => {
                pac_script = Some(
                    args.next()
                        .unwrap_or_else(|| usage_error("--pac-script requires a value")),
                );
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other if other.starts_with('-') && other != "-" => {
                usage_error(&format!("unknown option: {other}"));
            }
            _ => urls.push(arg),
        }
    }
    if iterations == 0 {
        usage_error("--iterations must be greater than zero");
    }
    Args {
        iterations,
        pac_script,
        urls,
    }
}

fn main() {
    let args = parse_args();

    let script = match &args.pac_script {
        Some(path) => std::fs::read_to_string(path).unwrap_or_else(|e| {
            eprintln!("error: cannot read PAC file {path}: {e}");
            std::process::exit(1);
        }),
        None => DEFAULT_PAC.to_string(),
    };

    let raw_urls: Vec<String> = if args.urls.is_empty() {
        DEFAULT_URLS.iter().map(|s| s.to_string()).collect()
    } else {
        args.urls.clone()
    };
    let urls: Vec<Url> = raw_urls
        .iter()
        .map(|u| {
            Url::parse(u).unwrap_or_else(|e| {
                eprintln!("error: invalid URL {u}: {e}");
                std::process::exit(1);
            })
        })
        .collect();

    let resolver = ProxyResolver::new();
    let pac_url = serve_pac(script.clone());

    println!("PAC benchmark");
    println!(
        "  iterations : {} per engine (across {} URLs)",
        args.iterations,
        urls.len()
    );
    println!(
        "  pac source : {}",
        args.pac_script.as_deref().unwrap_or("<built-in>")
    );
    println!("  served at  : {pac_url}");
    if cfg!(windows) {
        println!("  platform   : windows (system = WinHTTP, quickjs = embedded)");
    } else {
        println!("  platform   : non-windows (both paths use the embedded engine)");
    }
    println!();

    // Cross-check the two engines on each URL before timing, so divergences
    // (e.g. WinHTTP dropping a trailing DIRECT) are reported up front.
    cross_check(&resolver, &pac_url, &script, &urls);

    let system = bench("system", args.iterations, &urls, |u| {
        resolver
            .evaluate_pac_source(&pac_url, u)
            .map_err(|e| e.to_string())
    });
    system.print();

    match bench_quickjs(&resolver, &script, args.iterations, &urls) {
        Some(quickjs) => {
            quickjs.print();
            compare(&system, &quickjs);
        }
        None => {
            println!();
            println!(
                "quickjs : not compiled in on this build — rebuild with \
                 `--features pac-engine` on Windows to compare against WinHTTP."
            );
        }
    }
}

/// Run the embedded-QuickJS path when it is compiled in.
#[cfg(any(not(windows), feature = "pac-engine"))]
fn bench_quickjs(
    resolver: &ProxyResolver,
    script: &str,
    iterations: usize,
    urls: &[Url],
) -> Option<Stats> {
    Some(bench("quickjs", iterations, urls, |u| {
        resolver.evaluate_pac(script, u).map_err(|e| e.to_string())
    }))
}

#[cfg(all(windows, not(feature = "pac-engine")))]
fn bench_quickjs(_: &ProxyResolver, _: &str, _: usize, _: &[Url]) -> Option<Stats> {
    None
}

fn cross_check(resolver: &ProxyResolver, pac_url: &str, script: &str, urls: &[Url]) {
    let mut mismatches = 0;
    for u in urls {
        let system = resolver
            .evaluate_pac_source(pac_url, u)
            .map(render)
            .unwrap_or_else(|e| format!("<error: {e}>"));
        let quickjs = quickjs_result(resolver, script, u);
        match quickjs {
            Some(q) if q != system => {
                mismatches += 1;
                println!("  diff {u}");
                println!("       system  -> {system}");
                println!("       quickjs -> {q}");
            }
            _ => {}
        }
    }
    if mismatches == 0 {
        println!("cross-check: engines agree on all {} URLs", urls.len());
    } else {
        println!("cross-check: {mismatches} URL(s) differ between engines (see above)");
    }
    println!();
}

#[cfg(any(not(windows), feature = "pac-engine"))]
fn quickjs_result(resolver: &ProxyResolver, script: &str, url: &Url) -> Option<String> {
    Some(
        resolver
            .evaluate_pac(script, url)
            .map(render)
            .unwrap_or_else(|e| format!("<error: {e}>")),
    )
}

#[cfg(all(windows, not(feature = "pac-engine")))]
fn quickjs_result(_: &ProxyResolver, _: &str, _: &Url) -> Option<String> {
    None
}

fn render(list: Vec<ProxyKind>) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Timing statistics for one engine, in nanoseconds.
struct Stats {
    label: &'static str,
    samples: Vec<u128>,
    errors: usize,
}

impl Stats {
    fn mean(&self) -> f64 {
        if self.samples.is_empty() {
            return 0.0;
        }
        self.samples.iter().sum::<u128>() as f64 / self.samples.len() as f64
    }

    /// `p` in `0.0..=1.0`. Requires `samples` sorted ascending.
    fn percentile(&self, p: f64) -> u128 {
        if self.samples.is_empty() {
            return 0;
        }
        let idx = ((self.samples.len() - 1) as f64 * p).round() as usize;
        self.samples[idx]
    }

    fn print(&self) {
        let n = self.samples.len();
        println!("{}", self.label);
        if n == 0 {
            println!("  no successful samples ({} errors)", self.errors);
            return;
        }
        println!("  calls   : {n} ({} errors)", self.errors);
        println!("  mean    : {}", fmt_ns(self.mean() as u128));
        println!("  p50     : {}", fmt_ns(self.percentile(0.50)));
        println!("  p90     : {}", fmt_ns(self.percentile(0.90)));
        println!("  p99     : {}", fmt_ns(self.percentile(0.99)));
        println!(
            "  min/max : {} / {}",
            fmt_ns(self.samples[0]),
            fmt_ns(self.samples[n - 1])
        );
        let per_sec = if self.mean() > 0.0 {
            1e9 / self.mean()
        } else {
            0.0
        };
        println!("  throughput: {per_sec:.0} calls/s");
    }
}

fn bench<F>(label: &'static str, iterations: usize, urls: &[Url], mut call: F) -> Stats
where
    F: FnMut(&Url) -> Result<Vec<ProxyKind>, String>,
{
    // Warm up so first-call costs (PAC download/compile, WinHTTP autoproxy
    // cache priming) don't skew the samples.
    for u in urls {
        let _ = call(u);
    }

    let mut samples = Vec::with_capacity(iterations);
    let mut errors = 0;
    for i in 0..iterations {
        let u = &urls[i % urls.len()];
        let start = Instant::now();
        let result = call(u);
        let elapsed = start.elapsed();
        if result.is_ok() {
            samples.push(elapsed.as_nanos());
        } else {
            errors += 1;
        }
    }
    samples.sort_unstable();
    Stats {
        label,
        samples,
        errors,
    }
}

fn compare(system: &Stats, quickjs: &Stats) {
    let (a, b) = (system.mean(), quickjs.mean());
    if a <= 0.0 || b <= 0.0 {
        return;
    }
    println!();
    if a < b {
        println!("=> system is {:.2}x faster than quickjs (by mean)", b / a);
    } else if b < a {
        println!("=> quickjs is {:.2}x faster than system (by mean)", a / b);
    } else {
        println!("=> system and quickjs are on par (by mean)");
    }
}

fn fmt_ns(ns: u128) -> String {
    let d = Duration::from_nanos(ns as u64);
    if d.as_secs() >= 1 {
        format!("{:.3} s", d.as_secs_f64())
    } else if d.as_millis() >= 1 {
        format!("{:.3} ms", d.as_secs_f64() * 1e3)
    } else {
        format!("{:.1} us", d.as_secs_f64() * 1e6)
    }
}

/// Serve `script` from an ephemeral `127.0.0.1` HTTP endpoint for the whole
/// life of the process (WinHTTP only loads PAC over http(s)). Each connection
/// is answered with the script and closed; the accept loop lives on a detached
/// thread.
fn serve_pac(script: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|e| {
        eprintln!("error: cannot start local PAC server: {e}");
        std::process::exit(1);
    });
    let addr = listener.local_addr().expect("local address");
    let body = script.into_bytes();
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

fn print_usage() {
    eprintln!(
        "usage: pac_bench [--iterations N] [--pac-script <path>] [<url>...]\n\
         \n\
         Compares the system PAC path (WinHTTP on Windows) against the embedded\n\
         QuickJS engine on the same PAC script and URLs. Build with\n\
         `--features pac-engine` on Windows to include the QuickJS side."
    );
}

fn usage_error(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_usage();
    std::process::exit(2);
}
