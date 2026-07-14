/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Benchmark every available PAC evaluation path against the others on the
//! same PAC script and URLs:
//!
//! * **system** (Windows only) — [`ProxyResolver::evaluate_pac_source`], i.e.
//!   WinHTTP (`WinHttpGetProxyForUrl`). Off Windows that API uses the same
//!   embedded engine as `native`, so it is not timed separately there.
//! * **native** — [`ProxyResolver::evaluate_pac`] with the default backend:
//!   the in-process QuickJS-NG engine. Always built off Windows; on Windows
//!   only with `--features pac-engine`.
//! * **wasmtime** — the same QuickJS-NG compiled to WebAssembly and run in a
//!   Wasmtime sandbox (`--features pac-engine-wasmtime`, any platform
//!   Cranelift can AOT-compile for), selected via
//!   [`ResolverOptions::pac_backend`].
//! * **wasmtime-jit** — the same Wasmtime sandbox with Cranelift compiled into
//!   the runtime (`--features pac-engine-wasmtime-jit`), so the raw guest is
//!   compiled when the process starts instead of AOT-compiled by `build.rs`.
//! * **wasm2c** — the same wasm guest translated to portable C with WABT's
//!   `wasm2c` (`--features pac-engine-wasm2c`, any platform with a C
//!   compiler, including 32-bit armv7).
//!
//! All embedded backends run byte-identical engine + helper sources, so the
//! cross-check requires them to agree **exactly** on every URL and the process
//! exits non-zero on any diff. WinHTTP is allowed to differ (it e.g. drops a
//! trailing DIRECT); its diffs are reported but not fatal. For CI builds that
//! compile one backend per binary, `--backend` selects that path and
//! `--results-file` emits deterministic TSV for cross-process comparison.
//!
//! ```text
//! cargo run --release --example pac_bench \
//!     --features "pac-engine pac-engine-wasmtime pac-engine-wasm2c"
//! cargo run --release --example pac_bench --features pac-engine -- \
//!     --iterations 5000 --pac-script my.pac https://a.example/ http://b.corp/
//! ```
//!
//! On Windows the PAC script is additionally served from an ephemeral
//! `127.0.0.1` HTTP endpoint (WinHTTP only loads PAC over http(s)); all
//! engines still evaluate identical input.

#[cfg(any(
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
use os_proxy_resolver::{PacBackendKind, ResolverOptions};
use os_proxy_resolver::{ProxyKind, ProxyResolver};
use std::time::{Duration, Instant};
use url::Url;

/// A small but non-trivial PAC script: a few helper calls and branches so the
/// measurement reflects real evaluation cost rather than a bare `return`.
/// Keep this identical to DEFAULT_PAC in bench/electron/main.js.
const DEFAULT_PAC: &str = r#"
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
        (host === "127.0.0.1" &&
         isInNet(host, "127.0.0.0", "255.0.0.0"))) {
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

/// Keep this identical to DEFAULT_URLS in bench/electron/main.js.
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
    backend: Option<String>,
    results_file: Option<String>,
    urls: Vec<String>,
}

fn parse_args() -> Args {
    let mut iterations = 2000usize;
    let mut pac_script = None;
    let mut backend = None;
    let mut results_file = None;
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
            "--backend" => {
                backend = Some(
                    args.next()
                        .unwrap_or_else(|| usage_error("--backend requires a value")),
                );
            }
            "--results-file" => {
                results_file = Some(
                    args.next()
                        .unwrap_or_else(|| usage_error("--results-file requires a value")),
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
        backend,
        results_file,
        urls,
    }
}

/// One PAC evaluation as run by a backend.
type EvalFn = Box<dyn Fn(&Url) -> Result<Vec<ProxyKind>, String>>;

/// One benchmarked evaluation path.
struct Backend {
    label: &'static str,
    /// Backends flagged `exact` must agree with each other byte-for-byte
    /// (they run the same engine sources); a diff is a bug and fails the run.
    exact: bool,
    call: EvalFn,
}

/// Assembles every path compiled into this build.
fn backends(script: &str) -> Vec<Backend> {
    let mut backends: Vec<Backend> = Vec::new();

    // WinHTTP: only meaningful on Windows (off Windows evaluate_pac_source
    // uses the same embedded engine as the `native` entry below).
    #[cfg(windows)]
    {
        let resolver = ProxyResolver::new();
        let pac_url = serve_pac(script.to_string());
        println!("  winhttp    : PAC served at {pac_url}");
        backends.push(Backend {
            label: "winhttp",
            exact: false,
            call: Box::new(move |u| {
                resolver
                    .evaluate_pac_source(&pac_url, u)
                    .map_err(|e| e.to_string())
            }),
        });
    }

    #[cfg(feature = "pac-engine")]
    {
        let mut options = ResolverOptions::default();
        options.pac_backend = PacBackendKind::Native;
        let resolver = ProxyResolver::with_options(options);
        let script = script.to_string();
        backends.push(Backend {
            label: "native",
            exact: true,
            call: Box::new(move |u| resolver.evaluate_pac(&script, u).map_err(|e| e.to_string())),
        });
    }

    #[cfg(feature = "pac-engine-wasmtime")]
    {
        let mut options = ResolverOptions::default();
        options.pac_backend = PacBackendKind::Wasmtime;
        let resolver = ProxyResolver::with_options(options);
        let script = script.to_string();
        backends.push(Backend {
            label: "wasmtime",
            exact: true,
            call: Box::new(move |u| resolver.evaluate_pac(&script, u).map_err(|e| e.to_string())),
        });
    }

    #[cfg(feature = "pac-engine-wasm2c")]
    {
        let mut options = ResolverOptions::default();
        options.pac_backend = PacBackendKind::Wasm2c;
        let resolver = ProxyResolver::with_options(options);
        let script = script.to_string();
        backends.push(Backend {
            label: "wasm2c",
            exact: true,
            call: Box::new(move |u| resolver.evaluate_pac(&script, u).map_err(|e| e.to_string())),
        });
    }

    #[cfg(feature = "pac-engine-wasmtime-jit")]
    {
        let mut options = ResolverOptions::default();
        options.pac_backend = PacBackendKind::WasmtimeJit;
        let resolver = ProxyResolver::with_options(options);
        let script = script.to_string();
        backends.push(Backend {
            label: "wasmtime-jit",
            exact: true,
            call: Box::new(move |u| resolver.evaluate_pac(&script, u).map_err(|e| e.to_string())),
        });
    }

    backends
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
    let mut backends = backends(&script);
    if let Some(requested) = &args.backend {
        let available = backends
            .iter()
            .map(|backend| backend.label)
            .collect::<Vec<_>>()
            .join(", ");
        backends.retain(|backend| backend.label == requested);
        if backends.is_empty() {
            usage_error(&format!(
                "backend {requested:?} is not compiled in (available: {available})"
            ));
        }
    }
    if args.results_file.is_some() && backends.len() != 1 {
        usage_error("--results-file requires selecting exactly one backend with --backend");
    }
    println!(
        "  backends   : {}",
        backends
            .iter()
            .map(|b| b.label)
            .collect::<Vec<_>>()
            .join(", ")
    );
    report_binary_size();
    println!();

    if backends.is_empty() {
        println!(
            "no PAC backend compiled in — build with `--features pac-engine` \
             (and/or `pac-engine-wasmtime`, `pac-engine-wasm2c`)."
        );
        return;
    }

    // Cross-check all backends on each URL before timing, so divergences
    // (e.g. WinHTTP dropping a trailing DIRECT) are reported up front. The
    // `exact` embedded backends run byte-identical engine sources and MUST
    // agree; anything else is a bug in a wasm backend.
    let exact_diffs = cross_check(&backends, &urls, args.results_file.as_deref());

    let mut stats: Vec<Stats> = Vec::new();
    for backend in &backends {
        let s = bench(backend.label, args.iterations, &urls, &backend.call);
        s.print();
        stats.push(s);
    }
    let timed_errors: usize = stats.iter().map(|stats| stats.errors).sum();
    if timed_errors == 0 {
        compare(&stats);
    }

    if exact_diffs > 0 {
        eprintln!();
        eprintln!(
            "error: the embedded backends diverged on {exact_diffs} URL(s) — \
             they run identical engine sources, so this is a bug."
        );
        std::process::exit(1);
    }
    if timed_errors > 0 {
        eprintln!();
        eprintln!("error: PAC benchmark had {timed_errors} timed call error(s)");
        std::process::exit(1);
    }
}

/// Returns the number of URLs on which the `exact` backends disagreed.
fn cross_check(backends: &[Backend], urls: &[Url], results_file: Option<&str>) -> usize {
    use std::io::Write;

    let mut result_output = results_file.map(|path| {
        let file = std::fs::File::create(path).unwrap_or_else(|e| {
            eprintln!("error: cannot create results file {path}: {e}");
            std::process::exit(1);
        });
        std::io::BufWriter::new(file)
    });
    let mut diffs = 0;
    let mut exact_diffs = 0;
    for u in urls {
        let results: Vec<(usize, String)> = backends
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let r = (b.call)(u)
                    .map(render)
                    .unwrap_or_else(|e| format!("<error: {e}>"));
                (i, r)
            })
            .collect();
        if let Some(output) = &mut result_output {
            writeln!(output, "{u}\t{}", results[0].1).unwrap_or_else(|e| {
                eprintln!("error: cannot write results file: {e}");
                std::process::exit(1);
            });
        }
        let all_equal = results.windows(2).all(|w| w[0].1 == w[1].1);
        if !all_equal {
            diffs += 1;
            println!("  diff {u}");
            for (i, r) in &results {
                println!("       {:<8} -> {r}", backends[*i].label);
            }
        }
        let exact: Vec<&String> = results
            .iter()
            .filter(|(i, _)| backends[*i].exact)
            .map(|(_, r)| r)
            .collect();
        if exact.windows(2).any(|w| w[0] != w[1]) {
            exact_diffs += 1;
        }
    }
    if let Some(output) = &mut result_output {
        output.flush().unwrap_or_else(|e| {
            eprintln!("error: cannot flush results file: {e}");
            std::process::exit(1);
        });
    }
    if backends.len() == 1 {
        println!(
            "result capture: {} evaluated all {} URLs",
            backends[0].label,
            urls.len()
        );
    } else if diffs == 0 {
        println!(
            "cross-check: all {} backends agree on all {} URLs",
            backends.len(),
            urls.len()
        );
    } else {
        println!("cross-check: {diffs} URL(s) differ between backends (see above)");
    }
    println!();
    exact_diffs
}

fn render(list: Vec<ProxyKind>) -> String {
    list.iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

fn report_binary_size() {
    if let Ok(exe) = std::env::current_exe() {
        if let Ok(meta) = std::fs::metadata(&exe) {
            println!(
                "  binary     : {} ({:.2} MiB)",
                exe.display(),
                meta.len() as f64 / (1024.0 * 1024.0)
            );
        }
    }
    #[cfg(feature = "pac-engine-wasmtime")]
    println!(
        "  wasm guest : {:.2} MiB AOT artifact embedded (plus the Wasmtime \
         runtime; compare against a `--features pac-engine`-only build for \
         the full delta)",
        os_proxy_resolver::pac_wasm_artifact_size() as f64 / (1024.0 * 1024.0)
    );
}

/// Timing statistics for one engine, in nanoseconds.
struct Stats {
    label: &'static str,
    samples: Vec<u128>,
    errors: usize,
    first_error: Option<String>,
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
            if let Some(error) = &self.first_error {
                println!("  first error: {error}");
            }
            return;
        }
        println!("  calls   : {n} ({} errors)", self.errors);
        if let Some(error) = &self.first_error {
            println!("  first error: {error}");
        }
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

fn bench(label: &'static str, iterations: usize, urls: &[Url], call: &EvalFn) -> Stats {
    // Warm up so first-call costs (PAC download/compile, WinHTTP autoproxy
    // cache priming, wasm instantiation) don't skew the samples.
    for u in urls {
        let _ = call(u);
    }

    let mut samples = Vec::with_capacity(iterations);
    let mut errors = 0;
    let mut first_error = None;
    for i in 0..iterations {
        let u = &urls[i % urls.len()];
        let start = Instant::now();
        let result = call(u);
        let elapsed = start.elapsed();
        match result {
            Ok(_) => samples.push(elapsed.as_nanos()),
            Err(error) => {
                errors += 1;
                first_error.get_or_insert(error);
            }
        }
    }
    samples.sort_unstable();
    Stats {
        label,
        samples,
        errors,
        first_error,
    }
}

/// Pairwise mean comparison of all timed backends.
fn compare(stats: &[Stats]) {
    if stats.len() < 2 {
        return;
    }
    println!();
    for i in 0..stats.len() {
        for j in (i + 1)..stats.len() {
            let (a, b) = (&stats[i], &stats[j]);
            let (ma, mb) = (a.mean(), b.mean());
            if ma <= 0.0 || mb <= 0.0 {
                continue;
            }
            if ma < mb {
                println!(
                    "=> {} is {:.2}x faster than {} (by mean)",
                    a.label,
                    mb / ma,
                    b.label
                );
            } else {
                println!(
                    "=> {} is {:.2}x faster than {} (by mean)",
                    b.label,
                    ma / mb,
                    a.label
                );
            }
        }
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
#[cfg(windows)]
fn serve_pac(script: String) -> String {
    use std::io::{Read, Write};
    use std::net::TcpListener;

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
        "usage: pac_bench [--iterations N] [--pac-script <path>]\n\
         [--backend <name>] [--results-file <path>] [<url>...]\n\
         \n\
         Times every compiled-in PAC path (WinHTTP on Windows, the native\n\
         QuickJS engine, Wasmtime AOT/JIT, and wasm2c) on the same PAC script\n\
         and URLs. `--backend` times one compiled-in path. With exactly one\n\
         selected backend, `--results-file` writes deterministic TSV rows for\n\
         cross-process result comparison."
    );
}

fn usage_error(msg: &str) -> ! {
    eprintln!("error: {msg}");
    print_usage();
    std::process::exit(2);
}
