# os-proxy-resolver

Resolve the OS-configured proxy for a URL — static config, PAC scripts, and
WPAD — with change notification and a bad-proxy feedback loop.

```rust
use os_proxy_resolver::{resolve_proxy, ProxyKind};

let url = url::Url::parse("https://example.com/").unwrap();
for proxy in resolve_proxy(&url)? {
    match proxy {
        ProxyKind::Direct => { /* connect directly */ }
        ProxyKind::Http(host_port) => { /* HTTP proxy (CONNECT for https) */ }
        ProxyKind::Socks(host_port) => { /* SOCKS proxy */ }
    }
}
```

Results mirror PAC semantics: `"PROXY a:8080; DIRECT"` → an *ordered* fallback
list `[Http("a:8080"), Direct]`. The API is synchronous; PAC evaluation runs
on a dedicated worker thread. Calls may block on network I/O up to configured
timeouts, so use `spawn_blocking` (or similar) from async runtimes.

## Resolution precedence

1. `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy` env vars
   (lowercase or uppercase; `no_proxy` supports hosts, `.suffix`, globs,
   `host:port`, CIDR, `*`)
2. OS proxy configuration: WPAD auto-detect → configured PAC URL → static
   per-scheme rules with bypass list
3. `DIRECT`

PAC/WPAD failures fall through to the next layer instead of failing the
resolution.

## Platform strategy

| | config source | PAC + WPAD | change signal |
|---|---|---|---|
| **Windows** | `WinHttpGetIEProxyConfigForCurrentUser` | WinHTTP `WinHttpGetProxyForUrl` (PAC eval + DHCP/DNS WPAD in the OS) | registry change notification |
| **macOS** | `SCDynamicStoreCopyProxies` | built-in [QuickJS] PAC engine + DNS WPAD | `SCDynamicStore` callback |
| **Linux** | GNOME `org.gnome.system.proxy` via `gsettings` | built-in [QuickJS] PAC engine + DNS WPAD | `dconf watch` / `gsettings monitor` |

Windows builds are **pure Rust** — the QuickJS PAC engine is neither compiled
nor linked there. On macOS/Linux the PAC engine embeds QuickJS-NG via the
MIT-licensed `rquickjs-sys` crate (which compiles the QuickJS-NG C sources);
no autotools/make, which keeps cross-compilation clean. The PAC helper
functions are first-party JavaScript implemented from the public PAC
specification.

Non-goals: DHCP-based WPAD (option 252) on macOS/Linux (Windows gets it via
WinHTTP), KDE proxy settings, proxy authentication credentials.

## The PAC cage

A PAC file is untrusted JavaScript running on a live JS engine. The embedded
QuickJS context is neither `Send` nor `Sync`, and its `dnsResolve()` /
`myIpAddress()` builtins block on real network I/O. Containment:

- **One process-global worker thread** owns the PAC engine; every
  parse/find_proxy is serialized through a command channel.
- **Hard timeout** on every `FindProxyForURL` call. A runaway JS loop is
  interrupted inside the engine by its own deadline; a blocking native
  builtin (e.g. slow DNS) that outlasts the caller's deadline makes
  subsequent calls fail fast into the fallback path instead of queueing,
  and service resumes once the worker recovers.
- **URL sanitization** before evaluation (Chromium-style): identity is always
  stripped; for https URLs the path and query are dropped, so a hostile
  PAC/WPAD author can't read request details.
- The worker protocol is process-agnostic by design, so the evaluator can
  later be moved out-of-process entirely (subprocess with resource limits you
  can kill) — the Chromium end-state.

WPAD discovery is aggressive about not stalling: `wpad.<search-domain>` DNS
probes get ~300ms each (walking up the domain, never into a TLD), the
`wpad.dat` fetch 2s, and negative results are cached.

## Change notification

Identical API on all platforms:

```rust
let resolver = os_proxy_resolver::ProxyResolver::new();

// 1. Generation counter — cheap synchronous poll for cache staleness.
let generation = resolver.config_generation();

// 2. Callback — runs on the watcher thread; keep it cheap, never call
//    resolve_proxy() from it. Drop the subscription to unregister.
let sub = resolver.on_change(|| { /* schedule re-resolution elsewhere */ });

// 3. Optional, with `--features tokio`:
let mut rx = resolver.watch(); // tokio::sync::watch::Receiver<u64>
```

These are the primitives an FFI bridge adapts — e.g. a napi-rs
`ThreadsafeFunction` (NonBlocking, unref'd) feeding a Node `EventEmitter`
`'change'` event, with `config_generation` exposed as a sync getter (i64 in
JS). The payload is intentionally dumb: "changed", no diff.

VPN connect, Wi-Fi switch, and resume all invalidate cached PAC state: caches
store the generation they were built at and re-resolve when it moves.

## Bad-proxy feedback

```rust
resolver.report_proxy_failed(&proxy);
```

marks a proxy dead for a cooldown (default 5 min); subsequent resolutions
demote it to the end of the list — so `"PROXY a; PROXY b; DIRECT"` stops
retrying dead `a` first on every request (mirrors Chromium's
`ProxyRetryInfo`). If everything in a list is marked bad, the original order
is returned and retried.

## Building

```sh
git clone <repo>
cargo build                             # needs a C compiler on macOS/Linux only
cargo test
```

Examples:

```sh
cargo run --example resolve -- https://example.com/   # live OS config
cargo run --example resolve -- --watch                # watch for changes
cargo run --example proxytester -- --pac-script file.pac http://url/ # test a PAC file
```

To compare the two PAC engines head-to-head — WinHTTP versus the embedded
QuickJS engine — on the same script and URLs, run the `pac_bench` example. On
Windows the QuickJS side is only built with the `pac-engine` feature (off
Windows the engine is always built); production Windows builds never link it:

```sh
cargo run --release --example pac_bench --features pac-engine
```

Builds as both `rlib` and `cdylib`. Release automation with `cargo-dist` is a
natural fit (the CI matrix below already covers the seven targets) but is not
wired up yet.

## CI

GitHub Actions builds and tests: Windows x64 + arm64 (pure Rust), macOS x64 +
arm64, Linux x86_64 (native), Linux aarch64 + armv7 (via `cross`, whose images
ship the C cross-toolchain QuickJS needs). Two Windows benchmark jobs establish
the performance picture on the same runner: `pac_bench`
(`--features pac-engine`) times WinHTTP against the embedded QuickJS engine, and
[`bench/electron`](bench/electron) times Chromium's own V8 PAC resolver (what
Electron uses by default) as the baseline.

## License

The first-party code in this repository is licensed under the [MIT License](LICENSE.txt),
Copyright (c) Microsoft Corporation.

On macOS/Linux the built-in PAC engine embeds QuickJS-NG (MIT) via the
MIT-licensed `rquickjs-sys` crate, statically linked into the compiled library;
the PAC helper functions are first-party JavaScript implemented from the public
PAC specification. Everything is permissively licensed. Windows binaries
contain no JavaScript engine at all (WinHTTP handles PAC).

[QuickJS]: https://github.com/quickjs-ng/quickjs
