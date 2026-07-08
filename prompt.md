# Task: Build an independent, MIT-licensed Rust crate that evaluates PAC
# (Proxy Auto-Config) files using an embedded QuickJS engine.

Create a self-contained Rust library crate (Cargo) that parses a PAC script and
answers `FindProxyForURL(url, host)` queries. Embed the QuickJS JavaScript
engine (the MIT-licensed `quickjs-ng` fork) to run the script. The crate must
stand on its own with a clean public Rust API and no dependencies on any other
project's layout.

## Hard licensing constraints (must follow)
- Do NOT read, copy, translate, or paraphrase any code from `pacparser`,
  `libproxy`, Chromium, or any other GPL/LGPL/copyleft PAC project.
- Reimplement every PAC helper function from the PUBLIC SPECIFICATION only:
  Netscape "Navigator Proxy Auto-Config File Format" (1996) and Microsoft's
  published IPv6 PAC extension docs. Specs describe behavior, not code.
- Only link against QuickJS's public MIT-licensed C API.
- All original code you write is MIT-licensed. Include a `LICENSE` (MIT) and a
  third-party notices file recording QuickJS's MIT license.
- Add a header comment to the JS helper source stating the helpers are
  implemented from the public PAC specification.

## Crate shape
- A library crate named e.g. `pac-eval`. Cargo build system.
- How to embed QuickJS: EITHER depend on a maintained, permissively licensed
  `quickjs-ng` -sys crate, OR vendor the QuickJS C sources and compile them via
  a `build.rs` using the `cc` crate. State which you chose and why; keep the FFI
  surface minimal and isolated in a private `ffi`/`sys` module.
- Keep all `unsafe` confined to the FFI/binding layer behind a safe API.
- Optional Cargo features: `microsoft-extensions` (on by default) to toggle the
  `*Ex` helpers.

## Public Rust API (safe, ergonomic)
Design an idiomatic API roughly like:
- `struct PacEngine` — owns one QuickJS runtime/context and the loaded script.
- `PacEngine::new() -> Result<PacEngine, Error>` — creates the engine and
  installs the built-in helper library.
- `PacEngine::load(&mut self, script: &str) -> Result<(), Error>` — evaluates a
  PAC script; returns a clear error on syntax/eval failure.
- `PacEngine::find_proxy(&mut self, url: &str, host: &str) -> Result<String, Error>`
  — verifies `FindProxyForURL` exists, calls it, returns the raw result string
  (e.g. `"PROXY host:port; DIRECT"`). Do not reformat multi-directive results.
- Convenience: `PacEngine::eval_once(script, url, host) -> Result<String, Error>`.
- Configuration hooks:
  - `set_my_ip(Option<IpAddr>)` — override what `myIpAddress()` returns
    (essential for deterministic tests).
  - `set_timeout(Duration)` — max wall-clock time for a single `find_proxy`
    call (see interrupt handling below).
  - `set_log_sink(impl Fn(&str))` or similar — receive `alert()`/`console.log`
    output instead of stderr.
- A well-typed `Error` enum (e.g. `ScriptSyntax`, `FunctionMissing`,
  `JsException(String)`, `Timeout`, `Internal`). Implement `std::error::Error`
  and `Display`.
- Document thread-safety honestly: a `PacEngine` wraps a non-`Send`/non-`Sync`
  C context; do not fake `Send`/`Sync`. If cross-thread use is needed, document
  the "own it on one thread / serialize calls" pattern rather than adding locks.

## Timeout / hostile-script defense
Treat PAC scripts as untrusted input.
- Install a QuickJS interrupt handler (`JS_SetInterruptHandler`) driven by a
  deadline so a runaway `FindProxyForURL` (e.g. `while(true){}`) is interrupted
  inside the engine and returns `Error::Timeout` instead of hanging.
- Set a QuickJS runtime memory limit.
- Sandbox: expose no filesystem, module loading, timers, or network to the
  script beyond the native PAC helpers below.

## Native (host-provided) functions on the JS global
Implement natively and bind into the global scope (these need OS/network I/O):
- `dnsResolve(host)`   -> first IPv4 as string, or `null` on failure.
- `dnsResolveEx(host)` -> `;`-separated IPv4/IPv6 list, or `""`.
- `myIpAddress()`      -> primary IPv4 string; fall back to `"127.0.0.1"`;
  honor the `set_my_ip` override.
- `myIpAddressEx()`    -> `;`-separated local IP list, or `""`.
- `alert(...)`, `console.log(...)` -> route to the configured log sink;
  never panic/crash on non-string args.
Use Rust std (`std::net::ToSocketAddrs`) or `getaddrinfo`; handle IPv6. Free
every QuickJS value / C string — no leaks across repeated calls.

## Built-in JS helper library (implement in JS, from the spec)
Evaluate at construction so scripts can use the standard helpers, dependency-
free: `isPlainHostName`, `dnsDomainIs`, `localHostOrDomainIs`, `isResolvable`,
`isResolvableEx`, `isInNet` (IPv4 dotted-quad + mask), `dnsDomainLevels`,
`shExpMatch` (shell glob: only `*` and `?` are wildcards, anchored to the whole
string, all regex metacharacters escaped, `.` literal), `weekdayRange`,
`dateRange` (full overloaded arg-count dispatch incl. optional trailing
`"GMT"`), `timeRange` (full overloaded form). Microsoft extensions (feature-
gated): `isInNetEx(ipaddr, "addr/prefixlen")` for IPv4 and IPv6, plus IPv6
parsing helpers, and support a script-defined `FindProxyForURLEx`.

## Correctness details real-world PAC files depend on
- `shExpMatch` anchoring and metacharacter escaping.
- `dateRange`/`timeRange`/`weekdayRange` argument-count overloading (most
  common bug source) and the GMT flag.
- Correct IPv6 prefix matching in `isInNetEx`.
- Return `FindProxyForURL`'s string verbatim (callers parse the directives).

## Tests
- Unit-test each helper against spec examples (e.g.
  `dnsDomainIs("[www.example.com](https://www.example.com)", ".example.com") == true`,
  `shExpMatch("http://a/b", "*/b") == true`,
  `isInNet("10.1.2.3","10.0.0.0","255.0.0.0") == true`, IPv6 `isInNetEx`, a
  month/day `dateRange` matrix).
- Integration tests with representative PAC files: DIRECT-only, host/domain
  routing, subnet routing, multi-proxy fallback, Microsoft `*Ex` functions.
- Robustness: malformed PAC -> `Error::ScriptSyntax` (no panic); missing
  `FindProxyForURL` -> `Error::FunctionMissing`; `while(true){}` -> `Timeout`
  within the configured deadline.
- Determinism: `set_my_ip` override is respected; `dnsResolve` behavior is
  either mocked or tested against loopback to avoid network flakiness.
- Run under `cargo test`; keep tests hermetic (no reliance on external DNS).

## Deliverables
- `Cargo.toml`, `src/lib.rs` with the public API, the FFI/sys module, the JS
  helper source (as `include_str!` or an embedded `&str`), `build.rs` if
  vendoring QuickJS, the test suite, `LICENSE` (MIT), third-party notices, and
  a `README.md` documenting the API, supported helpers, sandboxing/timeout
  behavior, thread-safety, and that helpers are implemented from the public PAC
  specification.
- Idiomatic Rust: no `unwrap`/`panic` on untrusted input, `clippy`-clean,
  `rustfmt`-formatted, documented public items (`#![warn(missing_docs)]`).