# pac-eval

Evaluate PAC ([Proxy Auto-Config](https://en.wikipedia.org/wiki/Proxy_auto-config))
files from Rust, using an embedded [QuickJS-NG](https://github.com/quickjs-ng/quickjs)
JavaScript engine.

- **MIT licensed, spec-clean.** All PAC helper functions are implemented from
  the public specification only — the Netscape "Navigator Proxy Auto-Config
  File Format" document (1996) and Microsoft's published IPv6 PAC extension
  documentation. No code from pacparser, libproxy, Chromium or any other PAC
  implementation was used. See [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
- **Self-contained.** QuickJS-NG is embedded through the MIT-licensed
  [`rquickjs-sys`](https://crates.io/crates/rquickjs-sys) crate, which vendors
  and compiles the engine's C sources with `cc` — no system libraries, no
  `bindgen`/libclang requirement. This crate keeps its entire FFI surface in
  one private module; everything else is safe Rust.
- **Hostile-script defense.** PAC scripts are treated as untrusted input:
  wall-clock timeouts enforced inside the engine, a runtime memory limit, and
  no filesystem/network/module/timer APIs exposed to the script.

## Usage

```rust
use pac_eval::PacEngine;

fn main() -> Result<(), pac_eval::Error> {
    let mut engine = PacEngine::new()?;
    engine.load(r#"
        function FindProxyForURL(url, host) {
            if (isPlainHostName(host) || dnsDomainIs(host, ".internal.example.com"))
                return "DIRECT";
            if (isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0"))
                return "PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080; DIRECT";
            return "DIRECT";
        }
    "#)?;

    let proxy = engine.find_proxy("https://www.example.org/", "www.example.org")?;
    // The result string is returned verbatim, e.g.
    // "PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080; DIRECT".
    // Parsing the proxy directives is up to the caller.
    println!("{proxy}");
    Ok(())
}
```

One-shot evaluation: `PacEngine::eval_once(script, url, host)`.

### API overview

| Method | Purpose |
| --- | --- |
| `PacEngine::new()` | Create an engine with the PAC helper library installed. |
| `load(&mut self, script)` | Evaluate a PAC script (`Error::ScriptSyntax` on parse failure). |
| `find_proxy(&mut self, url, host)` | Call `FindProxyForURL(url, host)`, return its string verbatim. |
| `find_proxy_ex(&mut self, url, host)` | Call `FindProxyForURLEx`, falling back to `FindProxyForURL` (feature `microsoft-extensions`). |
| `eval_once(script, url, host)` | Convenience: new engine + `load` + `find_proxy`. |
| `set_my_ip(Option<IpAddr>)` | Override `myIpAddress()`/`myIpAddressEx()` (deterministic tests). |
| `set_timeout(Duration)` | Wall-clock limit per call (default 10 s). |
| `set_memory_limit(usize)` | QuickJS runtime memory limit (default 64 MiB). |
| `set_log_sink(impl Fn(&str))` | Receive `alert()`/`console.log()` output instead of stderr. |

Errors are a typed enum: `ScriptSyntax`, `FunctionMissing`, `JsException`
(with message and stack trace), `ReturnedNonString`, `Timeout`, `Internal`.
It implements `std::error::Error` and `Display`.

## Supported PAC helpers

Standard helpers (Netscape specification), always available:

`isPlainHostName`, `dnsDomainIs`, `localHostOrDomainIs`, `isResolvable`,
`isInNet` (IPv4 dotted-quad + mask; host names are resolved first),
`dnsDomainLevels`, `shExpMatch` (shell glob: only `*` and `?` are wildcards,
anchored to the whole string, regex metacharacters are literal),
`weekdayRange`, `dateRange`, `timeRange` (all with the full argument-count
overloading and the optional trailing `"GMT"` flag), `dnsResolve`,
`myIpAddress`, `alert` and `console.log`.

Microsoft IPv6 extensions (Cargo feature `microsoft-extensions`, enabled by
default):

`dnsResolveEx` (`;`-separated IPv4/IPv6 list, `""` on failure),
`myIpAddressEx`, `isResolvableEx`, `isInNetEx` (CIDR prefix match for IPv4
and IPv6; also accepts a `;`-separated list of prefixes),
`sortIpAddressList` (ascending, IPv6 before IPv4), `getClientVersion`, and
the `FindProxyForURLEx` entry point via `find_proxy_ex`.

Behavioral notes:

- `find_proxy` returns the script's string result **verbatim**; multi-proxy
  directives such as `"PROXY a:1; PROXY b:2; DIRECT"` are not reformatted.
- `timeRange` treats range ends as exclusive at the stated granularity
  (`timeRange(9, 17)` is 09:00:00–16:59:59), matching the specification's
  examples; ranges wrap past midnight. `dateRange` day and month ranges wrap
  (e.g. `dateRange("NOV", "FEB")`); ranges that include a year are absolute.
- `dnsResolve` returns the first IPv4 address only (per the original
  specification); use `dnsResolveEx` for IPv6.
- String comparisons in `dnsDomainIs` etc. are case-sensitive, as in the
  specification; browsers pass `host` lowercased.

## Sandboxing and timeouts

PAC scripts are untrusted input:

- **Timeout:** every `load`/`find_proxy*` call runs under a deadline
  (default 10 seconds, `set_timeout`). A QuickJS interrupt handler stops a
  runaway script (`while (true) {}`) inside the engine and the call returns
  `Error::Timeout`; the engine remains usable afterwards. The interrupt
  handler cannot fire *during* a native call, so a slow blocking DNS lookup
  in `dnsResolve` can overrun the deadline.
- **Memory:** the runtime has a memory limit (default 64 MiB,
  `set_memory_limit`); exceeding it fails the call with an exception.
- **No ambient capabilities:** the script sees standard ECMAScript plus the
  PAC helpers — no filesystem, no module loading, no timers, no sockets. The
  only I/O reachable from a script is DNS resolution through
  `dnsResolve`/`dnsResolveEx` and messages through the log sink.

## Thread safety

`PacEngine` wraps a QuickJS context, which is not thread-safe; the type is
deliberately neither `Send` nor `Sync`, and no internal locking pretends
otherwise. Either create one engine per thread, or own a single engine on a
dedicated thread and serialize calls to it (e.g. via an `mpsc` channel).

## Building and testing

```sh
cargo build            # compiles quickjs-ng from source via cc
cargo test             # hermetic: no external DNS is required
cargo test --no-default-features   # without the Microsoft extensions
```

## License

The first-party code in this repository is licensed under the [MIT License](LICENSE.txt),
Copyright (c) Microsoft Corporation. QuickJS-NG and `rquickjs-sys` are also MIT
licensed; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
