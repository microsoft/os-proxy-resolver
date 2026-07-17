/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Resolve the OS-configured proxy for a URL — static config, PAC scripts,
//! and WPAD — with change notification and a bad-proxy feedback loop.
//!
//! ```no_run
//! use os_proxy_resolver::{resolve_proxy, ProxyKind};
//!
//! let url = url::Url::parse("https://example.com/").unwrap();
//! for proxy in resolve_proxy(&url).unwrap() {
//!     match proxy {
//!         ProxyKind::Direct => println!("connect directly"),
//!         ProxyKind::Http(hp) => println!("HTTP proxy {hp}"),
//!         ProxyKind::Socks(hp) => println!("SOCKS proxy {hp}"),
//!     }
//! }
//! ```
//!
//! The result mirrors PAC semantics: an *ordered* fallback list
//! (`"PROXY a:8080; DIRECT"` → `[Http("a:8080"), Direct]`). Try entries in
//! order; when one fails, tell the resolver via
//! [`ProxyResolver::report_proxy_failed`] so it's demoted for a cooldown.
//!
//! # Resolution precedence
//!
//! 1. `http_proxy` / `https_proxy` / `all_proxy` / `no_proxy` environment
//!    variables (lowercase or uppercase)
//! 2. OS proxy configuration — WPAD auto-detect, then a configured PAC URL,
//!    then static per-scheme rules with their bypass list
//! 3. `DIRECT`
//!
//! PAC and WPAD failures never fail a resolution; they fall through to the
//! next layer.
//!
//! # Platforms
//!
//! | | config source | PAC/WPAD engine | change signal |
//! |---|---|---|---|
//! | Windows | `WinHttpGetIEProxyConfigForCurrentUser` | selected embedded backend + DHCP/DNS WPAD; WinHTTP fallback with no backend | registry notification |
//! | macOS | `SCDynamicStoreCopyProxies` | built-in [QuickJS] PAC engine + DNS WPAD | `SCDynamicStore` callback |
//! | Linux | GNOME `org.gnome.system.proxy` (gsettings) | built-in [QuickJS] PAC engine + DNS WPAD | `dconf watch` / `gsettings monitor` |
//!
//! On Windows, WinHTTP always reads Internet Settings. DHCP option 252 is
//! probed before the shared DNS WPAD path; an embedded PAC backend evaluates
//! the discovered script, while a backend-less build delegates PAC evaluation
//! to WinHTTP. DHCP-based WPAD is not available on macOS/Linux; DNS-based WPAD
//! walks `wpad.<search-domain>` with tight timeouts.
//!
//! # The PAC cage
//!
//! A PAC file is untrusted JavaScript on a live JS engine. The embedded
//! QuickJS context is neither `Send` nor `Sync` and has synchronously-blocking
//! DNS builtins. All engine calls are therefore serialized on one dedicated
//! worker thread, every `FindProxyForURL` call has a hard timeout (a runaway
//! JS loop is interrupted inside the engine), URLs are stripped (identity
//! always; path+query for https) before evaluation, and a worker stuck in a
//! blocking builtin makes callers fail fast into the fallback path instead of
//! queueing. The worker protocol is process-agnostic so the evaluator can
//! later move out-of-process entirely (Chromium-style sandboxing).
//!
//! With the `pac-engine-wasmtime` feature (available on any platform),
//! the cage gains a wall: [`ResolverOptions::pac_backend`] selects
//! [`PacBackendKind::Wasmtime`] by default, which runs the same QuickJS-NG
//! compiled to WebAssembly inside a Wasmtime sandbox (ahead-of-time compiled
//! — no JIT or compiler at runtime). A memory-safety bug in the C engine is
//! then contained to the guest's linear memory, and the script's only reach
//! into the host is the DNS/local-IP/log callbacks; runaway scripts are
//! stopped by epoch interruption. See the "PAC cage" section of the README for
//! details.
//!
//! # Change notification
//!
//! Completed per-URL decisions are cached briefly and invalidated immediately
//! when the OS proxy configuration changes. Three complementary change
//! primitives are also available to consumers, identically across platforms:
//!
//! - [`ProxyResolver::config_generation`] — a cheap synchronous counter,
//!   bumped on every OS config change. External derived state can remember the
//!   generation it was computed at.
//! - [`ProxyResolver::on_change`] — a callback (drop the [`Subscription`] to
//!   unregister). Runs on the watcher thread: keep it cheap, never call
//!   `resolve_proxy` from it. This is the primitive an FFI bridge (e.g. a
//!   napi-rs `ThreadsafeFunction` feeding a Node `EventEmitter`) adapts.
//! - With the `tokio` feature, [`ProxyResolver::watch`] additionally exposes
//!   a `tokio::sync::watch::Receiver<u64>` for async consumers.
//!
//! [QuickJS]: https://github.com/quickjs-ng/quickjs

mod bypass;
mod env_cfg;
mod fetch;
mod notify;
// The PAC subsystem is present whenever an embedded engine is compiled in, and
// always off Windows (where at least one backend is required — see the
// compile_error below). On Windows a backend-less build resolves PAC via
// WinHTTP and omits this module entirely.
#[cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
mod pac;
mod platform;
mod resolver;
mod types;
mod wpad;

// Off Windows there is no OS PAC evaluator, so at least one embedded backend
// must be selected. On Windows a backend-less build falls back to WinHTTP.
#[cfg(all(
    not(windows),
    not(feature = "pac-engine"),
    not(feature = "pac-engine-wasmtime"),
    not(feature = "pac-engine-wasmtime-jit"),
    not(feature = "pac-engine-wasm2c")
))]
compile_error!(
    "No PAC backend selected. On non-Windows platforms enable at least one of the \
     `pac-engine` (native QuickJS), `pac-engine-wasmtime` (sandboxed Wasmtime) or \
    `pac-engine-wasm2c` (sandboxed portable C) features."
);

pub use notify::Subscription;
pub use resolver::{ProxyResolver, ResolverOptions};
pub use types::{
    Error, LinuxProxyConfig, MacosProxyConfig, PacBackendKind, PacScript, PacScriptSource,
    PacSourceState, PacSourceStatus, PlatformProxyConfig, ProxyConfig, ProxyKind, Result,
    StaticProxyRules, WindowsProxyConfig,
};

/// Size in bytes of the embedded ahead-of-time-compiled PAC guest module —
/// the dominant binary-size contribution of the `pac-engine-wasmtime`
/// feature. Exposed for the `pac_bench` example's size report; not a stable
/// API.
#[cfg(feature = "pac-engine-wasmtime")]
#[doc(hidden)]
pub fn pac_wasm_artifact_size() -> usize {
    pac::engine_wasmtime::CWASM_SIZE
}

/// Resolve the ordered proxy list for `url` using the process-wide
/// [`ProxyResolver`] (created on first use).
///
/// See [`ProxyResolver::resolve_proxy`] for semantics and blocking behavior.
pub fn resolve_proxy(url: &url::Url) -> Result<Vec<ProxyKind>> {
    ProxyResolver::global().resolve_proxy(url)
}

/// Read the operating-system proxy configuration using the process-wide
/// [`ProxyResolver`]. See [`ProxyResolver::read_proxy_config`] for details.
pub fn read_proxy_config() -> ProxyConfig {
    ProxyResolver::global().read_proxy_config()
}

/// Resolve the ordered proxy list asynchronously using the process-wide
/// [`ProxyResolver`]. Blocking resolution is scheduled onto a dedicated background thread
/// (PAC evaluation uses the existing PAC worker thread), and identical concurrent calls share one result.
///
/// See [`ProxyResolver::resolve_proxy_async`] for details.
#[cfg(feature = "tokio")]
pub async fn resolve_proxy_async(url: &url::Url) -> Result<Vec<ProxyKind>> {
    ProxyResolver::global().resolve_proxy_async(url).await
}
