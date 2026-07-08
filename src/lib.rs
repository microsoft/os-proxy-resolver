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
//! | Windows | `WinHttpGetIEProxyConfigForCurrentUser` | WinHTTP (`WinHttpGetProxyForUrl`, incl. DHCP+DNS WPAD) | registry notification |
//! | macOS | `SCDynamicStoreCopyProxies` | built-in [QuickJS] PAC engine + DNS WPAD | `SCDynamicStore` callback |
//! | Linux | GNOME `org.gnome.system.proxy` (gsettings) | built-in [QuickJS] PAC engine + DNS WPAD | `dconf watch` / `gsettings monitor` |
//!
//! On Windows no JS engine is built or linked — PAC evaluation, DHCP and DNS
//! WPAD are all WinHTTP's. On macOS/Linux, DHCP-based WPAD (option 252) is a
//! documented non-goal; DNS-based WPAD walks `wpad.<search-domain>` with
//! tight timeouts.
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
//! # Change notification
//!
//! Two complementary primitives, identical across platforms:
//!
//! - [`ProxyResolver::config_generation`] — a cheap synchronous counter,
//!   bumped on every OS config change. Cached results should remember the
//!   generation they were computed at.
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
#[cfg(not(windows))]
mod fetch;
mod notify;
#[cfg(not(windows))]
mod pac;
mod platform;
mod resolver;
mod types;
#[cfg(not(windows))]
mod wpad;

pub use notify::Subscription;
pub use resolver::{ProxyResolver, ResolverOptions};
pub use types::{Error, ProxyKind, Result};

/// Resolve the ordered proxy list for `url` using the process-wide
/// [`ProxyResolver`] (created on first use).
///
/// See [`ProxyResolver::resolve_proxy`] for semantics and blocking behavior.
pub fn resolve_proxy(url: &url::Url) -> Result<Vec<ProxyKind>> {
    ProxyResolver::global().resolve_proxy(url)
}
