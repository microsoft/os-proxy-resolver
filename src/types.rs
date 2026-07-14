/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use std::fmt;

/// A single hop of a proxy resolution result, mirroring PAC semantics.
///
/// A PAC result like `"PROXY a:8080; SOCKS b:1080; DIRECT"` becomes
/// `[Http("a:8080"), Socks("b:1080"), Direct]` — callers should try entries
/// in order and fall through on connection failure (see
/// [`ProxyResolver::report_proxy_failed`](crate::ProxyResolver::report_proxy_failed)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProxyKind {
    /// Connect directly, no proxy.
    Direct,
    /// An HTTP proxy as `host:port` (use CONNECT for https URLs). If the PAC
    /// script used the `HTTPS` token (TLS to the proxy itself), the string is
    /// prefixed: `https://host:port`.
    Http(String),
    /// A SOCKS proxy as `host:port`. The SOCKS4/SOCKS5 distinction of the PAC
    /// tokens is not preserved; modern proxies speak SOCKS5 — try that first.
    Socks(String),
}

impl fmt::Display for ProxyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyKind::Direct => write!(f, "DIRECT"),
            ProxyKind::Http(hp) => write!(f, "PROXY {hp}"),
            ProxyKind::Socks(hp) => write!(f, "SOCKS {hp}"),
        }
    }
}

/// Selects which embedded engine evaluates PAC scripts on the caged worker
/// (see [`ResolverOptions::pac_backend`](crate::ResolverOptions)). Does not
/// affect Windows' regular resolution path, which delegates PAC to WinHTTP.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PacBackendKind {
    /// The in-process QuickJS-NG engine (C, compiled to native code). Built
    /// on macOS/Linux always, on Windows behind the `pac-engine` feature.
    Native,
    /// The same QuickJS-NG engine compiled to WebAssembly and run inside a
    /// Wasmtime sandbox, so a memory-safety bug triggered by a hostile
    /// PAC/WPAD script is contained to the guest's linear memory. This is the
    /// default backend; it requires the `pac-engine-wasmtime` feature (enabled
    /// by default). Selecting it without that feature makes PAC evaluation
    /// fail with [`Error::PacEval`].
    Wasmtime,
    /// The same WebAssembly guest as [`Wasmtime`](Self::Wasmtime), but
    /// translated to portable C with WABT's `wasm2c` and compiled like any
    /// other C code — the wasm sandbox for targets Wasmtime/Cranelift cannot
    /// AOT-compile for (e.g. 32-bit armv7). Slower than the Wasmtime backend
    /// (software bounds checks on every memory access), never the default.
    /// Requires the `pac-engine-wasm2c` feature; selecting it without that
    /// feature makes PAC evaluation fail with [`Error::PacEval`].
    Wasm2c,
    /// JIT variant of [`Wasmtime`](Self::Wasmtime): the same guest and host
    /// code, but with Cranelift in the runtime and the wasm JIT-compiled at
    /// startup instead of AOT-precompiled at build time. Simplest to build
    /// (no compile step, no target-specific artifact) at the cost of the
    /// largest binary, a one-time startup compile, and the AOT build's "no
    /// compiler at runtime" hardening. Requires the
    /// `pac-engine-wasmtime-jit` feature; selecting it without that feature
    /// makes PAC evaluation fail with [`Error::PacEval`].
    WasmtimeJit,
}

impl Default for PacBackendKind {
    /// The first compiled-in backend in preference order — Wasmtime (the
    /// default feature set), then Native, then Wasm2c, then WasmtimeJit — so
    /// the default is always one that actually works. (Backend-less builds
    /// are Windows-only, where PAC never reaches an embedded backend.)
    fn default() -> Self {
        if cfg!(feature = "pac-engine-wasmtime") {
            PacBackendKind::Wasmtime
        } else if cfg!(feature = "pac-engine") {
            PacBackendKind::Native
        } else if cfg!(feature = "pac-engine-wasm2c") {
            PacBackendKind::Wasm2c
        } else if cfg!(feature = "pac-engine-wasmtime-jit") {
            PacBackendKind::WasmtimeJit
        } else {
            PacBackendKind::Native
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Errors from proxy resolution. PAC/WPAD failures are generally *not*
/// surfaced here — resolution falls back to the next layer and ultimately to
/// `DIRECT`. Errors mean the input was unusable or a platform call failed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// The URL has no host or is otherwise not resolvable against a proxy config.
    InvalidUrl(String),
    /// Fetching a PAC script failed (only surfaced by direct PAC APIs).
    PacFetch(String),
    /// The PAC script failed to parse or `FindProxyForURL` threw.
    PacEval(String),
    /// A `FindProxyForURL` call exceeded the hard timeout. The evaluator may
    /// be wedged (e.g. an infinite JS loop); subsequent calls fail fast until
    /// it recovers.
    PacTimeout,
    /// An OS API failed.
    Platform(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidUrl(s) => write!(f, "invalid URL for proxy resolution: {s}"),
            Error::PacFetch(s) => write!(f, "failed to fetch PAC script: {s}"),
            Error::PacEval(s) => write!(f, "PAC evaluation failed: {s}"),
            Error::PacTimeout => write!(f, "PAC evaluation timed out"),
            Error::Platform(s) => write!(f, "platform error: {s}"),
        }
    }
}

impl std::error::Error for Error {}

/// Parse a PAC-style result string ("PROXY h:p; SOCKS h:p; DIRECT") into an
/// ordered list. Unknown tokens are skipped. Missing ports get the
/// conventional defaults (80 for PROXY/HTTP, 443 for HTTPS, 1080 for SOCKS).
/// On Windows, WinHTTP parses PAC results itself — this is only for tests.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn parse_pac_result(s: &str) -> Vec<ProxyKind> {
    let mut out = Vec::new();
    for part in s.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let (token, rest) = match part.split_once(char::is_whitespace) {
            Some((t, r)) => (t, r.trim()),
            None => (part, ""),
        };
        match token.to_ascii_uppercase().as_str() {
            "DIRECT" => out.push(ProxyKind::Direct),
            "PROXY" | "HTTP" if !rest.is_empty() => {
                out.push(ProxyKind::Http(with_default_port(rest, 80)))
            }
            "HTTPS" if !rest.is_empty() => out.push(ProxyKind::Http(format!(
                "https://{}",
                with_default_port(rest, 443)
            ))),
            "SOCKS" | "SOCKS4" | "SOCKS5" if !rest.is_empty() => {
                out.push(ProxyKind::Socks(with_default_port(rest, 1080)))
            }
            _ => log::warn!("ignoring unrecognized PAC result entry: {part:?}"),
        }
    }
    out
}

/// Append `:default` if `host_port` has no explicit port. Handles bracketed
/// IPv6 literals ("[::1]:8080").
pub(crate) fn with_default_port(host_port: &str, default: u16) -> String {
    let has_port = match host_port.rfind(']') {
        Some(bracket) => host_port[bracket..].contains(':'),
        None => host_port.contains(':'),
    };
    if has_port {
        host_port.to_string()
    } else {
        format!("{host_port}:{default}")
    }
}

/// Sanitize a URL before it is handed to (untrusted) PAC machinery, following
/// Chromium: identity and fragment are always stripped; for anything other
/// than plain http the path and query are dropped too, so a hostile PAC/WPAD
/// author (or the MITM proxy sharing its owner) can't read request details.
pub(crate) fn sanitize_url_for_pac(url: &url::Url) -> String {
    let scheme = url.scheme();
    let host = url.host_str().unwrap_or("");
    let port = match url.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    if scheme == "http" {
        let query = match url.query() {
            Some(q) => format!("?{q}"),
            None => String::new(),
        };
        format!("{scheme}://{host}{port}{}{query}", url.path())
    } else {
        format!("{scheme}://{host}{port}/")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ordered_list() {
        let got = parse_pac_result("PROXY a:8080; SOCKS b:1080; DIRECT");
        assert_eq!(
            got,
            vec![
                ProxyKind::Http("a:8080".into()),
                ProxyKind::Socks("b:1080".into()),
                ProxyKind::Direct
            ]
        );
    }

    #[test]
    fn applies_default_ports() {
        assert_eq!(
            parse_pac_result("PROXY a; SOCKS5 b; HTTPS c"),
            vec![
                ProxyKind::Http("a:80".into()),
                ProxyKind::Socks("b:1080".into()),
                ProxyKind::Http("https://c:443".into()),
            ]
        );
    }

    #[test]
    fn skips_garbage_and_handles_case() {
        assert_eq!(
            parse_pac_result("bogus x; direct; proxy P:1"),
            vec![ProxyKind::Direct, ProxyKind::Http("P:1".into())]
        );
        assert_eq!(parse_pac_result(""), vec![]);
    }

    #[test]
    fn ipv6_port_detection() {
        assert_eq!(with_default_port("[::1]:9", 80), "[::1]:9");
        assert_eq!(with_default_port("[::1]", 80), "[::1]:80");
    }
}
