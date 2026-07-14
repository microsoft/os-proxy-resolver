/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! proxytester-style corpus: (pac file, url) -> expected proxy list. Catches
//! drift in the built-in PAC engine builtins cheaply. Runs against every
//! compiled-in backend — the native engine (`pac-engine`), the sandboxed
//! Wasmtime engine (`pac-engine-wasmtime`) and/or the portable wasm2c engine
//! (`pac-engine-wasm2c`) — which must agree on every case.

#![cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]

use os_proxy_resolver::{PacBackendKind, ProxyKind, ProxyResolver, ResolverOptions};
use std::sync::OnceLock;

fn resolver_for(kind: PacBackendKind) -> ProxyResolver {
    let mut options = ResolverOptions::default();
    options.pac_backend = kind;
    // Upper bound only (calls return as soon as the worker replies); the
    // default 5s is too tight for the wasm2c backend under qemu in debug CI
    // builds and for the JIT backend's first-call Cranelift compile.
    options.pac_timeout = std::time::Duration::from_secs(120);
    ProxyResolver::with_options(options)
}

/// One resolver per compiled-in backend; process-wide like the engines'
/// worker threads.
fn resolvers() -> Vec<(PacBackendKind, &'static ProxyResolver)> {
    #[allow(unused_mut)]
    let mut resolvers: Vec<(PacBackendKind, &'static ProxyResolver)> = Vec::new();
    #[cfg(feature = "pac-engine")]
    {
        static NATIVE: OnceLock<ProxyResolver> = OnceLock::new();
        resolvers.push((
            PacBackendKind::Native,
            NATIVE.get_or_init(|| resolver_for(PacBackendKind::Native)),
        ));
    }
    #[cfg(feature = "pac-engine-wasmtime")]
    {
        static WASMTIME: OnceLock<ProxyResolver> = OnceLock::new();
        resolvers.push((
            PacBackendKind::Wasmtime,
            WASMTIME.get_or_init(|| resolver_for(PacBackendKind::Wasmtime)),
        ));
    }
    #[cfg(feature = "pac-engine-wasm2c")]
    {
        static WASM2C: OnceLock<ProxyResolver> = OnceLock::new();
        resolvers.push((
            PacBackendKind::Wasm2c,
            WASM2C.get_or_init(|| resolver_for(PacBackendKind::Wasm2c)),
        ));
    }
    #[cfg(feature = "pac-engine-wasmtime-jit")]
    {
        static WASMTIME_JIT: OnceLock<ProxyResolver> = OnceLock::new();
        resolvers.push((
            PacBackendKind::WasmtimeJit,
            WASMTIME_JIT.get_or_init(|| resolver_for(PacBackendKind::WasmtimeJit)),
        ));
    }
    resolvers
}

fn check(pac_file: &str, url: &str, expected: &[ProxyKind]) {
    let path = format!("{}/tests/data/{pac_file}", env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(path).unwrap();
    let parsed = url::Url::parse(url).unwrap();
    for (kind, resolver) in resolvers() {
        let got = resolver.evaluate_pac(&script, &parsed).unwrap();
        assert_eq!(got, expected, "url: {url}, backend: {kind:?}");
    }
}

fn http(hp: &str) -> ProxyKind {
    ProxyKind::Http(hp.into())
}

fn socks(hp: &str) -> ProxyKind {
    ProxyKind::Socks(hp.into())
}

#[test]
fn corporate_pac_corpus() {
    let cases: &[(&str, Vec<ProxyKind>)] = &[
        ("http://intranet/", vec![ProxyKind::Direct]),
        ("http://wiki.corp.example.com/page", vec![ProxyKind::Direct]),
        ("http://10.1.2.3/", vec![ProxyKind::Direct]),
        (
            "http://ads.blocked.example/",
            vec![http("blackhole.corp.example.com:9")],
        ),
        (
            "https://www.example.org/",
            vec![http("secure.corp.example.com:8443"), ProxyKind::Direct],
        ),
        (
            "http://www.example.org/",
            vec![
                http("proxy.corp.example.com:3128"),
                http("backup.corp.example.com:3128"),
                ProxyKind::Direct,
            ],
        ),
    ];
    for (url, expected) in cases {
        check("corporate.pac", url, expected);
    }
}

#[test]
fn socks_chain_corpus() {
    check(
        "socks_chain.pac",
        "http://always-direct.example/",
        &[ProxyKind::Direct],
    );
    // Default ports are filled in for portless entries.
    check(
        "socks_chain.pac",
        "http://no-port.example/",
        &[http("noport:80"), socks("nosocks:1080")],
    );
    check(
        "socks_chain.pac",
        "http://other.example/",
        &[
            socks("socks.example.com:1080"),
            socks("legacy.example.com:1080"),
            ProxyKind::Direct,
        ],
    );
}

#[test]
fn microsoft_extensions_take_precedence() {
    // The HTTPS token means "TLS to the proxy itself" and is carried in the
    // Http entry as a https:// prefix.
    check(
        "ms_extensions.pac",
        "http://x.example/",
        &[
            http("https://tls-proxy.example.com:8443"),
            ProxyKind::Direct,
        ],
    );
}
