/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Verifies the *in-engine* deadline (10 s default), not the caller-side one:
//! with a caller timeout larger than the engine backstop, a hostile loop must
//! be interrupted inside the engine and — unlike a caller-side timeout, which
//! wedges the worker — leave the worker immediately usable again. For the
//! wasm backends this exercises the guest's QuickJS interrupt handler polling
//! `host_should_interrupt`; for the native backend, the QuickJS interrupt
//! handler in ffi.rs.
//!
//! Ignored by default: each backend burns the full 10 s engine deadline. Run
//! with `cargo test --test slow_timeout -- --ignored`.

#![cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]

use os_proxy_resolver::{Error, PacBackendKind, ProxyKind, ProxyResolver, ResolverOptions};
use std::time::{Duration, Instant};

fn engine_deadline_interrupts_and_recovers(kind: PacBackendKind) {
    let mut options = ResolverOptions::default();
    // Caller-side timeout well above the engine's 10 s internal deadline, so
    // the engine interrupt must fire first.
    options.pac_timeout = Duration::from_secs(20);
    options.pac_backend = kind;
    let resolver = ProxyResolver::with_options(options);
    let url = url::Url::parse("http://example.com/").unwrap();

    let start = Instant::now();
    match resolver.evaluate_pac(
        "function FindProxyForURL(url, host) { while (true) {} }",
        &url,
    ) {
        Err(Error::PacTimeout) => {}
        other => panic!("expected PacTimeout, got {other:?} (backend: {kind:?})"),
    }
    let elapsed = start.elapsed();
    assert!(
        elapsed > Duration::from_secs(8) && elapsed < Duration::from_secs(15),
        "expected the ~10s engine deadline, got {elapsed:?} (backend: {kind:?})"
    );

    // The engine unwound cleanly (no caller-side timeout, no wedge): the very
    // next evaluation must work.
    let got = resolver
        .evaluate_pac(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            &url,
        )
        .unwrap();
    assert_eq!(got, vec![ProxyKind::Direct], "backend: {kind:?}");
}

#[cfg(feature = "pac-engine")]
#[test]
#[ignore = "burns the full 10s engine deadline"]
fn engine_deadline_native() {
    engine_deadline_interrupts_and_recovers(PacBackendKind::Native);
}

#[cfg(feature = "pac-engine-wasmtime")]
#[test]
#[ignore = "burns the full 10s engine deadline"]
fn engine_deadline_wasmtime() {
    engine_deadline_interrupts_and_recovers(PacBackendKind::Wasmtime);
}

#[cfg(feature = "pac-engine-wasm2c")]
#[test]
#[ignore = "burns the full 10s engine deadline"]
fn engine_deadline_wasm2c() {
    engine_deadline_interrupts_and_recovers(PacBackendKind::Wasm2c);
}

#[cfg(feature = "pac-engine-wasmtime-jit")]
#[test]
#[ignore = "burns the full 10s engine deadline"]
fn engine_deadline_wasmtime_jit() {
    engine_deadline_interrupts_and_recovers(PacBackendKind::WasmtimeJit);
}
