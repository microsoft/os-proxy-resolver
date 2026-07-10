/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! A hostile PAC script (infinite JS loop) must time out and leave the
//! resolver failing fast, not hanging. This lives in its own integration-test
//! binary because it deliberately wedges the process-global PAC worker
//! threads for good — no other test may share this process. (Each backend has
//! its own worker, so the per-backend tests below don't interfere with each
//! other either way.)

#![cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasm2c"
))]

use os_proxy_resolver::{Error, PacBackendKind, ProxyResolver, ResolverOptions};
use std::time::{Duration, Instant};

fn hostile_infinite_loop(kind: PacBackendKind) {
    let mut options = ResolverOptions::default();
    options.pac_timeout = Duration::from_millis(300);
    options.pac_backend = kind;
    let resolver = ProxyResolver::with_options(options);
    let url = url::Url::parse("http://example.com/").unwrap();
    let script = "function FindProxyForURL(url, host) { while (true) {} }";

    let start = Instant::now();
    match resolver.evaluate_pac(script, &url) {
        Err(Error::PacTimeout) => {}
        other => panic!("expected PacTimeout, got {other:?} (backend: {kind:?})"),
    }
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "backend: {kind:?}"
    );

    // Worker is wedged: the next call must fail immediately, not queue up
    // behind the stuck request and burn another full timeout.
    let start = Instant::now();
    match resolver.evaluate_pac(script, &url) {
        Err(Error::PacTimeout) => {}
        other => panic!("expected fast-fail PacTimeout, got {other:?} (backend: {kind:?})"),
    }
    assert!(
        start.elapsed() < Duration::from_millis(100),
        "backend: {kind:?}"
    );
    // The wedged worker thread intentionally leaks; the process exits when
    // all tests are done.
}

#[cfg(feature = "pac-engine")]
#[test]
fn hostile_infinite_loop_times_out_and_fails_fast() {
    hostile_infinite_loop(PacBackendKind::Native);
}

/// Same containment for the sandboxed backend, enforced by the guest's
/// QuickJS interrupt handler with Wasmtime epoch interruption as backstop.
#[cfg(feature = "pac-engine-wasmtime")]
#[test]
fn hostile_infinite_loop_times_out_and_fails_fast_wasmtime() {
    hostile_infinite_loop(PacBackendKind::Wasmtime);
}

/// Same containment for the wasm2c backend, which has no epoch interruption:
/// the guest's QuickJS interrupt handler polling `host_should_interrupt` is
/// the only in-engine deadline, and the caller-side wedge provides fail-fast.
#[cfg(feature = "pac-engine-wasm2c")]
#[test]
fn hostile_infinite_loop_times_out_and_fails_fast_wasm2c() {
    hostile_infinite_loop(PacBackendKind::Wasm2c);
}
