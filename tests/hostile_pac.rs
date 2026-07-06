/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! A hostile PAC script (infinite JS loop) must time out and leave the
//! resolver failing fast, not hanging. This lives in its own integration-test
//! binary because it deliberately wedges the process-global PAC worker thread
//! for good — no other test may share this process.

#![cfg(not(windows))]

use os_proxy_resolver::{Error, ProxyResolver, ResolverOptions};
use std::time::{Duration, Instant};

#[test]
fn hostile_infinite_loop_times_out_and_fails_fast() {
    let mut options = ResolverOptions::default();
    options.pac_timeout = Duration::from_millis(300);
    let resolver = ProxyResolver::with_options(options);
    let url = url::Url::parse("http://example.com/").unwrap();
    let script = "function FindProxyForURL(url, host) { while (true) {} }";

    let start = Instant::now();
    match resolver.evaluate_pac(script, &url) {
        Err(Error::PacTimeout) => {}
        other => panic!("expected PacTimeout, got {other:?}"),
    }
    assert!(start.elapsed() < Duration::from_secs(2));

    // Worker is wedged: the next call must fail immediately, not queue up
    // behind the stuck request and burn another full timeout.
    let start = Instant::now();
    match resolver.evaluate_pac(script, &url) {
        Err(Error::PacTimeout) => {}
        other => panic!("expected fast-fail PacTimeout, got {other:?}"),
    }
    assert!(start.elapsed() < Duration::from_millis(100));
    // The wedged worker thread intentionally leaks; the process exits here.
}
