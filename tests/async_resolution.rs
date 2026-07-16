/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#![cfg(feature = "tokio")]

use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use os_proxy_resolver::{ProxyKind, ProxyResolver};
use url::Url;

const CHILD_ENV: &str = "OS_PROXY_RESOLVER_ASYNC_WORKER_CHILD";

/// Run the potentially wedging worker scenario in a subprocess: a deadlocked
/// `std::thread` keeps its process alive even after a Tokio timeout fires, so an
/// in-process timeout cannot fail cleanly. The parent can kill the child and
/// report a bounded test failure instead of hanging the whole suite.
#[test]
fn async_resolution_worker_processes_second_distinct_request() {
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "async_resolution_distinct_request_child",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(error) if error.raw_os_error() == Some(8) => {
            eprintln!("skipping nested subprocess unsupported by this target runner");
            return;
        }
        Err(error) => panic!("failed to spawn async resolver child: {error}"),
    };

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            // Cross-target CI launches this test through a Cargo runner (QEMU,
            // Wine, ...), but a nested `Command` cannot recover that runner and
            // may fail immediately when executing the foreign binary directly.
            // Native jobs still exercise the regression; a deadlocked child is
            // distinguished by remaining alive until the deadline below.
            if status.code() == Some(2) {
                eprintln!("skipping nested subprocess unsupported by this target runner");
                return;
            }
            assert!(status.success(), "async resolver child failed: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("async resolver worker did not process its second distinct request");
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn async_resolution_distinct_request_child() {
    if std::env::var_os(CHILD_ENV).is_none() {
        return;
    }

    // ProxyResolver snapshots its environment at construction. Clear every
    // supported spelling before setting the canonical uppercase value last:
    // Windows environment names are case-insensitive, so removing an uppercase
    // alias after setting lowercase would remove the test value too.
    for name in [
        "http_proxy",
        "HTTP_PROXY",
        "https_proxy",
        "HTTPS_PROXY",
        "all_proxy",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        std::env::remove_var(name);
    }
    std::env::set_var("HTTPS_PROXY", "http://proxy.example:3128");

    tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap()
        .block_on(async {
            let resolver = ProxyResolver::new();
            for host in ["first.example.com", "second.example.com"] {
                let target = Url::parse(&format!("https://{host}/")).unwrap();
                assert_eq!(
                    resolver.resolve_proxy_async(&target).await.unwrap(),
                    vec![ProxyKind::Http("proxy.example:3128".into())]
                );
            }
        });
}
