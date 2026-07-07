/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! DNS-based WPAD discovery (macOS/Linux only — Windows gets WPAD, including
//! DHCP option 252, from WinHTTP). DHCP-based WPAD is a documented non-goal
//! here.
//!
//! Strategy: take the DNS search domains from the OS resolver configuration
//! (macOS `SCDynamicStore`, Linux `/etc/resolv.conf`), and for each, walk up
//! the suffix (`wpad.a.b.example.com`, `wpad.b.example.com`,
//! `wpad.example.com`) — never above the registrable-ish boundary (a
//! candidate must keep at least two labels after `wpad.`, so `wpad.com` is
//! never queried; WPAD walking into a TLD is a classic hijack vector).
//!
//! Networks without WPAD must not stall every first request: each DNS probe
//! gets a short timeout (Chromium uses ~100ms budgets here), the wpad.dat
//! fetch gets a slightly longer one, and the caller caches negative results.

use crate::fetch::fetch_pac;
use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::time::Duration;

/// Returns the fetched `wpad.dat` PAC script, or `None` when this network has
/// no (usable) WPAD.
pub(crate) fn discover(dns_timeout: Duration, fetch_timeout: Duration) -> Option<String> {
    discover_with_domains(&search_domains(), dns_timeout, fetch_timeout)
}

fn discover_with_domains(
    domains: &[String],
    dns_timeout: Duration,
    fetch_timeout: Duration,
) -> Option<String> {
    for candidate in candidate_hosts(domains) {
        if !resolves(&candidate, dns_timeout) {
            continue;
        }
        let url = format!("http://{candidate}/wpad.dat");
        match fetch_pac(&url, fetch_timeout) {
            Ok(script) if script.contains("FindProxyForURL") => {
                log::info!("WPAD: using {url}");
                return Some(script);
            }
            Ok(_) => log::warn!("WPAD: {url} does not look like a PAC script, skipping"),
            Err(e) => log::debug!("WPAD: {e}"),
        }
    }
    None
}

/// `wpad.` candidates from the search domains, deduplicated, order-preserving.
pub(crate) fn candidate_hosts(domains: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for domain in domains {
        let mut labels: Vec<&str> = domain
            .trim()
            .trim_matches('.')
            .split('.')
            .filter(|l| !l.is_empty())
            .collect();
        // Keep >= 2 labels after "wpad." — never query wpad.<tld>.
        while labels.len() >= 2 {
            let host = format!("wpad.{}", labels.join("."));
            if !out.contains(&host) {
                out.push(host);
            }
            labels.remove(0);
        }
    }
    out
}

fn search_domains() -> Vec<String> {
    crate::platform::dns_search_domains()
}

/// DNS probe with a hard timeout. `ToSocketAddrs` has no timeout knob, so the
/// lookup runs on a throwaway thread and we stop waiting after `timeout` (the
/// thread finishes in the background; the result is discarded).
fn resolves(host: &str, timeout: Duration) -> bool {
    let (tx, rx) = mpsc::sync_channel(1);
    let host_owned = format!("{host}:80");
    std::thread::Builder::new()
        .name("os-proxy-wpad-dns".into())
        .spawn(move || {
            let ok = host_owned.to_socket_addrs().map(|mut a| a.next().is_some());
            let _ = tx.send(ok.unwrap_or(false));
        })
        .is_ok()
        && rx.recv_timeout(timeout).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_suffixes_but_stops_above_two_labels() {
        let got = candidate_hosts(&["eng.corp.example.com".into()]);
        assert_eq!(
            got,
            vec![
                "wpad.eng.corp.example.com",
                "wpad.corp.example.com",
                "wpad.example.com"
            ]
        );
    }

    #[test]
    fn never_queries_wpad_tld() {
        assert!(candidate_hosts(&["com".into()]).is_empty());
        assert!(candidate_hosts(&["localdomain".into()]).is_empty());
        assert_eq!(
            candidate_hosts(&["example.com.".into()]),
            vec!["wpad.example.com"]
        );
    }

    #[test]
    fn dedupes_across_domains() {
        let got = candidate_hosts(&["a.example.com".into(), "b.example.com".into()]);
        assert_eq!(
            got,
            vec![
                "wpad.a.example.com",
                "wpad.example.com",
                "wpad.b.example.com"
            ]
        );
    }

    #[test]
    fn dns_probe_times_out_quickly() {
        // Reserved TLD guaranteed not to resolve; mainly checks the timeout path.
        let start = std::time::Instant::now();
        let _ = resolves("wpad.example.invalid", Duration::from_millis(200));
        assert!(start.elapsed() < Duration::from_secs(1));
    }
}
