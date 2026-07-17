/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! DNS-based WPAD discovery. Windows probes DHCP option 252 separately before
//! falling back to this shared DNS path. DHCP-based discovery is otherwise a
//! documented non-goal here.
//!
//! Strategy: take the DNS search domains from the OS resolver configuration
//! (macOS `SCDynamicStore`, Linux `/etc/resolv.conf`), and for each, walk up
//! the suffix (`wpad.a.b.example.com`, `wpad.b.example.com`,
//! `wpad.example.com`) — never past the registrable-domain (eTLD+1) boundary
//! as determined by the Public Suffix List, so `wpad.com` (and multi-label
//! cases like `wpad.co.uk`) are never queried; WPAD walking into a public
//! suffix is a classic hijack vector.
//!
//! Networks without WPAD must not stall every first request: each DNS probe
//! gets a short timeout (Chromium uses ~100ms budgets here), the wpad.dat
//! fetch gets a slightly longer one, and the caller caches negative results.

use crate::fetch::fetch_pac;
use crate::types::PacScriptSource;
use std::net::ToSocketAddrs;
use std::sync::mpsc;
use std::time::Duration;

#[derive(Debug, Clone)]
pub(crate) struct DiscoveredPac {
    pub url: String,
    pub content: String,
    pub source: PacScriptSource,
}

/// Returns the fetched `wpad.dat` PAC script and its discovered URL, or `None`
/// when this network has no usable DNS WPAD.
pub(crate) fn discover(dns_timeout: Duration, fetch_timeout: Duration) -> Option<DiscoveredPac> {
    discover_with_domains(&search_domains(), dns_timeout, fetch_timeout)
}

fn discover_with_domains(
    domains: &[String],
    dns_timeout: Duration,
    fetch_timeout: Duration,
) -> Option<DiscoveredPac> {
    discover_with_domains_using(
        domains,
        |candidate| resolves(candidate, dns_timeout),
        |url| fetch_pac(url, fetch_timeout),
    )
}

fn discover_with_domains_using(
    domains: &[String],
    mut resolves: impl FnMut(&str) -> bool,
    mut fetch: impl FnMut(&str) -> crate::Result<String>,
) -> Option<DiscoveredPac> {
    for candidate in candidate_hosts(domains) {
        if !resolves(&candidate) {
            continue;
        }
        let url = format!("http://{candidate}/wpad.dat");
        match fetch(&url) {
            Ok(script) if script.contains("FindProxyForURL") => {
                log::info!("WPAD: using {url}");
                return Some(DiscoveredPac {
                    url,
                    content: script,
                    source: PacScriptSource::WpadDns,
                });
            }
            Ok(_) => log::warn!("WPAD: {url} does not look like a PAC script, skipping"),
            Err(e) => log::debug!("WPAD: {e}"),
        }
    }
    None
}

/// `wpad.` candidates from the search domains, deduplicated, order-preserving.
///
/// The suffix walk stops at the registrable domain (eTLD+1) as determined by
/// the Public Suffix List, matching what browsers do: `wpad.example.com` is a
/// candidate but `wpad.com` is not, and multi-label public suffixes such as
/// `co.uk` are handled correctly (`wpad.co.uk` is never queried). Search
/// domains that are themselves a public suffix (or otherwise have no
/// registrable part) contribute no candidates.
pub(crate) fn candidate_hosts(domains: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for domain in domains {
        let mut labels: Vec<&str> = domain
            .trim()
            .trim_matches('.')
            .split('.')
            .filter(|l| !l.is_empty())
            .collect();
        // Registrable-domain (eTLD+1) label count for this suffix; `None` when
        // the name has no registrable part (a bare public suffix, a single
        // label, ...), in which case it contributes no candidates.
        let Some(min_labels) = registrable_label_count(&labels) else {
            continue;
        };
        // Walk up to, and including, the registrable domain; never into the
        // public suffix itself.
        while labels.len() >= min_labels {
            let host = format!("wpad.{}", labels.join("."));
            if !out.contains(&host) {
                out.push(host);
            }
            labels.remove(0);
        }
    }
    out
}

/// Number of labels in the registrable domain (eTLD+1) of `labels`, per the
/// Public Suffix List, or `None` when there is no registrable domain (the name
/// is itself a public suffix, a single label, or otherwise unregistrable).
fn registrable_label_count(labels: &[&str]) -> Option<usize> {
    let name = labels.join(".");
    let registrable = psl::domain_str(&name)?;
    Some(registrable.split('.').filter(|l| !l.is_empty()).count())
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
    fn stops_at_registrable_domain_for_multi_label_suffix() {
        // The old label-count heuristic wrongly walked into `wpad.co.uk`; with
        // the Public Suffix List the walk stops at the registrable domain.
        let got = candidate_hosts(&["eng.example.co.uk".into()]);
        assert_eq!(got, vec!["wpad.eng.example.co.uk", "wpad.example.co.uk"]);
    }

    #[test]
    fn bare_public_suffix_yields_nothing() {
        assert!(candidate_hosts(&["co.uk".into()]).is_empty());
        assert!(candidate_hosts(&["com".into()]).is_empty());
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

    #[test]
    fn returns_discovered_url_with_script() {
        let pac = discover_with_domains_using(
            &["corp.example.com".into()],
            |host| host == "wpad.corp.example.com",
            |url| {
                assert_eq!(url, "http://wpad.corp.example.com/wpad.dat");
                Ok("function FindProxyForURL() { return 'DIRECT'; }".into())
            },
        )
        .unwrap();
        assert_eq!(pac.url, "http://wpad.corp.example.com/wpad.dat");
        assert!(pac.content.contains("FindProxyForURL"));
        assert_eq!(pac.source, PacScriptSource::WpadDns);
    }
}
