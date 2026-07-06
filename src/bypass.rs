/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! One bypass matcher shared by every layer that has an exclusion list:
//! `NO_PROXY`, macOS `ExceptionsList`, GNOME `ignore-hosts`, and the WinHTTP
//! bypass string. Supports exact hosts, leading-dot / `*.` suffixes, simple
//! `*` globs, `host:port` qualification, IPv4/IPv6 CIDR blocks, `*`
//! (match-all) and `<local>` (hosts without a dot).

use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub(crate) struct BypassRules {
    entries: Vec<BypassEntry>,
    match_all: bool,
    /// `<local>` on Windows, `ExcludeSimpleHostnames` on macOS.
    bypass_simple_hostnames: bool,
}

#[derive(Debug, Clone)]
enum BypassEntry {
    Exact { host: String, port: Option<u16> },
    Suffix { suffix: String, port: Option<u16> },
    Glob { pattern: String, port: Option<u16> },
    Cidr { net: IpAddr, prefix_len: u8 },
}

impl BypassRules {
    pub fn parse<'a>(items: impl IntoIterator<Item = &'a str>) -> Self {
        let mut rules = BypassRules::default();
        for raw in items {
            for item in raw.split([',', ';']) {
                rules.add(item);
            }
        }
        rules
    }

    /// Used by the macOS config source (`ExcludeSimpleHostnames`); other
    /// platforms express this as a `<local>` list entry.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn set_bypass_simple_hostnames(&mut self, on: bool) {
        self.bypass_simple_hostnames = on;
    }

    fn add(&mut self, item: &str) {
        let item = item.trim().trim_end_matches('.');
        if item.is_empty() {
            return;
        }
        if item == "*" {
            self.match_all = true;
            return;
        }
        if item.eq_ignore_ascii_case("<local>") {
            self.bypass_simple_hostnames = true;
            return;
        }
        // CIDR block, e.g. "10.0.0.0/8" or "fe80::/10". macOS also writes
        // shorthand like "169.254/16" — pad missing IPv4 octets.
        if let Some((addr, prefix)) = item.split_once('/') {
            if let Ok(prefix_len) = prefix.parse::<u8>() {
                let addr = pad_ipv4_shorthand(addr);
                if let Ok(net) = addr.parse::<IpAddr>() {
                    self.entries.push(BypassEntry::Cidr { net, prefix_len });
                    return;
                }
            }
        }
        let (host, port) = split_host_port(item);
        let host = host.to_ascii_lowercase();
        if let Some(suffix) = host.strip_prefix("*.") {
            self.entries.push(BypassEntry::Suffix {
                suffix: suffix.to_string(),
                port,
            });
        } else if let Some(suffix) = host.strip_prefix('.') {
            self.entries.push(BypassEntry::Suffix {
                suffix: suffix.to_string(),
                port,
            });
        } else if host.contains('*') {
            self.entries.push(BypassEntry::Glob {
                pattern: host,
                port,
            });
        } else {
            self.entries.push(BypassEntry::Exact { host, port });
        }
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.match_all {
            return true;
        }
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if self.bypass_simple_hostnames && !host.contains('.') && host.parse::<IpAddr>().is_err() {
            return true;
        }
        let ip = host.parse::<IpAddr>().ok();
        self.entries.iter().any(|e| {
            let port_ok = |p: &Option<u16>| p.is_none() || *p == Some(port);
            match e {
                BypassEntry::Exact { host: h, port: p } => port_ok(p) && *h == host,
                BypassEntry::Suffix { suffix, port: p } => {
                    port_ok(p)
                        && (host == *suffix
                            || host
                                .strip_suffix(suffix.as_str())
                                .is_some_and(|rest| rest.ends_with('.')))
                }
                BypassEntry::Glob { pattern, port: p } => port_ok(p) && glob_match(pattern, host),
                BypassEntry::Cidr { net, prefix_len } => {
                    ip.is_some_and(|ip| cidr_contains(net, *prefix_len, &ip))
                }
            }
        })
    }
}

/// Split a trailing `:port` off, being careful with IPv6 literals.
fn split_host_port(item: &str) -> (&str, Option<u16>) {
    let colon = match item.rfind(']') {
        Some(bracket) => item[bracket..].find(':').map(|i| bracket + i),
        None if item.matches(':').count() > 1 => None, // bare IPv6, no port
        None => item.rfind(':'),
    };
    match colon {
        Some(i) => match item[i + 1..].parse::<u16>() {
            Ok(port) => (&item[..i], Some(port)),
            Err(_) => (item, None),
        },
        None => (item, None),
    }
}

/// "169.254/16" -> "169.254.0.0"
fn pad_ipv4_shorthand(addr: &str) -> String {
    if addr.contains(':') || addr.parse::<IpAddr>().is_ok() {
        return addr.to_string();
    }
    let dots = addr.matches('.').count();
    if dots < 3 && addr.chars().all(|c| c.is_ascii_digit() || c == '.') {
        let mut s = addr.to_string();
        for _ in dots..3 {
            s.push_str(".0");
        }
        s
    } else {
        addr.to_string()
    }
}

fn cidr_contains(net: &IpAddr, prefix_len: u8, ip: &IpAddr) -> bool {
    fn octets_match(a: &[u8], b: &[u8], prefix_len: u8) -> bool {
        let full = (prefix_len / 8) as usize;
        let rem = prefix_len % 8;
        if full > a.len() {
            return false;
        }
        if a[..full] != b[..full] {
            return false;
        }
        if rem == 0 || full >= a.len() {
            return true;
        }
        let mask = 0xffu8 << (8 - rem);
        a[full] & mask == b[full] & mask
    }
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => octets_match(&n.octets(), &i.octets(), prefix_len),
        (IpAddr::V6(n), IpAddr::V6(i)) => octets_match(&n.octets(), &i.octets(), prefix_len),
        _ => false,
    }
}

/// Minimal `*` glob (matches any run of characters, including empty).
fn glob_match(pattern: &str, text: &str) -> bool {
    let mut parts = pattern.split('*');
    let first = parts.next().unwrap_or("");
    if !text.starts_with(first) {
        return false;
    }
    let mut pos = first.len();
    let mut rest: Vec<&str> = parts.collect();
    let last = rest.pop();
    for part in rest {
        match text[pos..].find(part) {
            Some(i) => pos = pos + i + part.len(),
            None => return false,
        }
    }
    match last {
        Some(last) => text.len() >= pos + last.len() && text.ends_with(last),
        None => pos == text.len(), // no '*' at all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_suffix() {
        let r = BypassRules::parse(["example.com", ".corp.net"]);
        assert!(r.matches("example.com", 80));
        assert!(!r.matches("sub.example.com", 80));
        assert!(r.matches("a.corp.net", 443));
        assert!(r.matches("corp.net", 443));
        assert!(!r.matches("evilcorp.net", 443));
    }

    #[test]
    fn star_suffix_and_glob() {
        let r = BypassRules::parse(["*.local", "10.*"]);
        assert!(r.matches("printer.local", 80));
        assert!(r.matches("local", 80)); // "*.local" also matches the bare suffix
        assert!(r.matches("10.1.2.3", 80));
        assert!(!r.matches("110.1.2.3", 80));
    }

    #[test]
    fn ports_and_match_all() {
        let r = BypassRules::parse(["example.com:8080"]);
        assert!(r.matches("example.com", 8080));
        assert!(!r.matches("example.com", 80));
        let all = BypassRules::parse(["*"]);
        assert!(all.matches("anything", 1));
    }

    #[test]
    fn cidr() {
        let r = BypassRules::parse(["10.0.0.0/8", "169.254/16", "fe80::/10"]);
        assert!(r.matches("10.250.1.1", 80));
        assert!(!r.matches("11.0.0.1", 80));
        assert!(r.matches("169.254.9.9", 80));
        assert!(r.matches("fe80::1", 80));
        assert!(!r.matches("fd00::1", 80));
    }

    #[test]
    fn local_and_simple_hostnames() {
        let r = BypassRules::parse(["<local>"]);
        assert!(r.matches("intranet", 80));
        assert!(!r.matches("intranet.example.com", 80));
        assert!(!r.matches("127.0.0.1", 80)); // IPs are not "simple hostnames"
    }

    #[test]
    fn ipv6_entries() {
        let r = BypassRules::parse(["::1"]);
        assert!(r.matches("::1", 80));
        assert!(r.matches("[::1]", 80));
    }
}
