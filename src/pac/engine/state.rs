/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Host-side state shared with the native functions exposed to PAC scripts.
//!
//! A pointer to [`HostState`] is stored as the QuickJS context/interrupt
//! opaque, so native callbacks can reach configuration (logging sink,
//! `myIpAddress()` override) and the evaluation deadline. All fields use
//! interior mutability because callbacks only ever see a shared reference.

use std::cell::{Cell, RefCell};
use std::net::{IpAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

/// Callback receiving `alert()` / `console.log()` output.
pub(crate) type LogSink = Box<dyn Fn(&str)>;

pub(crate) struct HostState {
    /// Override for `myIpAddress()` / `myIpAddressEx()`.
    pub(crate) my_ip: Cell<Option<IpAddr>>,
    /// Wall-clock budget for a single script evaluation or PAC call.
    pub(crate) timeout: Cell<Duration>,
    /// Deadline armed while JavaScript is executing; read by the QuickJS
    /// interrupt handler.
    pub(crate) deadline: Cell<Option<Instant>>,
    /// Set by the interrupt handler when it aborts execution, so an engine
    /// exception can be told apart from a script exception.
    pub(crate) interrupted: Cell<bool>,
    /// Destination for `alert()` / `console.log()`; `None` means stderr.
    pub(crate) log_sink: RefCell<Option<LogSink>>,
}

impl HostState {
    pub(crate) fn new(default_timeout: Duration) -> Self {
        HostState {
            my_ip: Cell::new(None),
            timeout: Cell::new(default_timeout),
            deadline: Cell::new(None),
            interrupted: Cell::new(false),
            log_sink: RefCell::new(None),
        }
    }

    /// Arms the deadline before handing control to QuickJS.
    pub(crate) fn begin_call(&self) {
        self.interrupted.set(false);
        self.deadline.set(Some(Instant::now() + self.timeout.get()));
    }

    /// Disarms the deadline once QuickJS has returned.
    pub(crate) fn end_call(&self) {
        self.deadline.set(None);
    }

    pub(crate) fn log(&self, message: &str) {
        match &*self.log_sink.borrow() {
            Some(sink) => sink(message),
            None => eprintln!("{message}"),
        }
    }

    /// `dnsResolve(host)`: first IPv4 address, if any.
    pub(crate) fn dns_resolve(&self, host: &str) -> Option<String> {
        lookup(host)
            .into_iter()
            .find(|ip| ip.is_ipv4())
            .map(|ip| ip.to_string())
    }

    /// `dnsResolveEx(host)`: all addresses (IPv4 and IPv6), `;`-separated.
    pub(crate) fn dns_resolve_ex(&self, host: &str) -> String {
        let mut out: Vec<String> = Vec::new();
        for ip in lookup(host) {
            let s = ip.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
        out.join(";")
    }

    /// `myIpAddress()`: the configured override, a best-effort primary IPv4
    /// address, or `"127.0.0.1"`.
    pub(crate) fn my_ip_address(&self) -> String {
        if let Some(ip) = self.my_ip.get() {
            return ip.to_string();
        }
        primary_local_ip(false)
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "127.0.0.1".to_string())
    }

    /// `myIpAddressEx()`: the configured override, or a best-effort
    /// `;`-separated list of local IPv4/IPv6 addresses (may be empty).
    pub(crate) fn my_ip_address_ex(&self) -> String {
        if let Some(ip) = self.my_ip.get() {
            return ip.to_string();
        }
        let mut out: Vec<String> = Vec::new();
        for v6 in [false, true] {
            if let Some(ip) = primary_local_ip(v6) {
                let s = ip.to_string();
                if !out.contains(&s) {
                    out.push(s);
                }
            }
        }
        out.join(";")
    }
}

/// Resolves a host name (or parses an IP literal) into its addresses.
/// Returns an empty list on any failure; PAC evaluation must never error out
/// because of DNS.
fn lookup(host: &str) -> Vec<IpAddr> {
    if host.is_empty() {
        return Vec::new();
    }
    match (host, 0u16).to_socket_addrs() {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Determines the local address the OS would use for outbound traffic by
/// `connect()`ing a UDP socket to a well-known address. No packets are sent.
fn primary_local_ip(v6: bool) -> Option<IpAddr> {
    let (bind, probe) = if v6 {
        ("[::]:0", "[2001:4860:4860::8888]:53")
    } else {
        ("0.0.0.0:0", "8.8.8.8:53")
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(probe).ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_unspecified() {
        None
    } else {
        Some(ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_parses_ip_literals_without_dns() {
        assert_eq!(
            lookup("127.0.0.1"),
            vec!["127.0.0.1".parse::<IpAddr>().expect("literal")]
        );
        assert_eq!(lookup(""), Vec::<IpAddr>::new());
    }

    #[test]
    fn my_ip_override_wins() {
        let state = HostState::new(Duration::from_secs(1));
        state
            .my_ip
            .set(Some("203.0.113.7".parse().expect("literal")));
        assert_eq!(state.my_ip_address(), "203.0.113.7");
        assert_eq!(state.my_ip_address_ex(), "203.0.113.7");
    }
}
