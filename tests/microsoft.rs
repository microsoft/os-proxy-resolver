/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Tests for the Microsoft IPv6 PAC extension helpers.

#![cfg(feature = "microsoft-extensions")]

mod common;

use common::{eval_bool, eval_expr};
use pac_eval::PacEngine;

#[test]
fn is_in_net_ex_ipv4() {
    assert!(eval_bool(r#"isInNetEx("198.51.100.7", "198.51.100.0/24")"#));
    assert!(!eval_bool(
        r#"isInNetEx("198.51.101.7", "198.51.100.0/24")"#
    ));
    // Prefix lengths that are not a multiple of 8.
    assert!(eval_bool(r#"isInNetEx("10.0.0.14", "10.0.0.0/28")"#));
    assert!(!eval_bool(r#"isInNetEx("10.0.0.17", "10.0.0.0/28")"#));
    // /0 matches everything; a missing length means a full match.
    assert!(eval_bool(r#"isInNetEx("8.8.8.8", "0.0.0.0/0")"#));
    assert!(eval_bool(r#"isInNetEx("10.1.2.3", "10.1.2.3")"#));
    assert!(!eval_bool(r#"isInNetEx("10.1.2.4", "10.1.2.3")"#));
}

#[test]
fn is_in_net_ex_ipv6() {
    assert!(eval_bool(r#"isInNetEx("2001:db8::1", "2001:db8::/32")"#));
    assert!(!eval_bool(r#"isInNetEx("2001:db9::1", "2001:db8::/32")"#));
    // Prefix length not on a group boundary: bit 33 differs.
    assert!(eval_bool(
        r#"isInNetEx("2001:db8:8000::1", "2001:db8:8000::/33")"#
    ));
    assert!(!eval_bool(
        r#"isInNetEx("2001:db8::1", "2001:db8:8000::/33")"#
    ));
    // "::" compression and full form are equivalent.
    assert!(eval_bool(
        r#"isInNetEx("2001:db8::1", "2001:0db8:0:0:0:0:0:1/128")"#
    ));
    assert!(eval_bool(r#"isInNetEx("::1", "::1/128")"#));
    // Embedded IPv4 tail.
    assert!(eval_bool(
        r#"isInNetEx("::ffff:10.1.2.3", "::ffff:10.0.0.0/104")"#
    ));
}

#[test]
fn is_in_net_ex_edge_cases() {
    // Address family mismatch never matches.
    assert!(!eval_bool(r#"isInNetEx("10.0.0.1", "2001:db8::/32")"#));
    assert!(!eval_bool(r#"isInNetEx("2001:db8::1", "10.0.0.0/8")"#));
    // Semicolon-separated prefix lists: any match wins.
    assert!(eval_bool(
        r#"isInNetEx("10.1.2.3", "192.168.0.0/16; 10.0.0.0/8")"#
    ));
    assert!(!eval_bool(
        r#"isInNetEx("172.16.0.1", "192.168.0.0/16; 10.0.0.0/8")"#
    ));
    // Malformed input.
    assert!(!eval_bool(r#"isInNetEx("not-an-ip", "10.0.0.0/8")"#));
    assert!(!eval_bool(r#"isInNetEx("10.1.2.3", "10.0.0.0/33")"#));
    assert!(!eval_bool(r#"isInNetEx("10.1.2.3", "garbage")"#));
    assert!(!eval_bool(r#"isInNetEx("1:2:3:4:5:6:7:8:9", "::/0")"#));
    assert!(!eval_bool(r#"isInNetEx("1::2::3", "::/0")"#));
}

#[test]
fn sort_ip_address_list() {
    assert_eq!(
        eval_expr(r#"sortIpAddressList("10.0.0.2;10.0.0.1")"#),
        "10.0.0.1;10.0.0.2"
    );
    // IPv6 addresses sort before IPv4 addresses.
    assert_eq!(
        eval_expr(r#"sortIpAddressList("10.0.0.1;2001:db8::1;::1")"#),
        "::1;2001:db8::1;10.0.0.1"
    );
    assert_eq!(eval_expr(r#"sortIpAddressList("bogus")"#), "false");
    assert_eq!(eval_expr(r#"sortIpAddressList("")"#), "false");
}

#[test]
fn get_client_version() {
    assert_eq!(eval_expr("getClientVersion()"), "1.0");
}

#[test]
fn is_resolvable_ex_and_dns_resolve_ex() {
    assert!(eval_bool(r#"isResolvableEx("localhost")"#));
    assert!(!eval_bool(r#"isResolvableEx("")"#));
    // IP literals resolve to themselves without DNS.
    let resolved = eval_expr(r#"dnsResolveEx("127.0.0.1")"#);
    assert!(
        resolved.split(';').any(|ip| ip == "127.0.0.1"),
        "dnsResolveEx returned {resolved:?}"
    );
    assert_eq!(eval_expr(r#"dnsResolveEx("")"#), "");
}

#[test]
fn my_ip_address_ex_honors_override() {
    let mut engine = PacEngine::new().expect("engine");
    engine.set_my_ip(Some("2001:db8::42".parse().expect("literal")));
    engine
        .load("function FindProxyForURL(url, host) { return myIpAddressEx(); }")
        .expect("load");
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "2001:db8::42"
    );
}

#[test]
fn find_proxy_ex_prefers_ex_entry_point() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) { return "PROXY v4:8080"; }
            function FindProxyForURLEx(url, host) {
                var first = dnsResolveEx(host).split(";")[0];
                if (isInNetEx(first, "::1/128;127.0.0.0/8"))
                    return "DIRECT";
                return "PROXY v6proxy:8080";
            }
            "#,
        )
        .expect("load");
    assert_eq!(
        engine
            .find_proxy_ex("http://localhost/", "localhost")
            .expect("find_proxy_ex"),
        "DIRECT"
    );
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "PROXY v4:8080"
    );
}

#[test]
fn find_proxy_ex_falls_back_to_find_proxy_for_url() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(r#"function FindProxyForURL(url, host) { return "PROXY only:1"; }"#)
        .expect("load");
    assert_eq!(
        engine.find_proxy_ex("http://x/", "x").expect("fallback"),
        "PROXY only:1"
    );
}
