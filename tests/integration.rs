/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Integration tests with representative PAC files.

mod common;

use std::cell::RefCell;
use std::rc::Rc;

use pac_eval::PacEngine;

#[test]
fn direct_only() {
    let result = PacEngine::eval_once(
        r#"function FindProxyForURL(url, host) { return "DIRECT"; }"#,
        "http://example.com/",
        "example.com",
    )
    .expect("eval_once");
    assert_eq!(result, "DIRECT");
}

#[test]
fn host_and_domain_routing() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                if (isPlainHostName(host) || dnsDomainIs(host, ".intra.example.com"))
                    return "DIRECT";
                if (shExpMatch(url, "http://static.example.com/*"))
                    return "PROXY static-proxy.example.com:3128";
                return "PROXY proxy.example.com:8080";
            }
            "#,
        )
        .expect("load");
    let mut check = |url: &str, host: &str, expected: &str| {
        assert_eq!(engine.find_proxy(url, host).expect("find_proxy"), expected);
    };
    check("http://intranet/", "intranet", "DIRECT");
    check(
        "http://wiki.intra.example.com/",
        "wiki.intra.example.com",
        "DIRECT",
    );
    check(
        "http://static.example.com/logo.png",
        "static.example.com",
        "PROXY static-proxy.example.com:3128",
    );
    check(
        "https://www.example.org/",
        "www.example.org",
        "PROXY proxy.example.com:8080",
    );
}

#[test]
fn subnet_routing_with_my_ip_override() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                if (isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0"))
                    return "PROXY internal-proxy.example.com:8080";
                return "DIRECT";
            }
            "#,
        )
        .expect("load");
    engine.set_my_ip(Some("10.1.2.3".parse().expect("literal")));
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "PROXY internal-proxy.example.com:8080"
    );
    engine.set_my_ip(Some("192.168.1.1".parse().expect("literal")));
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "DIRECT"
    );
}

#[test]
fn multi_proxy_result_is_returned_verbatim() {
    let result = PacEngine::eval_once(
        r#"
        function FindProxyForURL(url, host) {
            return "PROXY p1.example.com:8080; PROXY p2.example.com:8080; DIRECT";
        }
        "#,
        "http://example.com/",
        "example.com",
    )
    .expect("eval_once");
    assert_eq!(
        result,
        "PROXY p1.example.com:8080; PROXY p2.example.com:8080; DIRECT"
    );
}

#[test]
fn dns_resolve_is_deterministic_for_ip_literals() {
    let result = PacEngine::eval_once(
        r#"function FindProxyForURL(url, host) { return "" + dnsResolve("127.0.0.1") + "|" + dnsResolve(""); }"#,
        "http://x/",
        "x",
    )
    .expect("eval_once");
    assert_eq!(result, "127.0.0.1|null");
}

#[test]
fn log_sink_receives_alert_and_console_log() {
    let messages: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&messages);
    let mut engine = PacEngine::new().expect("engine");
    engine.set_log_sink(move |msg| sink.borrow_mut().push(msg.to_string()));
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                alert("resolving", host, 42);
                console.log("via console");
                return "DIRECT";
            }
            "#,
        )
        .expect("load");
    engine.find_proxy("http://x/", "x").expect("find_proxy");
    assert_eq!(
        *messages.borrow(),
        vec!["resolving x 42".to_string(), "via console".to_string()]
    );
}

#[test]
fn non_ascii_url_and_host_round_trip() {
    let result = PacEngine::eval_once(
        r#"function FindProxyForURL(url, host) { return "PROXY " + host + "|" + url; }"#,
        "http://bücher.example/päge",
        "bücher.example",
    )
    .expect("eval_once");
    assert_eq!(result, "PROXY bücher.example|http://bücher.example/päge");
}

#[test]
fn repeated_calls_reuse_the_engine() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                return shExpMatch(host, "*.example.com")
                    ? "PROXY proxy.example.com:8080" : "DIRECT";
            }
            "#,
        )
        .expect("load");
    for i in 0..1000 {
        let host = format!("h{i}.example.com");
        assert_eq!(
            engine
                .find_proxy(&format!("http://{host}/"), &host)
                .expect("find_proxy"),
            "PROXY proxy.example.com:8080"
        );
        assert_eq!(
            engine
                .find_proxy("http://other.org/", "other.org")
                .expect("find_proxy"),
            "DIRECT"
        );
    }
}

#[test]
fn load_replaces_previous_definitions() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(r#"function FindProxyForURL(url, host) { return "PROXY a:1"; }"#)
        .expect("load");
    engine
        .load(r#"function FindProxyForURL(url, host) { return "PROXY b:2"; }"#)
        .expect("load");
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "PROXY b:2"
    );
}
