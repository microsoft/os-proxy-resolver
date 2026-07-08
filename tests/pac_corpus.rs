/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! pactester-style corpus: (pac file, url) -> expected proxy list. Catches
//! drift in the built-in QuickJS PAC engine builtins cheaply.

#![cfg(not(windows))]

use os_proxy_resolver::{ProxyKind, ProxyResolver};

fn eval(pac_file: &str, url: &str) -> Vec<ProxyKind> {
    let path = format!("{}/tests/data/{pac_file}", env!("CARGO_MANIFEST_DIR"));
    let script = std::fs::read_to_string(path).unwrap();
    ProxyResolver::global()
        .evaluate_pac(&script, &url::Url::parse(url).unwrap())
        .unwrap()
}

fn http(hp: &str) -> ProxyKind {
    ProxyKind::Http(hp.into())
}

fn socks(hp: &str) -> ProxyKind {
    ProxyKind::Socks(hp.into())
}

#[test]
fn corporate_pac_corpus() {
    let cases: &[(&str, Vec<ProxyKind>)] = &[
        ("http://intranet/", vec![ProxyKind::Direct]),
        ("http://wiki.corp.example.com/page", vec![ProxyKind::Direct]),
        ("http://10.1.2.3/", vec![ProxyKind::Direct]),
        (
            "http://ads.blocked.example/",
            vec![http("blackhole.corp.example.com:9")],
        ),
        (
            "https://www.example.org/",
            vec![http("secure.corp.example.com:8443"), ProxyKind::Direct],
        ),
        (
            "http://www.example.org/",
            vec![
                http("proxy.corp.example.com:3128"),
                http("backup.corp.example.com:3128"),
                ProxyKind::Direct,
            ],
        ),
    ];
    for (url, expected) in cases {
        assert_eq!(&eval("corporate.pac", url), expected, "url: {url}");
    }
}

#[test]
fn socks_chain_corpus() {
    assert_eq!(
        eval("socks_chain.pac", "http://always-direct.example/"),
        vec![ProxyKind::Direct]
    );
    // Default ports are filled in for portless entries.
    assert_eq!(
        eval("socks_chain.pac", "http://no-port.example/"),
        vec![http("noport:80"), socks("nosocks:1080")]
    );
    assert_eq!(
        eval("socks_chain.pac", "http://other.example/"),
        vec![
            socks("socks.example.com:1080"),
            socks("legacy.example.com:1080"),
            ProxyKind::Direct,
        ]
    );
}

#[test]
fn microsoft_extensions_take_precedence() {
    // The HTTPS token means "TLS to the proxy itself" and is carried in the
    // Http entry as a https:// prefix.
    assert_eq!(
        eval("ms_extensions.pac", "http://x.example/"),
        vec![
            http("https://tls-proxy.example.com:8443"),
            ProxyKind::Direct
        ]
    );
}
