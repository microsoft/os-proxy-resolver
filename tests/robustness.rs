/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Robustness tests: malformed and hostile PAC scripts must produce typed
//! errors, never panics or hangs.

mod common;

use std::time::{Duration, Instant};

use pac_eval::{Error, PacEngine};

#[test]
fn malformed_script_is_a_syntax_error() {
    let mut engine = PacEngine::new().expect("engine");
    let err = engine
        .load("function FindProxyForURL(url, host { return")
        .expect_err("must fail");
    assert!(
        matches!(err, Error::ScriptSyntax(_)),
        "expected ScriptSyntax, got {err:?}"
    );
}

#[test]
fn script_with_nul_byte_is_a_syntax_error() {
    let mut engine = PacEngine::new().expect("engine");
    let err = engine
        .load("var a = 1;\0var b = 2;")
        .expect_err("must fail");
    assert!(matches!(err, Error::ScriptSyntax(_)), "got {err:?}");
}

#[test]
fn missing_find_proxy_for_url() {
    let mut engine = PacEngine::new().expect("engine");
    engine.load("var unrelated = 1;").expect("load");
    let err = engine.find_proxy("http://x/", "x").expect_err("must fail");
    match &err {
        Error::FunctionMissing(name) => assert_eq!(name, "FindProxyForURL"),
        other => panic!("expected FunctionMissing, got {other:?}"),
    }
    // A non-callable global of the same name is also "missing".
    engine.load("var FindProxyForURL = 42;").expect("load");
    let err = engine.find_proxy("http://x/", "x").expect_err("must fail");
    assert!(matches!(err, Error::FunctionMissing(_)), "got {err:?}");
}

#[test]
fn infinite_loop_in_find_proxy_times_out() {
    let mut engine = PacEngine::new().expect("engine");
    engine.set_timeout(Duration::from_millis(250));
    engine
        .load("function FindProxyForURL(url, host) { while (true) {} }")
        .expect("load");
    let start = Instant::now();
    let err = engine.find_proxy("http://x/", "x").expect_err("must fail");
    let elapsed = start.elapsed();
    assert!(matches!(err, Error::Timeout), "got {err:?}");
    assert!(
        elapsed < Duration::from_secs(5),
        "interrupt took too long: {elapsed:?}"
    );
    // The engine stays usable after a timeout.
    engine
        .load(r#"function FindProxyForURL(url, host) { return "DIRECT"; }"#)
        .expect("load after timeout");
    assert_eq!(
        engine.find_proxy("http://x/", "x").expect("find_proxy"),
        "DIRECT"
    );
}

#[test]
fn infinite_loop_at_top_level_times_out() {
    let mut engine = PacEngine::new().expect("engine");
    engine.set_timeout(Duration::from_millis(250));
    let start = Instant::now();
    let err = engine.load("while (true) {}").expect_err("must fail");
    assert!(matches!(err, Error::Timeout), "got {err:?}");
    assert!(start.elapsed() < Duration::from_secs(5));
}

#[test]
fn script_exception_is_reported_with_message() {
    let mut engine = PacEngine::new().expect("engine");
    engine
        .load(r#"function FindProxyForURL(url, host) { throw new Error("boom"); }"#)
        .expect("load");
    let err = engine.find_proxy("http://x/", "x").expect_err("must fail");
    match &err {
        Error::JsException(msg) => assert!(msg.contains("boom"), "message: {msg}"),
        other => panic!("expected JsException, got {other:?}"),
    }
}

#[test]
fn top_level_throw_is_a_js_exception_not_syntax() {
    let mut engine = PacEngine::new().expect("engine");
    let err = engine
        .load(r#"throw new Error("top");"#)
        .expect_err("must fail");
    assert!(matches!(err, Error::JsException(_)), "got {err:?}");
}

#[test]
fn non_string_return_is_a_typed_error() {
    for body in ["return 42;", "return null;", "return;", "return {};"] {
        let script = format!("function FindProxyForURL(url, host) {{ {body} }}");
        let err = PacEngine::eval_once(&script, "http://x/", "x").expect_err("must fail");
        assert!(
            matches!(err, Error::ReturnedNonString(_)),
            "body `{body}` gave {err:?}"
        );
    }
}

#[test]
fn helpers_never_crash_on_non_string_arguments() {
    let result = PacEngine::eval_once(
        r#"
        function FindProxyForURL(url, host) {
            alert();
            alert(undefined, null, 42, {}, [1, 2], Symbol("s"));
            console.log(3.14);
            var results = [
                isPlainHostName(null),
                dnsDomainIs(undefined, 7),
                localHostOrDomainIs({}, []),
                isResolvable(undefined),
                isInNet(null, null, null),
                dnsDomainLevels(123),
                shExpMatch(null, 99),
                weekdayRange(null),
                dateRange({}),
                timeRange([]),
                dnsResolve(undefined) === null || typeof dnsResolve(undefined) === "string",
                typeof myIpAddress() === "string"
            ];
            return "OK:" + results.length;
        }
        "#,
        "http://x/",
        "x",
    )
    .expect("must not crash");
    assert_eq!(result, "OK:12");
}

#[test]
fn memory_limit_is_enforced() {
    let mut engine = PacEngine::new().expect("engine");
    engine.set_memory_limit(8 * 1024 * 1024);
    engine
        .load(
            r#"
            function FindProxyForURL(url, host) {
                var chunks = [];
                for (;;) chunks.push(new Array(65536).join("x"));
            }
            "#,
        )
        .expect("load");
    let err = engine.find_proxy("http://x/", "x").expect_err("must fail");
    assert!(
        matches!(err, Error::JsException(_)),
        "expected JsException from allocation failure, got {err:?}"
    );
}

#[test]
fn error_display_is_informative() {
    let syntax = PacEngine::new()
        .expect("engine")
        .load("function (")
        .expect_err("must fail");
    assert!(syntax.to_string().contains("syntax"), "{syntax}");
    assert!(
        Error::Timeout.to_string().contains("time limit"),
        "{}",
        Error::Timeout
    );
    let source: &dyn std::error::Error = &syntax;
    assert!(source.source().is_none());
}
