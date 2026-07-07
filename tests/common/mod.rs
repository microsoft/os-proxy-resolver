/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Shared test utilities: evaluate a JS expression through the public
//! `PacEngine` API by wrapping it in a `FindProxyForURL` body.

// Each test binary uses a different subset of these helpers.
#![allow(dead_code)]

use pac_eval::PacEngine;

/// Evaluates a JS expression inside a PAC script and returns
/// `String(<expr>)`.
pub fn eval_expr(expr: &str) -> String {
    let script = format!("function FindProxyForURL(url, host) {{ return String({expr}); }}");
    PacEngine::eval_once(&script, "http://test.invalid/", "test.invalid")
        .unwrap_or_else(|e| panic!("evaluation of `{expr}` failed: {e}"))
}

/// Evaluates a boolean JS expression inside a PAC script.
pub fn eval_bool(expr: &str) -> bool {
    match eval_expr(expr).as_str() {
        "true" => true,
        "false" => false,
        other => panic!("`{expr}` returned non-boolean `{other}`"),
    }
}

/// Runs a block of JS checks inside a PAC script. The block can call
/// `check(name, cond)` and `stable(fn)`; the test fails with the names of
/// all failed checks.
///
/// `stable(fn)` calls `fn(before)` with a `Date` snapshot and only trusts
/// the outcome when the wall clock (at second resolution) did not tick
/// while `fn` ran, so time-based helpers can be compared against the same
/// instant without flaking at day/hour boundaries.
pub fn run_checks(body: &str) {
    let script = format!(
        r#"
function FindProxyForURL(url, host) {{
    var fails = [];
    function check(name, cond) {{
        if (cond !== true) fails.push(name);
    }}
    function stable(fn) {{
        for (var i = 0; i < 5; i++) {{
            var before = new Date();
            var result = fn(before);
            var after = new Date();
            if (Math.floor(before.getTime() / 1000) === Math.floor(after.getTime() / 1000)
                && Math.floor(after.getTime() / 1000) === Math.floor(new Date().getTime() / 1000)) {{
                return result;
            }}
        }}
        return true; // clock kept ticking across seconds; skip instead of flaking
    }}
    {body}
    return fails.length === 0 ? "OK" : fails.join(",");
}}"#
    );
    let out = PacEngine::eval_once(&script, "http://test.invalid/", "test.invalid")
        .unwrap_or_else(|e| panic!("check script failed: {e}"));
    assert_eq!(out, "OK", "failed checks: {out}");
}
