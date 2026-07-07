/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Unit tests for the built-in PAC helper functions against examples from
//! the Netscape PAC specification.

mod common;

use common::{eval_bool, run_checks};

#[test]
fn is_plain_host_name() {
    assert!(eval_bool(r#"isPlainHostName("www")"#));
    assert!(!eval_bool(r#"isPlainHostName("www.example.com")"#));
}

#[test]
fn dns_domain_is() {
    assert!(eval_bool(
        r#"dnsDomainIs("www.example.com", ".example.com")"#
    ));
    assert!(!eval_bool(r#"dnsDomainIs("www", ".com")"#));
    assert!(!eval_bool(
        r#"dnsDomainIs("www.example.com", ".example.org")"#
    ));
    assert!(eval_bool(
        r#"dnsDomainIs("www.example.com", "example.com")"#
    ));
}

#[test]
fn local_host_or_domain_is() {
    assert!(eval_bool(
        r#"localHostOrDomainIs("www.example.com", "www.example.com")"#
    ));
    assert!(eval_bool(
        r#"localHostOrDomainIs("www", "www.example.com")"#
    ));
    assert!(!eval_bool(
        r#"localHostOrDomainIs("www.mcom.com", "www.example.com")"#
    ));
    assert!(!eval_bool(
        r#"localHostOrDomainIs("home.example.com", "www.example.com")"#
    ));
}

#[test]
fn is_resolvable() {
    // Resolves via /etc/hosts (or equivalent); no external DNS involved.
    assert!(eval_bool(r#"isResolvable("localhost")"#));
    assert!(eval_bool(r#"isResolvable("127.0.0.1")"#));
    assert!(!eval_bool(r#"isResolvable("")"#));
}

#[test]
fn is_in_net() {
    assert!(eval_bool(r#"isInNet("10.1.2.3", "10.0.0.0", "255.0.0.0")"#));
    assert!(!eval_bool(
        r#"isInNet("172.16.0.1", "10.0.0.0", "255.0.0.0")"#
    ));
    assert!(eval_bool(
        r#"isInNet("192.168.1.1", "192.168.0.0", "255.255.0.0")"#
    ));
    assert!(eval_bool(
        r#"isInNet("198.51.100.7", "198.51.100.7", "255.255.255.255")"#
    ));
    // Host names are resolved before matching.
    assert!(eval_bool(
        r#"isInNet("localhost", "127.0.0.0", "255.0.0.0")"#
    ));
    // Invalid patterns, masks or unresolvable hosts never match.
    assert!(!eval_bool(r#"isInNet("10.1.2.3", "10.0.0.0", "garbage")"#));
    assert!(!eval_bool(
        r#"isInNet("10.1.2.3", "10.0.0.256", "255.0.0.0")"#
    ));
    assert!(!eval_bool(r#"isInNet("", "10.0.0.0", "255.0.0.0")"#));
}

#[test]
fn dns_domain_levels() {
    assert!(eval_bool(r#"dnsDomainLevels("www") === 0"#));
    assert!(eval_bool(r#"dnsDomainLevels("www.example.com") === 2"#));
}

#[test]
fn sh_exp_match() {
    assert!(eval_bool(r#"shExpMatch("http://a/b", "*/b")"#));
    assert!(!eval_bool(r#"shExpMatch("http://a/c", "*/b")"#));
    assert!(eval_bool(
        r#"shExpMatch("www.example.com", "*.example.com")"#
    ));
    // Anchored to the whole string.
    assert!(!eval_bool(r#"shExpMatch("xhttp", "http")"#));
    assert!(!eval_bool(r#"shExpMatch("httpx", "http")"#));
    // "?" matches exactly one character.
    assert!(eval_bool(r#"shExpMatch("ab", "a?")"#));
    assert!(!eval_bool(r#"shExpMatch("abc", "a?")"#));
    // Regex metacharacters are literal; "." does not match any character.
    assert!(eval_bool(r#"shExpMatch("a.b", "a.b")"#));
    assert!(!eval_bool(r#"shExpMatch("axb", "a.b")"#));
    assert!(eval_bool(r#"shExpMatch("a+b(c)|d", "a+b(c)|d")"#));
    assert!(eval_bool(r#"shExpMatch("a[1]b", "a[?]b")"#));
    assert!(eval_bool(r#"shExpMatch("", "*")"#));
}

#[test]
fn weekday_range() {
    run_checks(
        r#"
    var WD = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
    check("single day", stable(function (d) {
        return weekdayRange(WD[d.getDay()]) === true
            && weekdayRange(WD[(d.getDay() + 3) % 7]) === false;
    }));
    check("range", stable(function (d) {
        return weekdayRange(WD[(d.getDay() + 6) % 7], WD[(d.getDay() + 1) % 7]) === true
            && weekdayRange(WD[(d.getDay() + 2) % 7], WD[(d.getDay() + 5) % 7]) === false;
    }));
    check("gmt flag", stable(function (d) {
        return weekdayRange(WD[d.getUTCDay()], "GMT") === true
            && weekdayRange(WD[(d.getUTCDay() + 6) % 7], WD[(d.getUTCDay() + 1) % 7], "GMT") === true;
    }));
    check("invalid", weekdayRange("XXX") === false && weekdayRange() === false);
    "#,
    );
}

#[test]
fn date_range() {
    run_checks(
        r#"
    var MN = ["JAN", "FEB", "MAR", "APR", "MAY", "JUN",
              "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"];
    check("day exact", stable(function (d) {
        var day = d.getDate();
        return dateRange(day) === true
            && dateRange(day === 1 ? 2 : day - 1) === false;
    }));
    check("day range", stable(function (d) {
        var day = d.getDate();
        var next = day === 31 ? 1 : day + 1;
        var prev = day === 1 ? 31 : day - 1;
        return dateRange(1, 31) === true
            && dateRange(day, day) === true
            && dateRange(next, prev) === false;
    }));
    check("month exact", stable(function (d) {
        return dateRange(MN[d.getMonth()]) === true
            && dateRange(MN[(d.getMonth() + 6) % 12]) === false;
    }));
    check("month range wrap", stable(function (d) {
        var m = d.getMonth();
        return dateRange(MN[(m + 11) % 12], MN[(m + 1) % 12]) === true
            && dateRange(MN[(m + 2) % 12], MN[(m + 10) % 12]) === false;
    }));
    check("year", stable(function (d) {
        var y = d.getFullYear();
        return dateRange(y) === true && dateRange(y + 1) === false
            && dateRange(y, y + 1) === true && dateRange(y + 1, y + 2) === false;
    }));
    check("day-month matrix", stable(function (d) {
        var day = d.getDate(), m = d.getMonth();
        return dateRange(day, MN[m], day, MN[m]) === true
            && dateRange(28, MN[(m + 11) % 12], 2, MN[(m + 1) % 12]) === true
            && dateRange(1, MN[(m + 2) % 12], 28, MN[(m + 10) % 12]) === false;
    }));
    check("month-year range", stable(function (d) {
        var m = d.getMonth(), y = d.getFullYear();
        return dateRange(MN[m], y, MN[m], y) === true
            && dateRange(MN[m], y + 1, MN[m], y + 2) === false;
    }));
    check("full date range", stable(function (d) {
        var y = d.getFullYear();
        return dateRange(1, "JAN", y - 1, 31, "DEC", y + 1) === true
            && dateRange(1, "JAN", y + 2, 31, "DEC", y + 3) === false;
    }));
    check("gmt flag", stable(function (d) {
        return dateRange(d.getUTCDate(), MN[d.getUTCMonth()], d.getUTCFullYear(),
                         d.getUTCDate(), MN[d.getUTCMonth()], d.getUTCFullYear(),
                         "GMT") === true;
    }));
    check("invalid", dateRange() === false && dateRange(32) === false
        && dateRange("XXX") === false && dateRange(1, 2, 3) === false);
    "#,
    );
}

#[test]
fn time_range() {
    run_checks(
        r#"
    check("single hour", stable(function (d) {
        return timeRange(d.getHours()) === true
            && timeRange((d.getHours() + 5) % 24) === false;
    }));
    check("hour window with wrap", stable(function (d) {
        var h = d.getHours();
        return timeRange((h + 23) % 24, (h + 2) % 24) === true
            && timeRange((h + 5) % 24, (h + 8) % 24) === false;
    }));
    check("minute window", stable(function (d) {
        var h = d.getHours(), m = d.getMinutes();
        var eh = m === 59 ? (h + 1) % 24 : h;
        var em = m === 59 ? 0 : m + 1;
        return timeRange(h, m, eh, em) === true;
    }));
    check("seconds form full day", stable(function (d) {
        return timeRange(0, 0, 0, 24, 0, 0) === true;
    }));
    check("gmt flag", stable(function (d) {
        return timeRange(d.getUTCHours(), "GMT") === true;
    }));
    check("invalid", timeRange(99) === false && timeRange("x") === false
        && timeRange(1, 2, 3) === false && timeRange() === false);
    "#,
    );
}
