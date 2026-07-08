/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/*
 * Built-in PAC (Proxy Auto-Config) helper functions.
 *
 * These helpers are implemented from the public PAC specification only:
 * the Netscape "Navigator Proxy Auto-Config File Format" document (1996).
 * No code from any other PAC implementation was used or consulted.
 *
 * The native functions dnsResolve(), myIpAddress() and alert() are provided
 * by the embedding Rust crate before this file is evaluated.
 *
 * SPDX-License-Identifier: MIT
 */
(function (global) {
    "use strict";

    function toStr(v) {
        return typeof v === "string" ? v : String(v);
    }

    /* Strict dotted-quad IPv4 parser; returns a number in [0, 2^32) or null. */
    function parseIPv4(s) {
        var parts = s.split(".");
        if (parts.length !== 4) {
            return null;
        }
        var n = 0;
        for (var i = 0; i < 4; i++) {
            if (!/^\d{1,3}$/.test(parts[i])) {
                return null;
            }
            var octet = parseInt(parts[i], 10);
            if (octet > 255) {
                return null;
            }
            n = n * 256 + octet;
        }
        return n;
    }

    /* True when there is no domain part (no dots) in the host name. */
    global.isPlainHostName = function (host) {
        return toStr(host).indexOf(".") === -1;
    };

    /* True when the host name ends in the given domain suffix. */
    global.dnsDomainIs = function (host, domain) {
        host = toStr(host);
        domain = toStr(domain);
        return (
            domain.length <= host.length &&
            host.substring(host.length - domain.length) === domain
        );
    };

    /*
     * True when the host matches exactly, or when the host is unqualified
     * (no domain part) and matches the host part of the fully qualified name.
     */
    global.localHostOrDomainIs = function (host, hostdom) {
        host = toStr(host);
        hostdom = toStr(hostdom);
        if (host === hostdom) {
            return true;
        }
        if (host.indexOf(".") !== -1) {
            return false;
        }
        var dot = hostdom.indexOf(".");
        return host === (dot === -1 ? hostdom : hostdom.substring(0, dot));
    };

    /* True when the host name can be resolved to an IPv4 address. */
    global.isResolvable = function (host) {
        return dnsResolve(toStr(host)) !== null;
    };

    /*
     * True when the host (an IP address or a resolvable host name) belongs
     * to the given IPv4 network, i.e. (host & mask) == (pattern & mask).
     */
    global.isInNet = function (host, pattern, mask) {
        var pat = parseIPv4(toStr(pattern));
        var msk = parseIPv4(toStr(mask));
        if (pat === null || msk === null) {
            return false;
        }
        var hostStr = toStr(host);
        var ip = parseIPv4(hostStr);
        if (ip === null) {
            var resolved = dnsResolve(hostStr);
            if (resolved === null) {
                return false;
            }
            ip = parseIPv4(resolved);
            if (ip === null) {
                return false;
            }
        }
        return ((ip & msk) >>> 0) === ((pat & msk) >>> 0);
    };

    /* Number of DNS domain levels (number of dots) in the host name. */
    global.dnsDomainLevels = function (host) {
        var m = toStr(host).match(/\./g);
        return m === null ? 0 : m.length;
    };

    /*
     * Shell-glob match anchored to the whole string. "*" matches any
     * sequence, "?" matches any single character, and "[...]" is a shell
     * character class (with "[!...]" / "[^...]" negation and ranges such as
     * "[0-9]"); every other character, including regular-expression
     * metacharacters such as ".", is literal.
     */
    global.shExpMatch = function (str, shexp) {
        str = toStr(str);
        shexp = toStr(shexp);
        var re = "";
        var i = 0;
        var n = shexp.length;
        while (i < n) {
            var c = shexp.charAt(i);
            if (c === "*") {
                re += ".*";
                i++;
            } else if (c === "?") {
                re += ".";
                i++;
            } else if (c === "[") {
                var j = i + 1;
                var negate = false;
                if (j < n && (shexp.charAt(j) === "!" || shexp.charAt(j) === "^")) {
                    negate = true;
                    j++;
                }
                var start = j;
                /* A "]" right after "[" (or "[!") is a literal member. */
                if (j < n && shexp.charAt(j) === "]") {
                    j++;
                }
                while (j < n && shexp.charAt(j) !== "]") {
                    j++;
                }
                if (j >= n) {
                    /* No closing bracket: treat "[" as a literal character. */
                    re += "\\[";
                    i++;
                } else {
                    /* Escape "\" and "]" so the class body is safe in a JS
                       regex; ranges and other members pass through. */
                    var body = shexp
                        .substring(start, j)
                        .replace(/[\\\]]/g, "\\$&");
                    re += "[" + (negate ? "^" : "") + body + "]";
                    i = j + 1;
                }
            } else if (/[.+^${}()|\\]/.test(c)) {
                re += "\\" + c;
                i++;
            } else {
                re += c;
                i++;
            }
        }
        try {
            return new RegExp("^" + re + "$").test(str);
        } catch (e) {
            return false;
        }
    };

    var WEEKDAYS = { SUN: 0, MON: 1, TUE: 2, WED: 3, THU: 4, FRI: 5, SAT: 6 };
    var MONTHS = {
        JAN: 0, FEB: 1, MAR: 2, APR: 3, MAY: 4, JUN: 5,
        JUL: 6, AUG: 7, SEP: 8, OCT: 9, NOV: 10, DEC: 11
    };

    /* Removes a trailing "GMT" argument; returns whether it was present. */
    function stripGmt(args) {
        if (args.length > 0 && args[args.length - 1] === "GMT") {
            args.pop();
            return true;
        }
        return false;
    }

    /* Inclusive range test that wraps around (e.g. FRI..MON). */
    function inWrappedRange(value, lo, hi) {
        return lo <= hi ? value >= lo && value <= hi : value >= lo || value <= hi;
    }

    /*
     * weekdayRange(wd1 [, wd2] [, "GMT"]): true when the current weekday is
     * wd1, or falls in the inclusive range wd1..wd2 (wrapping past SAT).
     */
    global.weekdayRange = function () {
        var args = Array.prototype.slice.call(arguments);
        var gmt = stripGmt(args);
        if (args.length < 1 || args.length > 2) {
            return false;
        }
        var now = new Date();
        var weekday = gmt ? now.getUTCDay() : now.getDay();
        var wd1 = WEEKDAYS[toStr(args[0]).toUpperCase()];
        if (wd1 === undefined) {
            return false;
        }
        if (args.length === 1) {
            return weekday === wd1;
        }
        var wd2 = WEEKDAYS[toStr(args[1]).toUpperCase()];
        if (wd2 === undefined) {
            return false;
        }
        return inWrappedRange(weekday, wd1, wd2);
    };

    /*
     * Classifies a dateRange() argument as a day of month (1-31), a month
     * name (JAN..DEC) or a four-digit year. Returns null for anything else.
     */
    function dateArg(a) {
        if (typeof a === "string") {
            var month = MONTHS[a.toUpperCase()];
            if (month !== undefined) {
                return { kind: "m", value: month };
            }
            if (!/^\d+$/.test(a)) {
                return null;
            }
            a = parseInt(a, 10);
        }
        if (typeof a !== "number" || !isFinite(a) || Math.floor(a) !== a) {
            return null;
        }
        if (a >= 1 && a <= 31) {
            return { kind: "d", value: a };
        }
        if (a >= 1000 && a <= 9999) {
            return { kind: "y", value: a };
        }
        return null;
    }

    /*
     * dateRange(...) with the full argument-count overloading of the spec:
     *   day | month | year
     *   day1, day2 | month1, month2 | year1, year2
     *   day1, month1, day2, month2 | month1, year1, month2, year2
     *   day1, month1, year1, day2, month2, year2
     * each optionally followed by "GMT". Day and month ranges wrap; ranges
     * that include a year are absolute. All bounds are inclusive.
     */
    global.dateRange = function () {
        var args = Array.prototype.slice.call(arguments);
        var gmt = stripGmt(args);
        var parsed = [];
        for (var i = 0; i < args.length; i++) {
            var p = dateArg(args[i]);
            if (p === null) {
                return false;
            }
            parsed.push(p);
        }
        var kinds = parsed
            .map(function (x) { return x.kind; })
            .join("");
        var v = parsed.map(function (x) { return x.value; });
        var now = new Date();
        var year = gmt ? now.getUTCFullYear() : now.getFullYear();
        var month = gmt ? now.getUTCMonth() : now.getMonth();
        var day = gmt ? now.getUTCDate() : now.getDate();
        switch (kinds) {
            case "d":
                return day === v[0];
            case "m":
                return month === v[0];
            case "y":
                return year === v[0];
            case "dd":
                return inWrappedRange(day, v[0], v[1]);
            case "mm":
                return inWrappedRange(month, v[0], v[1]);
            case "yy":
                return year >= v[0] && year <= v[1];
            case "dmdm":
                return inWrappedRange(
                    month * 32 + day,
                    v[1] * 32 + v[0],
                    v[3] * 32 + v[2]
                );
            case "mymy":
                var cur = year * 12 + month;
                return cur >= v[1] * 12 + v[0] && cur <= v[3] * 12 + v[2];
            case "dmydmy":
                var today = (year * 12 + month) * 32 + day;
                var lo = (v[2] * 12 + v[1]) * 32 + v[0];
                var hi = (v[5] * 12 + v[4]) * 32 + v[3];
                return today >= lo && today <= hi;
            default:
                return false;
        }
    };

    /*
     * timeRange(...) with the argument-count overloading of the spec:
     *   hour                          -- true during that hour
     *   hour1, hour2                  -- [hour1:00:00, hour2:00:00)
     *   hour1, min1, hour2, min2      -- [h1:m1:00, h2:m2:00)
     *   h1, m1, s1, h2, m2, s2        -- [h1:m1:s1, h2:m2:s2)
     * each optionally followed by "GMT". Ranges wrap past midnight when the
     * start is later than the end.
     */
    global.timeRange = function () {
        var args = Array.prototype.slice.call(arguments);
        var gmt = stripGmt(args);
        var nums = [];
        for (var i = 0; i < args.length; i++) {
            var n = typeof args[i] === "number" ? args[i] : Number(args[i]);
            if (!isFinite(n) || Math.floor(n) !== n || n < 0) {
                return false;
            }
            nums.push(n);
        }
        var valid = function (hour, min, sec) {
            return hour <= 24 && min <= 59 && sec <= 59;
        };
        var now = new Date();
        var hour = gmt ? now.getUTCHours() : now.getHours();
        var min = gmt ? now.getUTCMinutes() : now.getMinutes();
        var sec = gmt ? now.getUTCSeconds() : now.getSeconds();
        var cur = hour * 3600 + min * 60 + sec;
        var lo, hi;
        switch (nums.length) {
            case 1:
                return valid(nums[0], 0, 0) && hour === nums[0];
            case 2:
                if (!valid(nums[0], 0, 0) || !valid(nums[1], 0, 0)) {
                    return false;
                }
                lo = nums[0] * 3600;
                hi = nums[1] * 3600;
                break;
            case 4:
                if (!valid(nums[0], nums[1], 0) || !valid(nums[2], nums[3], 0)) {
                    return false;
                }
                lo = nums[0] * 3600 + nums[1] * 60;
                hi = nums[2] * 3600 + nums[3] * 60;
                break;
            case 6:
                if (
                    !valid(nums[0], nums[1], nums[2]) ||
                    !valid(nums[3], nums[4], nums[5])
                ) {
                    return false;
                }
                lo = nums[0] * 3600 + nums[1] * 60 + nums[2];
                hi = nums[3] * 3600 + nums[4] * 60 + nums[5];
                break;
            default:
                return false;
        }
        if (lo === hi) {
            return cur === lo;
        }
        return lo < hi ? cur >= lo && cur < hi : cur >= lo || cur < hi;
    };

    /* console.log routes to the same sink as the native alert(). */
    global.console = { log: global.alert };
})(globalThis);
