/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/*
 * Microsoft IPv6 PAC extension helper functions.
 *
 * Implemented from Microsoft's published documentation of the IPv6-aware
 * proxy-auto-configuration extensions (the "*Ex" helper family) only.
 * No code from any other PAC implementation was used or consulted.
 *
 * The native functions dnsResolveEx() and myIpAddressEx() are provided by
 * the embedding Rust crate before this file is evaluated.
 *
 * SPDX-License-Identifier: MIT
 */
(function (global) {
    "use strict";

    function toStr(v) {
        return typeof v === "string" ? v : String(v);
    }

    /* Strict dotted-quad IPv4 parser; returns [a, b, c, d] or null. */
    function parseIPv4Bytes(s) {
        var parts = s.split(".");
        if (parts.length !== 4) {
            return null;
        }
        var bytes = [];
        for (var i = 0; i < 4; i++) {
            if (!/^\d{1,3}$/.test(parts[i])) {
                return null;
            }
            var octet = parseInt(parts[i], 10);
            if (octet > 255) {
                return null;
            }
            bytes.push(octet);
        }
        return bytes;
    }

    /*
     * RFC 4291 textual IPv6 parser supporting "::" compression and an
     * embedded dotted-quad IPv4 tail; returns 16 bytes or null. A zone
     * suffix ("%eth0") is ignored.
     */
    function parseIPv6Bytes(s) {
        if (s.indexOf(":") === -1) {
            return null;
        }
        var zone = s.indexOf("%");
        if (zone !== -1) {
            s = s.substring(0, zone);
        }
        var dbl = s.indexOf("::");
        if (dbl !== -1 && s.indexOf("::", dbl + 1) !== -1) {
            return null;
        }

        /* Parses a colon-separated run into 16-bit groups. */
        function groupsOf(part, v4Allowed) {
            if (part === "") {
                return [];
            }
            var items = part.split(":");
            var groups = [];
            for (var i = 0; i < items.length; i++) {
                var g = items[i];
                if (g.indexOf(".") !== -1) {
                    if (!v4Allowed || i !== items.length - 1) {
                        return null;
                    }
                    var v4 = parseIPv4Bytes(g);
                    if (v4 === null) {
                        return null;
                    }
                    groups.push(v4[0] * 256 + v4[1], v4[2] * 256 + v4[3]);
                } else {
                    if (!/^[0-9A-Fa-f]{1,4}$/.test(g)) {
                        return null;
                    }
                    groups.push(parseInt(g, 16));
                }
            }
            return groups;
        }

        var groups;
        if (dbl !== -1) {
            var head = groupsOf(s.substring(0, dbl), false);
            var tail = groupsOf(s.substring(dbl + 2), true);
            if (head === null || tail === null || head.length + tail.length > 7) {
                return null;
            }
            var zeros = new Array(8 - head.length - tail.length).fill(0);
            groups = head.concat(zeros, tail);
        } else {
            groups = groupsOf(s, true);
            if (groups === null || groups.length !== 8) {
                return null;
            }
        }
        var bytes = [];
        for (var i = 0; i < 8; i++) {
            bytes.push(groups[i] >> 8, groups[i] & 0xff);
        }
        return bytes;
    }

    /* Parses either address family: { family: 4|6, bytes: [...] } or null. */
    function parseAddress(s) {
        var v4 = parseIPv4Bytes(s);
        if (v4 !== null) {
            return { family: 4, bytes: v4 };
        }
        var v6 = parseIPv6Bytes(s);
        if (v6 !== null) {
            return { family: 6, bytes: v6 };
        }
        return null;
    }

    /* True when the first `bits` bits of the two byte arrays are equal. */
    function prefixMatch(a, b, bits) {
        var fullBytes = bits >> 3;
        for (var i = 0; i < fullBytes; i++) {
            if (a[i] !== b[i]) {
                return false;
            }
        }
        var remainder = bits & 7;
        if (remainder === 0) {
            return true;
        }
        var mask = (0xff00 >> remainder) & 0xff;
        return (a[fullBytes] & mask) === (b[fullBytes] & mask);
    }

    /*
     * isInNetEx(ipAddress, ipPrefix): true when the IPv4 or IPv6 address
     * falls inside the CIDR prefix ("198.51.100.0/24", "2001:db8::/32").
     * A `;`-separated list of prefixes is accepted; any match wins. A
     * prefix without "/length" is compared in full.
     */
    global.isInNetEx = function (ipAddress, ipPrefix) {
        var addr = parseAddress(toStr(ipAddress));
        if (addr === null) {
            return false;
        }
        var ranges = toStr(ipPrefix).split(";");
        for (var i = 0; i < ranges.length; i++) {
            var range = ranges[i].trim();
            if (range === "") {
                continue;
            }
            var slash = range.indexOf("/");
            var net = parseAddress(
                slash === -1 ? range : range.substring(0, slash)
            );
            if (net === null || net.family !== addr.family) {
                continue;
            }
            var maxBits = net.family === 4 ? 32 : 128;
            var bits = maxBits;
            if (slash !== -1) {
                var lenStr = range.substring(slash + 1);
                if (!/^\d+$/.test(lenStr)) {
                    continue;
                }
                bits = parseInt(lenStr, 10);
                if (bits > maxBits) {
                    continue;
                }
            }
            if (prefixMatch(addr.bytes, net.bytes, bits)) {
                return true;
            }
        }
        return false;
    };

    /* True when the host resolves to at least one IPv4 or IPv6 address. */
    global.isResolvableEx = function (host) {
        return dnsResolveEx(toStr(host)) !== "";
    };

    /*
     * sortIpAddressList(list): sorts a `;`-separated address list in
     * ascending order, IPv6 addresses before IPv4 addresses. Returns false
     * when the list is empty or contains an unparsable address.
     */
    global.sortIpAddressList = function (list) {
        var items = toStr(list).split(";");
        var parsed = [];
        for (var i = 0; i < items.length; i++) {
            var item = items[i].trim();
            if (item === "") {
                return false;
            }
            var addr = parseAddress(item);
            if (addr === null) {
                return false;
            }
            parsed.push({ text: item, addr: addr });
        }
        if (parsed.length === 0) {
            return false;
        }
        parsed.sort(function (x, y) {
            if (x.addr.family !== y.addr.family) {
                return x.addr.family === 6 ? -1 : 1;
            }
            for (var i = 0; i < x.addr.bytes.length; i++) {
                if (x.addr.bytes[i] !== y.addr.bytes[i]) {
                    return x.addr.bytes[i] - y.addr.bytes[i];
                }
            }
            return 0;
        });
        return parsed
            .map(function (x) { return x.text; })
            .join(";");
    };

    /* Version of the PAC extension interface implemented here. */
    global.getClientVersion = function () {
        return "1.0";
    };
})(globalThis);
