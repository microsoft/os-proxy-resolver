/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// The host <-> guest ABI shared between the Wasmtime PAC backend and the
// `pac-wasm-guest` crate (which pulls this file in with `include!` so the two
// sides can never drift apart).
//
// # Calling convention
//
// Strings cross the boundary as (ptr, len) pairs in guest linear memory,
// always UTF-8.
//
// Guest exports:
// * `pac_alloc(len) -> ptr` / `pac_free(ptr, len)` — buffers the host writes
//   arguments into.
// * `pac_load(ptr, len) -> packed` — (re)creates the JS runtime, installs the
//   PAC helper library and evaluates the PAC script.
// * `pac_find_proxy(url_ptr, url_len, host_ptr, host_len) -> packed` — calls
//   `FindProxyForURLEx`, falling back to `FindProxyForURL`.
//
// `packed` is `(result_ptr << 32) | result_len`, pointing at a guest-owned
// buffer that stays valid until the next `pac_load`/`pac_find_proxy` call.
// Its first byte is one of the `STATUS_*` codes below; the rest is the PAC
// result string (`STATUS_OK`) or an error message.
//
// Host imports (module `pac_host`): `host_dns_resolve` / `host_dns_resolve_ex`
// / `host_my_ip` / `host_my_ip_ex` return the byte length of a result the
// host stages on its side (`RESULT_NONE` for "no result"); the guest then
// allocates a buffer and fetches the bytes with `host_take_result`.
// `host_alert` forwards one log message. These five functions are the guest's
// *only* reach into the host — no WASI capability is granted (the handful of
// WASI imports wasi-libc needs are host-side stubs: an empty environment, a
// clock and a non-cryptographic RNG).

/// Import module name for the host-provided PAC callbacks.
pub const HOST_MODULE: &str = "pac_host";

/// First byte of every guest result: success, payload is the PAC result.
pub const STATUS_OK: u8 = 0;
/// The PAC script failed to parse; payload is the SyntaxError message.
pub const STATUS_SCRIPT_SYNTAX: u8 = 1;
/// Entry point not defined; payload is the function name.
pub const STATUS_FUNCTION_MISSING: u8 = 2;
/// Script threw; payload is the message (plus stack when available).
pub const STATUS_JS_EXCEPTION: u8 = 3;
/// Entry point returned a non-string; payload is the function name.
pub const STATUS_RETURNED_NON_STRING: u8 = 4;
/// Engine-level failure; payload is the message.
pub const STATUS_INTERNAL: u8 = 5;

/// Returned by the staging host imports when there is no result (JS `null`).
pub const RESULT_NONE: i32 = -1;
