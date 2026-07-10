/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The PAC guest: QuickJS-NG (through the Javy crate) compiled to
//! wasm32-wasip1 and driven by `src/pac/engine_wasmtime/` in the parent crate.
//!
//! The JavaScript surface mirrors the native backend exactly: the same
//! `pac_helpers.js` / `pac_helpers_ms.js` sources are installed (pulled in
//! with `include_str!` from the parent crate, so they cannot drift), and the
//! host-backed builtins (`dnsResolve`, `dnsResolveEx`, `myIpAddress`,
//! `myIpAddressEx`, `alert`) call back into the host process through the
//! `pac_host` imports, where the same `HostState` methods as the native
//! engine's FFI trampolines serve them.
//!
//! See `src/pac/wasm_abi.rs` (included below) for the ABI contract.

use std::cell::RefCell;

use javy::quickjs::convert::Coerced;
use javy::quickjs::{Ctx, Error as JsError, FromJs, Function, Value};
use javy::{Config, Runtime};

// Single source of truth for the ABI, shared with the host backends
// (Wasmtime and wasm2c).
mod abi {
    #![allow(dead_code)]
    include!("../../src/pac/wasm_abi.rs");
}
use abi::*;

const HELPERS_JS: &str = include_str!("../../src/pac/engine/pac_helpers.js");
const HELPERS_MS_JS: &str = include_str!("../../src/pac/engine/pac_helpers_ms.js");

/// Bridges the raw `__pac_*` natives to the standard PAC globals with exact
/// native-backend semantics: argument coercion failures and missing arguments
/// degrade to `null`/`""` instead of throwing, `dnsResolve` returns `null`
/// (not `undefined`) for "no address", and `alert` joins all its arguments.
const GLUE_JS: &str = r#"
(function (global) {
    "use strict";
    var rawAlert = global.__pac_alert;
    var rawDns = global.__pac_dns_resolve;
    var rawDnsEx = global.__pac_dns_resolve_ex;
    var rawMyIp = global.__pac_my_ip;
    var rawMyIpEx = global.__pac_my_ip_ex;
    delete global.__pac_alert;
    delete global.__pac_dns_resolve;
    delete global.__pac_dns_resolve_ex;
    delete global.__pac_my_ip;
    delete global.__pac_my_ip_ex;
    function toStr(v) { try { return String(v); } catch (e) { return "<unprintable>"; } }
    global.alert = function () {
        var parts = [];
        for (var i = 0; i < arguments.length; i++) parts.push(toStr(arguments[i]));
        rawAlert(parts.join(" "));
    };
    global.dnsResolve = function (host) {
        if (arguments.length === 0) return null;
        var h; try { h = String(host); } catch (e) { return null; }
        var r = rawDns(h);
        return r === undefined || r === null ? null : r;
    };
    global.dnsResolveEx = function (host) {
        if (arguments.length === 0) return "";
        var h; try { h = String(host); } catch (e) { return ""; }
        return rawDnsEx(h);
    };
    global.myIpAddress = function () { return rawMyIp(); };
    global.myIpAddressEx = function () { return rawMyIpEx(); };
})(globalThis);
"#;

/// Same limit as the native backend's `DEFAULT_MEMORY_LIMIT`; the host adds a
/// Wasmtime linear-memory cap on top.
const MEMORY_LIMIT: usize = 64 * 1024 * 1024;

#[link(wasm_import_module = "pac_host")]
extern "C" {
    fn host_dns_resolve(ptr: *const u8, len: usize) -> i32;
    fn host_dns_resolve_ex(ptr: *const u8, len: usize) -> i32;
    fn host_my_ip() -> i32;
    fn host_my_ip_ex() -> i32;
    fn host_take_result(dest: *mut u8);
    fn host_alert(ptr: *const u8, len: usize);
    /// Polled from the QuickJS interrupt handler while JS executes; nonzero
    /// aborts execution and the call reports [`STATUS_TIMEOUT`]. This is the
    /// only timeout mechanism available to hosts without instruction-level
    /// interruption (wasm2c); Wasmtime keeps epoch interruption as a backstop
    /// on top.
    fn host_should_interrupt() -> i32;
}

/// Fetches a host-staged result announced as `len` (see `abi::RESULT_NONE`).
fn take_host_string(len: i32) -> Option<String> {
    if len < 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    if len > 0 {
        // SAFETY: the host writes exactly `len` bytes into `buf`.
        unsafe { host_take_result(buf.as_mut_ptr()) };
    }
    Some(String::from_utf8_lossy(&buf).into_owned())
}

thread_local! {
    /// The JS runtime with the helpers and the current PAC script loaded.
    /// (wasm32-wasip1 is single-threaded; thread_local is just the sanctioned
    /// way to hold non-Sync globals.)
    static ENGINE: RefCell<Option<Runtime>> = const { RefCell::new(None) };
    /// Backing storage for the (ptr, len) result returned to the host; valid
    /// until the next exported call.
    static RESULT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    /// Set by the interrupt handler when it aborts execution, so the deadline
    /// abort can be told apart from a script exception (mirrors the native
    /// backend's `HostState::interrupted`).
    static INTERRUPTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// QuickJS interrupt callback (installed once per runtime): polls the host
/// deadline. Registered through the raw `qjs` bindings because Javy's
/// [`Runtime`] does not expose the inner [`javy::quickjs::Runtime`].
unsafe extern "C" fn interrupt_handler(
    _rt: *mut javy::quickjs::qjs::JSRuntime,
    _opaque: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    // SAFETY: plain host import with no arguments.
    if unsafe { host_should_interrupt() } != 0 {
        INTERRUPTED.with(|i| i.set(true));
        1
    } else {
        0
    }
}

/// Stores `status` + `payload` in the result buffer and packs its address.
fn pack(status: u8, payload: &str) -> u64 {
    RESULT.with(|r| {
        let mut buf = r.borrow_mut();
        buf.clear();
        buf.reserve(payload.len() + 1);
        buf.push(status);
        buf.extend_from_slice(payload.as_bytes());
        ((buf.as_ptr() as u32 as u64) << 32) | buf.len() as u32 as u64
    })
}

/// Allocates `len` bytes of guest memory for the host to write into.
///
/// # Safety
/// The host must pair every allocation with `pac_free(ptr, len)`.
#[no_mangle]
pub extern "C" fn pac_alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf);
    ptr
}

/// Releases a `pac_alloc` allocation.
///
/// # Safety
/// `ptr`/`len` must come from a single prior `pac_alloc(len)` call.
#[no_mangle]
pub unsafe extern "C" fn pac_free(ptr: *mut u8, len: usize) {
    // SAFETY: per the function contract.
    unsafe { drop(Vec::from_raw_parts(ptr, 0, len.max(1))) };
}

/// (Re)creates the runtime and loads a PAC script. Returns a packed status
/// result (`STATUS_OK` with an empty payload on success).
///
/// # Safety
/// `ptr`/`len` must describe a live guest buffer (from `pac_alloc`).
#[no_mangle]
pub unsafe extern "C" fn pac_load(ptr: *const u8, len: usize) -> u64 {
    // SAFETY: per the function contract.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let script = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return pack(STATUS_INTERNAL, "PAC script is not valid UTF-8"),
    };
    // The native backend feeds QuickJS a C string, so a NUL byte is a load
    // error there; mirror that instead of silently accepting it.
    if script.contains('\0') {
        return pack(STATUS_SCRIPT_SYNTAX, "script contains a NUL byte");
    }
    let (status, payload) = load_impl(script);
    pack(status, &payload)
}

/// Evaluates `FindProxyForURLEx(url, host)`, falling back to
/// `FindProxyForURL` when the script does not define the Ex entry point
/// (mirroring `PacEngine::find_proxy_ex`).
///
/// # Safety
/// Both pointers must describe live guest buffers (from `pac_alloc`).
#[no_mangle]
pub unsafe extern "C" fn pac_find_proxy(
    url_ptr: *const u8,
    url_len: usize,
    host_ptr: *const u8,
    host_len: usize,
) -> u64 {
    // SAFETY: per the function contract.
    let (url, host) = unsafe {
        (
            String::from_utf8_lossy(std::slice::from_raw_parts(url_ptr, url_len)),
            String::from_utf8_lossy(std::slice::from_raw_parts(host_ptr, host_len)),
        )
    };
    let (status, payload) = find_proxy_impl(&url, &host);
    pack(status, &payload)
}

fn load_impl(script: &str) -> (u8, String) {
    INTERRUPTED.with(|i| i.set(false));
    // A new script gets a pristine runtime, exactly like the native worker
    // (which rebuilds its PacEngine per load) — no stale globals survive.
    let runtime = match build_runtime() {
        Ok(rt) => rt,
        Err(msg) => return (STATUS_INTERNAL, msg),
    };
    let outcome = runtime
        .context()
        .with(|ctx| match ctx.eval::<Value, _>(script.as_bytes()) {
            Ok(_) => (STATUS_OK, String::new()),
            Err(e) => error_from_js(&ctx, e, true),
        });
    if outcome.0 == STATUS_OK {
        ENGINE.with(|e| *e.borrow_mut() = Some(runtime));
    }
    outcome
}

fn find_proxy_impl(url: &str, host: &str) -> (u8, String) {
    INTERRUPTED.with(|i| i.set(false));
    ENGINE.with(|e| {
        let engine = e.borrow();
        let Some(runtime) = engine.as_ref() else {
            return (STATUS_INTERNAL, "no PAC script loaded".to_string());
        };
        runtime.context().with(|ctx| {
            let globals = ctx.globals();
            let name = if globals
                .get::<_, Value>("FindProxyForURLEx")
                .is_ok_and(|v| v.is_function())
            {
                "FindProxyForURLEx"
            } else {
                "FindProxyForURL"
            };
            let func = match globals.get::<_, Value>(name) {
                Ok(v) if v.is_function() => v.into_function().expect("checked is_function"),
                _ => return (STATUS_FUNCTION_MISSING, name.to_string()),
            };
            match func.call::<_, Value>((url, host)) {
                Ok(ret) => match ret.into_string() {
                    Some(s) => match s.to_string() {
                        Ok(s) => (STATUS_OK, s),
                        Err(_) => (STATUS_INTERNAL, "failed to read result string".to_string()),
                    },
                    None => (STATUS_RETURNED_NON_STRING, name.to_string()),
                },
                Err(e) => error_from_js(&ctx, e, false),
            }
        })
    })
}

/// Creates a runtime with the QuickJS memory limit, the host-backed natives
/// and the PAC helper library installed — the wasm counterpart of
/// `PacEngine::new`.
fn build_runtime() -> Result<Runtime, String> {
    let mut config = Config::default();
    config.memory_limit(MEMORY_LIMIT);
    let runtime =
        Runtime::new(config).map_err(|e| format!("failed to create QuickJS runtime: {e}"))?;
    runtime
        .context()
        .with(|ctx| -> Result<(), String> {
            // SAFETY: the context (and its runtime) is live for the duration
            // of the call; the handler is a plain function with no state.
            unsafe {
                javy::quickjs::qjs::JS_SetInterruptHandler(
                    javy::quickjs::qjs::JS_GetRuntime(ctx.as_raw().as_ptr()),
                    Some(interrupt_handler),
                    std::ptr::null_mut(),
                );
            }
            register_natives(&ctx).map_err(|e| js_error_text(&ctx, e))?;
            let install = |source: &str, what: &str| {
                ctx.eval::<Value, _>(source.as_bytes())
                    .map(|_| ())
                    .map_err(|e| format!("failed to install {what}: {}", js_error_text(&ctx, e)))
            };
            install(GLUE_JS, "PAC host glue")?;
            install(HELPERS_JS, "PAC helper library")?;
            install(HELPERS_MS_JS, "PAC helper library (MS extensions)")?;
            Ok(())
        })
        .map_err(|e| format!("failed to install PAC helper library: {e}"))?;
    Ok(runtime)
}

/// Installs the raw `__pac_*` natives; `GLUE_JS` wraps them into the standard
/// PAC globals and removes the raw names again.
fn register_natives(ctx: &Ctx<'_>) -> Result<(), JsError> {
    let globals = ctx.globals();
    globals.set(
        "__pac_alert",
        Function::new(ctx.clone(), |msg: String| {
            // SAFETY: passes a live (ptr, len) pair; the host copies the bytes.
            unsafe { host_alert(msg.as_ptr(), msg.len()) };
        })?,
    )?;
    globals.set(
        "__pac_dns_resolve",
        Function::new(ctx.clone(), |host: String| -> Option<String> {
            // SAFETY: live (ptr, len) pair; result fetched right after.
            take_host_string(unsafe { host_dns_resolve(host.as_ptr(), host.len()) })
        })?,
    )?;
    globals.set(
        "__pac_dns_resolve_ex",
        Function::new(ctx.clone(), |host: String| -> String {
            // SAFETY: live (ptr, len) pair; result fetched right after.
            take_host_string(unsafe { host_dns_resolve_ex(host.as_ptr(), host.len()) })
                .unwrap_or_default()
        })?,
    )?;
    globals.set(
        "__pac_my_ip",
        Function::new(ctx.clone(), || -> String {
            // SAFETY: no arguments; result fetched right after.
            take_host_string(unsafe { host_my_ip() }).unwrap_or_default()
        })?,
    )?;
    globals.set(
        "__pac_my_ip_ex",
        Function::new(ctx.clone(), || -> String {
            // SAFETY: no arguments; result fetched right after.
            take_host_string(unsafe { host_my_ip_ex() }).unwrap_or_default()
        })?,
    )?;
    Ok(())
}

/// Maps a JS error to a `(STATUS_*, message)` pair, mirroring the native
/// backend's `error_from_exception` (message plus stack when available,
/// `SyntaxError` classified separately during load).
fn error_from_js(ctx: &Ctx<'_>, error: JsError, classify_syntax: bool) -> (u8, String) {
    // A deadline abort surfaces as an (uncatchable) exception; report it as a
    // timeout instead, mirroring the native backend's `error_from_exception`.
    if INTERRUPTED.with(|i| i.get()) {
        let _ = ctx.catch(); // drain the pending exception
        return (STATUS_TIMEOUT, String::new());
    }
    if !matches!(error, JsError::Exception) {
        return (STATUS_INTERNAL, error.to_string());
    }
    let exception = ctx.catch();
    let name = string_property(&exception, "name");
    let mut text = Coerced::<String>::from_js(ctx, exception.clone())
        .map(|c| c.0)
        .unwrap_or_else(|_| "unknown JavaScript exception".to_string());
    if let Some(stack) = string_property(&exception, "stack") {
        let stack = stack.trim_end();
        if !stack.is_empty() {
            text.push('\n');
            text.push_str(stack);
        }
    }
    if classify_syntax && name.as_deref() == Some("SyntaxError") {
        (STATUS_SCRIPT_SYNTAX, text)
    } else {
        (STATUS_JS_EXCEPTION, text)
    }
}

/// Reads a string-valued property of an object; `None` for anything else.
fn string_property(value: &Value<'_>, name: &str) -> Option<String> {
    let obj = value.as_object()?;
    let prop = obj.get::<_, Value>(name).ok()?;
    prop.into_string()?.to_string().ok()
}

/// Formats a JS error (draining any pending exception) for embedding in an
/// internal error message.
fn js_error_text(ctx: &Ctx<'_>, error: JsError) -> String {
    error_from_js(ctx, error, false).1
}
