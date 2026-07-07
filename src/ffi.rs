/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Private FFI layer over the QuickJS-NG C API (linked via the MIT-licensed
//! `rquickjs-sys` crate, which vendors and compiles the MIT-licensed
//! quickjs-ng sources).
//!
//! All `unsafe` code in this crate is confined to this module; everything it
//! exposes to the rest of the crate is a safe method on [`Context`].

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::time::Instant;

use rquickjs_sys as q;

use crate::Error;
use crate::state::HostState;

/// Signature of a native function callable from JavaScript.
type NativeFn =
    unsafe extern "C" fn(*mut q::JSContext, q::JSValue, c_int, *mut q::JSValue) -> q::JSValue;

/// One QuickJS runtime + context pair with the host state wired up as the
/// context/interrupt opaque.
///
/// Contains raw pointers, so it is automatically `!Send` and `!Sync`; this is
/// intentional (a QuickJS context must stay on one thread).
pub(crate) struct Context {
    rt: *mut q::JSRuntime,
    ctx: *mut q::JSContext,
    /// Boxed so the pointers registered with QuickJS stay valid for the
    /// lifetime of the runtime, wherever the `Context` itself moves.
    state: Box<HostState>,
}

impl Context {
    pub(crate) fn new(state: Box<HostState>, memory_limit: usize) -> Result<Self, Error> {
        // SAFETY: runtime and context are created, checked for null and freed
        // in `Drop`. The opaque pointer handed to QuickJS points into the
        // boxed `HostState`, which outlives the runtime (it is dropped after
        // `Drop::drop` runs `JS_FreeRuntime`).
        unsafe {
            let rt = q::JS_NewRuntime();
            if rt.is_null() {
                return Err(Error::Internal("failed to create QuickJS runtime".into()));
            }
            let ctx = q::JS_NewContext(rt);
            if ctx.is_null() {
                q::JS_FreeRuntime(rt);
                return Err(Error::Internal("failed to create QuickJS context".into()));
            }
            let this = Context { rt, ctx, state };
            this.set_memory_limit(memory_limit);
            let opaque = std::ptr::from_ref::<HostState>(&this.state)
                .cast_mut()
                .cast::<c_void>();
            q::JS_SetContextOpaque(ctx, opaque);
            q::JS_SetInterruptHandler(rt, Some(interrupt_handler), opaque);
            this.register_natives()?;
            Ok(this)
        }
    }

    pub(crate) fn state(&self) -> &HostState {
        &self.state
    }

    pub(crate) fn set_memory_limit(&self, bytes: usize) {
        // SAFETY: `self.rt` is a valid runtime for the lifetime of `self`.
        unsafe { q::JS_SetMemoryLimit(self.rt, bytes as q::size_t) }
    }

    /// Installs the native PAC helper functions on the global object.
    fn register_natives(&self) -> Result<(), Error> {
        self.register(c"alert", tramp_alert, 1)?;
        self.register(c"dnsResolve", tramp_dns_resolve, 1)?;
        self.register(c"myIpAddress", tramp_my_ip_address, 0)?;
        #[cfg(feature = "microsoft-extensions")]
        {
            self.register(c"dnsResolveEx", tramp_dns_resolve_ex, 1)?;
            self.register(c"myIpAddressEx", tramp_my_ip_address_ex, 0)?;
        }
        Ok(())
    }

    fn register(&self, name: &CStr, func: NativeFn, arity: c_int) -> Result<(), Error> {
        // SAFETY: `name` is a valid NUL-terminated string; the function value
        // returned by `JS_NewCFunction2` is either consumed by
        // `JS_SetPropertyStr` (which takes ownership even on failure) or is
        // the non-refcounted exception marker.
        unsafe {
            let value = q::JS_NewCFunction2(
                self.ctx,
                Some(func),
                name.as_ptr(),
                arity,
                q::JSCFunctionEnum_JS_CFUNC_generic,
                0,
            );
            if q::JS_IsException(value) {
                self.drain_exception();
                return Err(Error::Internal(format!(
                    "failed to create native function {}",
                    name.to_string_lossy()
                )));
            }
            let global = q::JS_GetGlobalObject(self.ctx);
            let rc = q::JS_SetPropertyStr(self.ctx, global, name.as_ptr(), value);
            q::JS_FreeValue(self.ctx, global);
            if rc < 0 {
                self.drain_exception();
                return Err(Error::Internal(format!(
                    "failed to register native function {}",
                    name.to_string_lossy()
                )));
            }
            Ok(())
        }
    }

    /// Evaluates a script in the global scope, subject to the configured
    /// deadline. `classify_syntax` maps `SyntaxError` to
    /// [`Error::ScriptSyntax`].
    pub(crate) fn eval(
        &self,
        script: &str,
        filename: &CStr,
        classify_syntax: bool,
    ) -> Result<(), Error> {
        let code = CString::new(script)
            .map_err(|_| Error::ScriptSyntax("script contains a NUL byte".into()))?;
        self.state.begin_call();
        // SAFETY: `code` is NUL-terminated and lives across the call; the
        // returned value is freed (the exception marker is not refcounted).
        let ret = unsafe {
            q::JS_Eval(
                self.ctx,
                code.as_ptr(),
                script.len() as q::size_t,
                filename.as_ptr(),
                q::JS_EVAL_TYPE_GLOBAL as c_int,
            )
        };
        self.state.end_call();
        // SAFETY: see above.
        unsafe {
            if q::JS_IsException(ret) {
                return Err(self.error_from_exception(classify_syntax));
            }
            q::JS_FreeValue(self.ctx, ret);
        }
        Ok(())
    }

    /// Returns whether a global with the given name exists and is callable.
    #[cfg(feature = "microsoft-extensions")]
    pub(crate) fn has_global_function(&self, name: &CStr) -> bool {
        // SAFETY: property lookup on the global object; all obtained values
        // are freed.
        unsafe {
            let global = q::JS_GetGlobalObject(self.ctx);
            let value = q::JS_GetPropertyStr(self.ctx, global, name.as_ptr());
            q::JS_FreeValue(self.ctx, global);
            if q::JS_IsException(value) {
                self.drain_exception();
                return false;
            }
            let is_function = q::JS_IsFunction(self.ctx, value);
            q::JS_FreeValue(self.ctx, value);
            is_function
        }
    }

    /// Calls the global PAC entry point `name(url, host)` and returns its
    /// string result.
    pub(crate) fn call_pac_function(
        &self,
        name: &CStr,
        url: &str,
        host: &str,
    ) -> Result<String, Error> {
        let missing = || Error::FunctionMissing(name.to_string_lossy().into_owned());
        // SAFETY: all values created here (function, argument strings, return
        // value) are freed on every path; the exception marker is not
        // refcounted and is never freed.
        unsafe {
            let global = q::JS_GetGlobalObject(self.ctx);
            let func = q::JS_GetPropertyStr(self.ctx, global, name.as_ptr());
            q::JS_FreeValue(self.ctx, global);
            if q::JS_IsException(func) {
                self.drain_exception();
                return Err(missing());
            }
            if !q::JS_IsFunction(self.ctx, func) {
                q::JS_FreeValue(self.ctx, func);
                return Err(missing());
            }

            let mut argv = [
                q::JS_NewStringLen(self.ctx, url.as_ptr().cast::<c_char>(), url.len() as _),
                q::JS_NewStringLen(self.ctx, host.as_ptr().cast::<c_char>(), host.len() as _),
            ];
            if argv.iter().any(|v| q::JS_IsException(*v)) {
                for v in argv {
                    if !q::JS_IsException(v) {
                        q::JS_FreeValue(self.ctx, v);
                    }
                }
                q::JS_FreeValue(self.ctx, func);
                self.drain_exception();
                return Err(Error::Internal(
                    "failed to allocate argument strings".into(),
                ));
            }

            self.state.begin_call();
            let ret = q::JS_Call(
                self.ctx,
                func,
                q::JS_UNDEFINED,
                argv.len() as c_int,
                argv.as_mut_ptr(),
            );
            self.state.end_call();
            for v in argv {
                q::JS_FreeValue(self.ctx, v);
            }
            q::JS_FreeValue(self.ctx, func);

            if q::JS_IsException(ret) {
                return Err(self.error_from_exception(false));
            }
            if !q::JS_IsString(ret) {
                q::JS_FreeValue(self.ctx, ret);
                return Err(Error::ReturnedNonString(
                    name.to_string_lossy().into_owned(),
                ));
            }
            let result = self.value_to_string(ret);
            q::JS_FreeValue(self.ctx, ret);
            result.ok_or_else(|| Error::Internal("failed to read result string".into()))
        }
    }

    /// Converts the pending exception into an [`Error`], preferring
    /// [`Error::Timeout`] when the interrupt handler fired.
    fn error_from_exception(&self, classify_syntax: bool) -> Error {
        if self.state.interrupted.get() {
            self.drain_exception();
            return Error::Timeout;
        }
        let (name, text) = self.take_exception();
        if classify_syntax && name.as_deref() == Some("SyntaxError") {
            Error::ScriptSyntax(text)
        } else {
            Error::JsException(text)
        }
    }

    /// Takes the pending exception, returning its `name` property (if any)
    /// and a human-readable message including the stack trace when available.
    fn take_exception(&self) -> (Option<String>, String) {
        // SAFETY: the exception value and every property value are freed.
        unsafe {
            let exc = q::JS_GetException(self.ctx);
            let name = self.get_string_property(exc, c"name");
            let mut text = self
                .value_to_string(exc)
                .unwrap_or_else(|| "unknown JavaScript exception".to_string());
            if let Some(stack) = self.get_string_property(exc, c"stack") {
                let stack = stack.trim_end();
                if !stack.is_empty() {
                    text.push('\n');
                    text.push_str(stack);
                }
            }
            q::JS_FreeValue(self.ctx, exc);
            (name, text)
        }
    }

    /// Reads a string-valued property of an object; `None` for anything else.
    fn get_string_property(&self, obj: q::JSValue, name: &CStr) -> Option<String> {
        // SAFETY: `obj` is a live value owned by the caller.
        unsafe {
            if !q::JS_IsObject(obj) {
                return None;
            }
            let value = q::JS_GetPropertyStr(self.ctx, obj, name.as_ptr());
            if q::JS_IsException(value) {
                self.drain_exception();
                return None;
            }
            if !q::JS_IsString(value) {
                q::JS_FreeValue(self.ctx, value);
                return None;
            }
            let s = self.value_to_string(value);
            q::JS_FreeValue(self.ctx, value);
            s
        }
    }

    /// Converts a value to a Rust `String` via its JS string conversion.
    /// Swallows any conversion exception and returns `None`.
    fn value_to_string(&self, value: q::JSValue) -> Option<String> {
        // SAFETY: `value` is live; the C string is copied and freed.
        unsafe { value_to_string_raw(self.ctx, value) }
    }

    /// Clears any pending exception, discarding it.
    fn drain_exception(&self) {
        // SAFETY: the exception value is owned by us and freed.
        unsafe {
            let exc = q::JS_GetException(self.ctx);
            q::JS_FreeValue(self.ctx, exc);
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: pointers were checked non-null at construction and are
        // freed exactly once. `self.state` is dropped afterwards, so the
        // opaque pointers never dangle while the runtime is alive.
        unsafe {
            q::JS_FreeContext(self.ctx);
            q::JS_FreeRuntime(self.rt);
        }
    }
}

/// # Safety
/// `ctx` must be a live context and `value` a live value belonging to it.
unsafe fn value_to_string_raw(ctx: *mut q::JSContext, value: q::JSValue) -> Option<String> {
    // SAFETY: per the function contract; the returned C string is freed.
    unsafe {
        let mut len: usize = 0;
        let ptr = q::JS_ToCStringLen(ctx, &mut len, value);
        if ptr.is_null() {
            drain_exception_raw(ctx);
            return None;
        }
        let bytes = std::slice::from_raw_parts(ptr.cast::<u8>(), len);
        let s = String::from_utf8_lossy(bytes).into_owned();
        q::JS_FreeCString(ctx, ptr);
        Some(s)
    }
}

/// # Safety
/// `ctx` must be a live context.
unsafe fn drain_exception_raw(ctx: *mut q::JSContext) {
    // SAFETY: per the function contract.
    unsafe {
        let exc = q::JS_GetException(ctx);
        q::JS_FreeValue(ctx, exc);
    }
}

/// # Safety
/// `ctx` must be a live context whose opaque was set to a `HostState` that is
/// still alive (both are guaranteed by `Context`).
unsafe fn host_state<'a>(ctx: *mut q::JSContext) -> &'a HostState {
    // SAFETY: per the function contract.
    unsafe { &*q::JS_GetContextOpaque(ctx).cast::<HostState>() }
}

/// # Safety
/// `argv` must point to `argc` live values (guaranteed by QuickJS).
unsafe fn arg_to_string(
    ctx: *mut q::JSContext,
    argc: c_int,
    argv: *mut q::JSValue,
    index: usize,
) -> Option<String> {
    if index >= argc.max(0) as usize {
        return None;
    }
    // SAFETY: per the function contract; the value stays owned by QuickJS.
    unsafe { value_to_string_raw(ctx, *argv.add(index)) }
}

/// Builds a JS string, or the exception marker on allocation failure (which
/// then propagates naturally out of the native call).
///
/// # Safety
/// `ctx` must be a live context.
unsafe fn new_js_string(ctx: *mut q::JSContext, s: &str) -> q::JSValue {
    // SAFETY: pointer/length pair is valid for the duration of the call.
    unsafe { q::JS_NewStringLen(ctx, s.as_ptr().cast::<c_char>(), s.len() as _) }
}

/// Interrupt handler: aborts execution once the armed deadline has passed.
unsafe extern "C" fn interrupt_handler(_rt: *mut q::JSRuntime, opaque: *mut c_void) -> c_int {
    // SAFETY: `opaque` is the `HostState` registered at construction and
    // outlives the runtime.
    let state = unsafe { &*opaque.cast::<HostState>() };
    if let Some(deadline) = state.deadline.get()
        && Instant::now() >= deadline
    {
        state.interrupted.set(true);
        return 1;
    }
    0
}

/// `alert(...)` (also used for `console.log`): joins all arguments with
/// spaces and forwards them to the configured log sink. Never throws.
unsafe extern "C" fn tramp_alert(
    ctx: *mut q::JSContext,
    _this: q::JSValue,
    argc: c_int,
    argv: *mut q::JSValue,
) -> q::JSValue {
    let mut parts: Vec<String> = Vec::new();
    for i in 0..argc.max(0) as usize {
        // SAFETY: QuickJS guarantees `argv` holds `argc` live values.
        let part = unsafe { arg_to_string(ctx, argc, argv, i) };
        parts.push(part.unwrap_or_else(|| "<unprintable>".to_string()));
    }
    // SAFETY: the context opaque is a live `HostState`.
    let state = unsafe { host_state(ctx) };
    state.log(&parts.join(" "));
    q::JS_UNDEFINED
}

/// `dnsResolve(host)` -> first IPv4 address as a string, or `null`.
unsafe extern "C" fn tramp_dns_resolve(
    ctx: *mut q::JSContext,
    _this: q::JSValue,
    argc: c_int,
    argv: *mut q::JSValue,
) -> q::JSValue {
    // SAFETY: see `tramp_alert`.
    let (state, host) = unsafe { (host_state(ctx), arg_to_string(ctx, argc, argv, 0)) };
    match host.and_then(|h| state.dns_resolve(&h)) {
        // SAFETY: `ctx` is live.
        Some(ip) => unsafe { new_js_string(ctx, &ip) },
        None => q::JS_NULL,
    }
}

/// `myIpAddress()` -> IPv4 address string (override, best effort, or
/// `"127.0.0.1"`).
unsafe extern "C" fn tramp_my_ip_address(
    ctx: *mut q::JSContext,
    _this: q::JSValue,
    _argc: c_int,
    _argv: *mut q::JSValue,
) -> q::JSValue {
    // SAFETY: see `tramp_alert`.
    let state = unsafe { host_state(ctx) };
    let ip = state.my_ip_address();
    // SAFETY: `ctx` is live.
    unsafe { new_js_string(ctx, &ip) }
}

/// `dnsResolveEx(host)` -> `;`-separated address list, or `""`.
#[cfg(feature = "microsoft-extensions")]
unsafe extern "C" fn tramp_dns_resolve_ex(
    ctx: *mut q::JSContext,
    _this: q::JSValue,
    argc: c_int,
    argv: *mut q::JSValue,
) -> q::JSValue {
    // SAFETY: see `tramp_alert`.
    let (state, host) = unsafe { (host_state(ctx), arg_to_string(ctx, argc, argv, 0)) };
    let list = host.map(|h| state.dns_resolve_ex(&h)).unwrap_or_default();
    // SAFETY: `ctx` is live.
    unsafe { new_js_string(ctx, &list) }
}

/// `myIpAddressEx()` -> `;`-separated local address list, or `""`.
#[cfg(feature = "microsoft-extensions")]
unsafe extern "C" fn tramp_my_ip_address_ex(
    ctx: *mut q::JSContext,
    _this: q::JSValue,
    _argc: c_int,
    _argv: *mut q::JSValue,
) -> q::JSValue {
    // SAFETY: see `tramp_alert`.
    let state = unsafe { host_state(ctx) };
    let list = state.my_ip_address_ex();
    // SAFETY: `ctx` is live.
    unsafe { new_js_string(ctx, &list) }
}
