/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Hand-written bindings to pacparser's small C API (vendored, QuickJS-based)
//! plus the error-capture shim in `shim.c`.
//!
//! # Safety contract
//! pacparser has a single global, non-thread-safe context. Every function
//! here (except the version getter) must only ever be called from the one
//! worker thread owned by [`super::PacEvaluator`].

#![allow(dead_code)]

use std::os::raw::{c_char, c_int};

extern "C" {
    /// Returns 1 on success, 0 on failure.
    pub fn pacparser_init() -> c_int;
    /// Returns 1 on success, 0 on failure.
    pub fn pacparser_parse_pac_string(pacstring: *const c_char) -> c_int;
    /// Returns 1 on success, 0 on failure.
    pub fn pacparser_parse_pac_file(pacfile: *const c_char) -> c_int;
    /// Returns a library-owned string, valid until the next call — copy
    /// immediately, never free. NULL on error.
    pub fn pacparser_find_proxy(url: *const c_char, host: *const c_char) -> *mut c_char;
    pub fn pacparser_cleanup();
    /// Overrides what `myIpAddress()` returns. 1 on success.
    pub fn pacparser_setmyip(ip: *const c_char) -> c_int;
    /// Enables `FindProxyForURLEx` / `dnsResolveEx` etc. Call before init.
    pub fn pacparser_enable_microsoft_extensions();
    pub fn pacparser_version() -> *mut c_char;

    // shim.c
    pub fn ospr_install_error_printer();
    pub fn ospr_get_error() -> *const c_char;
    pub fn ospr_clear_error();
}

/// Read and clear the error buffer accumulated by the shim printer.
/// Only call from the worker thread.
pub(super) unsafe fn take_error() -> String {
    let ptr = ospr_get_error();
    let msg = if ptr.is_null() {
        String::new()
    } else {
        std::ffi::CStr::from_ptr(ptr)
            .to_string_lossy()
            .trim()
            .to_string()
    };
    ospr_clear_error();
    msg
}
