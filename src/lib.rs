/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Evaluate PAC (Proxy Auto-Config) files with an embedded [QuickJS-NG]
//! JavaScript engine.
//!
//! A [`PacEngine`] owns one JavaScript runtime, pre-loaded with the standard
//! PAC helper functions (`isPlainHostName`, `dnsDomainIs`, `shExpMatch`,
//! `isInNet`, `dateRange`, ... — implemented from the public Netscape PAC
//! specification) and, with the default `microsoft-extensions` feature, the
//! Microsoft IPv6 extensions (`dnsResolveEx`, `isInNetEx`, ...).
//!
//! ```
//! use pac_eval::PacEngine;
//!
//! # fn main() -> Result<(), pac_eval::Error> {
//! let mut engine = PacEngine::new()?;
//! engine.load(
//!     r#"
//!     function FindProxyForURL(url, host) {
//!         if (dnsDomainIs(host, ".example.com"))
//!             return "DIRECT";
//!         return "PROXY proxy.example.com:8080; DIRECT";
//!     }
//!     "#,
//! )?;
//! let proxy = engine.find_proxy("http://www.example.com/", "www.example.com")?;
//! assert_eq!(proxy, "DIRECT");
//! # Ok(())
//! # }
//! ```
//!
//! # Sandboxing and untrusted scripts
//!
//! PAC scripts are treated as untrusted input:
//!
//! * No filesystem, module loading, timer or network APIs are exposed to the
//!   script. The only host access is through the PAC helpers (`dnsResolve*`,
//!   `myIpAddress*`) and the log sink (`alert`, `console.log`).
//! * Every evaluation runs under a wall-clock deadline (default 10 seconds,
//!   see [`PacEngine::set_timeout`]) enforced by a QuickJS interrupt
//!   handler, so `while (true) {}` returns [`Error::Timeout`] instead of
//!   hanging. Note that the interrupt handler cannot fire while a *native*
//!   call is in progress, so a slow blocking DNS lookup inside `dnsResolve`
//!   can still exceed the deadline.
//! * The runtime has a memory limit (default 64 MiB, see
//!   [`PacEngine::set_memory_limit`]); scripts that exceed it fail with an
//!   exception instead of exhausting the process.
//!
//! # Thread safety
//!
//! A [`PacEngine`] wraps a QuickJS context, which must stay on the thread it
//! was created on. `PacEngine` is therefore neither [`Send`] nor [`Sync`],
//! and no locking is added to pretend otherwise. To use PAC evaluation from
//! multiple threads, either create one engine per thread, or own the engine
//! on a dedicated thread and serialize calls to it through a channel.
//!
//! [QuickJS-NG]: https://github.com/quickjs-ng/quickjs

#![warn(missing_docs)]

mod ffi;
mod state;

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use crate::state::HostState;

/// Default wall-clock budget for a single script evaluation or PAC call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default QuickJS runtime memory limit in bytes (64 MiB).
pub const DEFAULT_MEMORY_LIMIT: usize = 64 * 1024 * 1024;

const HELPERS_JS: &str = include_str!("pac_helpers.js");
#[cfg(feature = "microsoft-extensions")]
const HELPERS_MS_JS: &str = include_str!("pac_helpers_ms.js");

/// Errors returned by [`PacEngine`].
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The PAC script failed to parse.
    ScriptSyntax(String),
    /// The loaded script does not define the named entry point
    /// (`FindProxyForURL` / `FindProxyForURLEx`).
    FunctionMissing(String),
    /// The script threw an exception (message and stack trace, if available).
    JsException(String),
    /// The named entry point returned a value that is not a string.
    ReturnedNonString(String),
    /// Evaluation exceeded the configured wall-clock limit and was
    /// interrupted inside the engine.
    Timeout,
    /// An unexpected engine-level failure (allocation, embedding bug, ...).
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::ScriptSyntax(msg) => write!(f, "PAC script syntax error: {msg}"),
            Error::FunctionMissing(name) => {
                write!(f, "PAC script does not define function `{name}`")
            }
            Error::JsException(msg) => write!(f, "PAC script threw an exception: {msg}"),
            Error::ReturnedNonString(name) => {
                write!(f, "PAC function `{name}` returned a non-string value")
            }
            Error::Timeout => write!(f, "PAC evaluation exceeded the configured time limit"),
            Error::Internal(msg) => write!(f, "internal PAC engine error: {msg}"),
        }
    }
}

impl std::error::Error for Error {}

/// A PAC evaluator: one QuickJS runtime/context with the PAC helper library
/// installed and (after [`load`](PacEngine::load)) a PAC script.
///
/// Not `Send`/`Sync` — see the crate-level documentation on thread safety.
pub struct PacEngine {
    ctx: ffi::Context,
}

impl fmt::Debug for PacEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacEngine").finish_non_exhaustive()
    }
}

impl PacEngine {
    /// Creates an engine and installs the built-in PAC helper library.
    pub fn new() -> Result<Self, Error> {
        let state = Box::new(HostState::new(DEFAULT_TIMEOUT));
        let ctx = ffi::Context::new(state, DEFAULT_MEMORY_LIMIT)?;
        let install = |source, filename| {
            ctx.eval(source, filename, false)
                .map_err(|e| Error::Internal(format!("failed to install PAC helper library: {e}")))
        };
        install(HELPERS_JS, c"pac_helpers.js")?;
        #[cfg(feature = "microsoft-extensions")]
        install(HELPERS_MS_JS, c"pac_helpers_ms.js")?;
        Ok(PacEngine { ctx })
    }

    /// Evaluates a PAC script in the engine's global scope.
    ///
    /// Returns [`Error::ScriptSyntax`] when the script fails to parse,
    /// [`Error::JsException`] when its top-level code throws, and
    /// [`Error::Timeout`] when top-level execution exceeds the configured
    /// limit. Loading another script re-uses the same global scope, so later
    /// definitions override earlier ones.
    pub fn load(&mut self, script: &str) -> Result<(), Error> {
        self.ctx.eval(script, c"<pac>", true)
    }

    /// Calls `FindProxyForURL(url, host)` and returns its result string
    /// verbatim (e.g. `"PROXY proxy:8080; DIRECT"` — multi-directive results
    /// are not reformatted).
    pub fn find_proxy(&mut self, url: &str, host: &str) -> Result<String, Error> {
        self.ctx.call_pac_function(c"FindProxyForURL", url, host)
    }

    /// Calls the IPv6-aware entry point `FindProxyForURLEx(url, host)`,
    /// falling back to `FindProxyForURL` when the script does not define it
    /// (mirroring the behavior of IPv6-aware Windows PAC clients).
    #[cfg(feature = "microsoft-extensions")]
    pub fn find_proxy_ex(&mut self, url: &str, host: &str) -> Result<String, Error> {
        if self.ctx.has_global_function(c"FindProxyForURLEx") {
            self.ctx.call_pac_function(c"FindProxyForURLEx", url, host)
        } else {
            self.ctx.call_pac_function(c"FindProxyForURL", url, host)
        }
    }

    /// One-shot convenience: creates an engine, loads `script` and evaluates
    /// `FindProxyForURL(url, host)`.
    pub fn eval_once(script: &str, url: &str, host: &str) -> Result<String, Error> {
        let mut engine = Self::new()?;
        engine.load(script)?;
        engine.find_proxy(url, host)
    }

    /// Overrides what `myIpAddress()` and `myIpAddressEx()` return. Pass
    /// `None` to restore OS-based detection. Essential for deterministic
    /// tests.
    pub fn set_my_ip(&mut self, ip: Option<IpAddr>) {
        self.ctx.state().my_ip.set(ip);
    }

    /// Sets the maximum wall-clock time for a single [`load`](Self::load) or
    /// `find_proxy*` call. A runaway script is interrupted inside the engine
    /// and the call returns [`Error::Timeout`].
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.ctx.state().timeout.set(timeout);
    }

    /// Sets the QuickJS runtime memory limit in bytes.
    pub fn set_memory_limit(&mut self, bytes: usize) {
        self.ctx.set_memory_limit(bytes);
    }

    /// Routes `alert()` / `console.log()` output to `sink` instead of the
    /// default (stderr). Each call receives one message with all arguments
    /// converted to strings and joined by spaces.
    pub fn set_log_sink<F>(&mut self, sink: F)
    where
        F: Fn(&str) + 'static,
    {
        *self.ctx.state().log_sink.borrow_mut() = Some(Box::new(sink));
    }
}
