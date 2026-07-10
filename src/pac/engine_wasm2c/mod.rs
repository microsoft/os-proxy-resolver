/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The portable sandboxed PAC backend: the same QuickJS-NG wasm guest as the
//! Wasmtime backend (`pac-wasm-guest/pac_guest.wasm`), but translated to
//! standard C with WABT's `wasm2c` at build time and compiled into this crate
//! like any other C code.
//!
//! # Why a second wasm backend
//!
//! Wasmtime AOT needs a Cranelift code generator for the target, which does
//! not exist for 32-bit ARM (armv7) and other less common architectures.
//! `wasm2c` sidesteps code generation entirely: the C compiler that builds
//! this crate is by definition available for the target, so the wasm sandbox
//! — bounds-checked linear memory, no ambient capabilities — becomes portable
//! to every target the crate compiles on. The trade-off is speed (explicit
//! software bounds checks on every memory access; see shim.c for why guard
//! pages are deliberately not used) and no epoch interruption.
//!
//! # Timeouts
//!
//! wasm2c has no instruction-level interruption, so the per-call deadline is
//! enforced solely by the guest's QuickJS interrupt handler polling the
//! `host_should_interrupt` import ([`pac2c_rs_should_interrupt`]), answered
//! here from the [`HostState`] deadline armed around every call — the same
//! mechanism (and the same shared guest) as the Wasmtime backend's first
//! layer, just without its epoch backstop. A runaway *JS* loop therefore
//! times out cleanly with [`Error::Timeout`]; a hypothetical loop in the
//! interpreter's C code that never reaches a QuickJS interrupt poll cannot be
//! stopped and is covered by the caller-side wedge/fail-fast path, exactly
//! like a blocking DNS call in the native backend.
//!
//! # Memory containment
//!
//! Every linear-memory access in the generated C is bounds-checked
//! (`WASM_RT_USE_MMAP=0`, see build.rs), so a memory-safety bug in QuickJS
//! stays inside the guest's memory allocation. Growth is capped by
//! `max_pages` on top of the guest's own 64 MiB QuickJS heap limit. All host
//! callbacks receive the memory as an explicit (base, size) pair and
//! bounds-check every guest offset here before touching it.

use std::ffi::c_void;
use std::time::{Duration, Instant};

use super::engine::state::{HostState, LogSink};
use super::engine::{Error, DEFAULT_TIMEOUT};
use super::wasm_abi as abi;
use super::wasm_host::{
    clock_nanos, fill_pseudo_random, status_to_result, WASI_EBADF, WASI_SUCCESS,
};

/// Cap on the guest's wasm linear memory (see the Wasmtime backend's
/// equivalent constant for the rationale).
const DEFAULT_WASM_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

// WASI dispatcher function ids — keep in sync with shim.c.
const WASI_FD_WRITE: u32 = 0;
const WASI_ENVIRON_GET: u32 = 1;
const WASI_ENVIRON_SIZES_GET: u32 = 2;
const WASI_CLOCK_TIME_GET: u32 = 3;
const WASI_RANDOM_GET: u32 = 4;
const WASI_FD_CLOSE: u32 = 5;
const WASI_FD_FDSTAT_GET: u32 = 6;
const WASI_FD_SEEK: u32 = 7;
/// Sentinel return value telling the shim to trap the guest.
const WASI_TRAP: u32 = 0xffff_ffff;

/// Opaque instance handle owned by shim.c.
#[repr(C)]
struct Pac2cInstance {
    _opaque: [u8; 0],
}

extern "C" {
    fn pac2c_runtime_init();
    fn pac2c_instantiate(
        env: *mut c_void,
        max_memory_bytes: u64,
        trap_out: *mut i32,
    ) -> *mut Pac2cInstance;
    fn pac2c_destroy(inst: *mut Pac2cInstance);
    fn pac2c_set_max_memory(inst: *mut Pac2cInstance, max_memory_bytes: u64);
    fn pac2c_memory_base(inst: *mut Pac2cInstance) -> *mut u8;
    fn pac2c_memory_size(inst: *mut Pac2cInstance) -> u64;
    fn pac2c_alloc(inst: *mut Pac2cInstance, len: u32, ptr_out: *mut u32) -> i32;
    fn pac2c_dealloc(inst: *mut Pac2cInstance, ptr: u32, len: u32) -> i32;
    fn pac2c_load(inst: *mut Pac2cInstance, ptr: u32, len: u32, packed_out: *mut u64) -> i32;
    fn pac2c_find_proxy(
        inst: *mut Pac2cInstance,
        url_ptr: u32,
        url_len: u32,
        host_ptr: u32,
        host_len: u32,
        packed_out: *mut u64,
    ) -> i32;
}

/// The host context the shim passes back into every `pac2c_rs_*` callback.
/// Same [`HostState`] as the other backends plus the result staging buffer of
/// the string-passing ABI. Interior mutability throughout because callbacks
/// only ever see a shared reference (single-threaded: the guest runs on the
/// worker thread that owns the engine).
struct HostCtx {
    host: HostState,
    staged: std::cell::Cell<Option<Vec<u8>>>,
}

/// One live guest instance plus its host context.
struct Guest {
    inst: *mut Pac2cInstance,
    ctx: Box<HostCtx>,
    /// Set when a call ended in a wasm trap; the instance must be discarded.
    trapped: bool,
}

impl Drop for Guest {
    fn drop(&mut self) {
        // SAFETY: `inst` came from `pac2c_instantiate` and is destroyed once.
        unsafe { pac2c_destroy(self.inst) };
    }
}

impl Guest {
    fn new(memory_limit: usize) -> Result<Self, Error> {
        let ctx = Box::new(HostCtx {
            host: HostState::new(DEFAULT_TIMEOUT),
            staged: std::cell::Cell::new(None),
        });
        let env = &*ctx as *const HostCtx as *mut c_void;
        let mut trap = 0i32;
        // SAFETY: `env` outlives the instance (owned by the same struct and
        // dropped after `pac2c_destroy` in `Drop`); init is idempotent.
        let inst = unsafe {
            pac2c_runtime_init();
            pac2c_instantiate(env, memory_limit as u64, &mut trap)
        };
        if inst.is_null() {
            return Err(Error::Internal(format!(
                "failed to instantiate wasm2c PAC guest (trap code {trap})"
            )));
        }
        Ok(Guest {
            inst,
            ctx,
            trapped: false,
        })
    }

    /// Copies `s` into a fresh guest allocation.
    fn write_str(&mut self, s: &str) -> Result<(u32, u32), Error> {
        let len = u32::try_from(s.len())
            .map_err(|_| Error::Internal("string too large for guest memory".into()))?;
        let mut ptr = 0u32;
        // SAFETY: live instance; out-param is written on success.
        let trap = unsafe { pac2c_alloc(self.inst, len, &mut ptr) };
        if trap != 0 {
            self.trapped = true;
            return Err(Error::Internal(format!(
                "PAC guest trapped in pac_alloc (wasm trap code {trap})"
            )));
        }
        // Re-fetch the memory after the call — pac_alloc may have grown (and
        // thus moved) the linear memory.
        // SAFETY: base/size describe the current linear memory; the bounds
        // are checked before writing.
        unsafe {
            let base = pac2c_memory_base(self.inst);
            let size = pac2c_memory_size(self.inst);
            if (ptr as u64) + (len as u64) > size {
                return Err(Error::Internal("pac_alloc returned out-of-bounds".into()));
            }
            std::ptr::copy_nonoverlapping(s.as_ptr(), base.add(ptr as usize), s.len());
        }
        Ok((ptr, len))
    }

    fn free(&mut self, ptr: u32, len: u32) {
        // SAFETY: live instance; failures only matter as traps.
        let trap = unsafe { pac2c_dealloc(self.inst, ptr, len) };
        if trap != 0 {
            self.trapped = true;
        }
    }

    /// Reads and decodes a packed `(ptr << 32) | len` guest result.
    fn unpack(&self, packed: u64) -> Result<String, Error> {
        let ptr = packed >> 32;
        let len = packed & 0xffff_ffff;
        // SAFETY: bounds are checked against the current memory size before
        // the slice is formed; the buffer is copied out immediately.
        unsafe {
            let base = pac2c_memory_base(self.inst);
            let size = pac2c_memory_size(self.inst);
            if ptr + len > size {
                return Err(Error::Internal(
                    "out-of-bounds result from PAC guest".into(),
                ));
            }
            let buf = std::slice::from_raw_parts(base.add(ptr as usize), len as usize);
            status_to_result(buf)
        }
    }

    fn load(&mut self, script: &str, _timeout: Duration) -> Result<(), Error> {
        let (ptr, len) = self.write_str(script)?;
        self.ctx.host.begin_call();
        let mut packed = 0u64;
        // SAFETY: live instance; traps are caught by the shim's setjmp.
        let trap = unsafe { pac2c_load(self.inst, ptr, len, &mut packed) };
        self.ctx.host.end_call();
        if trap != 0 {
            self.trapped = true;
            return Err(Error::Internal(format!(
                "PAC guest trapped in pac_load (wasm trap code {trap})"
            )));
        }
        self.free(ptr, len);
        self.unpack(packed).map(|_| ())
    }

    fn find_proxy(&mut self, url: &str, host: &str, _timeout: Duration) -> Result<String, Error> {
        let (url_ptr, url_len) = self.write_str(url)?;
        let (host_ptr, host_len) = match self.write_str(host) {
            Ok(pair) => pair,
            Err(e) => {
                self.free(url_ptr, url_len);
                return Err(e);
            }
        };
        self.ctx.host.begin_call();
        let mut packed = 0u64;
        // SAFETY: live instance; traps are caught by the shim's setjmp.
        let trap = unsafe {
            pac2c_find_proxy(self.inst, url_ptr, url_len, host_ptr, host_len, &mut packed)
        };
        self.ctx.host.end_call();
        if trap != 0 {
            self.trapped = true;
            return Err(Error::Internal(format!(
                "PAC guest trapped in pac_find_proxy (wasm trap code {trap})"
            )));
        }
        self.free(url_ptr, url_len);
        self.free(host_ptr, host_len);
        self.unpack(packed)
    }
}

/// Log sink shared between the engine (for replay after rebuilds) and the
/// guest's [`HostState`].
type SharedLogSink = std::rc::Rc<dyn Fn(&str)>;

/// A PAC evaluator running QuickJS-NG inside a wasm2c-translated sandbox;
/// same [`super::PacBackend`] surface as the other backends.
pub(crate) struct Wasm2cPacEngine {
    guest: Guest,
    /// The loaded script, kept so the engine can rebuild itself after a trap.
    script: Option<String>,
    /// Settings replayed onto rebuilt instances.
    timeout: Duration,
    memory_limit: usize,
    my_ip: Option<std::net::IpAddr>,
    log_sink: Option<SharedLogSink>,
    /// Set when the previous call trapped; the next call rebuilds first.
    poisoned: bool,
}

impl super::PacBackend for Wasm2cPacEngine {
    const NAME: &'static str = "wasm2c";

    fn new() -> Result<Self, Error> {
        let guest = Guest::new(DEFAULT_WASM_MEMORY_LIMIT)?;
        Ok(Wasm2cPacEngine {
            guest,
            script: None,
            timeout: DEFAULT_TIMEOUT,
            memory_limit: DEFAULT_WASM_MEMORY_LIMIT,
            my_ip: None,
            log_sink: None,
            poisoned: false,
        })
    }

    fn load(&mut self, script: &str) -> Result<(), Error> {
        self.script = Some(script.to_string());
        self.poisoned = false;
        let result = self.guest.load(script, self.timeout);
        if self.guest.trapped || matches!(&result, Err(Error::Internal(_))) {
            self.poisoned = true;
        }
        result
    }

    fn find_proxy_ex(&mut self, url: &str, host: &str) -> Result<String, Error> {
        if self.poisoned {
            self.rebuild()?;
        }
        let result = self.guest.find_proxy(url, host, self.timeout);
        if self.guest.trapped {
            // Stopped mid-execution by a trap; QuickJS's internal state may
            // be inconsistent, discard the whole instance. (A deadline
            // enforced via the guest's interrupt handler returns
            // Error::Timeout *without* the trap flag and needs no rebuild.)
            self.poisoned = true;
        }
        result
    }

    fn set_my_ip(&mut self, ip: Option<std::net::IpAddr>) {
        self.my_ip = ip;
        self.guest.ctx.host.my_ip.set(ip);
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        self.guest.ctx.host.timeout.set(timeout);
    }

    /// For this backend the limit caps the wasm *linear memory* growth;
    /// QuickJS's 64 MiB heap limit is fixed inside the guest.
    fn set_memory_limit(&mut self, bytes: usize) {
        self.memory_limit = bytes;
        // SAFETY: live instance.
        unsafe { pac2c_set_max_memory(self.guest.inst, bytes as u64) };
    }

    fn set_log_sink(&mut self, sink: LogSink) {
        let sink: SharedLogSink = std::rc::Rc::from(sink);
        self.log_sink = Some(sink.clone());
        *self.guest.ctx.host.log_sink.borrow_mut() = Some(Box::new(move |msg| sink(msg)));
    }
}

impl Wasm2cPacEngine {
    /// Recreates the instance after a trap and replays the settings and the
    /// loaded script.
    fn rebuild(&mut self) -> Result<(), Error> {
        self.guest = Guest::new(self.memory_limit)?;
        self.guest.ctx.host.timeout.set(self.timeout);
        self.guest.ctx.host.my_ip.set(self.my_ip);
        if let Some(sink) = &self.log_sink {
            let sink = sink.clone();
            *self.guest.ctx.host.log_sink.borrow_mut() = Some(Box::new(move |msg| sink(msg)));
        }
        self.poisoned = false;
        if let Some(script) = &self.script {
            let script = script.clone();
            let result = self.guest.load(&script, self.timeout);
            if result.is_err() {
                self.poisoned = true;
            }
            result?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Callbacks from shim.c. All run on the worker thread that owns the engine,
// during a guest call. Every guest offset is validated against the (base,
// size) pair the shim passes before any memory is touched.

/// # Safety
/// `env` must be the `HostCtx` registered with the instance (guaranteed by
/// shim.c, which only ever passes the pointer from `pac2c_instantiate`).
unsafe fn host_ctx<'a>(env: *mut c_void) -> &'a HostCtx {
    // SAFETY: per the function contract.
    unsafe { &*(env as *const HostCtx) }
}

/// # Safety
/// `mem`/`mem_size` must describe the guest's current linear memory.
unsafe fn guest_bytes<'a>(mem: *const u8, mem_size: u64, ptr: u32, len: u32) -> Option<&'a [u8]> {
    if (ptr as u64) + (len as u64) > mem_size {
        return None;
    }
    // SAFETY: bounds checked above, per the function contract.
    Some(unsafe { std::slice::from_raw_parts(mem.add(ptr as usize), len as usize) })
}

/// # Safety
/// `mem`/`mem_size` must describe the guest's current linear memory.
unsafe fn write_guest(mem: *mut u8, mem_size: u64, ptr: u64, bytes: &[u8]) -> bool {
    if ptr + bytes.len() as u64 > mem_size {
        return false;
    }
    // SAFETY: bounds checked above, per the function contract.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), mem.add(ptr as usize), bytes.len()) };
    true
}

fn stage(ctx: &HostCtx, result: Option<String>) -> i32 {
    match result {
        None => abi::RESULT_NONE,
        Some(s) => {
            let len = s.len() as i32;
            ctx.staged.set(Some(s.into_bytes()));
            len
        }
    }
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_dns_resolve(
    env: *mut c_void,
    mem: *mut u8,
    mem_size: u64,
    ptr: u32,
    len: u32,
) -> i32 {
    // SAFETY: shim contract (see host_ctx/guest_bytes).
    let (ctx, bytes) = unsafe { (host_ctx(env), guest_bytes(mem, mem_size, ptr, len)) };
    let Some(bytes) = bytes else {
        return abi::RESULT_NONE;
    };
    let host = String::from_utf8_lossy(bytes).into_owned();
    stage(ctx, ctx.host.dns_resolve(&host))
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_dns_resolve_ex(
    env: *mut c_void,
    mem: *mut u8,
    mem_size: u64,
    ptr: u32,
    len: u32,
) -> i32 {
    // SAFETY: shim contract.
    let (ctx, bytes) = unsafe { (host_ctx(env), guest_bytes(mem, mem_size, ptr, len)) };
    let Some(bytes) = bytes else {
        return abi::RESULT_NONE;
    };
    let host = String::from_utf8_lossy(bytes).into_owned();
    stage(ctx, Some(ctx.host.dns_resolve_ex(&host)))
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_my_ip(env: *mut c_void) -> i32 {
    // SAFETY: shim contract.
    let ctx = unsafe { host_ctx(env) };
    stage(ctx, Some(ctx.host.my_ip_address()))
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_my_ip_ex(env: *mut c_void) -> i32 {
    // SAFETY: shim contract.
    let ctx = unsafe { host_ctx(env) };
    stage(ctx, Some(ctx.host.my_ip_address_ex()))
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_take_result(
    env: *mut c_void,
    mem: *mut u8,
    mem_size: u64,
    dest: u32,
) {
    // SAFETY: shim contract.
    let ctx = unsafe { host_ctx(env) };
    if let Some(bytes) = ctx.staged.take() {
        // SAFETY: shim contract; write_guest bounds-checks.
        unsafe { write_guest(mem, mem_size, dest as u64, &bytes) };
    }
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_alert(
    env: *mut c_void,
    mem: *mut u8,
    mem_size: u64,
    ptr: u32,
    len: u32,
) {
    // SAFETY: shim contract.
    let (ctx, bytes) = unsafe { (host_ctx(env), guest_bytes(mem, mem_size, ptr, len)) };
    if let Some(bytes) = bytes {
        ctx.host.log(&String::from_utf8_lossy(bytes));
    }
}

#[no_mangle]
unsafe extern "C" fn pac2c_rs_should_interrupt(env: *mut c_void) -> i32 {
    // SAFETY: shim contract. Runs on the worker thread that armed the
    // deadline, so reading the Cell is safe.
    let ctx = unsafe { host_ctx(env) };
    let deadline = ctx.host.deadline.get();
    deadline.is_some_and(|d| Instant::now() >= d) as i32
}

/// The WASI stub dispatcher (ids shared with shim.c). Same capability-free
/// behavior as the Wasmtime backend's `define_wasi_stubs`.
#[no_mangle]
unsafe extern "C" fn pac2c_rs_wasi(
    env: *mut c_void,
    func: u32,
    mem: *mut u8,
    mem_size: u64,
    a: u64,
    b: u64,
    c: u64,
    _d: u64,
) -> u32 {
    // SAFETY: shim contract.
    let ctx = unsafe { host_ctx(env) };
    // SAFETY (all arms): shim contract; every guest offset goes through
    // guest_bytes/write_guest which bounds-check.
    unsafe {
        match func {
            WASI_FD_WRITE => {
                let (fd, iovs, iovs_len, nwritten) = (a, b, c, _d);
                if fd != 1 && fd != 2 {
                    return WASI_EBADF as u32;
                }
                let mut gathered = Vec::new();
                for i in 0..iovs_len {
                    let Some(iov) = guest_bytes(mem, mem_size, (iovs + i * 8) as u32, 8) else {
                        return WASI_EBADF as u32;
                    };
                    let ptr = u32::from_le_bytes(iov[0..4].try_into().expect("4 bytes"));
                    let len = u32::from_le_bytes(iov[4..8].try_into().expect("4 bytes"));
                    let Some(chunk) = guest_bytes(mem, mem_size, ptr, len) else {
                        return WASI_EBADF as u32;
                    };
                    gathered.extend_from_slice(chunk);
                }
                let total = gathered.len() as u32;
                let text = String::from_utf8_lossy(&gathered);
                let text = text.trim_end_matches('\n');
                if !text.is_empty() {
                    ctx.host.log(text);
                }
                write_guest(mem, mem_size, nwritten, &total.to_le_bytes());
                WASI_SUCCESS as u32
            }
            WASI_ENVIRON_GET => WASI_SUCCESS as u32,
            WASI_ENVIRON_SIZES_GET => {
                write_guest(mem, mem_size, a, &0u32.to_le_bytes());
                write_guest(mem, mem_size, b, &0u32.to_le_bytes());
                WASI_SUCCESS as u32
            }
            WASI_CLOCK_TIME_GET => {
                // (id, _precision, out)
                let nanos = clock_nanos(a as u32);
                write_guest(mem, mem_size, c, &nanos.to_le_bytes());
                WASI_SUCCESS as u32
            }
            WASI_RANDOM_GET => {
                let mut bytes = vec![0u8; b as usize];
                fill_pseudo_random(&mut bytes);
                write_guest(mem, mem_size, a, &bytes);
                WASI_SUCCESS as u32
            }
            WASI_FD_CLOSE | WASI_FD_SEEK => WASI_EBADF as u32,
            WASI_FD_FDSTAT_GET => {
                let (fd, out) = (a, b);
                if fd > 2 {
                    return WASI_EBADF as u32;
                }
                // filetype = character_device, zero flags and rights.
                let mut stat = [0u8; 24];
                stat[0] = 2;
                write_guest(mem, mem_size, out, &stat);
                WASI_SUCCESS as u32
            }
            _ => WASI_TRAP,
        }
    }
}
