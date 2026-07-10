/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The sandboxed PAC backend: QuickJS-NG compiled to wasm32-wasip1 (see the
//! `pac-wasm-guest` crate) and executed with Wasmtime in AOT mode.
//!
//! # Why
//!
//! A PAC/WPAD script is untrusted input parsed by a large C codebase. The
//! native backend runs that C in-process, so a memory-safety bug there is
//! potential host-process compromise. Here the same C code runs inside a
//! WebAssembly linear memory: a heap overflow corrupts the guest's own data,
//! not host memory, and the guest's only reach into the process is the five
//! `pac_host` imports (DNS, local-IP, log) plus a stub WASI clock/RNG — no
//! filesystem, network, or environment capability exists inside the sandbox.
//!
//! # AOT only — no compiler at runtime
//!
//! This build of Wasmtime contains no Cranelift/JIT (see Cargo.toml). The
//! guest module is precompiled by build.rs into `OUT_DIR/pac_guest.cwasm` and
//! embedded into the binary; at runtime it is only [`Module::deserialize`]d.
//! That call is `unsafe` because a *malicious* artifact could misbehave — here
//! it is trusted first-party output of our own build.rs, compiled from the
//! vendored `pac-wasm-guest/pac_guest.wasm`.
//!
//! # Timeouts and memory
//!
//! Two layers stop a runaway JS loop:
//!
//! 1. The guest's QuickJS interrupt handler polls the `host_should_interrupt`
//!    import, which is answered here from the [`HostState`] deadline armed
//!    around every call. This unwinds *cleanly* (QuickJS raises its normal
//!    uncatchable interrupt exception, the guest reports
//!    [`abi::STATUS_TIMEOUT`]), so the instance stays usable. It is also the
//!    only mechanism the wasm2c backend has, which is why it lives in the
//!    shared guest.
//! 2. Wasmtime *epoch interruption* as a backstop for loops that never reach
//!    a QuickJS interrupt poll (e.g. a bug looping in the interpreter's C
//!    code): a process-global watchdog thread bumps the epoch every
//!    [`EPOCH_TICK`] while calls are in flight, and an expired deadline traps
//!    the guest. A trap tears the guest mid-execution, so the store is then
//!    discarded and rebuilt.
//!
//! Memory is capped twice: QuickJS's own 64 MiB limit inside the guest, and a
//! [`StoreLimits`] cap on the wasm linear memory itself.

use super::wasm_abi as abi;
use super::wasm_host::{
    clock_nanos, fill_pseudo_random, status_to_result, WASI_EBADF, WASI_SUCCESS,
};

use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, Trap,
    TypedFunc,
};

use super::engine::state::{HostState, LogSink};
use super::engine::{Error, DEFAULT_TIMEOUT};

/// The AOT-compiled guest module produced by build.rs for the current target.
static PAC_GUEST_CWASM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/pac_guest.cwasm"));

/// Size of the embedded AOT artifact — the dominant binary-size contribution
/// of this backend, reported by the `pac_bench` example.
pub(crate) const CWASM_SIZE: usize = PAC_GUEST_CWASM.len();

/// Granularity of epoch interruption. Finer ticks mean tighter timeout
/// enforcement but more watchdog wakeups while PAC calls are running.
const EPOCH_TICK: Duration = Duration::from_millis(10);

/// Cap on the guest's wasm linear memory. Generous compared to QuickJS's
/// 64 MiB heap limit inside the guest, because linear memory also holds the
/// interpreter's static data and allocator overhead; the exact value only
/// bounds worst-case waste, it does not affect PAC semantics.
const DEFAULT_WASM_MEMORY_LIMIT: usize = 256 * 1024 * 1024;

/// Everything a `Store` carries: the same [`HostState`] the native engine
/// wires into its FFI trampolines, the staging buffer of the string-passing
/// ABI, and the linear-memory limiter.
struct StoreData {
    host: HostState,
    /// Result staged by `host_dns_resolve*` / `host_my_ip*` until the guest
    /// fetches it with `host_take_result` (see `abi.rs`).
    staged: Option<Vec<u8>>,
    limits: StoreLimits,
}

/// One instantiation of the guest: a `Store` plus the typed exports.
struct GuestInstance {
    store: Store<StoreData>,
    memory: Memory,
    alloc: TypedFunc<u32, u32>,
    free: TypedFunc<(u32, u32), ()>,
    load: TypedFunc<(u32, u32), u64>,
    find_proxy: TypedFunc<(u32, u32, u32, u32), u64>,
    /// Set when the last call ended in a wasm trap (epoch interrupt, guest
    /// abort, ...). Unlike a clean `STATUS_TIMEOUT` unwind, a trap leaves the
    /// guest's internal state unusable, so the engine must rebuild.
    trapped: bool,
}

/// Log sink shared between the engine (for replay after rebuilds) and the
/// store's [`HostState`].
type SharedLogSink = std::rc::Rc<dyn Fn(&str)>;

/// A PAC evaluator running QuickJS-NG inside a Wasmtime sandbox; the wasm
/// counterpart of [`super::engine::PacEngine`], driven through the same
/// [`super::PacBackend`] trait.
pub(crate) struct WasmtimePacEngine {
    guest: GuestInstance,
    /// The loaded script, kept so the engine can rebuild itself after a trap
    /// (an interrupted guest cannot be trusted to still be consistent).
    script: Option<String>,
    /// Settings replayed onto rebuilt stores.
    timeout: Duration,
    memory_limit: usize,
    my_ip: Option<std::net::IpAddr>,
    log_sink: Option<SharedLogSink>,
    /// Set when the previous call trapped; the next call rebuilds first.
    poisoned: bool,
}

impl super::PacBackend for WasmtimePacEngine {
    const NAME: &'static str = "wasmtime";

    fn new() -> Result<Self, Error> {
        let guest = GuestInstance::new(DEFAULT_WASM_MEMORY_LIMIT)?;
        Ok(WasmtimePacEngine {
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
        // A trap tears the guest mid-execution; an Internal error leaves it in
        // an unknown state. A clean `STATUS_TIMEOUT` unwind does not poison.
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
            // Stopped mid-execution (epoch backstop or guest abort); QuickJS's
            // internal state may be inconsistent, discard the whole instance.
            // (A deadline enforced via the guest's own interrupt handler
            // returns Error::Timeout *without* the trap flag and needs no
            // rebuild.)
            self.poisoned = true;
        }
        result
    }

    fn set_my_ip(&mut self, ip: Option<std::net::IpAddr>) {
        self.my_ip = ip;
        self.guest.store.data().host.my_ip.set(ip);
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
        self.guest.store.data().host.timeout.set(timeout);
    }

    /// For this backend the limit applies to the wasm *linear memory* (the
    /// sandbox itself); QuickJS's 64 MiB heap limit is fixed inside the guest.
    fn set_memory_limit(&mut self, bytes: usize) {
        self.memory_limit = bytes;
        self.guest.store.data_mut().limits = StoreLimitsBuilder::new().memory_size(bytes).build();
    }

    fn set_log_sink(&mut self, sink: LogSink) {
        let sink: SharedLogSink = std::rc::Rc::from(sink);
        self.log_sink = Some(sink.clone());
        *self.guest.store.data().host.log_sink.borrow_mut() = Some(Box::new(move |msg| sink(msg)));
    }
}

impl WasmtimePacEngine {
    /// Recreates the store/instance after a trap and replays the settings and
    /// the loaded script.
    fn rebuild(&mut self) -> Result<(), Error> {
        self.guest = GuestInstance::new(self.memory_limit)?;
        self.guest.store.data().host.timeout.set(self.timeout);
        self.guest.store.data().host.my_ip.set(self.my_ip);
        if let Some(sink) = &self.log_sink {
            let sink = sink.clone();
            *self.guest.store.data().host.log_sink.borrow_mut() =
                Some(Box::new(move |msg| sink(msg)));
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

impl GuestInstance {
    fn new(memory_limit: usize) -> Result<Self, Error> {
        let engine = global_engine()?;
        let module = global_module()?;

        let mut linker: Linker<StoreData> = Linker::new(engine);
        define_pac_host_imports(&mut linker).map_err(internal("define host imports"))?;
        define_wasi_stubs(&mut linker).map_err(internal("define WASI stubs"))?;
        // Anything else the module might import is denied: it traps if called.
        linker
            .define_unknown_imports_as_traps(module)
            .map_err(internal("seal remaining imports"))?;

        let mut store = Store::new(
            engine,
            StoreData {
                host: HostState::new(DEFAULT_TIMEOUT),
                staged: None,
                limits: StoreLimitsBuilder::new().memory_size(memory_limit).build(),
            },
        );
        store.limiter(|data| &mut data.limits);
        // Instantiation runs no guest code (the module has no start function
        // and `_initialize` is absent — wasm-ld wires ctors into the exports),
        // but give it a deadline anyway in case that ever changes.
        store.set_epoch_deadline(ticks_for(DEFAULT_TIMEOUT));

        let instance = linker
            .instantiate(&mut store, module)
            .map_err(internal("instantiate PAC guest"))?;
        if let Some(init) = instance.get_func(&mut store, "_initialize") {
            let _guard = EpochGuard::begin();
            init.call(&mut store, &[], &mut [])
                .map_err(internal("initialize PAC guest"))?;
        }

        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| Error::Internal("PAC guest exports no memory".into()))?;
        let alloc = instance
            .get_typed_func(&mut store, "pac_alloc")
            .map_err(internal("resolve pac_alloc"))?;
        let free = instance
            .get_typed_func(&mut store, "pac_free")
            .map_err(internal("resolve pac_free"))?;
        let load = instance
            .get_typed_func(&mut store, "pac_load")
            .map_err(internal("resolve pac_load"))?;
        let find_proxy = instance
            .get_typed_func(&mut store, "pac_find_proxy")
            .map_err(internal("resolve pac_find_proxy"))?;

        Ok(GuestInstance {
            store,
            memory,
            alloc,
            free,
            load,
            find_proxy,
            trapped: false,
        })
    }

    fn load(&mut self, script: &str, timeout: Duration) -> Result<(), Error> {
        let (ptr, len) = self.write_str(script)?;
        let packed = self.with_deadline(timeout, |g, store| g.load.call(store, (ptr, len)));
        // Free the argument even when the call failed short of a trap.
        let _ = self.free.call(&mut self.store, (ptr, len));
        self.unpack(packed?).map(|_| ())
    }

    fn find_proxy(&mut self, url: &str, host: &str, timeout: Duration) -> Result<String, Error> {
        let (url_ptr, url_len) = self.write_str(url)?;
        let (host_ptr, host_len) = match self.write_str(host) {
            Ok(pair) => pair,
            Err(e) => {
                let _ = self.free.call(&mut self.store, (url_ptr, url_len));
                return Err(e);
            }
        };
        let packed = self.with_deadline(timeout, |g, store| {
            g.find_proxy
                .call(store, (url_ptr, url_len, host_ptr, host_len))
        });
        let _ = self.free.call(&mut self.store, (url_ptr, url_len));
        let _ = self.free.call(&mut self.store, (host_ptr, host_len));
        self.unpack(packed?)
    }

    /// Runs one guest call with the [`HostState`] deadline armed (answering
    /// the guest's `host_should_interrupt` polls) and the epoch watchdog as
    /// backstop, mapping an epoch trap to [`Error::Timeout`] and recording
    /// whether the call ended in a trap.
    fn with_deadline<R>(
        &mut self,
        timeout: Duration,
        call: impl FnOnce(&GuestFuncs, &mut Store<StoreData>) -> Result<R, wasmtime::Error>,
    ) -> Result<R, Error> {
        self.trapped = false;
        self.store.set_epoch_deadline(ticks_for(timeout));
        // Arms `HostState::deadline`; `host_should_interrupt` reads it. The
        // engine keeps `HostState::timeout` in sync via `set_timeout`.
        self.store.data().host.begin_call();
        let funcs = GuestFuncs {
            load: self.load.clone(),
            find_proxy: self.find_proxy.clone(),
        };
        let result = {
            let _guard = EpochGuard::begin();
            call(&funcs, &mut self.store)
        };
        self.store.data().host.end_call();
        result.map_err(|e| match e.downcast_ref::<Trap>() {
            Some(trap) => {
                self.trapped = true;
                if *trap == Trap::Interrupt {
                    Error::Timeout
                } else {
                    Error::Internal(format!("PAC guest call trapped: {e}"))
                }
            }
            None => Error::Internal(format!("PAC guest call failed: {e}")),
        })
    }

    /// Copies `s` into a fresh guest allocation.
    fn write_str(&mut self, s: &str) -> Result<(u32, u32), Error> {
        let len = u32::try_from(s.len())
            .map_err(|_| Error::Internal("string too large for guest memory".into()))?;
        let ptr = self
            .alloc
            .call(&mut self.store, len)
            .map_err(internal("allocate guest memory"))?;
        self.memory
            .write(&mut self.store, ptr as usize, s.as_bytes())
            .map_err(internal("write guest memory"))?;
        Ok((ptr, len))
    }

    /// Decodes a packed `(ptr << 32) | len` guest result (see `abi.rs`).
    fn unpack(&mut self, packed: u64) -> Result<String, Error> {
        let ptr = (packed >> 32) as usize;
        let len = (packed & 0xffff_ffff) as usize;
        if len == 0 {
            return Err(Error::Internal("empty result from PAC guest".into()));
        }
        let mut buf = vec![0u8; len];
        self.memory
            .read(&self.store, ptr, &mut buf)
            .map_err(internal("read guest result"))?;
        status_to_result(&buf)
    }
}

/// The subset of `GuestInstance` a `with_deadline` body may touch (borrowing
/// the whole struct would alias the `&mut Store`).
struct GuestFuncs {
    load: TypedFunc<(u32, u32), u64>,
    find_proxy: TypedFunc<(u32, u32, u32, u32), u64>,
}

fn internal<E: std::fmt::Display>(what: &'static str) -> impl Fn(E) -> Error {
    move |e| Error::Internal(format!("{what}: {e}"))
}

fn ticks_for(timeout: Duration) -> u64 {
    // +2: one tick may already be in flight when the deadline is armed, and
    // the division truncates.
    (timeout.as_nanos() / EPOCH_TICK.as_nanos()) as u64 + 2
}

// ---------------------------------------------------------------------------
// Process-global engine, module, and epoch watchdog.

/// The engine configuration must agree with build.rs on everything that
/// affects code generation (epoch interruption), or deserialization fails.
fn global_engine() -> Result<&'static Engine, Error> {
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    ENGINE
        .get_or_init(|| {
            let mut config = Config::new();
            config.epoch_interruption(true);
            // Must match build.rs: no CoW memory images (qemu-user, which
            // runs the aarch64 CI tests, cannot seal memfds, and this crate
            // instantiates rarely enough that CoW is worthless here).
            config.memory_init_cow(false);
            Engine::new(&config).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| Error::Internal(format!("failed to create Wasmtime engine: {e}")))
}

fn global_module() -> Result<&'static Module, Error> {
    static MODULE: OnceLock<Result<Module, String>> = OnceLock::new();
    MODULE
        .get_or_init(|| {
            let engine = global_engine().map_err(|e| e.to_string())?;
            // SAFETY: `Module::deserialize` must only be fed trusted bytes —
            // a doctored artifact can subvert the runtime. These bytes are
            // first-party: build.rs compiled them from the vendored guest
            // module and they were embedded into this binary at compile time.
            unsafe { Module::deserialize(engine, PAC_GUEST_CWASM) }.map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| Error::Internal(format!("failed to load PAC guest module: {e}")))
}

/// Watchdog driving epoch interruption: bumps the engine epoch every
/// [`EPOCH_TICK`] while at least one guest call is in flight, and parks
/// otherwise. One thread per process, started lazily.
struct EpochWatchdog {
    active: Mutex<usize>,
    wake: Condvar,
}

fn watchdog() -> &'static EpochWatchdog {
    static WATCHDOG: OnceLock<&'static EpochWatchdog> = OnceLock::new();
    WATCHDOG.get_or_init(|| {
        let watchdog: &'static EpochWatchdog = Box::leak(Box::new(EpochWatchdog {
            active: Mutex::new(0),
            wake: Condvar::new(),
        }));
        std::thread::Builder::new()
            .name("os-proxy-pac-epoch".into())
            .spawn(move || loop {
                {
                    let mut active = watchdog.active.lock().unwrap_or_else(|p| p.into_inner());
                    while *active == 0 {
                        active = watchdog
                            .wake
                            .wait(active)
                            .unwrap_or_else(|p| p.into_inner());
                    }
                }
                std::thread::sleep(EPOCH_TICK);
                if let Ok(engine) = global_engine() {
                    engine.increment_epoch();
                }
            })
            .expect("failed to spawn PAC epoch watchdog thread");
        watchdog
    })
}

/// RAII marker for "a guest call is running" — keeps the watchdog ticking.
struct EpochGuard;

impl EpochGuard {
    fn begin() -> EpochGuard {
        let watchdog = watchdog();
        let mut active = watchdog.active.lock().unwrap_or_else(|p| p.into_inner());
        *active += 1;
        watchdog.wake.notify_one();
        EpochGuard
    }
}

impl Drop for EpochGuard {
    fn drop(&mut self) {
        let watchdog = watchdog();
        let mut active = watchdog.active.lock().unwrap_or_else(|p| p.into_inner());
        *active -= 1;
    }
}

// ---------------------------------------------------------------------------
// Host imports.

/// Reads a guest string for a host import.
fn read_guest_str(
    caller: &mut Caller<'_, StoreData>,
    ptr: u32,
    len: u32,
) -> Result<String, wasmtime::Error> {
    let memory = guest_memory(caller)?;
    let mut buf = vec![0u8; len as usize];
    memory.read(&caller, ptr as usize, &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn guest_memory(caller: &mut Caller<'_, StoreData>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export("memory")
        .and_then(|e| e.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("PAC guest exports no memory"))
}

/// Stages `result` for the guest to fetch with `host_take_result`, returning
/// the length announcement (see `abi.rs`).
fn stage(caller: &mut Caller<'_, StoreData>, result: Option<String>) -> i32 {
    match result {
        None => abi::RESULT_NONE,
        Some(s) => {
            let len = s.len() as i32;
            caller.data_mut().staged = Some(s.into_bytes());
            len
        }
    }
}

/// The five PAC callbacks — the guest's entire reach into the host. Each one
/// forwards to the same [`HostState`] methods the native engine's FFI
/// trampolines call.
fn define_pac_host_imports(linker: &mut Linker<StoreData>) -> Result<(), wasmtime::Error> {
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_dns_resolve",
        |mut caller: Caller<'_, StoreData>, ptr: u32, len: u32| -> Result<i32, wasmtime::Error> {
            let host = read_guest_str(&mut caller, ptr, len)?;
            let result = caller.data().host.dns_resolve(&host);
            Ok(stage(&mut caller, result))
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_dns_resolve_ex",
        |mut caller: Caller<'_, StoreData>, ptr: u32, len: u32| -> Result<i32, wasmtime::Error> {
            let host = read_guest_str(&mut caller, ptr, len)?;
            let result = caller.data().host.dns_resolve_ex(&host);
            Ok(stage(&mut caller, Some(result)))
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_my_ip",
        |mut caller: Caller<'_, StoreData>| -> i32 {
            let result = caller.data().host.my_ip_address();
            stage(&mut caller, Some(result))
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_my_ip_ex",
        |mut caller: Caller<'_, StoreData>| -> i32 {
            let result = caller.data().host.my_ip_address_ex();
            stage(&mut caller, Some(result))
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_take_result",
        |mut caller: Caller<'_, StoreData>, dest: u32| -> Result<(), wasmtime::Error> {
            let Some(bytes) = caller.data_mut().staged.take() else {
                return Err(wasmtime::Error::msg("host_take_result: nothing staged"));
            };
            let memory = guest_memory(&mut caller)?;
            memory.write(&mut caller, dest as usize, &bytes)?;
            Ok(())
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_alert",
        |mut caller: Caller<'_, StoreData>, ptr: u32, len: u32| -> Result<(), wasmtime::Error> {
            let message = read_guest_str(&mut caller, ptr, len)?;
            caller.data().host.log(&message);
            Ok(())
        },
    )?;
    linker.func_wrap(
        abi::HOST_MODULE,
        "host_should_interrupt",
        |caller: Caller<'_, StoreData>| -> i32 {
            // Polled by the guest's QuickJS interrupt handler; runs on the
            // calling (worker) thread, so reading the Cell-based deadline is
            // safe. Nonzero aborts JS execution -> STATUS_TIMEOUT.
            let deadline = caller.data().host.deadline.get();
            deadline.is_some_and(|d| Instant::now() >= d) as i32
        },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// WASI stubs: no ambient authority.
//
// The guest is wasm32-wasip1, so wasi-libc needs a handful of imports; each is
// implemented here as a capability-free stub. There is deliberately no
// filesystem, no sockets, no environment and no args. stdout/stderr writes are
// routed to the same log sink as `alert()` (QuickJS panics/aborts end up
// there), the clock is real (PAC's `dateRange()`/`timeRange()` need civil
// time) and the RNG is a non-cryptographic splitmix64 (it only feeds
// `Math.random()` and QuickJS hash seeds inside the sandbox).

const WASI_MODULE: &str = "wasi_snapshot_preview1";

fn define_wasi_stubs(linker: &mut Linker<StoreData>) -> Result<(), wasmtime::Error> {
    linker.func_wrap(
        WASI_MODULE,
        "fd_write",
        |mut caller: Caller<'_, StoreData>,
         fd: i32,
         iovs: i32,
         iovs_len: i32,
         nwritten: i32|
         -> Result<i32, wasmtime::Error> {
            if fd != 1 && fd != 2 {
                return Ok(WASI_EBADF);
            }
            let memory = guest_memory(&mut caller)?;
            let mut gathered = Vec::new();
            for i in 0..iovs_len {
                let mut iov = [0u8; 8];
                memory.read(&caller, (iovs + i * 8) as usize, &mut iov)?;
                let ptr = u32::from_le_bytes(iov[0..4].try_into().expect("4 bytes")) as usize;
                let len = u32::from_le_bytes(iov[4..8].try_into().expect("4 bytes")) as usize;
                let start = gathered.len();
                gathered.resize(start + len, 0);
                memory.read(&caller, ptr, &mut gathered[start..])?;
            }
            let total = gathered.len() as u32;
            let text = String::from_utf8_lossy(&gathered);
            let text = text.trim_end_matches('\n');
            if !text.is_empty() {
                caller.data().host.log(text);
            }
            memory.write(&mut caller, nwritten as usize, &total.to_le_bytes())?;
            Ok(WASI_SUCCESS)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "environ_sizes_get",
        |mut caller: Caller<'_, StoreData>,
         count: i32,
         size: i32|
         -> Result<i32, wasmtime::Error> {
            let memory = guest_memory(&mut caller)?;
            memory.write(&mut caller, count as usize, &0u32.to_le_bytes())?;
            memory.write(&mut caller, size as usize, &0u32.to_le_bytes())?;
            Ok(WASI_SUCCESS)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "environ_get",
        |_caller: Caller<'_, StoreData>, _environ: i32, _buf: i32| -> i32 { WASI_SUCCESS },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "clock_time_get",
        |mut caller: Caller<'_, StoreData>,
         id: i32,
         _precision: i64,
         out: i32|
         -> Result<i32, wasmtime::Error> {
            let nanos = clock_nanos(id as u32);
            let memory = guest_memory(&mut caller)?;
            memory.write(&mut caller, out as usize, &nanos.to_le_bytes())?;
            Ok(WASI_SUCCESS)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "random_get",
        |mut caller: Caller<'_, StoreData>, buf: i32, len: i32| -> Result<i32, wasmtime::Error> {
            let mut bytes = vec![0u8; len as usize];
            fill_pseudo_random(&mut bytes);
            let memory = guest_memory(&mut caller)?;
            memory.write(&mut caller, buf as usize, &bytes)?;
            Ok(WASI_SUCCESS)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_close",
        |_caller: Caller<'_, StoreData>, _fd: i32| -> i32 { WASI_EBADF },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_fdstat_get",
        |mut caller: Caller<'_, StoreData>, fd: i32, out: i32| -> Result<i32, wasmtime::Error> {
            if !(0..=2).contains(&fd) {
                return Ok(WASI_EBADF);
            }
            // filetype = character_device, zero flags and rights.
            let mut stat = [0u8; 24];
            stat[0] = 2;
            let memory = guest_memory(&mut caller)?;
            memory.write(&mut caller, out as usize, &stat)?;
            Ok(WASI_SUCCESS)
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "fd_seek",
        |_caller: Caller<'_, StoreData>, _fd: i32, _offset: i64, _whence: i32, _out: i32| -> i32 {
            WASI_EBADF
        },
    )?;
    linker.func_wrap(
        WASI_MODULE,
        "proc_exit",
        |_caller: Caller<'_, StoreData>, code: i32| -> Result<(), wasmtime::Error> {
            Err(wasmtime::Error::msg(format!(
                "PAC guest called proc_exit({code})"
            )))
        },
    )?;
    Ok(())
}
