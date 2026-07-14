/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The caged PAC evaluator (macOS/Linux only — Windows delegates PAC to
//! WinHTTP).
//!
//! Three interchangeable backends implement [`PacBackend`]:
//!
//! * [`engine::PacEngine`] — QuickJS-NG compiled to native code, in-process.
//! * `engine_wasmtime::WasmtimePacEngine` (feature `pac-engine-wasmtime`) —
//!   the same QuickJS-NG compiled to WebAssembly, run inside a Wasmtime
//!   sandbox so a C-level memory-safety bug stays contained to the guest's
//!   linear memory.
//! * `engine_wasm2c::Wasm2cPacEngine` (feature `pac-engine-wasm2c`) — the
//!   same wasm guest translated to portable C with WABT's `wasm2c`, keeping
//!   the sandbox on targets Wasmtime/Cranelift cannot AOT-compile for
//!   (e.g. 32-bit armv7).
//!
//! Either engine wraps a JS context that is neither `Send` nor `Sync`, and
//! the PAC builtins `dnsResolve()` / `myIpAddress()` do synchronous network
//! I/O. Both problems are contained the same way: one dedicated worker thread
//! per backend kind owns the engine, all calls are serialized through a
//! command channel, and every `FindProxyForURL` call gets a hard timeout on
//! the caller side.
//!
//! A PAC script is untrusted JS on a live engine. A runaway JavaScript loop
//! is interrupted inside the engine by its own deadline (a QuickJS interrupt
//! handler natively; Wasmtime epoch interruption in the wasm backend), so the
//! worker recovers on its own. But a host builtin — most importantly a
//! blocking DNS lookup — cannot be interrupted, so it can still exceed the
//! caller's deadline. In that case callers fail fast ([`Error::PacTimeout`])
//! while a request is outstanding, and service resumes automatically once the
//! worker completes. The command/reply protocol here is deliberately
//! process-agnostic so a worker can be moved out-of-process later
//! (Chromium-style: a subprocess you can resource-limit and kill).

pub(crate) mod engine;
#[cfg(feature = "pac-engine-wasm2c")]
pub(crate) mod engine_wasm2c;
#[cfg(any(feature = "pac-engine-wasmtime", feature = "pac-engine-wasmtime-jit"))]
pub(crate) mod engine_wasmtime;
// The guest ABI and the runtime-agnostic host helpers shared by the wasm
// backends (the guest crate pulls wasm_abi in with `include!`; not every
// backend build uses every constant).
#[cfg(any(
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
#[allow(dead_code)]
pub(crate) mod wasm_abi;
#[cfg(any(
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
pub(crate) mod wasm_host;

use crate::types::{parse_pac_result, sanitize_url_for_pac, Error, ProxyKind, Result};
use crate::PacBackendKind;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// The engine surface the PAC worker drives. Implementations wrap one JS
/// runtime with the PAC helper library installed; they are used from a single
/// thread and need not be `Send`/`Sync` (the worker creates its engine on its
/// own thread and never lets it leave).
#[allow(dead_code)] // not every backend build uses every setter
pub(crate) trait PacBackend: Sized + 'static {
    /// Human-readable backend name (worker thread name, diagnostics).
    const NAME: &'static str;

    /// Creates an engine with the PAC helper library installed.
    fn new() -> std::result::Result<Self, engine::Error>;

    /// Evaluates a PAC script in the engine's global scope.
    fn load(&mut self, script: &str) -> std::result::Result<(), engine::Error>;

    /// Calls `FindProxyForURLEx(url, host)`, falling back to
    /// `FindProxyForURL`, and returns the raw result string.
    fn find_proxy_ex(
        &mut self,
        url: &str,
        host: &str,
    ) -> std::result::Result<String, engine::Error>;

    /// Overrides what `myIpAddress()` / `myIpAddressEx()` return (`None`
    /// restores OS-based detection).
    fn set_my_ip(&mut self, ip: Option<IpAddr>);

    /// Sets the wall-clock budget for a single load or `find_proxy*` call,
    /// enforced inside the engine.
    fn set_timeout(&mut self, timeout: Duration);

    /// Sets the JS runtime memory limit in bytes.
    fn set_memory_limit(&mut self, bytes: usize);

    /// Routes `alert()` / `console.log()` output to `sink` instead of stderr.
    fn set_log_sink(&mut self, sink: engine::state::LogSink);
}

#[cfg(feature = "pac-engine")]
impl PacBackend for engine::PacEngine {
    const NAME: &'static str = "native";

    fn new() -> std::result::Result<Self, engine::Error> {
        engine::PacEngine::new()
    }

    fn load(&mut self, script: &str) -> std::result::Result<(), engine::Error> {
        self.load(script)
    }

    fn find_proxy_ex(
        &mut self,
        url: &str,
        host: &str,
    ) -> std::result::Result<String, engine::Error> {
        self.find_proxy_ex(url, host)
    }

    fn set_my_ip(&mut self, ip: Option<IpAddr>) {
        self.set_my_ip(ip);
    }

    fn set_timeout(&mut self, timeout: Duration) {
        self.set_timeout(timeout);
    }

    fn set_memory_limit(&mut self, bytes: usize) {
        self.set_memory_limit(bytes);
    }

    fn set_log_sink(&mut self, sink: engine::state::LogSink) {
        self.set_log_sink(sink);
    }
}

/// Handle to a process-global PAC worker. Each backend kind gets one
/// dedicated worker thread per *process*, shared by all resolvers, created
/// lazily and never torn down. Only the timeout is per-handle.
pub(crate) struct PacEvaluator {
    timeout: Duration,
    kind: PacBackendKind,
}

struct Worker {
    tx: mpsc::Sender<EvalRequest>,
    shared: Arc<Shared>,
}

fn spawn_worker<B: PacBackend>() -> Worker {
    let (tx, rx) = mpsc::channel::<EvalRequest>();
    let shared = Arc::new(Shared {
        sent: AtomicU64::new(0),
        completed: AtomicU64::new(0),
        wedged_below: AtomicU64::new(0),
    });
    let worker_shared = shared.clone();
    std::thread::Builder::new()
        .name(format!("os-proxy-pac-{}", B::NAME))
        .spawn(move || worker_loop::<B>(rx, worker_shared))
        .expect("failed to spawn PAC worker thread");
    Worker { tx, shared }
}

/// The process-global worker for `kind`; `Err` when that backend is not
/// compiled into this build.
fn worker(kind: PacBackendKind) -> Result<&'static Worker> {
    match kind {
        #[cfg(feature = "pac-engine")]
        PacBackendKind::Native => {
            static WORKER: std::sync::OnceLock<Worker> = std::sync::OnceLock::new();
            Ok(WORKER.get_or_init(spawn_worker::<engine::PacEngine>))
        }
        #[cfg(not(feature = "pac-engine"))]
        PacBackendKind::Native => Err(Error::PacEval(
            "the native PAC backend is not compiled in (enable the \
             `pac-engine` feature)"
                .into(),
        )),
        #[cfg(feature = "pac-engine-wasmtime")]
        PacBackendKind::Wasmtime => {
            static WORKER: std::sync::OnceLock<Worker> = std::sync::OnceLock::new();
            Ok(WORKER.get_or_init(spawn_worker::<engine_wasmtime::WasmtimePacEngine>))
        }
        #[cfg(not(feature = "pac-engine-wasmtime"))]
        PacBackendKind::Wasmtime => Err(Error::PacEval(
            "the Wasmtime PAC backend is not compiled in (enable the \
             `pac-engine-wasmtime` feature)"
                .into(),
        )),
        #[cfg(feature = "pac-engine-wasm2c")]
        PacBackendKind::Wasm2c => {
            static WORKER: std::sync::OnceLock<Worker> = std::sync::OnceLock::new();
            Ok(WORKER.get_or_init(spawn_worker::<engine_wasm2c::Wasm2cPacEngine>))
        }
        #[cfg(not(feature = "pac-engine-wasm2c"))]
        PacBackendKind::Wasm2c => Err(Error::PacEval(
            "the wasm2c PAC backend is not compiled in (enable the \
             `pac-engine-wasm2c` feature)"
                .into(),
        )),
        #[cfg(feature = "pac-engine-wasmtime-jit")]
        PacBackendKind::WasmtimeJit => {
            static WORKER: std::sync::OnceLock<Worker> = std::sync::OnceLock::new();
            Ok(WORKER.get_or_init(spawn_worker::<engine_wasmtime::WasmtimeJitPacEngine>))
        }
        #[cfg(not(feature = "pac-engine-wasmtime-jit"))]
        PacBackendKind::WasmtimeJit => Err(Error::PacEval(
            "the Wasmtime JIT PAC backend is not compiled in (enable the \
             `pac-engine-wasmtime-jit` feature)"
                .into(),
        )),
    }
}

struct Shared {
    /// Highest request id handed to the worker.
    sent: AtomicU64,
    /// Highest request id the worker has finished (in submission order).
    completed: AtomicU64,
    /// Set to a request id when that request timed out; the evaluator is
    /// considered wedged until `completed` catches up to it.
    wedged_below: AtomicU64,
}

struct EvalRequest {
    id: u64,
    script: Arc<str>,
    url: String,
    host: String,
    my_ip: Option<String>,
    reply: mpsc::SyncSender<Result<String>>,
}

impl PacEvaluator {
    pub fn new(timeout: Duration, kind: PacBackendKind) -> Self {
        PacEvaluator { timeout, kind }
    }

    /// Evaluate `FindProxyForURL` for `url` against `script`.
    ///
    /// The URL is sanitized before it reaches the (untrusted) script: identity
    /// is always stripped, and for https/wss the path and query are dropped
    /// too, so a hostile PAC/WPAD author cannot exfiltrate request details.
    pub fn find_proxy(
        &self,
        script: &Arc<str>,
        url: &Url,
        my_ip: Option<String>,
    ) -> Result<Vec<ProxyKind>> {
        let host = url
            .host_str()
            .ok_or_else(|| Error::InvalidUrl(url.to_string()))?
            .to_string();
        let sanitized = sanitize_url_for_pac(url);

        let worker = worker(self.kind)?;
        // Fail fast while a previously timed-out call is still outstanding —
        // the worker may be stuck in blocking DNS or an infinite JS loop, and
        // queueing more work would just serialize more timeouts behind it.
        let completed = worker.shared.completed.load(Ordering::Acquire);
        if completed < worker.shared.wedged_below.load(Ordering::Acquire) {
            return Err(Error::PacTimeout);
        }

        let id = worker.shared.sent.fetch_add(1, Ordering::AcqRel) + 1;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let request = EvalRequest {
            id,
            script: script.clone(),
            url: sanitized,
            host,
            my_ip,
            reply: reply_tx,
        };
        if worker.tx.send(request).is_err() {
            return Err(Error::PacEval("PAC worker thread is gone".into()));
        }
        let result = match reply_rx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                worker.shared.wedged_below.fetch_max(id, Ordering::AcqRel);
                return Err(Error::PacTimeout);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::PacEval("PAC worker thread is gone".into()))
            }
        };
        let text = result?;
        Ok(parse_pac_result(&text))
    }
}

// ---------------------------------------------------------------------------
// Worker thread: the only code allowed to touch its JS engine.

struct WorkerState<B: PacBackend> {
    /// The engine with the current script loaded. `None` until the first
    /// successful load, and cleared whenever a (re)load fails.
    engine: Option<B>,
    /// Script currently loaded, with the load outcome cached so a broken
    /// script doesn't get re-parsed per request.
    current: Option<(Arc<str>, std::result::Result<(), String>)>,
    my_ip: Option<String>,
}

fn worker_loop<B: PacBackend>(rx: mpsc::Receiver<EvalRequest>, shared: Arc<Shared>) {
    let mut state = WorkerState::<B> {
        engine: None,
        current: None,
        my_ip: None,
    };
    while let Ok(request) = rx.recv() {
        let result = eval_one(&mut state, &request);
        shared.completed.store(request.id, Ordering::Release);
        // Receiver may have timed out and gone away; that's fine.
        let _ = request.reply.send(result);
    }
}

fn eval_one<B: PacBackend>(state: &mut WorkerState<B>, request: &EvalRequest) -> Result<String> {
    let needs_reload = match &state.current {
        Some((script, _)) => !same_script(script, &request.script),
        None => true,
    };
    if needs_reload {
        let outcome = load_script(state, &request.script);
        state.current = Some((request.script.clone(), outcome));
    }
    if let Some((_, Err(msg))) = &state.current {
        return Err(Error::PacEval(msg.clone()));
    }

    let engine = state
        .engine
        .as_mut()
        .expect("engine is present after a successful load");

    // A fresh engine starts with OS-based `myIpAddress`; only touch the
    // override when the requested value actually changes.
    if request.my_ip != state.my_ip {
        let ip = request
            .my_ip
            .as_deref()
            .and_then(|s| s.parse::<IpAddr>().ok());
        engine.set_my_ip(ip);
        state.my_ip = request.my_ip.clone();
    }

    match engine.find_proxy_ex(&request.url, &request.host) {
        Ok(result) => Ok(result),
        // A runaway JS loop is interrupted by the engine's own backstop
        // deadline; surface it the same way as a caller-side timeout.
        Err(engine::Error::Timeout) => Err(Error::PacTimeout),
        Err(e) => Err(Error::PacEval(e.to_string())),
    }
}

/// Builds a fresh engine for `script` (discarding any previous one, so a new
/// script never inherits stale globals) and loads it.
fn load_script<B: PacBackend>(
    state: &mut WorkerState<B>,
    script: &str,
) -> std::result::Result<(), String> {
    // Drop the old engine first so only one runtime exists at a time.
    state.engine = None;
    state.my_ip = None;
    let mut engine = B::new().map_err(|e| e.to_string())?;
    engine.load(script).map_err(|e| e.to_string())?;
    state.engine = Some(engine);
    Ok(())
}

fn same_script(a: &Arc<str>, b: &Arc<str>) -> bool {
    Arc::ptr_eq(a, b) || a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval_with(kind: PacBackendKind, pac: &str, url: &str) -> Result<Vec<ProxyKind>> {
        // Generous caller-side timeout: it is only an upper bound (the call
        // returns as soon as the worker replies). Slow-but-correct cases it
        // must absorb: the wasm2c backend under qemu in debug CI builds, and
        // the JIT backend's first call, which compiles the guest with a
        // debug-profile Cranelift.
        let evaluator = PacEvaluator::new(Duration::from_secs(120), kind);
        let script: Arc<str> = Arc::from(pac);
        evaluator.find_proxy(&script, &Url::parse(url).unwrap(), None)
    }

    /// The backends compiled into this build; unit tests run against all.
    fn kinds() -> Vec<PacBackendKind> {
        let mut kinds = Vec::new();
        if cfg!(feature = "pac-engine") {
            kinds.push(PacBackendKind::Native);
        }
        if cfg!(feature = "pac-engine-wasmtime") {
            kinds.push(PacBackendKind::Wasmtime);
        }
        if cfg!(feature = "pac-engine-wasm2c") {
            kinds.push(PacBackendKind::Wasm2c);
        }
        if cfg!(feature = "pac-engine-wasmtime-jit") {
            kinds.push(PacBackendKind::WasmtimeJit);
        }
        kinds
    }

    #[test]
    fn direct_pac() {
        for kind in kinds() {
            let got = eval_with(
                kind,
                "function FindProxyForURL(url, host) { return 'DIRECT'; }",
                "http://example.com/",
            )
            .unwrap();
            assert_eq!(got, vec![ProxyKind::Direct], "backend: {kind:?}");
        }
    }

    #[test]
    fn conditional_pac_and_script_switch() {
        for kind in kinds() {
            // Generous caller-side timeout: it is only an upper bound (the call
            // returns as soon as the worker replies), and the wasm2c backend
            // under qemu in debug CI builds needs several seconds per call.
            let evaluator = PacEvaluator::new(Duration::from_secs(60), kind);
            let pac_a: Arc<str> = Arc::from(
                "function FindProxyForURL(url, host) {\
                   if (dnsDomainIs(host, '.corp.example.com')) return 'PROXY p:3128; DIRECT';\
                   return 'DIRECT';\
                 }",
            );
            let url = Url::parse("https://db.corp.example.com/x").unwrap();
            assert_eq!(
                evaluator.find_proxy(&pac_a, &url, None).unwrap(),
                vec![ProxyKind::Http("p:3128".into()), ProxyKind::Direct],
                "backend: {kind:?}"
            );
            // Same evaluator, new script: context must be rebuilt.
            let pac_b: Arc<str> =
                Arc::from("function FindProxyForURL(url, host) { return 'SOCKS5 s:9'; }");
            assert_eq!(
                evaluator.find_proxy(&pac_b, &url, None).unwrap(),
                vec![ProxyKind::Socks("s:9".into())],
                "backend: {kind:?}"
            );
        }
    }

    #[test]
    fn https_url_is_stripped_before_eval() {
        for kind in kinds() {
            let got = eval_with(
                kind,
                "function FindProxyForURL(url, host) {\
                   if (url.indexOf('secret') != -1) return 'PROXY leak:1';\
                   return 'DIRECT';\
                 }",
                "https://user:pw@example.com/secret?token=secret",
            )
            .unwrap();
            assert_eq!(got, vec![ProxyKind::Direct], "backend: {kind:?}");
        }
    }

    #[test]
    fn http_url_keeps_path_but_not_identity() {
        assert_eq!(
            sanitize_url_for_pac(&Url::parse("http://u:p@h:8080/a/b?c=d#frag").unwrap()),
            "http://h:8080/a/b?c=d"
        );
        assert_eq!(
            sanitize_url_for_pac(&Url::parse("https://h/a/b?c=d").unwrap()),
            "https://h/"
        );
    }

    #[test]
    fn broken_script_reports_error() {
        for kind in kinds() {
            let err =
                eval_with(kind, "this is not javascript{{{", "http://example.com/").unwrap_err();
            match err {
                Error::PacEval(_) => {}
                other => panic!("expected PacEval, got {other:?} (backend: {kind:?})"),
            }
        }
    }

    #[test]
    fn myip_override() {
        for kind in kinds() {
            // Generous caller-side timeout: it is only an upper bound (the call
            // returns as soon as the worker replies), and the wasm2c backend
            // under qemu in debug CI builds needs several seconds per call.
            let evaluator = PacEvaluator::new(Duration::from_secs(60), kind);
            let script: Arc<str> = Arc::from(
                "function FindProxyForURL(url, host) { return 'PROXY ' + myIpAddress() + ':1'; }",
            );
            let url = Url::parse("http://example.com/").unwrap();
            let got = evaluator
                .find_proxy(&script, &url, Some("10.9.8.7".into()))
                .unwrap();
            assert_eq!(
                got,
                vec![ProxyKind::Http("10.9.8.7:1".into())],
                "backend: {kind:?}"
            );
        }
    }

    #[test]
    fn wasmtime_without_feature_reports_unavailable() {
        if cfg!(feature = "pac-engine-wasmtime") {
            return;
        }
        let err = eval_with(
            PacBackendKind::Wasmtime,
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
        )
        .unwrap_err();
        match err {
            Error::PacEval(msg) => assert!(msg.contains("pac-engine-wasmtime"), "{msg}"),
            other => panic!("expected PacEval, got {other:?}"),
        }
    }

    #[test]
    fn native_without_feature_reports_unavailable() {
        if cfg!(feature = "pac-engine") {
            return;
        }
        let err = eval_with(
            PacBackendKind::Native,
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
        )
        .unwrap_err();
        match err {
            Error::PacEval(msg) => assert!(msg.contains("pac-engine"), "{msg}"),
            other => panic!("expected PacEval, got {other:?}"),
        }
    }

    #[test]
    fn wasmtime_jit_without_feature_reports_unavailable() {
        if cfg!(feature = "pac-engine-wasmtime-jit") {
            return;
        }
        let err = eval_with(
            PacBackendKind::WasmtimeJit,
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
        )
        .unwrap_err();
        match err {
            Error::PacEval(msg) => assert!(msg.contains("pac-engine-wasmtime-jit"), "{msg}"),
            other => panic!("expected PacEval, got {other:?}"),
        }
    }

    #[test]
    fn wasm2c_without_feature_reports_unavailable() {
        if cfg!(feature = "pac-engine-wasm2c") {
            return;
        }
        let err = eval_with(
            PacBackendKind::Wasm2c,
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
        )
        .unwrap_err();
        match err {
            Error::PacEval(msg) => assert!(msg.contains("pac-engine-wasm2c"), "{msg}"),
            other => panic!("expected PacEval, got {other:?}"),
        }
    }

    // The hostile-PAC (infinite loop) timeout tests live in
    // tests/hostile_pac.rs: they permanently wedge the process-global
    // workers, so they need their own test process.
}
