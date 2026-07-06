/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The caged PAC evaluator (macOS/Linux only — Windows delegates PAC to
//! WinHTTP).
//!
//! pacparser has a single global, non-thread-safe context, and the PAC
//! builtins `dnsResolve()` / `myIpAddress()` do synchronous network I/O. Both
//! problems are contained the same way: one dedicated worker thread owns the
//! context, all calls are serialized through a command channel, and every
//! `FindProxyForURL` call gets a hard timeout on the caller side.
//!
//! A PAC script is untrusted JS on a live engine. If a hostile script loops
//! forever, the worker thread is wedged — it cannot be killed safely (the
//! global C context would be corrupted). Instead, callers fail fast
//! ([`Error::PacTimeout`]) while a request is outstanding past its deadline,
//! and service resumes automatically if the worker ever completes. The
//! command/reply protocol here is deliberately process-agnostic so the worker
//! can be moved out-of-process later (Chromium-style: a subprocess you can
//! resource-limit and kill), which is the real fix.

mod ffi;

use crate::types::{parse_pac_result, sanitize_url_for_pac, Error, ProxyKind, Result};
use std::ffi::{CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Handle to the process-global PAC worker. pacparser's context is a single
/// global — one worker thread per *process*, shared by all resolvers, created
/// lazily and never torn down. Only the timeout is per-handle.
pub(crate) struct PacEvaluator {
    timeout: Duration,
}

struct Worker {
    tx: mpsc::Sender<EvalRequest>,
    shared: Arc<Shared>,
}

fn worker() -> &'static Worker {
    static WORKER: std::sync::OnceLock<Worker> = std::sync::OnceLock::new();
    WORKER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<EvalRequest>();
        let shared = Arc::new(Shared {
            sent: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            wedged_below: AtomicU64::new(0),
        });
        let worker_shared = shared.clone();
        std::thread::Builder::new()
            .name("os-proxy-pac".into())
            .spawn(move || worker_loop(rx, worker_shared))
            .expect("failed to spawn PAC worker thread");
        Worker { tx, shared }
    })
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
    pub fn new(timeout: Duration) -> Self {
        PacEvaluator { timeout }
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

        let worker = worker();
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
// Worker thread: the only code allowed to touch pacparser.

struct WorkerState {
    /// Script currently loaded into the global context, with the parse
    /// outcome cached so a broken script doesn't get re-parsed per request.
    current: Option<(Arc<str>, std::result::Result<(), String>)>,
    initialized: bool,
    my_ip: Option<String>,
}

fn worker_loop(rx: mpsc::Receiver<EvalRequest>, shared: Arc<Shared>) {
    unsafe {
        ffi::ospr_install_error_printer();
        ffi::pacparser_enable_microsoft_extensions();
    }
    let mut state = WorkerState {
        current: None,
        initialized: false,
        my_ip: None,
    };
    while let Ok(request) = rx.recv() {
        let result = eval_one(&mut state, &request);
        shared.completed.store(request.id, Ordering::Release);
        // Receiver may have timed out and gone away; that's fine.
        let _ = request.reply.send(result);
    }
    if state.initialized {
        unsafe { ffi::pacparser_cleanup() };
    }
}

fn eval_one(state: &mut WorkerState, request: &EvalRequest) -> Result<String> {
    let needs_parse = match &state.current {
        Some((script, _)) => !same_script(script, &request.script),
        None => true,
    };
    if needs_parse {
        let outcome = parse_script(state, &request.script);
        state.current = Some((request.script.clone(), outcome));
    }
    if let Some((_, Err(msg))) = &state.current {
        return Err(Error::PacEval(msg.clone()));
    }

    if request.my_ip != state.my_ip {
        if let Some(ip) = &request.my_ip {
            if let Ok(c_ip) = CString::new(ip.as_str()) {
                unsafe { ffi::pacparser_setmyip(c_ip.as_ptr()) };
            }
        }
        state.my_ip = request.my_ip.clone();
    }

    let c_url =
        CString::new(request.url.as_str()).map_err(|_| Error::InvalidUrl(request.url.clone()))?;
    let c_host =
        CString::new(request.host.as_str()).map_err(|_| Error::InvalidUrl(request.host.clone()))?;
    unsafe {
        ffi::ospr_clear_error();
        let ptr = ffi::pacparser_find_proxy(c_url.as_ptr(), c_host.as_ptr());
        if ptr.is_null() {
            let msg = ffi::take_error();
            return Err(Error::PacEval(if msg.is_empty() {
                "FindProxyForURL returned no result".into()
            } else {
                msg
            }));
        }
        // Library-owned; copy before the next pacparser call frees it.
        Ok(CStr::from_ptr(ptr).to_string_lossy().into_owned())
    }
}

fn parse_script(state: &mut WorkerState, script: &str) -> std::result::Result<(), String> {
    unsafe {
        if state.initialized {
            ffi::pacparser_cleanup();
            state.initialized = false;
            state.my_ip = None;
        }
        ffi::ospr_clear_error();
        if ffi::pacparser_init() != 1 {
            return Err(format!("pacparser_init failed: {}", ffi::take_error()));
        }
        state.initialized = true;
        let c_script = CString::new(script).map_err(|_| "PAC script contains NUL".to_string())?;
        if ffi::pacparser_parse_pac_string(c_script.as_ptr()) != 1 {
            return Err(format!("PAC parse failed: {}", ffi::take_error()));
        }
        Ok(())
    }
}

fn same_script(a: &Arc<str>, b: &Arc<str>) -> bool {
    Arc::ptr_eq(a, b) || a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(pac: &str, url: &str) -> Result<Vec<ProxyKind>> {
        let evaluator = PacEvaluator::new(Duration::from_secs(2));
        let script: Arc<str> = Arc::from(pac);
        evaluator.find_proxy(&script, &Url::parse(url).unwrap(), None)
    }

    #[test]
    fn direct_pac() {
        let got = eval(
            "function FindProxyForURL(url, host) { return 'DIRECT'; }",
            "http://example.com/",
        )
        .unwrap();
        assert_eq!(got, vec![ProxyKind::Direct]);
    }

    #[test]
    fn conditional_pac_and_script_switch() {
        let evaluator = PacEvaluator::new(Duration::from_secs(2));
        let pac_a: Arc<str> = Arc::from(
            "function FindProxyForURL(url, host) {\
               if (dnsDomainIs(host, '.corp.example.com')) return 'PROXY p:3128; DIRECT';\
               return 'DIRECT';\
             }",
        );
        let url = Url::parse("https://db.corp.example.com/x").unwrap();
        assert_eq!(
            evaluator.find_proxy(&pac_a, &url, None).unwrap(),
            vec![ProxyKind::Http("p:3128".into()), ProxyKind::Direct]
        );
        // Same evaluator, new script: context must be rebuilt.
        let pac_b: Arc<str> =
            Arc::from("function FindProxyForURL(url, host) { return 'SOCKS5 s:9'; }");
        assert_eq!(
            evaluator.find_proxy(&pac_b, &url, None).unwrap(),
            vec![ProxyKind::Socks("s:9".into())]
        );
    }

    #[test]
    fn https_url_is_stripped_before_eval() {
        let got = eval(
            "function FindProxyForURL(url, host) {\
               if (url.indexOf('secret') != -1) return 'PROXY leak:1';\
               return 'DIRECT';\
             }",
            "https://user:pw@example.com/secret?token=secret",
        )
        .unwrap();
        assert_eq!(got, vec![ProxyKind::Direct]);
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
        let err = eval("this is not javascript{{{", "http://example.com/").unwrap_err();
        match err {
            Error::PacEval(_) => {}
            other => panic!("expected PacEval, got {other:?}"),
        }
    }

    #[test]
    fn myip_override() {
        let evaluator = PacEvaluator::new(Duration::from_secs(2));
        let script: Arc<str> = Arc::from(
            "function FindProxyForURL(url, host) { return 'PROXY ' + myIpAddress() + ':1'; }",
        );
        let url = Url::parse("http://example.com/").unwrap();
        let got = evaluator
            .find_proxy(&script, &url, Some("10.9.8.7".into()))
            .unwrap();
        assert_eq!(got, vec![ProxyKind::Http("10.9.8.7:1".into())]);
    }

    // The hostile-PAC (infinite loop) timeout test lives in
    // tests/hostile_pac.rs: it permanently wedges the process-global worker,
    // so it needs its own test process.
}
