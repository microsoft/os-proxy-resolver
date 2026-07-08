/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! The caged PAC evaluator (macOS/Linux only — Windows delegates PAC to
//! WinHTTP).
//!
//! The embedded QuickJS engine ([`engine::PacEngine`]) wraps a QuickJS
//! context that is neither `Send` nor `Sync`, and the PAC builtins
//! `dnsResolve()` / `myIpAddress()` do synchronous network I/O. Both problems
//! are contained the same way: one dedicated worker thread owns the engine,
//! all calls are serialized through a command channel, and every
//! `FindProxyForURL` call gets a hard timeout on the caller side.
//!
//! A PAC script is untrusted JS on a live engine. A runaway JavaScript loop
//! is interrupted inside the engine by its own deadline (see
//! [`engine::PacEngine::set_timeout`]), so the worker recovers on its own.
//! But a native builtin — most importantly a blocking DNS lookup — cannot be
//! interrupted, so it can still exceed the caller's deadline. In that case
//! callers fail fast ([`Error::PacTimeout`]) while a request is outstanding,
//! and service resumes automatically once the worker completes. The
//! command/reply protocol here is deliberately process-agnostic so the worker
//! can be moved out-of-process later (Chromium-style: a subprocess you can
//! resource-limit and kill).

mod engine;

use crate::types::{parse_pac_result, sanitize_url_for_pac, Error, ProxyKind, Result};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// Handle to the process-global PAC worker. The QuickJS engine lives on a
/// single dedicated worker thread — one per *process*, shared by all
/// resolvers, created lazily and never torn down. Only the timeout is
/// per-handle.
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
// Worker thread: the only code allowed to touch the QuickJS engine.

struct WorkerState {
    /// The engine with the current script loaded. `None` until the first
    /// successful load, and cleared whenever a (re)load fails.
    engine: Option<engine::PacEngine>,
    /// Script currently loaded, with the load outcome cached so a broken
    /// script doesn't get re-parsed per request.
    current: Option<(Arc<str>, std::result::Result<(), String>)>,
    my_ip: Option<String>,
}

fn worker_loop(rx: mpsc::Receiver<EvalRequest>, shared: Arc<Shared>) {
    let mut state = WorkerState {
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

fn eval_one(state: &mut WorkerState, request: &EvalRequest) -> Result<String> {
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
fn load_script(state: &mut WorkerState, script: &str) -> std::result::Result<(), String> {
    // Drop the old engine first so only one runtime exists at a time.
    state.engine = None;
    state.my_ip = None;
    let mut engine = engine::PacEngine::new().map_err(|e| e.to_string())?;
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
