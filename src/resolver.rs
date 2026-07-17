/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Orchestration: precedence (env vars → OS config → DIRECT), generation-
//! keyed caches, change notification, and the bad-proxy feedback loop.

use crate::env_cfg::EnvConfig;
use crate::notify::{Notifier, Subscription};
use crate::platform::{self, OsProxyConfig};
use crate::types::{
    Error, PacBackendKind, PacScript, PacScriptSource, PacSourceState, PacSourceStatus,
    ProxyConfig, ProxyKind, Result, StaticProxyRules,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};
use url::Url;

#[cfg(feature = "tokio")]
use std::sync::Weak;

#[cfg(feature = "tokio")]
const ASYNC_RESOLUTION_QUEUE_CAPACITY: usize = 256;

/// Tunables for a [`ProxyResolver`]. Construct with `Default::default()` and
/// override fields as needed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ResolverOptions {
    /// Hard timeout for a single embedded `FindProxyForURL` call.
    pub pac_timeout: Duration,
    /// Timeout for fetching an explicitly configured PAC script.
    pub pac_fetch_timeout: Duration,
    /// How long a fetched PAC script is reused before re-fetching (config
    /// changes invalidate it earlier via the generation counter).
    pub pac_ttl: Duration,
    /// Backoff before re-trying a failed PAC fetch.
    pub pac_error_retry: Duration,
    /// Timeout for each `wpad.<domain>` DNS probe. Kept tight so a network
    /// without WPAD doesn't stall first requests (Chromium uses ~100ms).
    pub wpad_dns_timeout: Duration,
    /// Timeout for fetching `wpad.dat` once a candidate resolves.
    pub wpad_fetch_timeout: Duration,
    /// How long "no WPAD on this network" is cached.
    pub wpad_negative_ttl: Duration,
    /// Cooldown during which a proxy reported via
    /// [`ProxyResolver::report_proxy_failed`] is demoted to the end of results.
    pub retry_cooldown: Duration,
    /// Re-read the OS config after this long even without a change signal
    /// (covers platforms where no watcher could be started).
    pub config_ttl: Duration,
    /// How long a completed per-URL proxy decision is reused. OS proxy config
    /// changes invalidate cached decisions immediately.
    pub resolution_ttl: Duration,
    /// Maximum number of completed per-URL proxy decisions to retain.
    pub resolution_cache_capacity: usize,
    /// Which embedded engine evaluates PAC scripts (normal resolution,
    /// [`ProxyResolver::evaluate_pac`], and the non-WinHTTP paths of
    /// [`ProxyResolver::evaluate_pac_source`]). The default is the sandboxed
    /// WebAssembly engine ([`PacBackendKind::Wasmtime`], which requires the
    /// `pac-engine-wasmtime` feature);
    /// [`PacBackendKind::Native`] selects the in-process native engine.
    pub pac_backend: PacBackendKind,
}

impl Default for ResolverOptions {
    fn default() -> Self {
        ResolverOptions {
            pac_timeout: Duration::from_secs(5),
            pac_fetch_timeout: Duration::from_secs(5),
            pac_ttl: Duration::from_secs(3600),
            pac_error_retry: Duration::from_secs(30),
            wpad_dns_timeout: Duration::from_millis(300),
            wpad_fetch_timeout: Duration::from_secs(2),
            wpad_negative_ttl: Duration::from_secs(300),
            retry_cooldown: Duration::from_secs(300),
            config_ttl: Duration::from_secs(30),
            resolution_ttl: Duration::from_secs(30),
            resolution_cache_capacity: 256,
            pac_backend: PacBackendKind::default(),
        }
    }
}

/// Resolves the proxy (or proxies) to use for a URL from the OS
/// configuration, mirroring PAC semantics. Cheap to clone (shared state).
///
/// Most callers can use the process-wide instance via
/// [`crate::resolve_proxy`] / [`ProxyResolver::global`].
#[derive(Clone)]
pub struct ProxyResolver {
    inner: Arc<Inner>,
}

struct Inner {
    options: ResolverOptions,
    env: EnvConfig,
    notifier: Arc<Notifier>,
    /// Keeps the platform change watcher alive; dropped with the resolver.
    _watcher: platform::Watcher,
    config_cache: Mutex<Option<ConfigCache>>,
    resolution_cache: Mutex<HashMap<String, ResolutionCacheEntry>>,
    retry: Mutex<HashMap<ProxyKind, Instant>>,
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    pac: OnceLock<crate::pac::PacEvaluator>,
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    pac_cache: Mutex<Option<PacScriptCache>>,
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    wpad_cache: Mutex<Option<WpadCache>>,
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    my_ip: Mutex<Option<(Instant, Option<String>)>>,
    #[cfg(all(
        windows,
        not(any(
            feature = "pac-engine",
            feature = "pac-engine-wasmtime",
            feature = "pac-engine-wasmtime-jit",
            feature = "pac-engine-wasm2c"
        ))
    ))]
    winhttp: OnceLock<Option<platform::WinHttpResolver>>,
    #[cfg(feature = "tokio")]
    async_worker: OnceLock<std::result::Result<AsyncResolverWorker, String>>,
    #[cfg(all(test, feature = "tokio"))]
    async_resolution_starts: std::sync::atomic::AtomicUsize,
    #[cfg(all(test, feature = "tokio"))]
    async_resolution_delay: Mutex<Option<Duration>>,
}

struct ConfigCache {
    generation: u64,
    read_at: Instant,
    config: OsProxyConfig,
}

struct ResolutionCacheEntry {
    generation: u64,
    at: Instant,
    proxies: Vec<ProxyKind>,
}

#[cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
struct PacScriptCache {
    source: String,
    generation: u64,
    at: Instant,
    /// `None` = fetch failed (negative-cached with `pac_error_retry`).
    script: Option<Arc<str>>,
}

#[cfg(any(
    not(windows),
    feature = "pac-engine",
    feature = "pac-engine-wasmtime",
    feature = "pac-engine-wasmtime-jit",
    feature = "pac-engine-wasm2c"
))]
struct WpadCache {
    generation: u64,
    at: Instant,
    /// `None` = no WPAD on this network (negative-cached).
    script: Option<Arc<str>>,
}

struct PacInspection {
    pac: Option<PacScript>,
    status: PacSourceStatus,
}

impl PacInspection {
    fn state(state: PacSourceState) -> Self {
        Self {
            pac: None,
            status: PacSourceStatus::new(state),
        }
    }

    fn available(pac: PacScript) -> Self {
        Self {
            status: PacSourceStatus {
                state: PacSourceState::Available,
                url: Some(pac.url.clone()),
                error: None,
            },
            pac: Some(pac),
        }
    }

    fn error(state: PacSourceState, url: Option<String>, error: String) -> Self {
        Self {
            pac: None,
            status: PacSourceStatus {
                state,
                url,
                error: Some(error),
            },
        }
    }
}

#[cfg(feature = "tokio")]
#[derive(Clone, PartialEq, Eq, Hash)]
struct AsyncResolutionKey {
    generation: u64,
    url: String,
}

#[cfg(feature = "tokio")]
type AsyncResolutionSender = tokio::sync::watch::Sender<Option<Result<Vec<ProxyKind>>>>;

#[cfg(feature = "tokio")]
struct AsyncResolutionRequest {
    key: AsyncResolutionKey,
    url: Url,
}

#[cfg(feature = "tokio")]
struct AsyncSubmissionGuard {
    key: AsyncResolutionKey,
    inflight: Arc<Mutex<HashMap<AsyncResolutionKey, AsyncResolutionSender>>>,
    armed: bool,
}

#[cfg(feature = "tokio")]
impl AsyncSubmissionGuard {
    fn new(
        key: AsyncResolutionKey,
        inflight: Arc<Mutex<HashMap<AsyncResolutionKey, AsyncResolutionSender>>>,
    ) -> Self {
        Self {
            key,
            inflight,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(feature = "tokio")]
impl Drop for AsyncSubmissionGuard {
    fn drop(&mut self) {
        if self.armed {
            lock(&self.inflight).remove(&self.key);
        }
    }
}

/// One blocking resolver thread per [`ProxyResolver`], created lazily by the
/// async API. The in-flight map lets identical callers await the same result
/// without occupying one blocking thread each; distinct targets queue on the
/// single worker so blocking OS/PAC/WPAD work has fixed thread consumption.
#[cfg(feature = "tokio")]
struct AsyncResolverWorker {
    tx: tokio::sync::mpsc::Sender<AsyncResolutionRequest>,
    inflight: Arc<Mutex<HashMap<AsyncResolutionKey, AsyncResolutionSender>>>,
}

#[cfg(feature = "tokio")]
impl AsyncResolverWorker {
    fn new(inner: Weak<Inner>) -> std::result::Result<Self, String> {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<AsyncResolutionRequest>(ASYNC_RESOLUTION_QUEUE_CAPACITY);
        let inflight: Arc<Mutex<HashMap<AsyncResolutionKey, AsyncResolutionSender>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let worker_inflight = inflight.clone();
        std::thread::Builder::new()
            .name("os-proxy-resolver".to_string())
            .spawn(move || {
                while let Some(request) = rx.blocking_recv() {
                    let result = match inner.upgrade() {
                        Some(inner) => {
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                #[cfg(all(test, feature = "tokio"))]
                                {
                                    use std::sync::atomic::Ordering;

                                    inner.async_resolution_starts.fetch_add(1, Ordering::SeqCst);
                                    if let Some(delay) = *lock(&inner.async_resolution_delay) {
                                        std::thread::sleep(delay);
                                    }
                                }
                                ProxyResolver { inner }.resolve_proxy(&request.url)
                            }))
                            .unwrap_or_else(|_| {
                                Err(Error::Platform(
                                    "proxy resolver worker panicked during resolution".to_string(),
                                ))
                            })
                        }
                        None => Err(Error::Platform(
                            "proxy resolver was dropped during async resolution".to_string(),
                        )),
                    };
                    // Remove while holding the lock, then notify after the guard
                    // is dropped. An `if let lock(...).get(...).cloned()` keeps
                    // the temporary guard alive through its body, so locking
                    // again there deadlocks this sole resolver thread.
                    let sender = lock(&worker_inflight).remove(&request.key);
                    if let Some(sender) = sender {
                        let _ = sender.send(Some(result));
                    }
                }
            })
            .map_err(|error| format!("failed to spawn proxy resolver worker: {error}"))?;
        Ok(Self { tx, inflight })
    }

    async fn resolve(&self, generation: u64, url: &Url) -> Result<Vec<ProxyKind>> {
        let mut key_url = url.clone();
        key_url.set_fragment(None);
        let _ = key_url.set_username("");
        let _ = key_url.set_password(None);
        let key = AsyncResolutionKey {
            generation,
            url: key_url.as_str().to_string(),
        };
        let (mut receiver, leader) = {
            let mut inflight = lock(&self.inflight);
            match inflight.get(&key) {
                Some(sender) => (sender.subscribe(), false),
                None => {
                    let (sender, receiver) = tokio::sync::watch::channel(None);
                    inflight.insert(key.clone(), sender);
                    (receiver, true)
                }
            }
        };

        if leader {
            // If this future is canceled while the bounded queue is full,
            // remove its unresolved in-flight entry. Dropping the sender wakes
            // followers with a closed-channel error so a later call can retry.
            let mut submission = AsyncSubmissionGuard::new(key.clone(), self.inflight.clone());
            if self
                .tx
                .send(AsyncResolutionRequest {
                    key: key.clone(),
                    url: url.clone(),
                })
                .await
                .is_err()
            {
                let error = Error::Platform("proxy resolver worker is unavailable".to_string());
                if let Some(sender) = lock(&self.inflight).remove(&key) {
                    let _ = sender.send(Some(Err(error.clone())));
                }
                submission.disarm();
                return Err(error);
            }
            submission.disarm();
        }

        let result = match receiver.wait_for(Option::is_some).await {
            Ok(result) => match result.clone() {
                Some(result) => result,
                None => Err(Error::Platform(
                    "proxy resolver worker returned no result".to_string(),
                )),
            },
            Err(_) => Err(Error::Platform(
                "proxy resolver worker stopped before returning a result".to_string(),
            )),
        };
        result
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ProxyResolver {
    /// Create a resolver with default options. The proxy environment
    /// variables are snapshotted here; the OS configuration is read (and
    /// watched) dynamically.
    pub fn new() -> Self {
        Self::with_options(ResolverOptions::default())
    }

    pub fn with_options(options: ResolverOptions) -> Self {
        Self::build(options, EnvConfig::from_env())
    }

    fn build(options: ResolverOptions, env: EnvConfig) -> Self {
        let notifier = Arc::new(Notifier::new());
        let for_watcher = notifier.clone();
        let watcher = platform::spawn_watcher(Arc::new(move || for_watcher.bump()));
        ProxyResolver {
            inner: Arc::new(Inner {
                options,
                env,
                notifier,
                _watcher: watcher,
                config_cache: Mutex::new(None),
                resolution_cache: Mutex::new(HashMap::new()),
                retry: Mutex::new(HashMap::new()),
                #[cfg(any(
                    not(windows),
                    feature = "pac-engine",
                    feature = "pac-engine-wasmtime",
                    feature = "pac-engine-wasmtime-jit",
                    feature = "pac-engine-wasm2c"
                ))]
                pac: OnceLock::new(),
                #[cfg(any(
                    not(windows),
                    feature = "pac-engine",
                    feature = "pac-engine-wasmtime",
                    feature = "pac-engine-wasmtime-jit",
                    feature = "pac-engine-wasm2c"
                ))]
                pac_cache: Mutex::new(None),
                #[cfg(any(
                    not(windows),
                    feature = "pac-engine",
                    feature = "pac-engine-wasmtime",
                    feature = "pac-engine-wasmtime-jit",
                    feature = "pac-engine-wasm2c"
                ))]
                wpad_cache: Mutex::new(None),
                #[cfg(any(
                    not(windows),
                    feature = "pac-engine",
                    feature = "pac-engine-wasmtime",
                    feature = "pac-engine-wasmtime-jit",
                    feature = "pac-engine-wasm2c"
                ))]
                my_ip: Mutex::new(None),
                #[cfg(all(
                    windows,
                    not(any(
                        feature = "pac-engine",
                        feature = "pac-engine-wasmtime",
                        feature = "pac-engine-wasmtime-jit",
                        feature = "pac-engine-wasm2c"
                    ))
                ))]
                winhttp: OnceLock::new(),
                #[cfg(feature = "tokio")]
                async_worker: OnceLock::new(),
                #[cfg(all(test, feature = "tokio"))]
                async_resolution_starts: std::sync::atomic::AtomicUsize::new(0),
                #[cfg(all(test, feature = "tokio"))]
                async_resolution_delay: Mutex::new(None),
            }),
        }
    }

    /// The process-wide resolver (created on first use).
    pub fn global() -> &'static ProxyResolver {
        static GLOBAL: OnceLock<ProxyResolver> = OnceLock::new();
        GLOBAL.get_or_init(ProxyResolver::new)
    }

    /// Resolve the ordered proxy list for `url`.
    ///
    /// Precedence: `http(s)_proxy`/`no_proxy` environment variables, then the
    /// OS proxy configuration (WPAD → PAC URL → static rules), then `DIRECT`.
    /// PAC/WPAD failures fall through to the next layer rather than erroring.
    ///
    /// This is a synchronous call and may block on network I/O (PAC fetch,
    /// WPAD probes, PAC `dnsResolve`) up to the configured timeouts — call it
    /// from a blocking-capable thread (`spawn_blocking` in async contexts).
    /// PAC evaluation itself runs on this resolver's dedicated worker thread.
    pub fn resolve_proxy(&self, url: &Url) -> Result<Vec<ProxyKind>> {
        if url.host_str().is_none() {
            return Err(Error::InvalidUrl(url.to_string()));
        }
        if let Some(list) = self.cached_resolution(url) {
            return Ok(self.demote_bad(list));
        }
        let generation = self.config_generation();
        let list = match self.inner.env.proxy_for(url) {
            Some(list) => list,
            None => {
                let config = self.os_config();
                self.resolve_from_os(&config, url)
            }
        };
        self.cache_resolution(url, generation, &list);
        Ok(self.demote_bad(list))
    }

    /// Read the current proxy configuration from the operating system.
    ///
    /// Inspects DHCP WPAD, DNS WPAD, and the configured PAC independently,
    /// including failures. `pac` is the first available script by precedence
    /// (DHCP, DNS, configured) and is never evaluated. Proxy environment
    /// variables are not part of this operating-system snapshot.
    pub fn read_proxy_config(&self) -> ProxyConfig {
        let config = self.os_config();
        let wpad_dhcp = self.inspect_dhcp_wpad(config.auto_detect);
        let wpad_dns = self.inspect_dns_wpad(config.auto_detect);
        let configured_pac = self.inspect_configured_pac(config.pac_url.as_deref());
        self.build_proxy_config(config, wpad_dhcp, wpad_dns, configured_pac)
    }

    /// Resolve the ordered proxy list without blocking an async-runtime worker.
    ///
    /// One lazily-created background thread owns all blocking resolution for
    /// this resolver. Concurrent calls for the same URL and configuration
    /// generation await one shared result; distinct URLs queue on that thread.
    /// This bounds blocking thread use even when many HTTP requests arrive at
    /// once. Enable the `tokio` feature to use this API.
    #[cfg(feature = "tokio")]
    pub async fn resolve_proxy_async(&self, url: &Url) -> Result<Vec<ProxyKind>> {
        if url.host_str().is_none() {
            return Err(Error::InvalidUrl(url.to_string()));
        }
        if let Some(list) = self.cached_resolution(url) {
            return Ok(self.demote_bad(list));
        }
        let worker = self
            .inner
            .async_worker
            .get_or_init(|| AsyncResolverWorker::new(Arc::downgrade(&self.inner)));
        match worker {
            Ok(worker) => worker.resolve(self.config_generation(), url).await,
            Err(error) => Err(Error::Platform(error.clone())),
        }
    }

    /// Current configuration generation. Bumped by the platform watcher on
    /// every (possible) OS proxy config change; poll it to detect staleness
    /// of anything you derived from a resolution.
    pub fn config_generation(&self) -> u64 {
        self.inner.notifier.generation()
    }

    /// Register a callback invoked on every OS proxy config change. The
    /// payload is intentionally dumb — "something changed", no diff.
    ///
    /// `f` runs on the internal watcher thread: it must be cheap and
    /// non-blocking, and must NOT call [`resolve_proxy`](Self::resolve_proxy)
    /// or register/drop subscriptions (schedule such work elsewhere, e.g.
    /// signal a channel). Dropping the returned [`Subscription`] unregisters
    /// the callback.
    pub fn on_change(&self, f: impl Fn() + Send + 'static) -> Subscription {
        self.inner.notifier.subscribe(f)
    }

    /// Async change notification: the receiver yields the new generation on
    /// every config change.
    #[cfg(feature = "tokio")]
    pub fn watch(&self) -> tokio::sync::watch::Receiver<u64> {
        self.inner.notifier.watch()
    }

    /// Report that connecting through `proxy` failed. For
    /// [`ResolverOptions::retry_cooldown`], subsequent resolutions demote it
    /// to the end of the list so callers stop re-trying a dead first entry
    /// (mirrors Chromium's `ProxyRetryInfo`). `Direct` reports are ignored.
    pub fn report_proxy_failed(&self, proxy: &ProxyKind) {
        if *proxy == ProxyKind::Direct {
            return;
        }
        lock(&self.inner.retry).insert(proxy.clone(), Instant::now());
    }

    /// Evaluate a PAC script directly (bypassing OS config) against `url`.
    /// Handy for testing PAC files when you already have the script text; see
    /// [`evaluate_pac_source`](Self::evaluate_pac_source) to load one from a
    /// path or URL. Runs on the caged evaluator thread with the same
    /// sanitization and hard timeout as regular resolution.
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    pub fn evaluate_pac(&self, script: &str, url: &Url) -> Result<Vec<ProxyKind>> {
        let script: Arc<str> = Arc::from(script);
        self.pac_evaluator().find_proxy(&script, url, self.my_ip())
    }

    /// Evaluate an explicit PAC source against `url`, bypassing OS config.
    ///
    /// `source` may be a local filesystem path, a `file://` URL, or an
    /// `http(s)://` URL. The script is read (or fetched) and run on the
    /// selected embedded backend. A backend-less Windows build instead
    /// delegates evaluation to WinHTTP, which only loads PAC over `http(s)`.
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    pub fn evaluate_pac_source(&self, source: &str, url: &Url) -> Result<Vec<ProxyKind>> {
        let pac_url = pac_source_to_url(source)?;
        let script =
            crate::fetch::fetch_pac(pac_url.as_str(), self.inner.options.pac_fetch_timeout)?;
        self.evaluate_pac(&script, url)
    }

    /// See the embedded-backend variant. WinHTTP performs the evaluation and
    /// only accepts `http(s)` PAC URLs.
    #[cfg(all(
        windows,
        not(any(
            feature = "pac-engine",
            feature = "pac-engine-wasmtime",
            feature = "pac-engine-wasmtime-jit",
            feature = "pac-engine-wasm2c"
        ))
    ))]
    pub fn evaluate_pac_source(&self, source: &str, url: &Url) -> Result<Vec<ProxyKind>> {
        if url.host_str().is_none() {
            return Err(Error::InvalidUrl(url.to_string()));
        }
        let pac_url = pac_source_to_url(source)?;
        if !matches!(pac_url.scheme(), "http" | "https") {
            return Err(Error::PacFetch(format!(
                "WinHTTP can only load PAC from http(s) URLs, not {source}"
            )));
        }
        let winhttp = self
            .winhttp()
            .ok_or_else(|| Error::Platform("WinHTTP session unavailable".into()))?;
        winhttp
            .get_proxy_for_url(url, false, Some(pac_url.as_str()))
            .ok_or_else(|| Error::PacEval(format!("WinHTTP could not evaluate PAC {source}")))
    }

    // -- internals ---------------------------------------------------------

    /// The lazily-created WinHTTP session used for PAC/WPAD resolution.
    #[cfg(all(
        windows,
        not(any(
            feature = "pac-engine",
            feature = "pac-engine-wasmtime",
            feature = "pac-engine-wasmtime-jit",
            feature = "pac-engine-wasm2c"
        ))
    ))]
    fn winhttp(&self) -> Option<&platform::WinHttpResolver> {
        self.inner
            .winhttp
            .get_or_init(|| {
                platform::WinHttpResolver::new()
                    .map_err(|e| log::warn!("{e}"))
                    .ok()
            })
            .as_ref()
    }

    fn os_config(&self) -> OsProxyConfig {
        let generation = self.inner.notifier.generation();
        let mut cache = lock(&self.inner.config_cache);
        if let Some(c) = cache.as_ref() {
            if c.generation == generation && c.read_at.elapsed() < self.inner.options.config_ttl {
                return c.config.clone();
            }
        }
        let config = platform::read_config();
        *cache = Some(ConfigCache {
            generation,
            read_at: Instant::now(),
            config: config.clone(),
        });
        config
    }

    fn cached_resolution(&self, url: &Url) -> Option<Vec<ProxyKind>> {
        if self.inner.options.resolution_ttl.is_zero()
            || self.inner.options.resolution_cache_capacity == 0
        {
            return None;
        }
        let key = resolution_cache_key(url);
        let generation = self.config_generation();
        let mut cache = lock(&self.inner.resolution_cache);
        match cache.get(&key) {
            Some(entry)
                if entry.generation == generation
                    && entry.at.elapsed() < self.inner.options.resolution_ttl =>
            {
                Some(entry.proxies.clone())
            }
            Some(_) => {
                cache.remove(&key);
                None
            }
            None => None,
        }
    }

    fn cache_resolution(&self, url: &Url, generation: u64, proxies: &[ProxyKind]) {
        let capacity = self.inner.options.resolution_cache_capacity;
        if self.inner.options.resolution_ttl.is_zero() || capacity == 0 {
            return;
        }
        if generation != self.config_generation() {
            return;
        }
        let key = resolution_cache_key(url);
        let mut cache = lock(&self.inner.resolution_cache);
        cache.retain(|_, entry| entry.generation == generation);
        if cache.len() >= capacity && !cache.contains_key(&key) {
            if let Some(oldest) = cache
                .iter()
                .min_by_key(|(_, entry)| entry.at)
                .map(|(key, _)| key.clone())
            {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            key,
            ResolutionCacheEntry {
                generation,
                at: Instant::now(),
                proxies: proxies.to_vec(),
            },
        );
    }

    fn build_proxy_config(
        &self,
        config: OsProxyConfig,
        wpad_dhcp: PacInspection,
        wpad_dns: PacInspection,
        configured_pac: PacInspection,
    ) -> ProxyConfig {
        let PacInspection {
            pac: dhcp_pac,
            status: wpad_dhcp,
        } = wpad_dhcp;
        let PacInspection {
            pac: dns_pac,
            status: wpad_dns,
        } = wpad_dns;
        let PacInspection {
            pac: configured,
            status: configured_pac,
        } = configured_pac;
        let pac = dhcp_pac.or(dns_pac).or(configured);
        let static_rules = config.static_rules.as_ref().map(|rules| StaticProxyRules {
            http: rules.http.clone(),
            https: rules.https.clone(),
            socks: rules.socks.clone(),
        });
        ProxyConfig {
            auto_detect: config.auto_detect,
            pac_url: config.pac_url,
            pac,
            wpad_dhcp,
            wpad_dns,
            configured_pac,
            static_rules,
            platform: config.platform,
        }
    }

    fn inspect_dhcp_wpad(&self, enabled: bool) -> PacInspection {
        #[cfg(not(windows))]
        {
            let _ = enabled;
            PacInspection::state(PacSourceState::Unsupported)
        }
        #[cfg(windows)]
        {
            if !enabled {
                return PacInspection::state(PacSourceState::Disabled);
            }
            let url = match platform::detect_dhcp_wpad_url() {
                Ok(Some(url)) => url,
                Ok(None) => return PacInspection::state(PacSourceState::NotFound),
                Err(error) => {
                    return PacInspection::error(PacSourceState::ErrorDiscovery, None, error)
                }
            };
            match crate::fetch::fetch_pac(&url, self.inner.options.wpad_fetch_timeout) {
                Ok(content) if content.contains("FindProxyForURL") => {
                    PacInspection::available(PacScript {
                        url,
                        content,
                        source: PacScriptSource::WpadDhcp,
                    })
                }
                Ok(_) => PacInspection::error(
                    PacSourceState::ErrorDownload,
                    Some(url.clone()),
                    format!("{url} does not look like a PAC script"),
                ),
                Err(error) => PacInspection::error(
                    PacSourceState::ErrorDownload,
                    Some(url),
                    error.to_string(),
                ),
            }
        }
    }

    fn inspect_dns_wpad(&self, enabled: bool) -> PacInspection {
        if !enabled {
            return PacInspection::state(PacSourceState::Disabled);
        }
        let (pac, status) = crate::wpad::inspect(
            self.inner.options.wpad_dns_timeout,
            self.inner.options.wpad_fetch_timeout,
        );
        PacInspection {
            pac: pac.map(|pac| PacScript {
                url: pac.url,
                content: pac.content,
                source: pac.source,
            }),
            status,
        }
    }

    fn inspect_configured_pac(&self, url: Option<&str>) -> PacInspection {
        let Some(url) = url else {
            return PacInspection::state(PacSourceState::Unconfigured);
        };
        match crate::fetch::fetch_pac(url, self.inner.options.pac_fetch_timeout) {
            Ok(content) => PacInspection::available(PacScript {
                url: url.to_string(),
                content,
                source: PacScriptSource::Configured,
            }),
            Err(error) => PacInspection::error(
                PacSourceState::ErrorDownload,
                Some(url.to_string()),
                error.to_string(),
            ),
        }
    }

    fn demote_bad(&self, list: Vec<ProxyKind>) -> Vec<ProxyKind> {
        let mut retry = lock(&self.inner.retry);
        let cooldown = self.inner.options.retry_cooldown;
        retry.retain(|_, marked| marked.elapsed() < cooldown);
        if retry.is_empty() {
            return list;
        }
        let (good, bad): (Vec<_>, Vec<_>) =
            list.iter().cloned().partition(|p| !retry.contains_key(p));
        if good.is_empty() {
            // Everything is marked bad — return the original order and let
            // the caller retry (mirrors Chromium reconsidering all proxies).
            list
        } else {
            let mut out = good;
            out.extend(bad);
            out
        }
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn resolve_from_os(&self, config: &OsProxyConfig, url: &Url) -> Vec<ProxyKind> {
        if config.auto_detect {
            if let Some(list) = self.try_wpad(url) {
                return list;
            }
        }
        if let Some(pac_url) = &config.pac_url {
            if let Some(list) = self.try_pac_url(pac_url, url) {
                return list;
            }
        }
        self.static_or_direct(config, url)
    }

    #[cfg(all(
        windows,
        not(any(
            feature = "pac-engine",
            feature = "pac-engine-wasmtime",
            feature = "pac-engine-wasmtime-jit",
            feature = "pac-engine-wasm2c"
        ))
    ))]
    fn resolve_from_os(&self, config: &OsProxyConfig, url: &Url) -> Vec<ProxyKind> {
        if config.auto_detect || config.pac_url.is_some() {
            if let Some(winhttp) = self.winhttp() {
                if let Some(list) =
                    winhttp.get_proxy_for_url(url, config.auto_detect, config.pac_url.as_deref())
                {
                    return list;
                }
            }
        }
        self.static_or_direct(config, url)
    }

    fn static_or_direct(&self, config: &OsProxyConfig, url: &Url) -> Vec<ProxyKind> {
        if let Some(rules) = &config.static_rules {
            let host = url.host_str().unwrap_or("");
            let port = url.port_or_known_default().unwrap_or(0);
            if rules.bypass.matches(host, port) {
                return vec![ProxyKind::Direct];
            }
            if let Some(proxy) = rules.proxy_for_scheme(url.scheme()) {
                return vec![proxy.clone()];
            }
        }
        vec![ProxyKind::Direct]
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn pac_evaluator(&self) -> &crate::pac::PacEvaluator {
        self.inner.pac.get_or_init(|| {
            crate::pac::PacEvaluator::new(
                self.inner.options.pac_timeout,
                self.inner.options.pac_backend,
            )
        })
    }

    /// Evaluate a PAC script for resolution; `None` means "PAC layer
    /// unavailable, fall through". An explicit DIRECT (or unparseable result
    /// text) is `Some([Direct])`.
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn eval_for_resolution(&self, script: &Arc<str>, url: &Url) -> Option<Vec<ProxyKind>> {
        match self.pac_evaluator().find_proxy(script, url, self.my_ip()) {
            Ok(list) if list.is_empty() => Some(vec![ProxyKind::Direct]),
            Ok(list) => Some(list),
            Err(e) => {
                log::warn!("PAC evaluation failed, falling back: {e}");
                None
            }
        }
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn try_pac_url(&self, pac_url: &str, url: &Url) -> Option<Vec<ProxyKind>> {
        let generation = self.inner.notifier.generation();
        let script = {
            let mut cache = lock(&self.inner.pac_cache);
            let valid = cache.as_ref().is_some_and(|c| {
                let ttl = if c.script.is_some() {
                    self.inner.options.pac_ttl
                } else {
                    self.inner.options.pac_error_retry
                };
                c.source == pac_url && c.generation == generation && c.at.elapsed() < ttl
            });
            if !valid {
                let script =
                    match crate::fetch::fetch_pac(pac_url, self.inner.options.pac_fetch_timeout) {
                        Ok(text) => Some(Arc::<str>::from(text)),
                        Err(e) => {
                            log::warn!("{e}");
                            None
                        }
                    };
                *cache = Some(PacScriptCache {
                    source: pac_url.to_string(),
                    generation,
                    at: Instant::now(),
                    script,
                });
            }
            cache.as_ref().and_then(|c| c.script.clone())?
        };
        self.eval_for_resolution(&script, url)
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn try_wpad(&self, url: &Url) -> Option<Vec<ProxyKind>> {
        let generation = self.inner.notifier.generation();
        let script = {
            let mut cache = lock(&self.inner.wpad_cache);
            let valid = cache.as_ref().is_some_and(|c| {
                let ttl = if c.script.is_some() {
                    self.inner.options.pac_ttl
                } else {
                    self.inner.options.wpad_negative_ttl
                };
                c.generation == generation && c.at.elapsed() < ttl
            });
            if !valid {
                let script = self
                    .discover_wpad()
                    .map(|pac| Arc::<str>::from(pac.content));
                *cache = Some(WpadCache {
                    generation,
                    at: Instant::now(),
                    script,
                });
            }
            cache.as_ref().and_then(|c| c.script.clone())?
        };
        self.eval_for_resolution(&script, url)
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn discover_wpad(&self) -> Option<crate::wpad::DiscoveredPac> {
        #[cfg(windows)]
        if let Ok(Some(url)) = platform::detect_dhcp_wpad_url() {
            match crate::fetch::fetch_pac(&url, self.inner.options.wpad_fetch_timeout) {
                Ok(content) if content.contains("FindProxyForURL") => {
                    log::info!("WPAD: using DHCP URL {url}");
                    return Some(crate::wpad::DiscoveredPac {
                        url,
                        content,
                        source: PacScriptSource::WpadDhcp,
                    });
                }
                Ok(_) => log::warn!("WPAD: DHCP URL {url} does not look like a PAC script"),
                Err(error) => log::debug!("WPAD: {error}"),
            }
        }

        crate::wpad::inspect(
            self.inner.options.wpad_dns_timeout,
            self.inner.options.wpad_fetch_timeout,
        )
        .0
    }

    /// Best-effort local IP for PAC `myIpAddress()`, so the engine doesn't
    /// fall back to resolving the hostname (slow, often wrong on multi-homed
    /// machines). A connected UDP socket never sends a packet.
    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    fn my_ip(&self) -> Option<String> {
        let mut cached = lock(&self.inner.my_ip);
        if let Some((at, ip)) = cached.as_ref() {
            if at.elapsed() < Duration::from_secs(60) {
                return ip.clone();
            }
        }
        let ip = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| {
                s.connect("8.8.8.8:53")?;
                s.local_addr()
            })
            .map(|a| a.ip().to_string())
            .ok();
        *cached = Some((Instant::now(), ip.clone()));
        ip
    }
}

fn resolution_cache_key(url: &Url) -> String {
    let mut key = url.clone();
    key.set_fragment(None);
    let _ = key.set_username("");
    let _ = key.set_password(None);
    key.into()
}

impl Default for ProxyResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Interpret a `--pac-script`-style value as a URL: a recognized scheme
/// (`http`/`https`/`file`) is kept as-is; anything else is treated as a local
/// filesystem path and canonicalized into a `file://` URL.
fn pac_source_to_url(source: &str) -> Result<Url> {
    if let Ok(u) = Url::parse(source) {
        if matches!(u.scheme(), "http" | "https" | "file") {
            return Ok(u);
        }
    }
    let path =
        std::fs::canonicalize(source).map_err(|e| Error::PacFetch(format!("{source}: {e}")))?;
    Url::from_file_path(&path).map_err(|_| Error::PacFetch(format!("{source}: not a file path")))
}

impl std::fmt::Debug for ProxyResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyResolver")
            .field("generation", &self.config_generation())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl ProxyResolver {
    /// Test-only constructor with an injected environment.
    pub(crate) fn with_env(options: ResolverOptions, env: EnvConfig) -> Self {
        Self::build(options, env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_cfg::EnvConfig;

    fn env(pairs: &[(&str, &str)]) -> EnvConfig {
        let pairs: Vec<(String, String)> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        EnvConfig::from_lookup(move |name| {
            pairs
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        })
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// Default options with a generous PAC timeout: it is only an upper bound
    /// (calls return as soon as the worker replies), and the first call on
    /// the JIT backend compiles the guest with a debug-profile Cranelift,
    /// which takes tens of seconds on CI runners.
    fn pac_test_options() -> ResolverOptions {
        ResolverOptions {
            pac_timeout: Duration::from_secs(120),
            ..Default::default()
        }
    }

    #[test]
    fn env_takes_precedence_and_demotion_works() {
        let r = ProxyResolver::with_env(
            ResolverOptions::default(),
            env(&[("http_proxy", "http://a:1"), ("all_proxy", "socks5://b:2")]),
        );
        assert_eq!(
            r.resolve_proxy(&url("http://x.com/")).unwrap(),
            vec![ProxyKind::Http("a:1".into())]
        );

        // Single entry marked bad: still returned (nothing better).
        r.report_proxy_failed(&ProxyKind::Http("a:1".into()));
        assert_eq!(
            r.resolve_proxy(&url("http://x.com/")).unwrap(),
            vec![ProxyKind::Http("a:1".into())]
        );
    }

    #[test]
    fn demotion_reorders_multi_entry_lists() {
        let r = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        r.report_proxy_failed(&ProxyKind::Http("a:1".into()));
        let list = vec![
            ProxyKind::Http("a:1".into()),
            ProxyKind::Http("b:2".into()),
            ProxyKind::Direct,
        ];
        assert_eq!(
            r.demote_bad(list),
            vec![
                ProxyKind::Http("b:2".into()),
                ProxyKind::Direct,
                ProxyKind::Http("a:1".into()),
            ]
        );
    }

    #[test]
    fn cooldown_expires() {
        let options = ResolverOptions {
            retry_cooldown: Duration::from_millis(10),
            ..Default::default()
        };
        let r = ProxyResolver::with_env(options, env(&[]));
        r.report_proxy_failed(&ProxyKind::Http("a:1".into()));
        std::thread::sleep(Duration::from_millis(20));
        let list = vec![ProxyKind::Http("a:1".into()), ProxyKind::Direct];
        assert_eq!(r.demote_bad(list.clone()), list);
    }

    #[test]
    fn invalid_url_errors() {
        let r = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        assert!(matches!(
            r.resolve_proxy(&url("data:text/plain,hi")),
            Err(Error::InvalidUrl(_))
        ));
    }

    #[test]
    fn completed_resolution_cache_is_invalidated_by_config_generation() {
        let resolver = ProxyResolver::with_env(
            ResolverOptions::default(),
            env(&[("https_proxy", "http://proxy.example:3128")]),
        );
        let target = url("https://example.com/path");
        resolver.cache_resolution(&target, resolver.config_generation(), &[ProxyKind::Direct]);

        assert_eq!(
            resolver.resolve_proxy(&target).unwrap(),
            vec![ProxyKind::Direct]
        );

        resolver.inner.notifier.bump();
        assert_eq!(
            resolver.resolve_proxy(&target).unwrap(),
            vec![ProxyKind::Http("proxy.example:3128".into())]
        );
    }

    #[test]
    fn stale_resolution_cannot_overwrite_current_generation() {
        let resolver = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        let target = url("https://example.com/path");
        let stale_generation = resolver.config_generation();
        resolver.inner.notifier.bump();
        resolver.cache_resolution(
            &target,
            resolver.config_generation(),
            &[ProxyKind::Http("current.example:3128".into())],
        );

        resolver.cache_resolution(&target, stale_generation, &[ProxyKind::Direct]);

        assert_eq!(
            resolver.cached_resolution(&target),
            Some(vec![ProxyKind::Http("current.example:3128".into())])
        );
    }

    #[test]
    fn resolution_cache_key_preserves_path_and_query() {
        assert_ne!(
            resolution_cache_key(&url("http://example.com/one?value=1#fragment")),
            resolution_cache_key(&url("http://example.com/two?value=1#fragment"))
        );
        assert_ne!(
            resolution_cache_key(&url("http://example.com/one?value=1")),
            resolution_cache_key(&url("http://example.com/one?value=2"))
        );
        assert_eq!(
            resolution_cache_key(&url("http://user:secret@example.com/one#first")),
            resolution_cache_key(&url("http://example.com/one#second"))
        );
    }

    #[test]
    fn proxy_config_prefers_wpad_and_does_not_evaluate() {
        let resolver = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        let config = OsProxyConfig {
            auto_detect: true,
            pac_url: Some("https://configured.example/proxy.pac".into()),
            static_rules: Some(platform::StaticRules {
                http: Some(ProxyKind::Http("proxy.example:8080".into())),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dns_pac = PacScript {
            url: "http://wpad.example/wpad.dat".into(),
            content: "function FindProxyForURL() { return 'DIRECT'; }".into(),
            source: PacScriptSource::WpadDns,
        };
        let configured_pac = PacScript {
            url: "https://configured.example/proxy.pac".into(),
            content: "configured script".into(),
            source: PacScriptSource::Configured,
        };
        let snapshot = resolver.build_proxy_config(
            config,
            PacInspection::state(PacSourceState::NotFound),
            PacInspection::available(dns_pac.clone()),
            PacInspection::available(configured_pac),
        );
        assert_eq!(snapshot.pac, Some(dns_pac));
        assert_eq!(snapshot.configured_pac.state, PacSourceState::Available);
        assert_eq!(
            snapshot.static_rules.unwrap().http,
            Some(ProxyKind::Http("proxy.example:8080".into()))
        );
        #[cfg(any(
            not(windows),
            feature = "pac-engine",
            feature = "pac-engine-wasmtime",
            feature = "pac-engine-wasmtime-jit",
            feature = "pac-engine-wasm2c"
        ))]
        assert!(resolver.inner.pac.get().is_none());
    }

    #[test]
    fn proxy_config_preserves_dhcp_wpad_source() {
        let resolver = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        let snapshot = resolver.build_proxy_config(
            OsProxyConfig {
                auto_detect: true,
                ..Default::default()
            },
            PacInspection::available(PacScript {
                url: "http://dhcp.example/proxy.pac".into(),
                content: "function FindProxyForURL() { return 'DIRECT'; }".into(),
                source: PacScriptSource::WpadDhcp,
            }),
            PacInspection::state(PacSourceState::NotFound),
            PacInspection::state(PacSourceState::Unconfigured),
        );

        assert_eq!(snapshot.pac.unwrap().source, PacScriptSource::WpadDhcp);
    }

    #[test]
    fn proxy_config_loads_configured_pac_after_wpad_miss() {
        let resolver = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        let config = OsProxyConfig {
            auto_detect: true,
            pac_url: Some("https://configured.example/proxy.pac".into()),
            ..Default::default()
        };
        let configured_pac = PacScript {
            url: "https://configured.example/proxy.pac".into(),
            content: "configured script".into(),
            source: PacScriptSource::Configured,
        };
        let snapshot = resolver.build_proxy_config(
            config,
            PacInspection::state(PacSourceState::NotFound),
            PacInspection::state(PacSourceState::NotFound),
            PacInspection::available(configured_pac.clone()),
        );
        assert_eq!(snapshot.pac, Some(configured_pac));
    }

    #[test]
    fn configured_pac_reports_download_error() {
        let resolver = ProxyResolver::with_env(ResolverOptions::default(), env(&[]));
        let inspection = resolver.inspect_configured_pac(Some("file:///nonexistent/proxy.pac"));
        assert_eq!(inspection.status.state, PacSourceState::ErrorDownload);
        assert_eq!(
            inspection.status.url.as_deref(),
            Some("file:///nonexistent/proxy.pac")
        );
        assert!(inspection.status.error.is_some());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test(flavor = "current_thread")]
    async fn async_resolution_coalesces_identical_concurrent_calls() {
        use std::sync::atomic::Ordering;

        let resolver = ProxyResolver::with_env(
            ResolverOptions::default(),
            env(&[("https_proxy", "http://proxy.example:3128")]),
        );
        *lock(&resolver.inner.async_resolution_delay) = Some(Duration::from_millis(100));

        let mut tasks = Vec::new();
        for _ in 0..32 {
            let resolver = resolver.clone();
            let target = url("https://example.com/");
            tasks.push(tokio::spawn(async move {
                resolver.resolve_proxy_async(&target).await.unwrap()
            }));
        }

        for task in tasks {
            assert_eq!(
                task.await.unwrap(),
                vec![ProxyKind::Http("proxy.example:3128".into())]
            );
        }
        assert_eq!(
            resolver
                .inner
                .async_resolution_starts
                .load(Ordering::SeqCst),
            1
        );

        assert_eq!(
            resolver
                .resolve_proxy_async(&url("https://example.com/"))
                .await
                .unwrap(),
            vec![ProxyKind::Http("proxy.example:3128".into())]
        );
        assert_eq!(
            resolver
                .inner
                .async_resolution_starts
                .load(Ordering::SeqCst),
            1
        );
    }

    #[cfg(any(
        not(windows),
        feature = "pac-engine",
        feature = "pac-engine-wasmtime",
        feature = "pac-engine-wasmtime-jit",
        feature = "pac-engine-wasm2c"
    ))]
    #[test]
    fn evaluate_pac_public_api() {
        let r = ProxyResolver::with_env(pac_test_options(), env(&[]));
        let got = r
            .evaluate_pac(
                "function FindProxyForURL(url, host) { return 'PROXY p:1; DIRECT'; }",
                &url("https://x.com/"),
            )
            .unwrap();
        assert_eq!(got, vec![ProxyKind::Http("p:1".into()), ProxyKind::Direct]);
    }

    // Serves a PAC over http and evaluates it via the public API, which is also
    // the path the `proxytester` example drives.
    #[test]
    fn evaluate_pac_source_over_http() {
        use std::io::{Read, Write};
        use std::net::TcpListener;

        let pac = "function FindProxyForURL(url, host) { return 'PROXY p:1; DIRECT'; }";
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = pac.to_string();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: application/x-ns-proxy-autoconfig\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(body.as_bytes());
                let _ = stream.flush();
            }
        });

        let r = ProxyResolver::with_env(pac_test_options(), env(&[]));
        let pac_url = format!("http://{addr}/proxy.pac");
        let got = r
            .evaluate_pac_source(&pac_url, &url("https://x.com/"))
            .unwrap();

        // WinHTTP drops a trailing DIRECT; the built-in engine keeps it. Both
        // agree on the primary proxy.
        assert_eq!(got.first(), Some(&ProxyKind::Http("p:1".into())));
    }
}
