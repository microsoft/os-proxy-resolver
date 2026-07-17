/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Mutex;

use napi::bindgen_prelude::{AsyncTask, Task};
use napi::threadsafe_function::{ThreadsafeFunction, ThreadsafeFunctionCallMode};
use napi::{Env, Error, JsFunction, JsUnknown, Result, Status};
use napi_derive::napi;
use os_proxy_resolver::{
    PacScriptSource, PacSourceState, PacSourceStatus, PlatformProxyConfig, ProxyKind,
    StaticProxyRules, Subscription,
};

#[napi(object)]
pub struct Proxy {
    pub kind: String,
    pub host: Option<String>,
}

impl From<ProxyKind> for Proxy {
    fn from(proxy: ProxyKind) -> Self {
        match proxy {
            ProxyKind::Direct => Proxy {
                kind: "direct".to_string(),
                host: None,
            },
            ProxyKind::Http(host) => Proxy {
                kind: "http".to_string(),
                host: Some(host),
            },
            ProxyKind::Socks(host) => Proxy {
                kind: "socks".to_string(),
                host: Some(host),
            },
        }
    }
}

impl TryFrom<&Proxy> for ProxyKind {
    type Error = Error;

    fn try_from(proxy: &Proxy) -> Result<Self> {
        match (proxy.kind.as_str(), proxy.host.as_deref()) {
            ("direct", None) => Ok(ProxyKind::Direct),
            ("http", Some(host)) => Ok(ProxyKind::Http(host.to_string())),
            ("socks", Some(host)) => Ok(ProxyKind::Socks(host.to_string())),
            ("direct", Some(_)) => Err(Error::new(
                Status::InvalidArg,
                "a direct proxy must not have a host".to_string(),
            )),
            ("http" | "socks", None) => Err(Error::new(
                Status::InvalidArg,
                format!("a {} proxy must have a host", proxy.kind),
            )),
            _ => Err(Error::new(
                Status::InvalidArg,
                format!("unknown proxy kind: {}", proxy.kind),
            )),
        }
    }
}

#[napi(object)]
pub struct NodePacScript {
    pub url: String,
    pub content: String,
    pub source: String,
}

#[napi(object)]
pub struct NodePacSourceStatus {
    pub state: String,
    pub url: Option<String>,
    pub error: Option<String>,
}

impl From<PacSourceStatus> for NodePacSourceStatus {
    fn from(status: PacSourceStatus) -> Self {
        Self {
            state: match status.state {
                PacSourceState::Disabled => "disabled",
                PacSourceState::Unsupported => "unsupported",
                PacSourceState::Unconfigured => "unconfigured",
                PacSourceState::NotFound => "not-found",
                PacSourceState::Available => "available",
                PacSourceState::ErrorDiscovery => "error-discovery",
                PacSourceState::ErrorDownload => "error-download",
                _ => "unknown",
            }
            .into(),
            url: status.url,
            error: status.error,
        }
    }
}

#[napi(object)]
pub struct NodeStaticProxyRules {
    pub http: Option<Proxy>,
    pub https: Option<Proxy>,
    pub socks: Option<Proxy>,
}

impl From<StaticProxyRules> for NodeStaticProxyRules {
    fn from(rules: StaticProxyRules) -> Self {
        Self {
            http: rules.http.map(Proxy::from),
            https: rules.https.map(Proxy::from),
            socks: rules.socks.map(Proxy::from),
        }
    }
}

#[napi(object)]
pub struct NodePlatformProxyConfig {
    pub kind: String,
    pub proxy: Option<String>,
    pub proxy_bypass: Option<String>,
    pub exceptions: Option<Vec<String>>,
    pub exclude_simple_hostnames: Option<bool>,
    pub mode: Option<String>,
    pub ignore_hosts: Option<Vec<String>>,
}

impl From<PlatformProxyConfig> for NodePlatformProxyConfig {
    fn from(config: PlatformProxyConfig) -> Self {
        match config {
            PlatformProxyConfig::Windows(config) => Self {
                kind: "windows".into(),
                proxy: config.proxy,
                proxy_bypass: config.proxy_bypass,
                exceptions: None,
                exclude_simple_hostnames: None,
                mode: None,
                ignore_hosts: None,
            },
            PlatformProxyConfig::Macos(config) => Self {
                kind: "macos".into(),
                proxy: None,
                proxy_bypass: None,
                exceptions: Some(config.exceptions),
                exclude_simple_hostnames: Some(config.exclude_simple_hostnames),
                mode: None,
                ignore_hosts: None,
            },
            PlatformProxyConfig::Linux(config) => Self {
                kind: "linux".into(),
                proxy: None,
                proxy_bypass: None,
                exceptions: None,
                exclude_simple_hostnames: None,
                mode: config.mode,
                ignore_hosts: Some(config.ignore_hosts),
            },
            _ => Self {
                kind: "unknown".into(),
                proxy: None,
                proxy_bypass: None,
                exceptions: None,
                exclude_simple_hostnames: None,
                mode: None,
                ignore_hosts: None,
            },
        }
    }
}

#[napi(object)]
pub struct NodeProxyConfig {
    pub auto_detect: bool,
    pub pac_url: Option<String>,
    pub pac: Option<NodePacScript>,
    pub wpad_dhcp: NodePacSourceStatus,
    pub wpad_dns: NodePacSourceStatus,
    pub configured_pac: NodePacSourceStatus,
    pub static_rules: Option<NodeStaticProxyRules>,
    pub platform: Option<NodePlatformProxyConfig>,
}

impl From<os_proxy_resolver::ProxyConfig> for NodeProxyConfig {
    fn from(config: os_proxy_resolver::ProxyConfig) -> Self {
        Self {
            auto_detect: config.auto_detect,
            pac_url: config.pac_url,
            pac: config.pac.map(|pac| NodePacScript {
                url: pac.url,
                content: pac.content,
                source: match pac.source {
                    PacScriptSource::WpadDns => "wpad-dns",
                    PacScriptSource::WpadDhcp => "wpad-dhcp",
                    PacScriptSource::Configured => "configured",
                    _ => "unknown",
                }
                .into(),
            }),
            wpad_dhcp: config.wpad_dhcp.into(),
            wpad_dns: config.wpad_dns.into(),
            configured_pac: config.configured_pac.into(),
            static_rules: config.static_rules.map(NodeStaticProxyRules::from),
            platform: config.platform.map(NodePlatformProxyConfig::from),
        }
    }
}

pub struct ResolveTask {
    resolver: os_proxy_resolver::ProxyResolver,
    url: String,
}

impl Task for ResolveTask {
    type Output = Vec<ProxyKind>;
    type JsValue = Vec<Proxy>;

    fn compute(&mut self) -> Result<Self::Output> {
        let url = url::Url::parse(&self.url)
            .map_err(|error| Error::new(Status::InvalidArg, error.to_string()))?;
        self.resolver
            .resolve_proxy(&url)
            .map_err(|error| Error::new(Status::GenericFailure, error.to_string()))
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output.into_iter().map(Proxy::from).collect())
    }
}

pub struct ReadProxyConfigTask {
    resolver: os_proxy_resolver::ProxyResolver,
}

impl Task for ReadProxyConfigTask {
    type Output = os_proxy_resolver::ProxyConfig;
    type JsValue = NodeProxyConfig;

    fn compute(&mut self) -> Result<Self::Output> {
        Ok(self.resolver.read_proxy_config())
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(NodeProxyConfig::from(output))
    }
}

#[napi(js_name = "ProxyResolver")]
pub struct NodeProxyResolver {
    resolver: os_proxy_resolver::ProxyResolver,
    subscriptions: Mutex<HashMap<u32, Subscription>>,
    next_subscription: AtomicU32,
}

#[napi]
impl NodeProxyResolver {
    #[napi(constructor)]
    pub fn new() -> Self {
        NodeProxyResolver {
            resolver: os_proxy_resolver::ProxyResolver::new(),
            subscriptions: Mutex::new(HashMap::new()),
            next_subscription: AtomicU32::new(1),
        }
    }

    #[napi]
    pub fn resolve(&self, url: String) -> AsyncTask<ResolveTask> {
        AsyncTask::new(ResolveTask {
            resolver: self.resolver.clone(),
            url,
        })
    }

    #[napi]
    pub fn read_proxy_config(&self) -> AsyncTask<ReadProxyConfigTask> {
        AsyncTask::new(ReadProxyConfigTask {
            resolver: self.resolver.clone(),
        })
    }

    #[napi(getter)]
    pub fn config_generation(&self) -> i64 {
        self.resolver.config_generation() as i64
    }

    #[napi]
    pub fn report_proxy_failed(&self, proxy: Proxy) -> Result<()> {
        self.resolver
            .report_proxy_failed(&ProxyKind::try_from(&proxy)?);
        Ok(())
    }

    #[napi]
    pub fn on_change(&self, env: Env, callback: JsFunction) -> Result<u32> {
        let mut callback: ThreadsafeFunction<()> =
            callback.create_threadsafe_function(0, |_context| Ok(Vec::<JsUnknown>::new()))?;
        callback.unref(&env)?;
        let subscription = self.resolver.on_change(move || {
            let _ = callback.call(Ok(()), ThreadsafeFunctionCallMode::NonBlocking);
        });
        let id = self.next_subscription.fetch_add(1, Ordering::Relaxed);
        self.subscriptions
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "subscription lock poisoned"))?
            .insert(id, subscription);
        Ok(id)
    }

    #[napi]
    pub fn off_change(&self, subscription: u32) -> Result<()> {
        self.subscriptions
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "subscription lock poisoned"))?
            .remove(&subscription);
        Ok(())
    }

    #[napi]
    pub fn close(&self) -> Result<()> {
        self.subscriptions
            .lock()
            .map_err(|_| Error::new(Status::GenericFailure, "subscription lock poisoned"))?
            .clear();
        Ok(())
    }
}

impl Default for NodeProxyResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
pub fn resolve_proxy(url: String) -> AsyncTask<ResolveTask> {
    AsyncTask::new(ResolveTask {
        resolver: os_proxy_resolver::ProxyResolver::global().clone(),
        url,
    })
}

#[napi]
pub fn read_proxy_config() -> AsyncTask<ReadProxyConfigTask> {
    AsyncTask::new(ReadProxyConfigTask {
        resolver: os_proxy_resolver::ProxyResolver::global().clone(),
    })
}
