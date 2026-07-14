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
use os_proxy_resolver::{ProxyKind, Subscription};

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
