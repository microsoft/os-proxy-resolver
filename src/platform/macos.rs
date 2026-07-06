/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! macOS: read proxy config via `SCDynamicStoreCopyProxies`, watch for
//! changes via an `SCDynamicStore` notification callback on a dedicated
//! CFRunLoop thread. Also watches the global IPv4 state so network switches
//! (Wi-Fi change, VPN connect, resume) invalidate cached PAC/WPAD state.

use super::{OsProxyConfig, StaticRules};
use crate::bypass::BypassRules;
use crate::types::ProxyKind;
use core_foundation::array::{CFArray, CFArrayRef};
use core_foundation::base::{CFGetTypeID, CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::runloop::{kCFRunLoopCommonModes, CFRunLoop};
use core_foundation::string::CFString;
use std::sync::mpsc;
use std::sync::Arc;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};

type ProxiesDict = CFDictionary<CFString, CFType>;

pub(crate) fn read_config() -> OsProxyConfig {
    let store = SCDynamicStoreBuilder::<()>::new("os-proxy-resolver").build();
    let Some(proxies) = store.get_proxies() else {
        return OsProxyConfig::default();
    };

    let mut config = OsProxyConfig {
        auto_detect: get_flag(&proxies, "ProxyAutoDiscoveryEnable"),
        ..Default::default()
    };
    if get_flag(&proxies, "ProxyAutoConfigEnable") {
        config.pac_url = get_string(&proxies, "ProxyAutoConfigURLString").filter(|s| !s.is_empty());
    }

    let mut rules = StaticRules::default();
    if get_flag(&proxies, "HTTPEnable") {
        rules.http = proxy_entry(&proxies, "HTTPProxy", "HTTPPort", 80).map(ProxyKind::Http);
    }
    if get_flag(&proxies, "HTTPSEnable") {
        rules.https = proxy_entry(&proxies, "HTTPSProxy", "HTTPSPort", 80).map(ProxyKind::Http);
    }
    if get_flag(&proxies, "SOCKSEnable") {
        rules.socks = proxy_entry(&proxies, "SOCKSProxy", "SOCKSPort", 1080).map(ProxyKind::Socks);
    }
    let exceptions: Vec<String> = proxies
        .find(CFString::from_static_string("ExceptionsList"))
        .and_then(|v| {
            // CFArray<CFType> has no ConcreteCFType impl, so downcast by hand.
            let type_ref = v.as_CFTypeRef();
            if unsafe { CFGetTypeID(type_ref) } == CFArray::<CFType>::type_id() {
                Some(unsafe { CFArray::<CFType>::wrap_under_get_rule(type_ref as CFArrayRef) })
            } else {
                None
            }
        })
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.downcast::<CFString>().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    rules.bypass = BypassRules::parse(exceptions.iter().map(|s| s.as_str()));
    rules
        .bypass
        .set_bypass_simple_hostnames(get_flag(&proxies, "ExcludeSimpleHostnames"));
    if !rules.is_empty() {
        config.static_rules = Some(rules);
    }
    config
}

fn get_flag(dict: &ProxiesDict, key: &'static str) -> bool {
    dict.find(CFString::from_static_string(key))
        .map(|v| {
            if let Some(n) = v.downcast::<CFNumber>() {
                n.to_i32() == Some(1)
            } else if let Some(b) = v.downcast::<CFBoolean>() {
                b.into()
            } else {
                false
            }
        })
        .unwrap_or(false)
}

fn get_string(dict: &ProxiesDict, key: &'static str) -> Option<String> {
    dict.find(CFString::from_static_string(key))
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string())
}

fn get_port(dict: &ProxiesDict, key: &'static str) -> Option<u16> {
    dict.find(CFString::from_static_string(key))
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|n| n.to_i32())
        .and_then(|p| u16::try_from(p).ok())
}

fn proxy_entry(
    dict: &ProxiesDict,
    host_key: &'static str,
    port_key: &'static str,
    default_port: u16,
) -> Option<String> {
    let host = get_string(dict, host_key).filter(|h| !h.is_empty())?;
    let port = get_port(dict, port_key).unwrap_or(default_port);
    Some(format!("{host}:{port}"))
}

// --------------------------------------------------------------------------
// Change watcher

pub(crate) struct Watcher {
    run_loop: Option<SendCFRunLoop>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// CFRunLoopStop is documented thread-safe; we only ever call `stop`.
struct SendCFRunLoop(CFRunLoop);
unsafe impl Send for SendCFRunLoop {}

pub(crate) fn spawn_watcher(on_change: Arc<dyn Fn() + Send + Sync>) -> Watcher {
    let (tx, rx) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("os-proxy-watch".into())
        .spawn(move || {
            let context = SCDynamicStoreCallBackContext {
                callout: changed_callback,
                info: on_change,
            };
            let store = SCDynamicStoreBuilder::new("os-proxy-resolver-watch")
                .callback_context(context)
                .build();
            let keys = CFArray::from_CFTypes(&[
                CFString::from_static_string("State:/Network/Global/Proxies"),
                CFString::from_static_string("State:/Network/Global/IPv4"),
            ]);
            let patterns = CFArray::from_CFTypes(&[] as &[CFString]);
            if !store.set_notification_keys(&keys, &patterns) {
                log::warn!("macOS proxy watcher: set_notification_keys failed");
                let _ = tx.send(None);
                return;
            }
            let source = store.create_run_loop_source();
            let run_loop = CFRunLoop::get_current();
            run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });
            let _ = tx.send(Some(SendCFRunLoop(run_loop)));
            CFRunLoop::run_current();
        })
        .ok();
    let run_loop = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .ok()
        .flatten();
    Watcher { run_loop, thread }
}

fn changed_callback(
    _store: SCDynamicStore,
    _changed_keys: CFArray<CFString>,
    on_change: &mut Arc<dyn Fn() + Send + Sync>,
) {
    (on_change)();
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if let Some(run_loop) = self.run_loop.take() {
            run_loop.0.stop();
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
