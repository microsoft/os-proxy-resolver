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
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
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

/// DNS search domains from the OS resolver configuration, read from
/// `SCDynamicStore` (`State:/Network/Global/DNS`). This reflects the live
/// configuration including VPN / per-interface resolvers, which the legacy
/// `/etc/resolv.conf` compatibility file often omits; we fall back to that
/// file only when the dynamic store reports none.
pub(crate) fn dns_search_domains() -> Vec<String> {
    let store = SCDynamicStoreBuilder::<()>::new("os-proxy-resolver-dns").build();
    let domains = read_dns_search_domains(&store);
    if domains.is_empty() {
        super::resolv_conf_search_domains()
    } else {
        domains
    }
}

fn read_dns_search_domains(store: &SCDynamicStore) -> Vec<String> {
    let Some(plist) = store.get(CFString::from_static_string("State:/Network/Global/DNS")) else {
        return Vec::new();
    };
    let type_ref = plist.as_CFTypeRef();
    if unsafe { CFGetTypeID(type_ref) } != CFDictionary::<CFString, CFType>::type_id() {
        return Vec::new();
    }
    let dns = unsafe {
        CFDictionary::<CFString, CFType>::wrap_under_get_rule(type_ref as CFDictionaryRef)
    };

    let mut out: Vec<String> = Vec::new();
    let mut push = |d: String| {
        if !d.is_empty() && !out.contains(&d) {
            out.push(d);
        }
    };

    // `SearchDomains` (array of strings) is the primary, ordered source.
    if let Some(v) = dns.find(CFString::from_static_string("SearchDomains")) {
        let arr_ref = v.as_CFTypeRef();
        if unsafe { CFGetTypeID(arr_ref) } == CFArray::<CFType>::type_id() {
            let arr = unsafe { CFArray::<CFType>::wrap_under_get_rule(arr_ref as CFArrayRef) };
            for item in arr.iter() {
                if let Some(s) = item.downcast::<CFString>() {
                    push(s.to_string());
                }
            }
        }
    }
    // `DomainName` is the primary connection-specific domain; include it too.
    if let Some(s) = dns
        .find(CFString::from_static_string("DomainName"))
        .and_then(|v| v.downcast::<CFString>())
    {
        push(s.to_string());
    }
    out
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
                CFString::from_static_string("State:/Network/Global/DNS"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    fn networksetup(args: &[&str]) -> Option<String> {
        let out = Command::new("networksetup").args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    /// Run one `scutil` `show <path>` query non-interactively.
    fn scutil_show(path: &str) -> Option<String> {
        let mut child = Command::new("scutil")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        {
            let mut stdin = child.stdin.take()?;
            stdin.write_all(format!("show {path}\n").as_bytes()).ok()?;
            // Dropping stdin closes it, signalling EOF so scutil exits.
        }
        let out = child.wait_with_output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn scutil_field(text: &str, key: &str) -> Option<String> {
        let prefix = format!("{key} :");
        text.lines()
            .find_map(|line| line.trim().strip_prefix(&prefix))
            .map(|v| v.trim().to_string())
    }

    /// The primary network service — the one whose proxy settings
    /// `SCDynamicStore` surfaces as the global configuration. Resolved from the
    /// live global IPv4 state rather than guessed from service order.
    fn primary_service() -> Option<String> {
        let ipv4 = scutil_show("State:/Network/Global/IPv4")?;
        let id = scutil_field(&ipv4, "PrimaryService")?;
        let setup = scutil_show(&format!("Setup:/Network/Service/{id}"))?;
        scutil_field(&setup, "UserDefinedName")
    }

    struct WebProxyState {
        server: String,
        port: String,
        enabled: bool,
    }

    fn get_webproxy(service: &str, secure: bool) -> Option<WebProxyState> {
        let cmd = if secure {
            "-getsecurewebproxy"
        } else {
            "-getwebproxy"
        };
        let out = networksetup(&[cmd, service])?;
        let mut state = WebProxyState {
            server: String::new(),
            port: String::new(),
            enabled: false,
        };
        for line in out.lines() {
            if let Some(v) = line.strip_prefix("Server:") {
                state.server = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Port:") {
                state.port = v.trim().to_string();
            } else if let Some(v) = line.strip_prefix("Enabled:") {
                state.enabled = v.trim() == "Yes";
            }
        }
        Some(state)
    }

    /// Restores the service's web/secure-web proxy settings on drop so the test
    /// never leaves the CI runner (or a developer's machine) reconfigured.
    struct ProxyGuard {
        service: String,
        web: Option<WebProxyState>,
        secure: Option<WebProxyState>,
    }

    impl ProxyGuard {
        fn save(service: &str) -> Self {
            ProxyGuard {
                service: service.to_string(),
                web: get_webproxy(service, false),
                secure: get_webproxy(service, true),
            }
        }
    }

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            for (state, secure) in [(&self.web, false), (&self.secure, true)] {
                let Some(state) = state else { continue };
                let (set, toggle) = if secure {
                    ("-setsecurewebproxy", "-setsecurewebproxystate")
                } else {
                    ("-setwebproxy", "-setwebproxystate")
                };
                let port = if state.port.is_empty() {
                    "0"
                } else {
                    state.port.as_str()
                };
                let _ = networksetup(&[set, &self.service, &state.server, port]);
                let _ = networksetup(&[
                    toggle,
                    &self.service,
                    if state.enabled { "on" } else { "off" },
                ]);
            }
        }
    }

    // Round-trips a static proxy config through the OS: writes it with
    // `networksetup` and reads it back via `SCDynamicStore`. Only runs when
    // `OS_PROXY_RESOLVER_OS_TESTS` is set (it mutates global network settings),
    // which the dedicated CI job does.
    #[test]
    fn os_roundtrip_reads_networksetup_static() {
        if std::env::var_os("OS_PROXY_RESOLVER_OS_TESTS").is_none() {
            eprintln!(
                "skipping os_roundtrip_reads_networksetup_static: \
                 set OS_PROXY_RESOLVER_OS_TESTS=1 to run OS round-trip tests"
            );
            return;
        }
        let Some(service) = primary_service() else {
            eprintln!("skipping os_roundtrip_reads_networksetup_static: no network service");
            return;
        };
        let _guard = ProxyGuard::save(&service);

        assert!(networksetup(&["-setwebproxy", &service, "hp.example.com", "3128"]).is_some());
        assert!(networksetup(&["-setwebproxystate", &service, "on"]).is_some());
        assert!(
            networksetup(&["-setsecurewebproxy", &service, "sp.example.com", "8443"]).is_some()
        );
        assert!(networksetup(&["-setsecurewebproxystate", &service, "on"]).is_some());

        // networksetup commits asynchronously; SCDynamicStore may briefly lag.
        let deadline = Instant::now() + Duration::from_secs(5);
        let rules = loop {
            if let Some(rules) = read_config().static_rules {
                if rules.http.is_some() && rules.https.is_some() {
                    break rules;
                }
            }
            assert!(
                Instant::now() < deadline,
                "read_config did not reflect the networksetup proxy within 5s"
            );
            std::thread::sleep(Duration::from_millis(100));
        };

        assert_eq!(
            rules.http,
            Some(ProxyKind::Http("hp.example.com:3128".into()))
        );
        assert_eq!(
            rules.https,
            Some(ProxyKind::Http("sp.example.com:8443".into()))
        );
    }
}
