/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Windows: everything delegates to WinHTTP, which owns static config, PAC
//! evaluation, and WPAD (both DHCP option 252 and DNS) natively — no vendored
//! JS engine ships on this platform.
//!
//! - `WinHttpGetIEProxyConfigForCurrentUser` -> static proxy string, PAC URL,
//!   auto-detect flag.
//! - `WinHttpGetProxyForUrl` -> the actual PAC/WPAD resolution.
//! - Change watching: `RegNotifyChangeKeyValue` on
//!   `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
//!   (subtree, so the WinINET `Connections` blob is covered).

use super::{OsProxyConfig, StaticRules};
use crate::bypass::BypassRules;
use crate::types::{with_default_port, Error, ProxyKind, Result};
use std::ffi::c_void;
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GlobalFree, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpGetIEProxyConfigForCurrentUser, WinHttpGetProxyForUrl, WinHttpOpen,
    WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_AUTOPROXY_AUTO_DETECT, WINHTTP_AUTOPROXY_CONFIG_URL,
    WINHTTP_AUTOPROXY_OPTIONS, WINHTTP_AUTO_DETECT_TYPE_DHCP, WINHTTP_AUTO_DETECT_TYPE_DNS_A,
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegNotifyChangeKeyValue, RegOpenKeyExW, HKEY, HKEY_CURRENT_USER, KEY_NOTIFY,
    REG_NOTIFY_CHANGE_LAST_SET, REG_NOTIFY_CHANGE_NAME,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE,
};

const ERROR_WINHTTP_LOGIN_FAILURE: u32 = 12015;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copy a WinHTTP-allocated wide string and `GlobalFree` it.
unsafe fn take_wide_string(ptr: *mut u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let s = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
    GlobalFree(ptr as *mut c_void);
    Some(s).filter(|s| !s.is_empty())
}

pub(crate) fn read_config() -> OsProxyConfig {
    let mut ie = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG {
        fAutoDetect: 0,
        lpszAutoConfigUrl: std::ptr::null_mut(),
        lpszProxy: std::ptr::null_mut(),
        lpszProxyBypass: std::ptr::null_mut(),
    };
    if unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie) } == 0 {
        return OsProxyConfig::default();
    }
    let pac_url = unsafe { take_wide_string(ie.lpszAutoConfigUrl) };
    let proxy = unsafe { take_wide_string(ie.lpszProxy) };
    let bypass = unsafe { take_wide_string(ie.lpszProxyBypass) };

    let mut config = OsProxyConfig {
        auto_detect: ie.fAutoDetect != 0,
        pac_url,
        ..Default::default()
    };
    if let Some(proxy) = proxy {
        let mut rules = parse_static_proxy(&proxy);
        if let Some(bypass) = bypass {
            rules.bypass = BypassRules::parse([bypass.as_str()]);
        }
        if !rules.is_empty() {
            config.static_rules = Some(rules);
        }
    }
    config
}

/// Parse the WinHTTP/WinINET static proxy format:
/// `([<scheme>=][<scheme>://]<server>[:<port>])` separated by `;` or space,
/// e.g. `"proxy:8080"` or `"http=hp:80;https=sp:443;socks=sk:1080"`.
fn parse_static_proxy(s: &str) -> StaticRules {
    let mut rules = StaticRules::default();
    for entry in s.split([';', ' ']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (scheme, server) = match entry.split_once('=') {
            Some((s, v)) => (s.trim().to_ascii_lowercase(), v.trim()),
            None => (String::new(), entry),
        };
        let server = server.split_once("://").map_or(server, |(_, rest)| rest);
        if server.is_empty() {
            continue;
        }
        match scheme.as_str() {
            "" => {
                // Applies to every scheme unless a specific one is also set.
                let p = ProxyKind::Http(with_default_port(server, 80));
                rules.http.get_or_insert_with(|| p.clone());
                rules.https.get_or_insert(p);
            }
            "http" => rules.http = Some(ProxyKind::Http(with_default_port(server, 80))),
            "https" => rules.https = Some(ProxyKind::Http(with_default_port(server, 443))),
            "socks" => rules.socks = Some(ProxyKind::Socks(with_default_port(server, 1080))),
            _ => {}
        }
    }
    rules
}

/// Parse a `WINHTTP_PROXY_INFO.lpszProxy` result list for a given URL scheme.
/// WinHTTP already picked the entries; scheme-prefixed entries still need
/// filtering. NOTE: WinHTTP drops trailing `DIRECT` entries from PAC results
/// ("PROXY a; DIRECT" comes back as just "a") — a known WinHTTP limitation.
fn parse_winhttp_result_list(s: &str, url_scheme: &str) -> Vec<ProxyKind> {
    let mut out = Vec::new();
    for entry in s.split([';', ' ']) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (scheme, server) = match entry.split_once('=') {
            Some((s, v)) => (s.trim().to_ascii_lowercase(), v.trim()),
            None => (String::new(), entry),
        };
        let server = server.split_once("://").map_or(server, |(_, rest)| rest);
        if server.is_empty() {
            continue;
        }
        let kind = match scheme.as_str() {
            "" => ProxyKind::Http(with_default_port(server, 80)),
            "socks" => ProxyKind::Socks(with_default_port(server, 1080)),
            s if s == url_scheme
                || (s == "http" && url_scheme == "ws")
                || (s == "https" && url_scheme == "wss") =>
            {
                ProxyKind::Http(with_default_port(server, 80))
            }
            _ => continue,
        };
        if !out.contains(&kind) {
            out.push(kind);
        }
    }
    out
}

/// A WinHTTP session handle for `WinHttpGetProxyForUrl`. Session handles are
/// thread-safe per WinHTTP docs.
pub(crate) struct WinHttpResolver {
    session: HANDLE,
}
unsafe impl Send for WinHttpResolver {}
unsafe impl Sync for WinHttpResolver {}

impl WinHttpResolver {
    pub fn new() -> Result<Self> {
        let agent = to_wide("os-proxy-resolver");
        let session = unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_NO_PROXY,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if session.is_null() {
            return Err(Error::Platform(format!("WinHttpOpen failed: {}", unsafe {
                GetLastError()
            })));
        }
        Ok(WinHttpResolver { session })
    }

    /// Run WinHTTP's PAC/WPAD machinery for `url`. Returns `None` when
    /// resolution failed benignly (e.g. autodetection found no PAC) so the
    /// caller can fall back to static config / DIRECT.
    pub fn get_proxy_for_url(
        &self,
        url: &url::Url,
        auto_detect: bool,
        pac_url: Option<&str>,
    ) -> Option<Vec<ProxyKind>> {
        let pac_wide = pac_url.map(to_wide);
        let mut options = WINHTTP_AUTOPROXY_OPTIONS {
            dwFlags: 0,
            dwAutoDetectFlags: 0,
            lpszAutoConfigUrl: std::ptr::null(),
            lpvReserved: std::ptr::null_mut(),
            dwReserved: 0,
            fAutoLogonIfChallenged: 0,
        };
        if auto_detect {
            options.dwFlags |= WINHTTP_AUTOPROXY_AUTO_DETECT;
            options.dwAutoDetectFlags =
                WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
        }
        if let Some(pac) = &pac_wide {
            options.dwFlags |= WINHTTP_AUTOPROXY_CONFIG_URL;
            options.lpszAutoConfigUrl = pac.as_ptr();
        }
        if options.dwFlags == 0 {
            return None;
        }

        // Sanitize like the PAC path on other platforms: never hand identity
        // or https path/query to the PAC script.
        let sanitized = crate::types::sanitize_url_for_pac(url);
        let url_wide = to_wide(&sanitized);
        let mut info = WINHTTP_PROXY_INFO {
            dwAccessType: 0,
            lpszProxy: std::ptr::null_mut(),
            lpszProxyBypass: std::ptr::null_mut(),
        };
        let mut ok = unsafe {
            WinHttpGetProxyForUrl(self.session, url_wide.as_ptr(), &mut options, &mut info)
        } != 0;
        if !ok && unsafe { GetLastError() } == ERROR_WINHTTP_LOGIN_FAILURE {
            options.fAutoLogonIfChallenged = 1;
            ok = unsafe {
                WinHttpGetProxyForUrl(self.session, url_wide.as_ptr(), &mut options, &mut info)
            } != 0;
        }
        if !ok {
            log::debug!("WinHttpGetProxyForUrl failed for {url}: error {}", unsafe {
                GetLastError()
            });
            return None;
        }

        let proxy = unsafe { take_wide_string(info.lpszProxy) };
        let _bypass = unsafe { take_wide_string(info.lpszProxyBypass) };
        if info.dwAccessType == WINHTTP_ACCESS_TYPE_NO_PROXY {
            return Some(vec![ProxyKind::Direct]);
        }
        let list = proxy
            .map(|p| parse_winhttp_result_list(&p, url.scheme()))
            .unwrap_or_default();
        if list.is_empty() {
            Some(vec![ProxyKind::Direct])
        } else {
            Some(list)
        }
    }
}

impl Drop for WinHttpResolver {
    fn drop(&mut self) {
        unsafe { WinHttpCloseHandle(self.session) };
    }
}

// --------------------------------------------------------------------------
// Change watcher

pub(crate) struct Watcher {
    stop_event: HANDLE,
    thread: Option<std::thread::JoinHandle<()>>,
}
unsafe impl Send for Watcher {}
unsafe impl Sync for Watcher {}

pub(crate) fn spawn_watcher(on_change: Arc<dyn Fn() + Send + Sync>) -> Watcher {
    let stop_event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
    if stop_event.is_null() {
        return Watcher {
            stop_event,
            thread: None,
        };
    }
    let stop = stop_event as usize;
    let thread = std::thread::Builder::new()
        .name("os-proxy-watch".into())
        .spawn(move || watch_registry(stop as HANDLE, on_change))
        .ok();
    Watcher { stop_event, thread }
}

fn watch_registry(stop_event: HANDLE, on_change: Arc<dyn Fn() + Send + Sync>) {
    let key_path = to_wide("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings");
    let mut hkey: HKEY = std::ptr::null_mut();
    if unsafe {
        RegOpenKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0,
            KEY_NOTIFY,
            &mut hkey,
        )
    } != 0
    {
        return;
    }
    let notify_event = unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) };
    if notify_event.is_null() {
        unsafe { RegCloseKey(hkey) };
        return;
    }
    loop {
        let armed = unsafe {
            RegNotifyChangeKeyValue(
                hkey,
                1, // watch subtree (covers Connections\DefaultConnectionSettings)
                REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
                notify_event,
                1, // asynchronous
            )
        } == 0;
        if !armed {
            break;
        }
        let handles = [stop_event, notify_event];
        let waited = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        if waited == WAIT_OBJECT_0 {
            break; // stop requested
        }
        if waited == WAIT_OBJECT_0 + 1 {
            on_change();
        } else {
            break;
        }
    }
    unsafe {
        CloseHandle(notify_event);
        RegCloseKey(hkey);
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        if !self.stop_event.is_null() {
            unsafe { SetEvent(self.stop_event) };
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if !self.stop_event.is_null() {
            unsafe { CloseHandle(self.stop_event) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_proxy_single_server() {
        let rules = parse_static_proxy("proxy:8080");
        assert_eq!(rules.http, Some(ProxyKind::Http("proxy:8080".into())));
        assert_eq!(rules.https, Some(ProxyKind::Http("proxy:8080".into())));
    }

    #[test]
    fn static_proxy_per_scheme() {
        let rules = parse_static_proxy("http=hp:80;https=sp;socks=sk");
        assert_eq!(rules.http, Some(ProxyKind::Http("hp:80".into())));
        assert_eq!(rules.https, Some(ProxyKind::Http("sp:443".into())));
        assert_eq!(rules.socks, Some(ProxyKind::Socks("sk:1080".into())));
    }

    #[test]
    fn result_list_filters_by_scheme() {
        let got = parse_winhttp_result_list("http=a:1;https=b:2;c:3", "https");
        assert_eq!(
            got,
            vec![ProxyKind::Http("b:2".into()), ProxyKind::Http("c:3".into())]
        );
    }
}
