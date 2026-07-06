/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Platform config *sources*, kept strictly separate from PAC *evaluation*
//! (mirroring Chromium's `ProxyConfigService` / `ProxyResolver` boundary).
//! Each platform provides:
//!
//! - `read_config()` — a snapshot of the OS proxy configuration
//! - `spawn_watcher(on_change)` — a thread wired to the native change signal
//!   (SCDynamicStore callback / dconf-gsettings monitor / registry notify)
//!   that invokes `on_change` on every possible change. Returned handle stops
//!   the watcher on drop.

use crate::bypass::BypassRules;
use crate::types::ProxyKind;

#[cfg(target_os = "macos")]
#[path = "macos.rs"]
mod imp;
#[cfg(all(unix, not(target_os = "macos")))]
#[path = "linux.rs"]
mod imp;
#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

#[cfg(windows)]
pub(crate) use imp::WinHttpResolver;
pub(crate) use imp::{read_config, spawn_watcher, Watcher};

/// Snapshot of the OS proxy configuration. Multiple mechanisms can be active
/// at once (macOS allows auto-detect + PAC URL + static simultaneously);
/// resolution tries them in that order.
#[derive(Debug, Clone, Default)]
pub(crate) struct OsProxyConfig {
    /// WPAD requested (macOS `ProxyAutoDiscoveryEnable`, GNOME mode "auto"
    /// with empty autoconfig-url, Windows `fAutoDetect`).
    pub auto_detect: bool,
    pub pac_url: Option<String>,
    pub static_rules: Option<StaticRules>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct StaticRules {
    /// Proxy for plain-http requests.
    pub http: Option<ProxyKind>,
    /// Proxy for https requests (an HTTP CONNECT proxy unless prefixed).
    pub https: Option<ProxyKind>,
    /// SOCKS fallback for schemes without a specific proxy.
    pub socks: Option<ProxyKind>,
    pub bypass: BypassRules,
}

impl StaticRules {
    pub fn proxy_for_scheme(&self, scheme: &str) -> Option<&ProxyKind> {
        let specific = match scheme {
            "http" | "ws" => self.http.as_ref(),
            "https" | "wss" => self.https.as_ref(),
            _ => None,
        };
        specific.or(self.socks.as_ref())
    }

    pub fn is_empty(&self) -> bool {
        self.http.is_none() && self.https.is_none() && self.socks.is_none()
    }
}
