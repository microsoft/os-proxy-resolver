/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Linux: GNOME's `org.gnome.system.proxy` GSettings tree, accessed in-process
//! through GIO. The shared libraries are loaded at runtime so headless systems
//! without GLib can still use the environment-variable layer. Change signals
//! are dispatched on a private GLib main context thread. KDE and proxy
//! authentication are non-goals.

use super::{OsProxyConfig, StaticRules};
use crate::bypass::BypassRules;
use crate::types::{LinuxProxyConfig, PlatformProxyConfig, ProxyKind};
use std::sync::Arc;

mod gio;
pub(crate) use gio::Watcher;

pub(crate) fn read_config() -> OsProxyConfig {
    gio::read_values()
        .map(config_from_values)
        .unwrap_or_default()
}

fn config_from_values(values: gio::Values) -> OsProxyConfig {
    let mut config = OsProxyConfig {
        platform: Some(PlatformProxyConfig::Linux(LinuxProxyConfig {
            mode: (!values.mode.is_empty()).then(|| values.mode.clone()),
            ignore_hosts: values.ignore_hosts.clone(),
        })),
        ..Default::default()
    };
    match values.mode.as_str() {
        "auto" => {
            config.pac_url = (!values.autoconfig_url.is_empty()).then_some(values.autoconfig_url);
            // GNOME semantics: "auto" with no PAC URL means WPAD.
            config.auto_detect = config.pac_url.is_none();
        }
        "manual" => {
            let rules = StaticRules {
                http: host_port(&values.http_host, values.http_port).map(ProxyKind::Http),
                https: host_port(&values.https_host, values.https_port).map(ProxyKind::Http),
                socks: host_port(&values.socks_host, values.socks_port).map(ProxyKind::Socks),
                bypass: BypassRules::parse(values.ignore_hosts.iter().map(String::as_str)),
            };
            if !rules.is_empty() {
                config.static_rules = Some(rules);
            }
        }
        _ => {} // "none", unset, or unknown -> direct
    }
    config
}

fn host_port(host: &str, port: i32) -> Option<String> {
    if host.is_empty() {
        return None;
    }
    let port = u16::try_from(port).ok().filter(|&port| port != 0)?;
    Some(format!("{host}:{port}"))
}

pub(crate) fn spawn_watcher(on_change: Arc<dyn Fn() + Send + Sync>) -> Watcher {
    gio::spawn_watcher(on_change)
}

/// DNS search domains from the OS resolver configuration. On Linux this is
/// `/etc/resolv.conf` (written by systemd-resolved / NetworkManager / the
/// DHCP client), which is the OS-native source.
pub(crate) fn dns_search_domains() -> Vec<String> {
    super::resolv_conf_search_domains()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::{mpsc, Mutex};
    use std::time::Duration;

    static OS_TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn builds_manual_mode() {
        let cfg = config_from_values(gio::Values {
            mode: "manual".into(),
            ignore_hosts: vec!["localhost".into(), "127.0.0.0/8".into(), "::1".into()],
            http_host: "hp.example.com".into(),
            http_port: 3128,
            socks_host: "sp.example.com".into(),
            socks_port: 1080,
            ..Default::default()
        });
        assert!(!cfg.auto_detect);
        assert_eq!(cfg.pac_url, None);
        let rules = cfg.static_rules.unwrap();
        assert_eq!(
            rules.http,
            Some(ProxyKind::Http("hp.example.com:3128".into()))
        );
        assert_eq!(rules.https, None);
        assert_eq!(
            rules.socks,
            Some(ProxyKind::Socks("sp.example.com:1080".into()))
        );
        assert!(rules.bypass.matches("localhost", 80));
        assert!(rules.bypass.matches("127.0.0.1", 80));
        // https falls back to socks
        assert_eq!(
            rules.proxy_for_scheme("https"),
            Some(&ProxyKind::Socks("sp.example.com:1080".into()))
        );
    }

    #[test]
    fn builds_auto_modes() {
        let cfg = config_from_values(gio::Values {
            mode: "auto".into(),
            autoconfig_url: "http://x/p.pac".into(),
            ..Default::default()
        });
        assert!(!cfg.auto_detect);
        assert_eq!(cfg.pac_url.as_deref(), Some("http://x/p.pac"));

        let cfg = config_from_values(gio::Values {
            mode: "auto".into(),
            ..Default::default()
        });
        assert!(cfg.auto_detect);
        assert_eq!(cfg.pac_url, None);
    }

    #[test]
    fn none_mode_is_direct() {
        let cfg = config_from_values(gio::Values {
            mode: "none".into(),
            ..Default::default()
        });
        assert!(!cfg.auto_detect);
        assert!(cfg.pac_url.is_none());
        assert!(cfg.static_rules.is_none());
    }

    fn gsettings_get(schema: &str, key: &str) -> Option<String> {
        let out = Command::new("gsettings")
            .args(["get", schema, key])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn gsettings_set(schema: &str, key: &str, value: &str) -> bool {
        Command::new("gsettings")
            .args(["set", schema, key, value])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Restores the touched GSettings keys on drop. Values captured with
    /// `gsettings get` are already in the exact form `gsettings set` accepts.
    struct GSettingsGuard {
        saved: Vec<(&'static str, &'static str, Option<String>)>,
    }

    impl GSettingsGuard {
        fn save(keys: &[(&'static str, &'static str)]) -> Self {
            let saved = keys
                .iter()
                .map(|&(schema, key)| (schema, key, gsettings_get(schema, key)))
                .collect();
            GSettingsGuard { saved }
        }
    }

    impl Drop for GSettingsGuard {
        fn drop(&mut self) {
            for (schema, key, value) in &self.saved {
                if let Some(value) = value {
                    let _ = gsettings_set(schema, key, value);
                }
            }
        }
    }

    // Round-trips manual and auto proxy configs through GNOME's GSettings and
    // reads them back via `read_config`. Only runs when
    // `OS_PROXY_RESOLVER_OS_TESTS` is set (it mutates the session's proxy
    // settings and needs a working D-Bus/dconf backend), which the dedicated
    // CI job provides via `dbus-run-session`.
    #[test]
    fn os_roundtrip_reads_gsettings_manual_and_auto() {
        if std::env::var_os("OS_PROXY_RESOLVER_OS_TESTS").is_none() {
            eprintln!(
                "skipping os_roundtrip_reads_gsettings_manual_and_auto: \
                 set OS_PROXY_RESOLVER_OS_TESTS=1 to run OS round-trip tests"
            );
            return;
        }
        let _test_lock = OS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // No working gsettings / GNOME proxy schema (e.g. headless minimal
        // image) means there is nothing to round-trip through.
        if gsettings_get("org.gnome.system.proxy", "mode").is_none() {
            eprintln!(
                "skipping os_roundtrip_reads_gsettings_manual_and_auto: \
                 gsettings org.gnome.system.proxy unavailable"
            );
            return;
        }

        let _guard = GSettingsGuard::save(&[
            ("org.gnome.system.proxy", "mode"),
            ("org.gnome.system.proxy", "autoconfig-url"),
            ("org.gnome.system.proxy", "ignore-hosts"),
            ("org.gnome.system.proxy.http", "host"),
            ("org.gnome.system.proxy.http", "port"),
            ("org.gnome.system.proxy.socks", "host"),
            ("org.gnome.system.proxy.socks", "port"),
        ]);

        assert!(gsettings_set(
            "org.gnome.system.proxy.http",
            "host",
            "hp.example.com"
        ));
        assert!(gsettings_set("org.gnome.system.proxy.http", "port", "3128"));
        assert!(gsettings_set(
            "org.gnome.system.proxy.socks",
            "host",
            "sp.example.com"
        ));
        assert!(gsettings_set(
            "org.gnome.system.proxy.socks",
            "port",
            "1080"
        ));
        assert!(gsettings_set(
            "org.gnome.system.proxy",
            "ignore-hosts",
            "['localhost', '127.0.0.0/8']"
        ));
        // Set the mode last so the read observes a fully-populated config.
        assert!(gsettings_set("org.gnome.system.proxy", "mode", "manual"));

        let cfg = read_config();
        let rules = cfg
            .static_rules
            .expect("expected static rules from manual gsettings config");
        assert_eq!(
            rules.http,
            Some(ProxyKind::Http("hp.example.com:3128".into()))
        );
        assert_eq!(
            rules.socks,
            Some(ProxyKind::Socks("sp.example.com:1080".into()))
        );
        assert!(rules.bypass.matches("localhost", 80));

        // Auto mode with an explicit PAC URL.
        assert!(gsettings_set(
            "org.gnome.system.proxy",
            "autoconfig-url",
            "http://wpad.example.com/proxy.pac"
        ));
        assert!(gsettings_set("org.gnome.system.proxy", "mode", "auto"));
        let cfg = read_config();
        assert_eq!(
            cfg.pac_url.as_deref(),
            Some("http://wpad.example.com/proxy.pac")
        );
        assert!(!cfg.auto_detect);
    }

    #[test]
    fn os_watcher_observes_root_and_child_changes() {
        if std::env::var_os("OS_PROXY_RESOLVER_OS_TESTS").is_none() {
            eprintln!(
                "skipping os_watcher_observes_root_and_child_changes: \
                 set OS_PROXY_RESOLVER_OS_TESTS=1 to run OS watcher tests"
            );
            return;
        }
        let _test_lock = OS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let current_mode = gsettings_get("org.gnome.system.proxy", "mode");
        if current_mode.is_none() {
            eprintln!(
                "skipping os_watcher_observes_root_and_child_changes: \
                 gsettings org.gnome.system.proxy unavailable"
            );
            return;
        }

        let _guard = GSettingsGuard::save(&[
            ("org.gnome.system.proxy", "mode"),
            ("org.gnome.system.proxy.http", "host"),
        ]);
        let (changed_tx, changed_rx) = mpsc::channel();
        let watcher = spawn_watcher(Arc::new(move || {
            let _ = changed_tx.send(());
        }));

        let next_mode = if current_mode.as_deref() == Some("'manual'") {
            "none"
        } else {
            "manual"
        };
        assert!(gsettings_set("org.gnome.system.proxy", "mode", next_mode));
        changed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("GIO watcher did not observe root proxy setting change");

        while changed_rx.try_recv().is_ok() {}
        assert!(gsettings_set(
            "org.gnome.system.proxy.http",
            "host",
            "watcher-test.example.com"
        ));
        changed_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("GIO watcher did not observe child proxy setting change");

        drop(watcher);
    }
}
