/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Highest-precedence layer: `http_proxy` / `https_proxy` / `all_proxy` /
//! `no_proxy` environment variables (lowercase preferred, uppercase accepted).
//! If a proxy variable applies, the OS configuration is not consulted; a
//! `no_proxy` match yields a definitive `DIRECT` (curl semantics), not a
//! fall-through to the OS config.

use crate::bypass::BypassRules;
use crate::types::{
    with_default_port, EnvironmentProxyConfig, EnvironmentVariableStatus, ProxyKind,
};
use url::Url;

#[derive(Debug, Default, Clone)]
pub(crate) struct EnvConfig {
    http: Option<ProxyKind>,
    https: Option<ProxyKind>,
    all: Option<ProxyKind>,
    no_proxy: BypassRules,
    diagnostics: EnvironmentProxyConfig,
}

impl EnvConfig {
    pub fn from_env() -> Self {
        Self::from_named_lookup(lookup_environment_variable)
    }

    #[cfg(test)]
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        Self::from_named_lookup(|name| get(name).map(|value| (name.to_string(), value)))
    }

    fn from_named_lookup(get: impl Fn(&str) -> Option<(String, String)>) -> Self {
        let (http, http_status) = inspect_proxy(get("http_proxy"));
        let (https, https_status) = inspect_proxy(get("https_proxy"));
        let (all, all_status) = inspect_proxy(get("all_proxy"));
        let (no_proxy, no_proxy_status) = inspect_no_proxy(get("no_proxy"));
        EnvConfig {
            http,
            https,
            all,
            no_proxy,
            diagnostics: EnvironmentProxyConfig {
                http_proxy: http_status,
                https_proxy: https_status,
                all_proxy: all_status,
                no_proxy: no_proxy_status,
            },
        }
    }

    pub fn diagnostics(&self) -> EnvironmentProxyConfig {
        self.diagnostics.clone()
    }

    /// `None` when the environment does not configure a proxy for this URL's
    /// scheme (fall through to OS config). `Some(vec![Direct])` when a proxy
    /// is configured but `no_proxy` excludes the host.
    pub fn proxy_for(&self, url: &Url) -> Option<Vec<ProxyKind>> {
        let proxy = match url.scheme() {
            "http" | "ws" => self.http.as_ref().or(self.all.as_ref()),
            "https" | "wss" => self.https.as_ref().or(self.all.as_ref()),
            _ => self.all.as_ref(),
        }?;
        let host = url.host_str()?;
        let port = url.port_or_known_default().unwrap_or(0);
        if self.no_proxy.matches(host, port) {
            return Some(vec![ProxyKind::Direct]);
        }
        Some(vec![proxy.clone()])
    }
}

#[cfg(windows)]
fn lookup_environment_variable(name: &str) -> Option<(String, String)> {
    std::env::vars_os().find_map(|(key, value)| {
        let key = key.into_string().ok()?;
        if key.eq_ignore_ascii_case(name) {
            value.into_string().ok().map(|value| (key, value))
        } else {
            None
        }
    })
}

#[cfg(not(windows))]
fn lookup_environment_variable(name: &str) -> Option<(String, String)> {
    let lowercase = name.to_ascii_lowercase();
    let uppercase = name.to_ascii_uppercase();
    std::env::var(&lowercase)
        .ok()
        .map(|value| (lowercase, value))
        .or_else(|| {
            std::env::var(&uppercase)
                .ok()
                .map(|value| (uppercase, value))
        })
}

fn inspect_proxy(
    setting: Option<(String, String)>,
) -> (Option<ProxyKind>, Option<EnvironmentVariableStatus>) {
    let Some((variable, value)) = setting else {
        return (None, None);
    };
    let Some(proxy) = parse_proxy_value(&value) else {
        return (
            None,
            Some(EnvironmentVariableStatus {
                variable,
                value,
                error: Some("proxy value is empty or has no host".into()),
            }),
        );
    };
    (
        Some(proxy),
        Some(EnvironmentVariableStatus {
            variable,
            value,
            error: None,
        }),
    )
}

fn inspect_no_proxy(
    setting: Option<(String, String)>,
) -> (BypassRules, Option<EnvironmentVariableStatus>) {
    let Some((variable, value)) = setting else {
        return (BypassRules::default(), None);
    };
    (
        BypassRules::parse([value.as_str()]),
        Some(EnvironmentVariableStatus {
            variable,
            value,
            error: None,
        }),
    )
}

/// Parse an env proxy value: `http://host:port`, `socks5://host:port`, or a
/// bare `host:port` (treated as an HTTP proxy).
fn parse_proxy_value(value: &str) -> Option<ProxyKind> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (scheme, rest) = match value.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => ("http".to_string(), value),
    };
    // Strip userinfo and any path; keep host[:port].
    let rest = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let host_port = rest.rsplit_once('@').map_or(rest, |(_, hp)| hp);
    if host_port.is_empty() {
        return None;
    }
    match scheme.as_str() {
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => {
            Some(ProxyKind::Socks(with_default_port(host_port, 1080)))
        }
        "https" => Some(ProxyKind::Http(format!(
            "https://{}",
            with_default_port(host_port, 443)
        ))),
        _ => Some(ProxyKind::Http(with_default_port(host_port, 80))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(pairs: &[(&str, &str)]) -> EnvConfig {
        EnvConfig::from_lookup(|name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.to_string())
        })
    }

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn scheme_selection_and_fallback() {
        let c = cfg(&[
            ("http_proxy", "http://hp:3128"),
            ("all_proxy", "socks5://sp:1080"),
        ]);
        assert_eq!(
            c.proxy_for(&url("http://x.com/")),
            Some(vec![ProxyKind::Http("hp:3128".into())])
        );
        assert_eq!(
            c.proxy_for(&url("https://x.com/")),
            Some(vec![ProxyKind::Socks("sp:1080".into())])
        );
        assert_eq!(
            c.proxy_for(&url("ftp://x.com/")),
            Some(vec![ProxyKind::Socks("sp:1080".into())])
        );
    }

    #[test]
    fn unset_env_falls_through() {
        let c = cfg(&[]);
        assert_eq!(c.proxy_for(&url("http://x.com/")), None);
        // no_proxy alone doesn't activate the env layer
        let c = cfg(&[("no_proxy", "x.com")]);
        assert_eq!(c.proxy_for(&url("http://x.com/")), None);
    }

    #[test]
    fn no_proxy_yields_direct() {
        let c = cfg(&[
            ("https_proxy", "hp:3128"),
            ("no_proxy", "localhost, .internal, 10.0.0.0/8"),
        ]);
        assert_eq!(
            c.proxy_for(&url("https://localhost:8443/")),
            Some(vec![ProxyKind::Direct])
        );
        assert_eq!(
            c.proxy_for(&url("https://svc.internal/")),
            Some(vec![ProxyKind::Direct])
        );
        assert_eq!(
            c.proxy_for(&url("https://10.1.2.3/")),
            Some(vec![ProxyKind::Direct])
        );
        assert_eq!(
            c.proxy_for(&url("https://example.com/")),
            Some(vec![ProxyKind::Http("hp:3128".into())])
        );
    }

    #[test]
    fn value_parsing() {
        assert_eq!(
            parse_proxy_value("http://user:pw@h:8080/ignored"),
            Some(ProxyKind::Http("h:8080".into()))
        );
        assert_eq!(parse_proxy_value("h"), Some(ProxyKind::Http("h:80".into())));
        assert_eq!(
            parse_proxy_value("socks://h"),
            Some(ProxyKind::Socks("h:1080".into()))
        );
        assert_eq!(
            parse_proxy_value("https://h"),
            Some(ProxyKind::Http("https://h:443".into()))
        );
        assert_eq!(parse_proxy_value("  "), None);
    }

    #[test]
    fn diagnostics_capture_effective_variables_and_raw_values() {
        let config = EnvConfig::from_named_lookup(|name| match name {
            "http_proxy" => Some(("HTTP_PROXY".into(), "http://user:secret@proxy:8080".into())),
            "https_proxy" => Some(("https_proxy".into(), "   ".into())),
            "no_proxy" => Some(("NO_PROXY".into(), "localhost,.internal".into())),
            _ => None,
        });
        let diagnostics = config.diagnostics();
        assert_eq!(
            diagnostics.http_proxy,
            Some(EnvironmentVariableStatus {
                variable: "HTTP_PROXY".into(),
                value: "http://user:secret@proxy:8080".into(),
                error: None,
            })
        );
        assert!(diagnostics.https_proxy.as_ref().unwrap().error.is_some());
        let no_proxy = diagnostics.no_proxy.as_ref().unwrap();
        assert_eq!(no_proxy.variable, "NO_PROXY");
        assert_eq!(no_proxy.value, "localhost,.internal");
        assert!(diagnostics.all_proxy.is_none());
    }
}
