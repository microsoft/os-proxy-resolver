/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! PAC / wpad.dat fetching (macOS/Linux only — Windows fetches PAC inside
//! WinHTTP). Small, sync, with tight timeouts and a size cap: a PAC URL can
//! point anywhere, including at something hostile or unresponsive.

use crate::types::{Error, Result};
use std::io::Read;
use std::time::Duration;

/// PAC scripts beyond this size are rejected (Chromium caps at 1 MiB).
const MAX_PAC_BYTES: u64 = 1024 * 1024;

pub(crate) fn fetch_pac(pac_url: &str, timeout: Duration) -> Result<String> {
    if let Some(rest) = pac_url.strip_prefix("file://") {
        let path = url::Url::parse(pac_url)
            .ok()
            .and_then(|u| u.to_file_path().ok())
            .unwrap_or_else(|| std::path::PathBuf::from(rest));
        return std::fs::read_to_string(&path)
            .map_err(|e| Error::PacFetch(format!("{}: {e}", path.display())));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(4)
        // The PAC URL must be reachable without a proxy — never recurse.
        .build();
    let response = agent
        .get(pac_url)
        .call()
        .map_err(|e| Error::PacFetch(format!("{pac_url}: {e}")))?;
    let mut body = String::new();
    response
        .into_reader()
        .take(MAX_PAC_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|e| Error::PacFetch(format!("{pac_url}: read: {e}")))?;
    if body.len() as u64 > MAX_PAC_BYTES {
        return Err(Error::PacFetch(format!(
            "{pac_url}: PAC script exceeds 1 MiB"
        )));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetches_file_urls() {
        let dir = std::env::temp_dir().join("os-proxy-resolver-test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.pac");
        std::fs::write(&path, "function FindProxyForURL(u, h) { return 'DIRECT'; }").unwrap();
        let url = url::Url::from_file_path(&path).unwrap();
        let got = fetch_pac(url.as_str(), Duration::from_secs(1)).unwrap();
        assert!(got.contains("FindProxyForURL"));
    }

    #[test]
    fn missing_file_is_an_error() {
        assert!(fetch_pac("file:///nonexistent/x.pac", Duration::from_secs(1)).is_err());
    }
}
