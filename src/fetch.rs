/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! PAC / wpad.dat fetching. HTTP uses WinHTTP/Schannel on Windows and
//! ureq/rustls with OS trust-store roots elsewhere; both feed the same
//! size-limited UTF-8 reader. The PAC URL can point anywhere, including at
//! something hostile or unresponsive.

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
        let file = std::fs::File::open(&path)
            .map_err(|e| Error::PacFetch(format!("{}: {e}", path.display())))?;
        return read_pac(file, &path.display().to_string());
    }

    read_pac(fetch_http(pac_url, timeout)?, pac_url)
}

fn read_pac(mut reader: impl Read, source: &str) -> Result<String> {
    let mut body = Vec::new();
    reader
        .by_ref()
        .take(MAX_PAC_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|e| Error::PacFetch(format!("{source}: read: {e}")))?;
    if body.len() as u64 > MAX_PAC_BYTES {
        return Err(Error::PacFetch(format!(
            "{source}: PAC script exceeds 1 MiB"
        )));
    }
    String::from_utf8(body).map_err(|e| Error::PacFetch(format!("{source}: {e}")))
}

#[cfg(not(windows))]
fn fetch_http(pac_url: &str, timeout: Duration) -> Result<impl Read> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(4)
        // The PAC URL must be reachable without a proxy — never recurse.
        .build();
    let response = agent
        .get(pac_url)
        .call()
        .map_err(|e| Error::PacFetch(format!("{pac_url}: {e}")))?;
    Ok(response.into_reader())
}

#[cfg(windows)]
fn fetch_http(pac_url: &str, timeout: Duration) -> Result<impl Read> {
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Networking::WinHttp::{
        WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders,
        WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
        WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_OPEN_REQUEST_FLAGS,
        WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE,
    };

    struct Handle(*mut std::ffi::c_void);
    impl Drop for Handle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { WinHttpCloseHandle(self.0) };
            }
        }
    }

    struct Response {
        _session: Handle,
        _connection: Handle,
        request: Handle,
    }

    impl Read for Response {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let mut read = 0u32;
            let buffer_len = buffer.len().min(u32::MAX as usize) as u32;
            if unsafe {
                WinHttpReadData(
                    self.request.0,
                    buffer.as_mut_ptr().cast(),
                    buffer_len,
                    &mut read,
                )
            } == 0
            {
                return Err(std::io::Error::from_raw_os_error(
                    unsafe { GetLastError() } as i32
                ));
            }
            Ok(read as usize)
        }
    }

    let url =
        url::Url::parse(pac_url).map_err(|error| Error::PacFetch(format!("{pac_url}: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(Error::PacFetch(format!(
            "{pac_url}: unsupported PAC URL scheme"
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| Error::PacFetch(format!("{pac_url}: missing host")))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| Error::PacFetch(format!("{pac_url}: missing port")))?;
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let wide = |value: &str| {
        value
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>()
    };
    let agent = wide("os-proxy-resolver");
    let session = Handle(unsafe {
        WinHttpOpen(
            agent.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    });
    if session.0.is_null() {
        return Err(Error::PacFetch(format!(
            "{pac_url}: WinHttpOpen failed: {}",
            unsafe { GetLastError() }
        )));
    }
    let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
    unsafe { WinHttpSetTimeouts(session.0, timeout_ms, timeout_ms, timeout_ms, timeout_ms) };
    let host = wide(host);
    let connection = Handle(unsafe { WinHttpConnect(session.0, host.as_ptr(), port, 0) });
    if connection.0.is_null() {
        return Err(Error::PacFetch(format!(
            "{pac_url}: WinHttpConnect failed: {}",
            unsafe { GetLastError() }
        )));
    }
    let verb = wide("GET");
    let path = wide(&path);
    let flags: WINHTTP_OPEN_REQUEST_FLAGS = if url.scheme() == "https" {
        WINHTTP_FLAG_SECURE
    } else {
        0
    };
    let request = Handle(unsafe {
        WinHttpOpenRequest(
            connection.0,
            verb.as_ptr(),
            path.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            flags,
        )
    });
    if request.0.is_null()
        || unsafe { WinHttpSendRequest(request.0, std::ptr::null(), 0, std::ptr::null(), 0, 0, 0) }
            == 0
        || unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) } == 0
    {
        return Err(Error::PacFetch(format!(
            "{pac_url}: WinHTTP request failed: {}",
            unsafe { GetLastError() }
        )));
    }
    let mut status = 0u32;
    let mut status_size = std::mem::size_of::<u32>() as u32;
    if unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            std::ptr::null(),
            (&mut status as *mut u32).cast(),
            &mut status_size,
            std::ptr::null_mut(),
        )
    } == 0
        || !(200..300).contains(&status)
    {
        return Err(Error::PacFetch(format!("{pac_url}: HTTP status {status}")));
    }

    Ok(Response {
        _session: session,
        _connection: connection,
        request,
    })
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

    #[test]
    fn rejects_oversized_pac_from_any_transport() {
        let body = vec![b'a'; MAX_PAC_BYTES as usize + 1];
        let error = read_pac(body.as_slice(), "test").unwrap_err();
        assert!(error.to_string().contains("exceeds 1 MiB"));
    }

    #[test]
    fn rejects_non_utf8_pac_from_any_transport() {
        let error = read_pac([0xff].as_slice(), "test").unwrap_err();
        assert!(error.to_string().contains("invalid utf-8"));
    }
}
