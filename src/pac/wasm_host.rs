/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Host-side pieces shared by the wasm PAC backends (Wasmtime and wasm2c):
//! the runtime-agnostic halves of the capability-free WASI stubs and the
//! mapping from guest status codes (see `wasm_abi.rs`) to [`Error`].

use std::sync::OnceLock;
use std::time::{Instant, SystemTime};

use super::engine::Error;
use super::wasm_abi as abi;

pub(crate) const WASI_SUCCESS: i32 = 0;
pub(crate) const WASI_EBADF: i32 = 8;

/// `clock_time_get` values: real time for `Date`/`dateRange()` (clock id 0),
/// process-monotonic nanoseconds for everything else.
pub(crate) fn clock_nanos(clock_id: u32) -> u64 {
    static MONOTONIC_START: OnceLock<Instant> = OnceLock::new();
    match clock_id {
        // CLOCK_REALTIME: civil time for Date / dateRange().
        0 => SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0),
        // CLOCK_MONOTONIC.
        _ => MONOTONIC_START
            .get_or_init(Instant::now)
            .elapsed()
            .as_nanos() as u64,
    }
}

/// splitmix64, seeded once per process. Non-cryptographic by design — inside
/// the sandbox it only serves `Math.random()` and QuickJS hash seeds.
pub(crate) fn fill_pseudo_random(buf: &mut [u8]) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static STATE: AtomicU64 = AtomicU64::new(0);
    static SEED: OnceLock<u64> = OnceLock::new();
    let seed = *SEED.get_or_init(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15)
            ^ (&STATE as *const _ as u64)
    });
    STATE
        .compare_exchange(0, seed, Ordering::Relaxed, Ordering::Relaxed)
        .ok();
    for chunk in buf.chunks_mut(8) {
        let mut z = STATE.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^= z >> 31;
        chunk.copy_from_slice(&z.to_le_bytes()[..chunk.len()]);
    }
}

/// Decodes a guest result payload (first byte is the `STATUS_*` code, see
/// `wasm_abi.rs`) into the shared engine error type.
pub(crate) fn status_to_result(buf: &[u8]) -> Result<String, Error> {
    let Some((&status, payload)) = buf.split_first() else {
        return Err(Error::Internal("empty result from PAC guest".into()));
    };
    let payload = String::from_utf8_lossy(payload).into_owned();
    match status {
        abi::STATUS_OK => Ok(payload),
        abi::STATUS_SCRIPT_SYNTAX => Err(Error::ScriptSyntax(payload)),
        abi::STATUS_FUNCTION_MISSING => Err(Error::FunctionMissing(payload)),
        abi::STATUS_JS_EXCEPTION => Err(Error::JsException(payload)),
        abi::STATUS_RETURNED_NON_STRING => Err(Error::ReturnedNonString(payload)),
        // Clean deadline unwind via the guest's interrupt handler; the
        // instance stays usable (no rebuild required).
        abi::STATUS_TIMEOUT => Err(Error::Timeout),
        _ => Err(Error::Internal(payload)),
    }
}
