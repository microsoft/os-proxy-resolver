/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! With the `pac-engine-wasmtime` feature, ahead-of-time compiles the vendored
//! PAC guest module (`pac-wasm-guest/pac_guest.wasm`, wasm32-wasip1) into a
//! target-specific native artifact in `OUT_DIR`. This is the only place a wasm
//! compiler (Cranelift, via the `wasmtime-aot` build-dependency) runs — the
//! library's runtime `wasmtime` dependency has no compiler at all and only
//! deserializes the artifact produced here.
//!
//! Without the feature this build script is a no-op, keeping the default build
//! byte-for-byte independent of Wasmtime.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "pac-engine-wasmtime")]
    precompile_pac_guest();
}

#[cfg(feature = "pac-engine-wasmtime")]
fn precompile_pac_guest() {
    // Cranelift's compilation is deeply recursive and can overflow the main
    // thread's stack (notably the smaller default on Windows), so run it on a
    // dedicated thread with a generous stack size.
    let child = std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(precompile_pac_guest_inner)
        .expect("failed to spawn PAC guest compiler thread");
    child.join().expect("PAC guest compiler thread panicked");
}

#[cfg(feature = "pac-engine-wasmtime")]
fn precompile_pac_guest_inner() {
    use std::path::PathBuf;

    // The vendored guest module. Point the env var at a fresh build of
    // pac-wasm-guest to test guest changes without touching the vendored copy
    // (see pac-wasm-guest/README.md).
    println!("cargo:rerun-if-env-changed=OS_PROXY_RESOLVER_PAC_GUEST_WASM");
    let wasm_path = std::env::var("OS_PROXY_RESOLVER_PAC_GUEST_WASM")
        .unwrap_or_else(|_| "pac-wasm-guest/pac_guest.wasm".to_string());
    println!("cargo:rerun-if-changed={wasm_path}");
    let wasm = std::fs::read(&wasm_path)
        .unwrap_or_else(|e| panic!("failed to read PAC guest module {wasm_path}: {e}"));

    // The engine configuration here must agree with the runtime engine in
    // src/pac/engine_wasmtime/ on everything that affects code generation
    // (most importantly epoch interruption); `Module::deserialize` verifies
    // this and refuses mismatched artifacts.
    let target = std::env::var("TARGET").expect("cargo sets TARGET");
    let mut config = wasmtime::Config::new();
    config
        .target(&target)
        .unwrap_or_else(|e| panic!("Wasmtime cannot compile for {target}: {e}"));
    config.epoch_interruption(true);
    let engine = wasmtime::Engine::new(&config).expect("failed to create Wasmtime compiler");
    let cwasm = engine
        .precompile_module(&wasm)
        .unwrap_or_else(|e| panic!("failed to precompile {wasm_path} for {target}: {e}"));

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("pac_guest.cwasm");
    std::fs::write(&out, cwasm)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out.display()));
}
