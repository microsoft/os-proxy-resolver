/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

//! Build steps for the sandboxed PAC backends. Both consume the same vendored
//! guest module (`pac-wasm-guest/pac_guest.wasm`, wasm32-wasip1):
//!
//! * `pac-engine-wasmtime` — ahead-of-time compiles it into a target-specific
//!   native artifact in `OUT_DIR`. This is the only place a wasm compiler
//!   (Cranelift, via the `wasmtime` build-dependency) runs — the library's
//!   runtime `wasmtime` dependency has no compiler at all and only
//!   deserializes the artifact produced here.
//! * `pac-engine-wasm2c` — translates it to standard C with WABT's `wasm2c`
//!   (required on the build host, pinned version below) and compiles the
//!   generated C together with the vendored wasm-rt runtime and the C shim.
//!   Because the output is plain C, this works for any target the C compiler
//!   supports — including 32-bit armv7, which Cranelift cannot AOT-compile
//!   for.
//!
//! Without these features this build script is a no-op.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(any(feature = "pac-engine-wasmtime", feature = "pac-engine-wasm2c"))]
    println!("cargo:rerun-if-env-changed=OS_PROXY_RESOLVER_PAC_GUEST_WASM");
    #[cfg(feature = "pac-engine-wasmtime")]
    precompile_pac_guest();
    #[cfg(feature = "pac-engine-wasm2c")]
    wasm2c_pac_guest();
}

/// The vendored guest module. Point the env var at a fresh build of
/// pac-wasm-guest to test guest changes without touching the vendored copy
/// (see pac-wasm-guest/README.md).
#[cfg(any(feature = "pac-engine-wasmtime", feature = "pac-engine-wasm2c"))]
fn guest_wasm_path() -> String {
    let wasm_path = std::env::var("OS_PROXY_RESOLVER_PAC_GUEST_WASM")
        .unwrap_or_else(|_| "pac-wasm-guest/pac_guest.wasm".to_string());
    println!("cargo:rerun-if-changed={wasm_path}");
    wasm_path
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

    let wasm_path = guest_wasm_path();
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
    // No copy-on-write memory images: qemu-user (which runs the aarch64 CI
    // tests) does not implement the memfd sealing fcntl the CoW path needs
    // ("cannot add seals to the memfd"), and this crate instantiates the
    // guest only on (re)load, so CoW instantiation speed buys nothing. This
    // is a tunable recorded in the artifact — the runtime engine in
    // src/pac/engine_wasmtime/ must match.
    config.memory_init_cow(false);
    let engine = wasmtime::Engine::new(&config).expect("failed to create Wasmtime compiler");
    let cwasm = engine
        .precompile_module(&wasm)
        .unwrap_or_else(|e| panic!("failed to precompile {wasm_path} for {target}: {e}"));

    let out = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"))
        .join("pac_guest.cwasm");
    std::fs::write(&out, cwasm)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", out.display()));
}

/// The WABT release the wasm2c backend is developed and tested against. The
/// generated C must be compiled with the wasm-rt runtime sources of the same
/// release (vendored under pac-wasm-guest/wasm-rt/), so the `wasm2c` binary
/// version is checked, not assumed.
#[cfg(feature = "pac-engine-wasm2c")]
const WABT_VERSION: &str = "1.0.41";

#[cfg(feature = "pac-engine-wasm2c")]
fn wasm2c_pac_guest() {
    use std::path::PathBuf;

    println!("cargo:rerun-if-env-changed=OS_PROXY_RESOLVER_WASM2C");
    println!("cargo:rerun-if-env-changed=OS_PROXY_RESOLVER_PAC_GUEST_C_DIR");
    println!("cargo:rerun-if-changed=pac-wasm-guest/wasm-rt");
    println!("cargo:rerun-if-changed=src/pac/engine_wasm2c/shim.c");

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets CARGO_MANIFEST_DIR"));

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("cargo sets OUT_DIR"));

    // The wasm2c output is target-independent C, so it can be generated once
    // on a machine where the pinned wasm2c runs and handed to builds that
    // cannot run it (e.g. `cross` containers, whose glibc is older than the
    // WABT release binaries need). The directory must contain the
    // pac_guest.c/pac_guest.h pair produced by `wasm2c --module-name
    // pac_guest`; a relative path is resolved against the manifest dir (which
    // keeps the value valid across the host/container path mapping).
    let c_file = match std::env::var("OS_PROXY_RESOLVER_PAC_GUEST_C_DIR") {
        Ok(dir) => {
            let dir = manifest_dir.join(dir);
            let c_file = dir.join("pac_guest.c");
            println!("cargo:rerun-if-changed={}", c_file.display());
            assert!(
                c_file.is_file(),
                "OS_PROXY_RESOLVER_PAC_GUEST_C_DIR is set but {} does not exist",
                c_file.display()
            );
            std::fs::copy(dir.join("pac_guest.h"), out_dir.join("pac_guest.h"))
                .expect("copy pregenerated pac_guest.h");
            c_file
        }
        Err(_) => {
            let c_file = out_dir.join("pac_guest.c");
            run_wasm2c(&guest_wasm_path(), &c_file);
            c_file
        }
    };
    let c_file = patch_generated_c(&c_file, &out_dir);

    // Compile the generated C + the vendored wasm-rt runtime + the shim.
    //
    // WASM_RT_USE_MMAP=0 selects explicit software bounds checks for every
    // linear-memory access instead of mmap'd guard pages: slower, but fully
    // portable (works on 32-bit targets where a 4 GiB reservation is
    // impossible) and requires no process-wide signal handler — something a
    // library must not install. Stack exhaustion is caught by wasm-rt's
    // depth counter under the same setting.
    cc::Build::new()
        .file(&c_file)
        .file("pac-wasm-guest/wasm-rt/wasm-rt-impl.c")
        .file("pac-wasm-guest/wasm-rt/wasm-rt-mem-impl.c")
        // Not for wasm exception handling (the guest uses none) — this is
        // where wasm_rt_set_unwind_target lives, which wasm_rt_impl_try needs.
        .file("pac-wasm-guest/wasm-rt/wasm-rt-exceptions-impl.c")
        .file("src/pac/engine_wasm2c/shim.c")
        .include(&out_dir)
        .include("pac-wasm-guest/wasm-rt")
        .define("WASM_RT_USE_MMAP", "0")
        // The generated C triggers benign warnings (unused labels/values) by
        // design; don't drown the build log in them.
        .warnings(false)
        .compile("pac_guest_wasm2c");
}

/// Works around three portability bugs in wasm2c 1.0.41's generated C. The
/// patterns are stable because the wasm2c version is pinned.
///
/// 1. For GNU compilers the function-type ids are declared as *pointer*
///    variables (`static const char* const tN = "..."`) and then used inside
///    the static element-segment initializer. A pointer variable's value is
///    not an address constant in C ("initializer element is not constant" on
///    GCC <= 9, e.g. in the `cross` container images; clang and GCC >= 13
///    fold it). The `#else` branch of the same macro block (used for MSVC)
///    declares arrays instead, whose addresses are valid constants everywhere
///    — force that branch unconditionally.
/// 2. `#if __has_builtin(__builtin_add_overflow)` — GCC only gained
///    `__has_builtin` in GCC 10. The only builtin probed in the file is
///    `__builtin_add_overflow`, which every GCC since 5 has, so a
///    `__has_builtin(x) 1` shim is safe for GNU compilers that lack it.
/// 3. `add_overflow`'s MSVC fallback calls `_addcarry_u64`, an x64-only
///    intrinsic — on ARM64 MSVC it becomes an implicit extern and fails at
///    link time (LNK2019). Guard it with `_M_X64` and fall back to the
///    portable unsigned-overflow check everywhere else.
#[cfg(feature = "pac-engine-wasm2c")]
fn patch_generated_c(c_file: &std::path::Path, out_dir: &std::path::Path) -> std::path::PathBuf {
    let source = std::fs::read_to_string(c_file)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", c_file.display()));

    let gnu_branch = "#if defined(__GNUC__) || defined(__clang__)\n\
                      #define FUNC_TYPE_DECL_EXTERN_T(x) extern const char* const x\n";
    let portable_branch = "#if 0 /* forced to the portable array branch; see build.rs */\n\
                           #define FUNC_TYPE_DECL_EXTERN_T(x) extern const char* const x\n";
    assert_eq!(
        source.matches(gnu_branch).count(),
        1,
        "wasm2c output changed shape; re-check the FUNC_TYPE_T patch in build.rs \
         against WABT {WABT_VERSION}"
    );
    let source = source.replacen(gnu_branch, portable_branch, 1);

    let generated_header = "/* Automatically generated by wasm2c */\n";
    let has_builtin_shim = "/* Automatically generated by wasm2c */\n\
                            /* Injected by build.rs: GCC < 10 has no __has_builtin; the only probe\n   \
                            in this file is __builtin_add_overflow (GCC >= 5). */\n\
                            #if !defined(__has_builtin) && defined(__GNUC__)\n\
                            #define __has_builtin(x) 1\n\
                            #endif\n";
    assert!(
        source.starts_with(generated_header),
        "wasm2c output changed shape; re-check the __has_builtin patch in build.rs \
         against WABT {WABT_VERSION}"
    );
    let source = source.replacen(generated_header, has_builtin_shim, 1);

    let msvc_addcarry = "#elif defined(_MSC_VER)\n\
                         \x20 return _addcarry_u64(0, a, b, resptr);\n\
                         #else\n\
                         #error \"Missing implementation of __builtin_add_overflow or _addcarry_u64\"\n\
                         #endif";
    let portable_addcarry = "#elif defined(_MSC_VER) && defined(_M_X64)\n\
                             \x20 return _addcarry_u64(0, a, b, resptr);\n\
                             #else\n\
                             \x20 /* Injected by build.rs: portable fallback (e.g. MSVC on ARM64,\n\
                             \x20    which has no _addcarry_u64). Unsigned add wraps iff sum < a. */\n\
                             \x20 *resptr = a + b;\n\
                             \x20 return *resptr < a;\n\
                             #endif";
    assert_eq!(
        source.matches(msvc_addcarry).count(),
        1,
        "wasm2c output changed shape; re-check the add_overflow patch in build.rs \
         against WABT {WABT_VERSION}"
    );
    let source = source.replacen(msvc_addcarry, portable_addcarry, 1);

    let patched = out_dir.join("pac_guest_patched.c");
    std::fs::write(&patched, source)
        .unwrap_or_else(|e| panic!("failed to write {}: {e}", patched.display()));
    patched
}

/// Runs the pinned `wasm2c` on the vendored guest, with the version check
/// that keeps the generated C in lockstep with the vendored wasm-rt runtime.
#[cfg(feature = "pac-engine-wasm2c")]
fn run_wasm2c(wasm_path: &str, c_file: &std::path::Path) {
    use std::process::Command;

    let install_hint = format!(
        "Install WABT {WABT_VERSION} (https://github.com/WebAssembly/wabt/releases) and put \
         `wasm2c` on PATH or point OS_PROXY_RESOLVER_WASM2C at the binary. Builds that cannot \
         run wasm2c at all (e.g. inside a `cross` container) can instead consume pregenerated C \
         via OS_PROXY_RESOLVER_PAC_GUEST_C_DIR; see pac-wasm-guest/README.md."
    );
    let wasm2c = std::env::var("OS_PROXY_RESOLVER_WASM2C").unwrap_or_else(|_| "wasm2c".to_string());
    let version = Command::new(&wasm2c)
        .arg("--version")
        .output()
        .unwrap_or_else(|e| panic!("running `{wasm2c} --version` failed: {e}. {install_hint}"));
    // A binary that is present but cannot run (missing DLLs on Windows, too
    // old a glibc for the loader, ...) reports through the exit status and
    // stderr — surface both instead of a baffling empty version string.
    if !version.status.success() {
        panic!(
            "`{wasm2c} --version` failed with {}: {}. {install_hint}",
            version.status,
            String::from_utf8_lossy(&version.stderr).trim()
        );
    }
    let version_str = String::from_utf8_lossy(&version.stdout).trim().to_string();
    if version_str != WABT_VERSION {
        panic!(
            "`{wasm2c}` is WABT {version_str:?}, but this crate pins WABT {WABT_VERSION} (the \
             vendored wasm-rt runtime in pac-wasm-guest/wasm-rt/ must match the generated C). \
             {install_hint}"
        );
    }

    let output = Command::new(&wasm2c)
        .arg(wasm_path)
        .args(["--module-name", "pac_guest", "-o"])
        .arg(c_file)
        .output()
        .unwrap_or_else(|e| panic!("failed to run {wasm2c}: {e}"));
    assert!(
        output.status.success(),
        "wasm2c failed on {wasm_path} with {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
}
