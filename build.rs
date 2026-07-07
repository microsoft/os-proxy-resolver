/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

fn main() {
    let target = std::env::var("TARGET").unwrap_or_default();
    if target.contains("windows") {
        // Windows delegates all proxy resolution (static, PAC, WPAD) to WinHTTP.
        // No C toolchain, no pacparser, no QuickJS.
        return;
    }

    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let src = std::path::Path::new("vendor/pacparser/src");
    if !src.join("pacparser.c").exists() {
        panic!("vendor/pacparser is missing. Run: git submodule update --init --recursive");
    }

    println!("cargo:rerun-if-changed=vendor/pacparser/src/pacparser.c");
    println!("cargo:rerun-if-changed=vendor/pacparser/src/pacparser.h");
    println!("cargo:rerun-if-changed=vendor/pacparser/src/pac_utils.h");
    println!("cargo:rerun-if-changed=vendor/pacparser/src/quickjs/quickjs.c");
    println!("cargo:rerun-if-changed=vendor/pacparser/src/quickjs/quickjs.h");
    println!("cargo:rerun-if-changed=src/pac/shim.c");

    // Compile pacparser + QuickJS + our error shim as position-independent
    // objects, but DO NOT archive them into a static lib. Instead we link them
    // into a *shared* library (`libpacparser`) below. Keeping pacparser (LGPL)
    // in its own replaceable shared object is the LGPL v3 §4(d) "suitable shared
    // library mechanism": a user can drop in a modified pacparser without
    // relinking the Rust application.
    let mut build = cc::Build::new();
    build
        .file(src.join("pacparser.c"))
        .file(src.join("quickjs/quickjs.c"))
        .file("src/pac/shim.c")
        .include(src.join("quickjs"))
        .define("VERSION", "\"1.5.1-vendored\"")
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-funsigned-char")
        // Shared objects require position-independent code.
        .pic(true)
        // The vendored C sources are not ours to lint.
        .warnings(false);

    if target.contains("linux") {
        build.define("_GNU_SOURCE", None);
    }

    let objects = build.compile_intermediates();

    // Link the objects into a shared library in OUT_DIR.
    let is_macos = target.contains("darwin") || target.contains("apple");
    let lib_file = if is_macos {
        "libpacparser.dylib"
    } else {
        "libpacparser.so"
    };
    let lib_path = out_dir.join(lib_file);

    let mut link = build.get_compiler().to_command();
    link.args(&objects);
    if is_macos {
        // An @rpath install name lets a distributor relocate the dylib and add
        // their own LC_RPATH (e.g. @loader_path) when they ship it alongside a
        // binary. libm/pthread live in libSystem, so nothing extra to link.
        link.arg("-dynamiclib")
            .arg("-install_name")
            .arg("@rpath/libpacparser.dylib");
    } else {
        // A soname keeps the runtime lookup name stable; QuickJS needs libm and
        // (on glibc) libpthread, so resolve them into the shared object itself.
        link.arg("-shared")
            .arg("-Wl,-soname,libpacparser.so")
            .arg("-lm")
            .arg("-lpthread");
    }
    link.arg("-o").arg(&lib_path);

    let status = link
        .status()
        .expect("failed to invoke the C compiler to link libpacparser");
    assert!(status.success(), "linking libpacparser failed: {status}");

    // Link the Rust crate dynamically against the shared pacparser.
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=dylib=pacparser");

    // Dev/test/examples in THIS package need to find the dylib at runtime; an
    // absolute OUT_DIR rpath makes `cargo test` / `cargo run --example` work in
    // place. NOTE: rpath link-args are NOT propagated to external consumers.
    // A distributor shipping a prebuilt binary should place libpacparser next
    // to it and add an $ORIGIN (Linux) / @loader_path (macOS) rpath instead.
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", out_dir.display());

    // Also add a *relocatable* rpath so a prebuilt binary can find
    // libpacparser when it's shipped right next to it (see the CI packaging).
    // This is harmless in-tree — the absolute OUT_DIR rpath above is what dev
    // builds actually use, since the dylib isn't next to the binary there.
    if is_macos {
        println!("cargo:rustc-link-arg=-Wl,-rpath,@loader_path");
    } else {
        println!("cargo:rustc-link-arg=-Wl,-rpath,$ORIGIN");
    }
}
