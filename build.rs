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

    let mut build = cc::Build::new();
    build
        .file(src.join("pacparser.c"))
        .file(src.join("quickjs/quickjs.c"))
        .file("src/pac/shim.c")
        .include(src.join("quickjs"))
        .define("VERSION", "\"1.5.1-vendored\"")
        .flag_if_supported("-fno-strict-aliasing")
        .flag_if_supported("-funsigned-char")
        // The vendored C sources are not ours to lint.
        .warnings(false);

    if target.contains("linux") {
        build.define("_GNU_SOURCE", None);
    }

    build.compile("pacparser");

    // QuickJS needs libm; glibc also wants libpthread for its atomics/threads use.
    if target.contains("linux") || target.contains("android") {
        println!("cargo:rustc-link-lib=m");
        println!("cargo:rustc-link-lib=pthread");
    }
}
