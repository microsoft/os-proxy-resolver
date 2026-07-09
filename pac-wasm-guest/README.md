# pac-wasm-guest

QuickJS-NG compiled to `wasm32-wasip1`, used by the `pac-engine-wasmtime`
feature of the parent crate as the sandboxed PAC engine. It is built on the
Bytecode Alliance's [Javy](https://github.com/bytecodealliance/javy) crate,
which pins rquickjs 0.12.x — the same vendored QuickJS-NG revision the native
backend links through `rquickjs-sys` 0.12.x, so PAC semantics are identical
across backends. The PAC helper sources (`pac_helpers.js`,
`pac_helpers_ms.js`) and the host ABI (`engine_wasmtime/abi.rs`) are pulled in
from the parent crate with `include_str!`/`include!`, so they cannot drift.

## The vendored artifact

The parent crate does **not** build this crate: `pac_guest.wasm` in this
directory is a vendored build of it, and the parent's build.rs only
ahead-of-time compiles that module for the build target (Cranelift runs at
build time only; the library's runtime Wasmtime has no compiler). This keeps
the wasm32 target, the wasi-sdk download and the Javy toolchain out of
ordinary builds.

## Regenerating pac_guest.wasm

After changing this crate, `pac_helpers*.js`, or `engine_wasmtime/abi.rs`:

```sh
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1   # run inside pac-wasm-guest/
cp target/wasm32-wasip1/release/pac_wasm_guest.wasm pac_guest.wasm
```

The first build downloads the wasi-sdk C toolchain (rquickjs-sys does this
itself) to compile the QuickJS-NG sources; network access is required once.
Commit the updated `pac_guest.wasm` together with the source change. To test
an uncommitted guest build without touching the vendored copy, point the
parent build at it:

```sh
OS_PROXY_RESOLVER_PAC_GUEST_WASM=pac-wasm-guest/target/wasm32-wasip1/release/pac_wasm_guest.wasm \
    cargo test --features pac-engine-wasmtime
```

## Sandbox surface

The module imports exactly six host functions (module `pac_host`: DNS
resolution, local-IP lookup, log/alert, result staging) plus a handful of
`wasi_snapshot_preview1` functions that wasi-libc requires; the host stubs
those with an empty environment, a real clock (PAC `dateRange()`/`timeRange()`
need civil time), a non-cryptographic RNG, and stdout/stderr routed to the log
sink. No filesystem, network, or environment capability exists inside the
sandbox. Unknown imports are defined as traps.
