# pac-wasm-guest

QuickJS-NG compiled to `wasm32-wasip1`, used by the parent crate's two
sandboxed PAC backends: `pac-engine-wasmtime` (Wasmtime, AOT) and
`pac-engine-wasm2c` (translated to portable C with WABT's `wasm2c` — the
sandbox for targets Cranelift can't compile for, e.g. 32-bit armv7). Both
backends consume the same vendored `pac_guest.wasm`, so their PAC semantics
cannot diverge. It is built on the
Bytecode Alliance's [Javy](https://github.com/bytecodealliance/javy) crate,
which pins rquickjs 0.12.x — the same vendored QuickJS-NG revision the native
backend links through `rquickjs-sys` 0.12.x, so PAC semantics are identical
across all backends. The PAC helper sources (`pac_helpers.js`,
`pac_helpers_ms.js`) and the host ABI (`src/pac/wasm_abi.rs`) are pulled in
from the parent crate with `include_str!`/`include!`, so they cannot drift.

## The vendored artifact

The parent crate does **not** build this crate: `pac_guest.wasm` in this
directory is a vendored build of it, and the parent's build.rs only
ahead-of-time compiles that module for the build target (Cranelift runs at
build time only; the library's runtime Wasmtime has no compiler). This keeps
the wasm32 target, the wasi-sdk download and the Javy toolchain out of
ordinary builds.

## Regenerating pac_guest.wasm

After changing this crate, `pac_helpers*.js`, or `src/pac/wasm_abi.rs`:

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

## The wasm2c backend and the vendored wasm-rt runtime

The `pac-engine-wasm2c` feature does not vendor generated C: the parent
build.rs runs WABT's `wasm2c` (pinned to **WABT 1.0.41**, verified via
`wasm2c --version`) on `pac_guest.wasm` at build time and compiles the output
with the `cc` crate. Install WABT 1.0.41 from
https://github.com/WebAssembly/wabt/releases (or point
`OS_PROXY_RESOLVER_WASM2C` at the binary). Builds on hosts that cannot run
the pinned wasm2c at all — CI's `cross` containers, whose glibc is older than
the WABT release binaries need — can consume pregenerated output instead: run
`wasm2c pac_guest.wasm --module-name pac_guest -o <dir>/pac_guest.c` with the
pinned wasm2c elsewhere and set `OS_PROXY_RESOLVER_PAC_GUEST_C_DIR=<dir>`
(manifest-relative paths allowed; the output is target-independent C, so
where it was generated doesn't matter). What *is* vendored is WABT's
wasm2c runtime — the `wasm-rt/` directory next to this file (Apache-2.0, see
its LICENSE) — because the generated C must be compiled against the runtime
sources of the same WABT release. When bumping the pinned WABT version, update
in lockstep: `WABT_VERSION` in build.rs, the `wasm-rt/` sources, `Cross.toml`,
and the CI install steps.

## Sandbox surface

The module imports exactly seven host functions (module `pac_host`: DNS
resolution, local-IP lookup, log/alert, result staging, and the
`host_should_interrupt` deadline poll driving the QuickJS interrupt handler)
plus a handful of `wasi_snapshot_preview1` functions that wasi-libc requires; the host stubs
those with an empty environment, a real clock (PAC `dateRange()`/`timeRange()`
need civil time), a non-cryptographic RNG, and stdout/stderr routed to the log
sink. No filesystem, network, or environment capability exists inside the
sandbox. Unknown imports are defined as traps.
