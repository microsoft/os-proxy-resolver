# Electron (Chromium) PAC baseline

A tiny [Electron](https://www.electronjs.org/) app that times Chromium's
built-in V8 PAC resolver via [`session.resolveProxy`](https://www.electronjs.org/docs/latest/api/session#sesresolveproxyurl),
so it can serve as the **baseline** for the Rust
[`pac_bench`](../../examples/pac_bench.rs) example.

## Why Electron?

Chromium — and therefore Electron — evaluates PAC scripts with its own
V8-based resolver by default. The OS resolver (WinHTTP on Windows,
`SystemConfiguration` on macOS) is only used with
`--use-system-proxy-resolver`, which is **not** the default. So "what Electron
actually does" for PAC is the Chromium V8 path, and that is what this harness
measures.

Put next to the Rust `pac_bench` example you get three numbers on the same
Windows machine, same PAC, same URLs:

| path | engine | measured by |
|---|---|---|
| `system` | WinHTTP | `pac_bench` (Rust) |
| `quickjs` | embedded QuickJS-NG | `pac_bench --features pac-engine` (Rust) |
| `electron` | Chromium V8 | this harness |

## Running

```sh
npm install
npm run bench -- --iterations 3000 --concurrency 32
```

Options (defaults match `examples/pac_bench.rs`):

- `--iterations N` — timed calls per run (default 2000).
- `--concurrency N` — additionally run a pass with N `resolveProxy` calls in
  flight (default 1 = sequential only). See the caveats below for why this
  matters.
- `--pac-script <path>` — PAC file to evaluate (default: the same built-in
  script as the Rust example).
- `--data-url` — load the PAC as a `data:` URL instead of over HTTP. Chromium
  supports this; **WinHTTP does not**, which is one of the capability gaps
  behind Chromium avoiding WinHTTP.
- `--unique-hosts` — rewrite each request host to be unique, defeating any
  per-endpoint caching so raw evaluation cost is measured. `<url>...` —
  override the URL list.

## Reading the numbers (caveats)

- **`resolveProxy` is asynchronous cross-process IPC, not an in-process call.**
  The benchmark runs in Electron's **main process** (`app.whenReady`, no
  renderer) and times `session.resolveProxy()`, but the PAC script is actually
  evaluated **out-of-process** in Chromium's network service — so each call is a
  Mojo round-trip (main → network service → main), not a local V8 call in the
  measuring process. The Rust `pac_bench` paths (WinHTTP, embedded QuickJS) are
  synchronous in-process calls, so they measure PAC evaluation itself (~170 µs).
  The Electron numbers measure evaluation **plus** the per-call IPC and
  event-loop latency, and there is no public API to time Chromium's V8 PAC eval
  without that IPC hop.
- **`resolveProxy` is throughput-serialized; concurrency does not help.** The
  CI run bears this out: the engine's `min` latency is ~100 µs (PAC eval is
  fast, and this is *not* cold start — a warmup pass runs first), yet throughput
  tops out around **250–310 calls/s on Windows** (≈1300/s on macOS), and raising
  `--concurrency` barely moves it (≈1.2×) while per-call latency balloons into
  queuing time. In other words Chromium resolves proxies one-at-a-time through
  its single-threaded resolver, so the ceiling is the async-IPC round-trip cost
  (amplified on Windows by the ~15.6 ms default timer/scheduler granularity),
  not PAC evaluation. `--concurrency` is kept because demonstrating that it
  *doesn't* lift throughput is exactly the evidence for serialization.
- **Don't compare this to the in-process numbers as an engine benchmark.** The
  ~20× gap between Electron's ~250/s and WinHTTP/QuickJS's ~5000/s is the cost
  of an async, serialized, cross-process API — not the V8 PAC engine being slow.
  For engine-vs-engine, compare WinHTTP against the embedded QuickJS in
  `pac_bench` (both ~170–200 µs, i.e. at parity).
- **Caching differs per engine.** WinHTTP keeps a session autoproxy cache, so
  its steady-state `pac_bench` numbers reflect cache hits. Chromium generally
  re-runs the PAC per resolution. The Rust `quickjs` path re-evaluates every
  call but keeps the compiled script. For a raw eval-cost comparison, run every
  tool in its cache-defeating mode (`--unique-hosts` here). For a realistic
  "what a request pays" comparison, use the default modes.
- The `resolutions:` block printed before the timings lets you diff Chromium's
  output against the Rust harness's `cross-check` output for the same URLs.

Pinned to Electron 42.5.0 (the version VS Code currently ships); any recent
Electron works if you bump `package.json`.
