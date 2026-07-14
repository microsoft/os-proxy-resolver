/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See LICENSE.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Electron/Chromium PAC baseline for os-proxy-resolver.
//
// Chromium (and therefore Electron) evaluates PAC scripts with its own
// V8-based resolver by default; the OS resolver (WinHTTP on Windows) is only
// used with --use-system-proxy-resolver, which is NOT the default. This
// harness times `session.resolveProxy()` so the numbers can sit next to the
// Rust `pac_bench` example (WinHTTP vs the embedded QuickJS engine): run all
// three on the same Windows runner with the same PAC and URLs.
//
//   npm install
//   npm run bench -- --iterations 3000
//   npm run bench -- --iterations 5000 --pac-script ../../my.pac https://a/ http://b/
//   npm run bench -- --data-url        # load the PAC as a data: URL (Chromium
//                                      # supports this; WinHTTP does not)
//
// The default PAC script and URL list are kept byte-for-byte identical to
// examples/pac_bench.rs so the outputs are directly comparable.

const { app, session } = require('electron');
const http = require('http');
const fs = require('fs');

// Keep this identical to DEFAULT_PAC in examples/pac_bench.rs.
const DEFAULT_PAC = `
function FindProxyForURL(url, host) {
    if (isPlainHostName(host) ||
        shExpMatch(host, "*.local") ||
    (host === "127.0.0.1" &&
     isInNet(host, "127.0.0.0", "255.0.0.0"))) {
        return "DIRECT";
    }
    if (dnsDomainIs(host, ".corp.example.com") ||
        shExpMatch(url, "http://intra.example.com/*")) {
        return "PROXY proxy1.example.com:8080; PROXY proxy2.example.com:8080; DIRECT";
    }
    if (shExpMatch(host, "*.example.net")) {
        return "SOCKS5 socks.example.com:1080; DIRECT";
    }
    return "PROXY edge.example.com:3128; DIRECT";
}
`;

// Keep this identical to DEFAULT_URLS in examples/pac_bench.rs.
const DEFAULT_URLS = [
  'http://plainhost/',
  'https://db.corp.example.com/',
  'http://intra.example.com/dashboard',
  'https://cdn.example.net/asset.js',
  'https://www.example.org/',
  'http://127.0.0.1/',
];

function parseArgs(argv) {
  const args = { iterations: 2000, concurrency: 1, pacScript: null, urls: [], dataUrl: false, uniqueHosts: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--iterations': {
        const v = parseInt(argv[++i], 10);
        if (!Number.isFinite(v) || v <= 0) usageError('--iterations requires a positive integer');
        args.iterations = v;
        break;
      }
      case '--concurrency': {
        const v = parseInt(argv[++i], 10);
        if (!Number.isFinite(v) || v <= 0) usageError('--concurrency requires a positive integer');
        args.concurrency = v;
        break;
      }
      case '--pac-script':
        args.pacScript = argv[++i];
        if (args.pacScript === undefined) usageError('--pac-script requires a value');
        break;
      case '--data-url':
        args.dataUrl = true;
        break;
      case '--unique-hosts':
        args.uniqueHosts = true;
        break;
      case '-h':
      case '--help':
        printUsage();
        app.exit(0);
        break;
      default:
        if (arg.startsWith('-') && arg !== '-') usageError(`unknown option: ${arg}`);
        args.urls.push(arg);
    }
  }
  return args;
}

// Serve `script` from an ephemeral 127.0.0.1 endpoint for the whole run.
function servePac(script) {
  return new Promise((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/x-ns-proxy-autoconfig' });
      res.end(script);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ url: `http://127.0.0.1:${port}/proxy.pac`, close: () => server.close() });
    });
  });
}

function dataUrl(script) {
  const b64 = Buffer.from(script, 'utf8').toString('base64');
  return `data:application/x-ns-proxy-autoconfig;base64,${b64}`;
}

// Chromium normalizes proxy results (e.g. "PROXY host:port") much like the
// Rust harness renders ProxyKind; normalize whitespace for a fair cross-check.
function normalize(result) {
  return result
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .join('; ');
}

function percentile(sorted, p) {
  if (sorted.length === 0) return 0;
  const idx = Math.round((sorted.length - 1) * p);
  return sorted[idx];
}

function fmtNs(ns) {
  if (ns >= 1e9) return `${(ns / 1e9).toFixed(3)} s`;
  if (ns >= 1e6) return `${(ns / 1e6).toFixed(3)} ms`;
  return `${(ns / 1e3).toFixed(1)} us`;
}

function printStats(stats) {
  const { label, samples, errors, wallNs, iterations, concurrency } = stats;
  const n = samples.length;
  console.log(label);
  if (n === 0) {
    console.log(`  no successful samples (${errors} errors)`);
    return;
  }
  const mean = samples.reduce((a, b) => a + b, 0) / n;
  // Throughput is wall-clock based so it stays honest under concurrency (the
  // per-call latencies below include queuing time when concurrency > 1).
  const throughput = wallNs > 0 ? (iterations / (wallNs / 1e9)).toFixed(0) : '0';
  console.log(`  calls      : ${n} (${errors} errors)`);
  console.log(`  concurrency: ${concurrency}`);
  console.log(`  latency mean/p50/p90/p99: ${fmtNs(mean)} / ${fmtNs(percentile(samples, 0.5))} / ${fmtNs(percentile(samples, 0.9))} / ${fmtNs(percentile(samples, 0.99))}`);
  console.log(`  latency min/max         : ${fmtNs(samples[0])} / ${fmtNs(samples[n - 1])}`);
  console.log(`  wall time  : ${fmtNs(wallNs)}`);
  console.log(`  throughput : ${throughput} calls/s`);
}

function targetUrl(raw, i, uniqueHosts) {
  if (!uniqueHosts) return raw;
  // Prefix a unique subdomain to defeat any per-endpoint caching and force a
  // fresh PAC evaluation every call. Changes which branch the PAC takes, so
  // it measures eval cost rather than the realistic (cache-friendly) path.
  const u = new URL(raw);
  u.hostname = `n${i}.${u.hostname}`;
  return u.toString();
}

// Runs `iterations` resolveProxy calls with up to `concurrency` in flight.
// resolveProxy is an async IPC to Chromium's network service, so sequential
// (concurrency 1) timing is dominated by per-call round-trip latency (and, on
// Windows, ~15.6ms timer coalescing in the tail); raising concurrency overlaps
// those round-trips and reveals the engine's real throughput.
async function bench(label, iterations, urls, resolveFn, { concurrency, uniqueHosts }) {
  for (const u of urls) {
    try { await resolveFn(u); } catch { /* warm up */ }
  }
  const samples = [];
  let errors = 0;
  let next = 0;
  const wall0 = process.hrtime.bigint();
  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= iterations) return;
      const u = targetUrl(urls[i % urls.length], i, uniqueHosts);
      const t0 = process.hrtime.bigint();
      try {
        await resolveFn(u);
        samples.push(Number(process.hrtime.bigint() - t0));
      } catch {
        errors++;
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  const wallNs = Number(process.hrtime.bigint() - wall0);
  samples.sort((a, b) => a - b);
  return { label, samples, errors, wallNs, iterations, concurrency };
}

function printUsage() {
  console.error(
    'usage: npm run bench -- [--iterations N] [--concurrency N] ' +
      '[--pac-script <path>] [--data-url] [--unique-hosts] [<url>...]\n\n' +
      "Times Chromium's V8 PAC resolver (Electron's resolveProxy) on the given\n" +
      'PAC script and URLs — a baseline for the Rust pac_bench example.\n' +
      'resolveProxy is an async IPC call: use --concurrency to measure real\n' +
      'throughput rather than sequential per-call round-trip latency.'
  );
}

function usageError(msg) {
  console.error(`error: ${msg}`);
  printUsage();
  app.exit(2);
}

// resolveProxy needs no window; keep the GPU/sandbox out of the way for CI.
app.commandLine.appendSwitch('disable-gpu');
app.disableHardwareAcceleration();

app.whenReady().then(async () => {
  const args = parseArgs(process.argv.slice(2));

  const script = args.pacScript
    ? readPac(args.pacScript)
    : DEFAULT_PAC;
  const rawUrls = args.urls.length ? args.urls : DEFAULT_URLS;

  // Fail loudly instead of hanging forever if the network service wedges.
  const guard = setTimeout(() => {
    console.error('error: benchmark timed out');
    app.exit(1);
  }, 300000);
  guard.unref?.();

  let served = null;
  let pacLocation;
  if (args.dataUrl) {
    pacLocation = dataUrl(script);
  } else {
    served = await servePac(script);
    pacLocation = served.url;
  }

  const ses = session.defaultSession;
  await ses.setProxy({ mode: 'pac_script', pacScript: pacLocation });

  console.log('Electron PAC baseline (Chromium V8 resolver)');
  console.log(`  electron   : ${process.versions.electron}`);
  console.log(`  chrome     : ${process.versions.chrome}`);
  console.log(`  iterations : ${args.iterations} (across ${rawUrls.length} URLs)`);
  console.log(`  pac source : ${args.pacScript || '<built-in>'}`);
  console.log(`  served at  : ${args.dataUrl ? 'data: URL (Chromium-only)' : pacLocation}`);
  console.log(`  mode       : ${args.uniqueHosts ? 'unique-hosts (eval-stress)' : 'realistic (cached)'}`);
  console.log();

  // Cross-check: print each URL's resolution so it can be diffed against the
  // Rust harness's output.
  console.log('resolutions:');
  for (const u of rawUrls) {
    try {
      console.log(`  ${u} -> ${normalize(await ses.resolveProxy(u))}`);
    } catch (e) {
      console.log(`  ${u} -> <error: ${e.message}>`);
    }
  }
  console.log();

  const resolve = (u) => ses.resolveProxy(u);

  // Sequential: exposes per-call round-trip latency of the async IPC API.
  const sequential = await bench('electron (chromium v8) — sequential', args.iterations, rawUrls, resolve, {
    concurrency: 1,
    uniqueHosts: args.uniqueHosts,
  });
  printStats(sequential);

  // Concurrent: overlaps the IPC round-trips to show the engine's real
  // throughput (how Electron actually issues resolutions).
  if (args.concurrency > 1) {
    console.log();
    const concurrent = await bench(
      `electron (chromium v8) — concurrency ${args.concurrency}`,
      args.iterations,
      rawUrls,
      resolve,
      { concurrency: args.concurrency, uniqueHosts: args.uniqueHosts }
    );
    printStats(concurrent);

    const seqTp = sequential.wallNs > 0 ? args.iterations / (sequential.wallNs / 1e9) : 0;
    const conTp = concurrent.wallNs > 0 ? args.iterations / (concurrent.wallNs / 1e9) : 0;
    if (seqTp > 0 && conTp > 0) {
      const ratio = conTp / seqTp;
      console.log();
      console.log(
        `=> concurrency ${args.concurrency}: throughput ${seqTp.toFixed(0)} -> ` +
          `${conTp.toFixed(0)} calls/s (${ratio.toFixed(1)}x).`
      );
      console.log(
        ratio < 2
          ? '   Overlap barely helps: resolveProxy is serialized through the network ' +
              'service, so the ceiling is async-IPC cost, not PAC evaluation.'
          : '   Overlap helps: the sequential number was latency-bound on the async IPC, ' +
              'not the PAC engine.'
      );
    }
  }

  clearTimeout(guard);
  served?.close();
  app.exit(0);
});

function readPac(path) {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch (e) {
    console.error(`error: cannot read PAC file ${path}: ${e.message}`);
    app.exit(1);
    return '';
  }
}
