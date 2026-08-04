// Benchmarks the paths adapter users actually hit in production: redact() on
// flat log strings, redact() on deep object graphs (pino/winston/http), and
// reversible vault mint + restore round trips. scan() throughput lives in
// performance.mjs; hostile input in adversarial-runtime.mjs.
import { performance } from 'node:perf_hooks';
import { redact, createVault, scan } from '../dist/index.js';
import { createRedactionMiddleware } from '../dist/middleware.js';
import { createScopedToolBoundary } from '../dist/tool.js';

const runs = Number(process.env.FLARE_BENCH_RUNS ?? 10);
const warmups = Number(process.env.FLARE_BENCH_WARMUPS ?? 3);

function percentile(values, p) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
}

function bench(name, payloadInfo, fn) {
  for (let i = 0; i < warmups; i++) fn();
  const samples = [];
  for (let i = 0; i < runs; i++) {
    const start = performance.now();
    fn();
    samples.push(performance.now() - start);
  }
  return {
    name,
    ...payloadInfo,
    runs,
    p50Ms: percentile(samples, 0.5),
    p95Ms: percentile(samples, 0.95),
    p99Ms: percentile(samples, 0.99),
  };
}

const logLine = 'INFO request done user=alice@example.com token=ghp_' + 'a'.repeat(36) + ' status=200\n';

function makeEvent(i) {
  return {
    level: 'info',
    requestId: `req-${i}`,
    user: { email: `user${i}@example.com`, name: `User ${i}` },
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcDEF123456' },
    note: i % 7 === 0 ? `pasted key AKIAIOSFODNN7EXAMPLE` : 'routine request',
    tags: ['api', 'v2'],
  };
}

const results = [];

for (const size of [10_000, 100_000]) {
  const input = logLine.repeat(Math.ceil(size / logLine.length)).slice(0, size);
  results.push(bench('redact:string', { bytes: Buffer.byteLength(input) }, () => redact(input)));
}

for (const count of [100, 1_000]) {
  const events = Array.from({ length: count }, (_, i) => makeEvent(i));
  results.push(bench('redact:object-graph', { objects: count }, () => redact(events)));
}

{
  const events = Array.from({ length: 100 }, (_, i) => makeEvent(i));
  results.push(bench('vault:redact+restore', { objects: 100 }, () => {
    const vault = createVault();
    const masked = vault.redact(events);
    vault.restore(masked);
  }));
}

{
  const input = logLine.repeat(Math.ceil(100_000 / logLine.length)).slice(0, 100_000);
  results.push(bench('scan:findings-per-line', { bytes: Buffer.byteLength(input) }, () => scan(input)));
}

{
  const events = Array.from({ length: 100 }, (_, i) => makeEvent(i));
  const middleware = createRedactionMiddleware();
  const sink = middleware.wrap((payload) => payload, { name: 'benchmark.sink' });
  results.push(bench('middleware:wrapped-input', { objects: 100 }, () => sink(events)));
}

{
  const value = 'database password=hunter2 owner=alice@example.com';
  results.push(bench('tool:scoped-round-trip', { scopes: 4 }, () => {
    const boundary = createScopedToolBoundary();
    for (const scope of ['database', 'email', 'storage', 'payments']) {
      const safe = boundary.redactForModel(scope, value);
      boundary.restoreForTool(scope, safe);
    }
  }));
}

process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  node: process.version,
  platform: process.platform,
  arch: process.arch,
  results,
}, null, 2) + '\n');
