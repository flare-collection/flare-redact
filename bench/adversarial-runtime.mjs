import { performance } from 'node:perf_hooks';
import { scan } from '../dist/index.js';

const lengths = [1_000, 10_000, 100_000];
if (process.env.FLARE_BENCH_INCLUDE_MIB === '1') lengths.push(1_000_000);
const cases = {
  repeatedAscii: (n) => 'a'.repeat(n) + '!',
  tokenLike: (n) => 'A'.repeat(n) + '=',
  separators: (n) => '1-'.repeat(Math.floor(n / 2)),
  unicode: (n) => '密'.repeat(n),
  schemeRun: (n) => 'a-b.'.repeat(Math.floor(n / 4)) + '://',
};

const results = [];
for (const [name, build] of Object.entries(cases)) {
  for (const length of lengths) {
    const input = build(length);
    const start = performance.now();
    const findings = scan(input);
    results.push({ name, length: input.length, durationMs: performance.now() - start, findings: findings.length });
  }
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, results }, null, 2) + '\n');
