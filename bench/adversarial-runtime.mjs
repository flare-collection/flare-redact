import { performance } from 'node:perf_hooks';
import { scan } from '../dist/index.js';

const lengths = [1_000, 10_000, 100_000];
if (process.env.FLARE_BENCH_INCLUDE_MIB === '1') lengths.push(1_000_000);
const cases = {
  repeatedAscii: (n) => 'a'.repeat(n) + '!',
  tokenLike: (n) => 'A'.repeat(n) + '=',
  separators: (n) => '1-'.repeat(Math.floor(n / 2)),
  unicode: (n) => '密'.repeat(n),
  // Shapes the opt-in national IDs look for: printed digit groups, dotted
  // groups, letter-digit runs and ID prefixes that never complete.
  spacedDigits: (n) => '12 '.repeat(Math.floor(n / 3)),
  dottedDigits: (n) => '12.'.repeat(Math.floor(n / 3)),
  letterDigitRun: (n) => 'AB1'.repeat(Math.floor(n / 3)),
  idPrefixes: (n) => 'ABCD850101H S1234567 010185-123 '.repeat(Math.floor(n / 32)),
};
// The default policy, and every opt-in identifier through the pii tag.
const policies = { default: {}, pii: { enable: ['pii'] } };

const results = [];
for (const [policy, options] of Object.entries(policies)) {
  for (const [name, build] of Object.entries(cases)) {
    for (const length of lengths) {
      const input = build(length);
      const start = performance.now();
      const findings = scan(input, options);
      results.push({ name, policy, length: input.length, durationMs: performance.now() - start, findings: findings.length });
    }
  }
}

process.stdout.write(JSON.stringify({ schemaVersion: 1, results }, null, 2) + '\n');
