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
  // Token prefixes followed by long runs of their body characters that never
  // complete a token: each pattern must give up in time linear in the run.
  tokenPrefixes: (n) => {
    const prefixes = ['glpat-', 'glrt-', 'pypi-AgEIcHlwaS5vcmc', 'ABSK', 'ops_eyJ', 'sntrys_eyJ', 'glc_', 'fm2_', 'pscale_tkn_', 'ATATT3', 'HRKU-', 'dckr_pat_', 'tvly-', 'pcsk_ab1cd_'];
    let out = '';
    for (let i = 0; out.length < n; i++) out += prefixes[i % prefixes.length] + 'A'.repeat(1_200) + '-';
    return out.slice(0, n);
  },
  hexRuns: (n) => ('0123456789abcdef'.repeat(4) + '-us ').repeat(Math.ceil(n / 68)).slice(0, n),
  atlasRuns: (n) => ('A'.repeat(14) + '.atlasv1.' + 'A'.repeat(90) + ' ').repeat(Math.ceil(n / 114)).slice(0, n),
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
