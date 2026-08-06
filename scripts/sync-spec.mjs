#!/usr/bin/env node
// Copy the canonical detector pack into each SDK.
//
// The pack has to sit next to the code that embeds it — Go needs it in the
// module directory for `go:embed`, Rust for `include_str!`, Python for package
// data. One canonical file plus a sync step beats four files that drift.
//
//   node scripts/sync-spec.mjs           # write the copies
//   node scripts/sync-spec.mjs --check   # fail if a copy is stale (CI)

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = join(root, 'spec', 'detectors.json');

const targets = [
  join(root, 'sdk', 'python', 'src', 'flare_redact', 'detectors.json'),
  join(root, 'sdk', 'go', 'detectors.json'),
  join(root, 'sdk', 'rust', 'src', 'detectors.json'),
];

const check = process.argv.includes('--check');
const canonical = readFileSync(source, 'utf8');

// Parse once so a malformed pack fails here rather than in three test suites.
JSON.parse(canonical);

let stale = 0;
for (const target of targets) {
  let current = null;
  try {
    current = readFileSync(target, 'utf8');
  } catch {
    current = null;
  }
  if (current === canonical) continue;
  stale++;
  const shown = relative(root, target);
  if (check) {
    process.stderr.write(`stale: ${shown}\n`);
  } else {
    writeFileSync(target, canonical);
    process.stdout.write(`updated ${shown}\n`);
  }
}

if (check && stale) {
  process.stderr.write(`\n${stale} vendored pack(s) differ from spec/detectors.json. Run: npm run spec:sync\n`);
  process.exitCode = 1;
} else if (!check && !stale) {
  process.stdout.write('all vendored packs are up to date\n');
}
