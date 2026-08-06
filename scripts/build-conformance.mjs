#!/usr/bin/env node
// Regenerate spec/conformance/expected.json from this engine.
//
// The expectations are whatever a conforming engine produces, so any of the four
// can generate them — and all four must then agree. Regenerate after an
// intentional behaviour change and *read the diff*: an unexplained line in it is
// a bug report.
//
//   node scripts/build-conformance.mjs           # check, exit 1 on a mismatch
//   node scripts/build-conformance.mjs --write   # rewrite expected.json

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { loadPack } from '../dist/pack.js';
import { createVault, redact, scan } from '../dist/index.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const corpusPath = join(root, 'spec', 'conformance', 'cases.json');
const expectedPath = join(root, 'spec', 'conformance', 'expected.json');

const pack = loadPack(JSON.parse(readFileSync(join(root, 'spec', 'detectors.json'), 'utf8')));
const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));

const round = (value) => Math.round(value * 1e6) / 1e6;

function normaliseFinding(finding) {
  const out = { detector: finding.detector, risk: finding.risk, confidence: round(finding.confidence) };
  for (const key of ['start', 'end', 'line', 'column', 'path', 'value']) {
    if (finding[key] !== undefined) out[key] = finding[key];
  }
  return out;
}

function runCase(testCase) {
  const options = { ...testCase.options, detectors: pack.detectors };
  const checks = testCase.checks ?? ['redact', 'scan'];
  const result = {};
  if (checks.includes('redact')) result.redact = redact(testCase.input, options);
  if (checks.includes('scan')) result.findings = scan(testCase.input, options).map(normaliseFinding);
  if (checks.includes('vault')) {
    const vault = createVault({ ...options, placeholderStyle: testCase.vault?.placeholderStyle ?? 'opaque' });
    const redacted = vault.redact(testCase.input);
    result.vault = { redacted, restored: vault.restore(redacted), entries: vault.entries() };
  }
  return result;
}

/** Stable key order, so the file is a readable diff rather than a churn magnet. */
function sortDeep(value) {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortDeep(value[key])]));
  }
  return value;
}

const results = {};
for (const testCase of corpus.cases) {
  if (testCase.name in results) throw new Error(`duplicate conformance case name: ${testCase.name}`);
  results[testCase.name] = runCase(testCase);
}

const serialised = JSON.stringify(sortDeep(results), null, 2) + '\n';

if (process.argv.includes('--write')) {
  writeFileSync(expectedPath, serialised);
  process.stdout.write(`wrote ${Object.keys(results).length} expectations to spec/conformance/expected.json\n`);
} else {
  const current = readFileSync(expectedPath, 'utf8');
  if (current === serialised) {
    process.stdout.write(`${Object.keys(results).length} conformance cases match expected.json\n`);
  } else {
    process.stderr.write('expected.json does not match this engine. Run: npm run spec:conformance -- --write\n');
    process.exitCode = 1;
  }
}
