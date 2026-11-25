// The Node engine must agree with the Python, Go, Rust, Java and .NET engines,
// case for case. See spec/SPEC.md §13; this file is the JavaScript part of that
// promise.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { loadPack } from '../dist/pack.js';
import { redact, scan, createVault, DETECTORS } from '../dist/index.js';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));

const packDocument = read('../spec/detectors.json');
const corpus = read('../spec/conformance/cases.json');
const expected = read('../spec/conformance/expected.json');
const pack = loadPack(packDocument);

/** Six decimals: finer than any decision made with the value, coarse enough that
 *  six languages' floating-point formatting cannot disagree about the text. */
const round = (value) => Math.round(value * 1e6) / 1e6;

function normaliseFinding(finding) {
  const out = { detector: finding.detector, risk: finding.risk, confidence: round(finding.confidence) };
  for (const key of ['start', 'end', 'line', 'column', 'path', 'value']) {
    if (finding[key] !== undefined) out[key] = finding[key];
  }
  return out;
}

// The corpus speaks the library's own option names, so a case's `options` block
// is a RedactOptions with the built-in detectors swapped for the pack's.
const withPack = (options = {}) => ({ ...options, detectors: pack.detectors });

function runCase(testCase) {
  const options = withPack(testCase.options);
  const checks = testCase.checks ?? ['redact', 'scan'];
  const result = {};
  if (checks.includes('redact')) result.redact = redact(testCase.input, options);
  if (checks.includes('scan')) result.findings = scan(testCase.input, options).map(normaliseFinding);
  if (checks.includes('vault')) {
    const vault = createVault({ ...options, placeholderStyle: testCase.vault?.placeholderStyle ?? 'opaque' });
    const redacted = vault.redact(testCase.input);
    result.vault = {
      redacted,
      restored: vault.restore(redacted),
      entries: vault.entries().map(([placeholder, original]) => [placeholder, original]),
    };
    if (testCase.vault && 'reply' in testCase.vault) result.vault.reply = vault.restore(testCase.vault.reply);
  }
  return result;
}

test('conformance corpus and expectations line up', () => {
  const names = corpus.cases.map((c) => c.name);
  assert.equal(new Set(names).size, names.length, 'duplicate case names in cases.json');
  assert.deepEqual(
    names.slice().sort(),
    Object.keys(expected).sort(),
    'cases.json and expected.json disagree; regenerate with npm run spec:conformance',
  );
});

for (const testCase of corpus.cases) {
  test(`conformance: ${testCase.name}`, () => {
    assert.deepStrictEqual(runCase(testCase), expected[testCase.name]);
  });
}

test('the pack only names detectors the built-in set also has', () => {
  const builtIn = new Set(DETECTORS.map((d) => d.id));
  for (const detector of pack.detectors) {
    assert.ok(
      builtIn.has(detector.id),
      `pack detector ${detector.id} has no counterpart in DETECTORS; the portable profile has drifted`,
    );
  }
});

test('the pack preserves each detector default, risk and tags', () => {
  const builtIn = new Map(DETECTORS.map((d) => [d.id, d]));
  for (const detector of pack.detectors) {
    const original = builtIn.get(detector.id);
    assert.equal(detector.default, original.default, `${detector.id}: default differs`);
    assert.deepEqual(detector.tags ?? [], original.tags ?? [], `${detector.id}: tags differ`);
  }
});

test('a pack entropy validator counts code points, as the other engines do', () => {
  // "Z😀a" is three code points, so its entropy is log2(3) ≈ 1.585. Dividing by
  // the UTF-16 length (4) instead gives 1.5 and refused the match.
  const document = {
    ...packDocument,
    detectors: [{
      id: 'emoji_token', label: 'Emoji token', why: 'test.', pattern: 'Z[^ ]{2}',
      validators: [{ name: 'entropy', min: 1.55 }],
      mask: { type: 'fixed', text: '[E]' }, default: true, risk: 'low', confidence: 0.5,
    }],
  };
  assert.equal(redact('see Z\u{1F600}a now', { detectors: loadPack(document).detectors }), 'see [E] now');
});
