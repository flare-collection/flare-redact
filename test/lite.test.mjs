// flare-redact/lite must give the same answers as flare-redact for everything
// that does not ask for entity recognition. Entity support is installed for the
// whole process once the full entry point loads, so lite runs in a child process
// that never imports it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

import { redact, scan } from '../dist/index.js';

const read = (path) => JSON.parse(readFileSync(new URL(path, import.meta.url), 'utf8'));
const corpus = read('../spec/conformance/cases.json');
const expected = read('../spec/conformance/expected.json');

const asksForEntities = (options = {}) =>
  Boolean(options.entities) ||
  ['llm', 'gdpr', 'strict'].includes(options.preset) ||
  [...(options.enable ?? []), ...(options.only ?? [])].some((e) => e === 'entities' || e.startsWith('private_'));

const cases = corpus.cases.filter((c) => !asksForEntities(c.options) && !(c.checks ?? []).includes('vault'));

function runLite(script) {
  // import() takes URLs: a bare Windows path such as D:\a\dist reads as scheme "d:".
  const lite = new URL('../dist/lite.js', import.meta.url).href;
  const pack = new URL('../dist/pack.js', import.meta.url).href;
  const source = `
    const lite = await import(${JSON.stringify(lite)});
    const { loadPack } = await import(${JSON.stringify(pack)});
    const { readFileSync } = await import('node:fs');
    const input = JSON.parse(readFileSync(0, 'utf8'));
    ${script}
  `;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', source], {
    input: JSON.stringify({ cases, pack: read('../spec/detectors.json') }),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(out);
}

test('lite: never loads entity recognition', () => {
  const out = runLite(`
    let code = '';
    try { lite.redact('Ada Lovelace', { entities: true }); } catch (e) { code = e.code; }
    process.stdout.write(JSON.stringify({ code, ids: lite.DETECTORS.map((d) => d.id) }));
  `);
  assert.equal(out.code, 'ERR_ENTITIES_UNAVAILABLE');
  assert.ok(!out.ids.includes('private_person'));
});

test('lite: matches the conformance corpus wherever entities are not asked for', () => {
  const out = runLite(`
    const pack = loadPack(input.pack);
    const result = {};
    for (const c of input.cases) {
      const options = { ...(c.options ?? {}), detectors: pack.detectors };
      result[c.name] = { redact: lite.redact(c.input, options), scan: lite.scan(c.input, options).length };
    }
    process.stdout.write(JSON.stringify(result));
  `);
  assert.ok(cases.length > 150, `expected most of the corpus to apply, got ${cases.length}`);
  for (const c of cases) {
    const want = expected[c.name];
    if ('redact' in want) assert.deepStrictEqual(out[c.name].redact, want.redact, c.name);
    if ('findings' in want) assert.equal(out[c.name].scan, want.findings.length, c.name);
  }
});

test('lite: matches the full build with the built-in detectors', () => {
  const out = runLite(`
    const result = {};
    for (const c of input.cases) result[c.name] = { redact: lite.redact(c.input, c.options), scan: lite.scan(c.input, c.options) };
    process.stdout.write(JSON.stringify(result));
  `);
  for (const c of cases) {
    assert.deepStrictEqual(out[c.name].redact, redact(c.input, c.options), c.name);
    assert.deepStrictEqual(out[c.name].scan, JSON.parse(JSON.stringify(scan(c.input, c.options))), c.name);
  }
});
