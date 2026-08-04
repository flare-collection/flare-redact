import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const entryPoints = [
  'index',
  'stream',
  'llm',
  'ml',
  'tool',
  'session',
  'pino',
  'winston',
  'http',
  'csv',
  'fetch',
  'middleware',
];

test('every public package entry point has importable JavaScript and declarations', async () => {
  for (const entry of entryPoints) {
    const module = await import(`../dist/${entry}.js`);
    assert.equal(typeof module, 'object', `${entry} JavaScript export`);
    const declaration = await readFile(new URL(`../dist/${entry}.d.ts`, import.meta.url), 'utf8');
    assert.ok(declaration.length > 0, `${entry} declaration export`);
  }
});
