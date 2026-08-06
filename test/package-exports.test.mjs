import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

// Derived from package.json rather than listed by hand, so a new subpath cannot
// be published without an importable build behind it.
const codeExports = Object.entries(packageJson.exports).filter(([, target]) => {
  const file = typeof target === 'string' ? target : target.default;
  return file.endsWith('.js');
});

test('every published entry point has importable JavaScript and declarations', async () => {
  assert.ok(codeExports.length >= 14, 'package.json should publish the documented entry points');
  for (const [subpath, target] of codeExports) {
    const javascript = typeof target === 'string' ? target : target.default;
    const module = await import(new URL(`../${javascript}`, import.meta.url).href);
    assert.equal(typeof module, 'object', `${subpath} JavaScript export`);

    const types = typeof target === 'string' ? javascript.replace(/\.js$/, '.d.ts') : target.types;
    const declaration = await readFile(new URL(`../${types}`, import.meta.url), 'utf8');
    assert.ok(declaration.length > 0, `${subpath} declaration export`);
  }
});

test('data exports resolve to files that exist', async () => {
  for (const [subpath, target] of Object.entries(packageJson.exports)) {
    if (typeof target !== 'string' || target.endsWith('.js')) continue;
    const contents = await readFile(new URL(`../${target}`, import.meta.url), 'utf8');
    assert.ok(contents.length > 0, `${subpath} resolves to a readable file`);
  }
});

test('the executables named in "bin" exist and are ESM entry points', async () => {
  for (const [name, path] of Object.entries(packageJson.bin)) {
    const source = await readFile(new URL(`../${path}`, import.meta.url), 'utf8');
    assert.match(source, /^#!\/usr\/bin\/env node/, `${name} needs a node shebang`);
    assert.match(source, /^import /m, `${name} should be ESM`);
  }
});

test('every path "files" promises to publish is present', async () => {
  for (const entry of packageJson.files) {
    const info = await stat(new URL(`../${entry}`, import.meta.url));
    assert.ok(info.isFile() || info.isDirectory(), `${entry} should exist`);
  }
});
