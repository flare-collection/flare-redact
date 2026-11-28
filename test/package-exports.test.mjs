import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));

// Derived from package.json rather than listed by hand, so a new subpath cannot
// be published without an importable build behind it. A target is a file, a
// { types, default } pair, or { import, require } with one pair each.
const conditions = (target) => (typeof target === 'string' ? { default: target } : target);
const esmTarget = (target) => {
  const t = conditions(target);
  return t.import ?? t;
};
const codeExports = Object.entries(packageJson.exports).filter(([, target]) => {
  const file = typeof target === 'string' ? target : esmTarget(target).default;
  return file.endsWith('.js');
});

test('every published entry point has importable JavaScript and declarations', async () => {
  assert.ok(codeExports.length >= 14, 'package.json should publish the documented entry points');
  for (const [subpath, target] of codeExports) {
    const esm = typeof target === 'string' ? { default: target } : esmTarget(target);
    const module = await import(new URL(`../${esm.default}`, import.meta.url).href);
    assert.equal(typeof module, 'object', `${subpath} JavaScript export`);

    const types = esm.types ?? esm.default.replace(/\.js$/, '.d.ts');
    const declaration = await readFile(new URL(`../${types}`, import.meta.url), 'utf8');
    assert.ok(declaration.length > 0, `${subpath} declaration export`);
  }
});

test('every library entry point also loads with require(), without require(esm)', async () => {
  const cjs = codeExports.filter(([, target]) => typeof target === 'object' && target.require);
  assert.ok(cjs.length >= 20, 'the library subpaths should ship a CommonJS build');
  const files = [];
  for (const [subpath, target] of cjs) {
    assert.match(target.require.default, /^\.\/dist\/cjs\//, `${subpath} require target`);
    const declaration = await readFile(new URL(`../${target.require.types}`, import.meta.url), 'utf8');
    assert.ok(declaration.length > 0, `${subpath} CommonJS declarations`);
    files.push(fileURLToPath(new URL(`../${target.require.default}`, import.meta.url)));
  }
  const script = `for (const f of ${JSON.stringify(files)}) { const m = require(f); if (!m || typeof m !== 'object') throw new Error(f); }
const { redact } = require(${JSON.stringify(files[0])});
process.stdout.write(redact({ db_password: 'x' }).db_password);`;
  const out = execFileSync(process.execPath, ['--no-experimental-require-module', '-e', script], { encoding: 'utf8' });
  assert.equal(out, '***');
});

test('the package publishes no source maps', async () => {
  const { readdir } = await import('node:fs/promises');
  const all = await readdir(new URL('../dist', import.meta.url), { recursive: true });
  assert.deepEqual(all.filter((f) => f.endsWith('.map')), []);
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
