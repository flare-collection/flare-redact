// .pre-commit-hooks.yaml is read by the pre-commit framework, not by this
// package, so nothing else would notice if it drifted from the CLI or from the
// way pre-commit installs a node hook.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { HELP } from '../dist/help.js';

const read = (file) => readFileSync(new URL(`../${file}`, import.meta.url), 'utf8');
const pkg = JSON.parse(read('package.json'));

// The file is a flat list of hooks with scalar or [inline, list] values, which
// is all this needs to read; no YAML dependency for it.
function parseHooks(text) {
  const hooks = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '');
    if (!line.trim() || line.trimStart().startsWith('#')) continue;
    const item = /^- (\w+):\s*(.*)$/.exec(line);
    const field = /^ {2}(\w+):\s*(.*)$/.exec(line);
    if (item) hooks.push({});
    const [, key, value] = item ?? field ?? [];
    assert.ok(key && hooks.length, `unexpected line in .pre-commit-hooks.yaml: ${raw}`);
    hooks.at(-1)[key] = value.replace(/^'(.*)'$/, '$1');
  }
  return hooks;
}

const hooks = parseHooks(read('.pre-commit-hooks.yaml'));
const byId = Object.fromEntries(hooks.map((hook) => [hook.id, hook]));

test('every hook runs a bin this package installs, with flags the CLI knows', () => {
  assert.deepEqual(Object.keys(byId), ['flare-redact', 'flare-redact-files']);
  for (const hook of hooks) {
    assert.equal(hook.language, 'node', hook.id);
    const [bin, ...flags] = hook.entry.split(/\s+/);
    assert.ok(pkg.bin[bin], `${hook.id}: ${bin} is not in package.json bin`);
    for (const flag of flags) {
      assert.match(HELP, new RegExp(`^\\s+${flag}\\b`, 'm'), `${hook.id}: ${flag} is not in the CLI help`);
    }
  }
});

test('the staged hook gets no filenames, the whole-file hook does', () => {
  // --staged reads the git index and throws on file arguments.
  assert.equal(byId['flare-redact'].entry, 'flare-redact --staged');
  assert.equal(byId['flare-redact'].pass_filenames, 'false');
  assert.equal(byId['flare-redact-files'].entry, 'flare-redact --scan');
  assert.equal(byId['flare-redact-files'].pass_filenames, undefined);
});

test('pre-commit can build the CLI from a git checkout', () => {
  // pre-commit installs a node hook with `npm install` then `npm pack`, and
  // dist/ is not committed, so packing has to build it...
  assert.match(pkg.scripts.prepack, /\bnpm run build\b/);
  // ...and the tarball name is read from `npm pack` stdout, where a lifecycle
  // script banner would otherwise be printed first.
  assert.match(read('.npmrc'), /^foreground-scripts=false$/m);
});

test('the usage examples pin the current release', () => {
  // A Windows checkout has CRLF line endings.
  const rev = new RegExp(`rev: v${pkg.version.replace(/\./g, '\\.')}\\r?\\n`);
  assert.match(read('.pre-commit-hooks.yaml'), rev);
  assert.match(read('docs/guide.md'), rev);
});
