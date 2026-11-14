// `--scan --staged` and `init --hook`: stop a commit for the secrets it adds, not the ones already there.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addedBlocks } from '../dist/staged.js';
import { preCommitHook, HOOK_COMMAND } from '../dist/init.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const token = (c) => 'ghp_' + c.repeat(36);

// Keep the developer's own git configuration (global hooks, signing) out of the tests.
const env = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
const git = (cwd, ...args) => {
  const result = spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8', env });
  return result;
};
const flare = (cwd, ...args) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', env });

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'flare-staged-'));
  assert.equal(git(dir, 'init', '-q').status, 0);
  return dir;
}

test('the diff parser keeps added lines and their line numbers', () => {
  const diff = [
    'diff --git a/a.txt b/a.txt',
    'index 1..2 100644',
    '--- a/a.txt',
    '+++ b/a.txt',
    '@@ -2 +2,2 @@',
    '-old',
    '+new one',
    '+new two\r',
    '@@ -9,0 +11 @@ context',
    '+tail',
    '\\ No newline at end of file',
  ].join('\n');
  assert.deepEqual(addedBlocks('a.txt', diff), [
    { file: 'a.txt', line: 2, text: 'new one\nnew two' },
    { file: 'a.txt', line: 11, text: 'tail' },
  ]);
  assert.deepEqual(addedBlocks('b.bin', 'Binary files a/b.bin and b/b.bin differ\n'), []);
});

test('only lines the commit adds are reported, at their staged line', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'a.txt'), `old line\nold token ${token('b')}\n`);
    git(dir, 'add', 'a.txt');
    git(dir, 'commit', '-qm', 'init');
    writeFileSync(join(dir, 'a.txt'), `old line\nold token ${token('b')}\nnew line\nkey = "AKIAIOSFODNN7EXAMPLE"\n`);
    mkdirSync(join(dir, 'sub dir'));
    writeFileSync(join(dir, 'sub dir', '*odd.md'), 'contact alice@corp.com\n');
    mkdirSync(join(dir, 'node_modules', 'x'), { recursive: true });
    writeFileSync(join(dir, 'node_modules', 'x', 'i.js'), `t = '${token('c')}'\n`);
    git(dir, 'add', '-f', '.');

    const pretty = flare(join(dir, 'sub dir'), '--staged');
    assert.equal(pretty.status, 1);
    assert.match(pretty.stdout, /at a\.txt:4:8/);
    assert.match(pretty.stdout, /at sub dir\/\*odd\.md:1:9/);
    assert.match(pretty.stdout, /git commit --no-verify/);
    assert.doesNotMatch(pretty.stdout, /a\.txt:2:/, 'the committed token is not reported again');

    const report = JSON.parse(flare(dir, '--scan', '--staged', '--format', 'json').stdout);
    assert.equal(report.summary.total, 2);
    assert.equal(report.summary.filesScanned, 2);
    assert.equal(report.summary.skipped.excluded, 1);
    assert.deepEqual(report.findings.map((f) => [f.file, f.line, f.start]), [['a.txt', 4, undefined], ['sub dir/*odd.md', 1, undefined]]);
    assert.equal(flare(dir, '--staged', '--exclude', '*.md', '--exclude', 'a.txt').status, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bad usage exits 2', () => {
  const outside = mkdtempSync(join(tmpdir(), 'flare-nogit-'));
  try {
    const result = flare(outside, '--staged');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /--staged needs a git repository/);
    assert.match(flare(outside, '--staged', 'file.txt').stderr, /takes no file arguments/);
  } finally {
    rmSync(outside, { recursive: true, force: true });
  }
});

test('init --hook installs a hook that stops a commit adding a secret', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'package.json'), '{}');
    // The hook prefers the project's own copy; point it at this checkout.
    mkdirSync(join(dir, 'node_modules', '.bin'), { recursive: true });
    const shim = join(dir, 'node_modules', '.bin', 'flare-redact');
    writeFileSync(shim, `#!/bin/sh\nexec "${process.execPath}" "${cli}" "$@"\n`);
    chmodSync(shim, 0o755);

    const install = flare(dir, 'init', '--hook');
    assert.equal(install.status, 0, install.stderr);
    assert.match(install.stdout, /Wrote \.git\/hooks\/pre-commit/);
    const hook = join(dir, '.git', 'hooks', 'pre-commit');
    assert.equal(readFileSync(hook, 'utf8'), preCommitHook(version));
    assert.ok(statSync(hook).mode & 0o100, 'the hook is executable');

    writeFileSync(join(dir, 'config.js'), `export const token = '${token('d')}';\n`);
    git(dir, 'add', 'config.js');
    const blocked = git(dir, 'commit', '-m', 'add token');
    assert.notEqual(blocked.status, 0, 'the commit is stopped');
    assert.match(blocked.stdout + blocked.stderr, /config\.js:1:/);

    writeFileSync(join(dir, 'config.js'), 'export const token = process.env.TOKEN;\n');
    git(dir, 'add', 'config.js');
    assert.equal(git(dir, 'commit', '-qm', 'read from env').status, 0);

    writeFileSync(hook, '#!/bin/sh\nexit 0\n');
    const kept = flare(dir, 'init', '--hook');
    assert.match(kept.stdout, /already exists; left unchanged/);
    assert.match(kept.stdout, new RegExp(HOOK_COMMAND.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')));
    assert.equal(readFileSync(hook, 'utf8'), '#!/bin/sh\nexit 0\n');
    flare(dir, 'init', '--hook', '--force');
    assert.equal(readFileSync(hook, 'utf8'), preCommitHook(version));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('init --hook leaves husky and shared hook folders alone', () => {
  const dir = repo();
  const shared = mkdtempSync(join(tmpdir(), 'flare-shared-hooks-'));
  try {
    git(dir, 'config', 'core.hooksPath', '.husky/_');
    const husky = flare(dir, 'init', '--hook');
    assert.equal(husky.status, 0);
    assert.match(husky.stdout, /husky\. Add this line to \.husky\/pre-commit/);

    git(dir, 'config', 'core.hooksPath', shared);
    const outside = flare(dir, 'init', '--hook');
    assert.match(outside.stdout, /outside it\. Add this line/);
    assert.throws(() => statSync(join(shared, 'pre-commit')));

    const none = mkdtempSync(join(tmpdir(), 'flare-nogit-'));
    const result = flare(none, 'init', '--hook');
    assert.equal(result.status, 2);
    assert.match(result.stderr, /needs a git repository/);
    rmSync(none, { recursive: true, force: true });
  } finally {
    rmSync(dir, { recursive: true, force: true });
    rmSync(shared, { recursive: true, force: true });
  }
});
