// Edge cases of `--staged`, `init --hook` and exclude globs found by review.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPathFilter } from '../dist/file-discovery.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const token = (c) => 'ghp_' + c.repeat(36);
const env = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' };
const git = (cwd, ...args) =>
  spawnSync('git', ['-c', 'user.name=t', '-c', 'user.email=t@example.invalid', '-c', 'commit.gpgsign=false', ...args], { cwd, encoding: 'utf8', env });
const flare = (cwd, ...args) => spawnSync(process.execPath, [cli, ...args], { cwd, encoding: 'utf8', env, input: '' });

function repo() {
  const dir = mkdtempSync(join(tmpdir(), 'flare-edge-'));
  assert.equal(git(dir, 'init', '-q').status, 0);
  return dir;
}
const cleanup = (...dirs) => { for (const dir of dirs) rmSync(dir, { recursive: true, force: true }); };

test('a file that replaces a symlink is scanned', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'target.txt'), 'nothing\n');
    symlinkSync('target.txt', join(dir, 'link'));
    git(dir, 'add', '.');
    git(dir, 'commit', '-qm', 'init');
    unlinkSync(join(dir, 'link'));
    writeFileSync(join(dir, 'link'), `token ${token('a')}\n`);
    git(dir, 'add', 'link');
    const result = flare(dir, '--staged');
    assert.equal(result.status, 1, result.stdout);
    assert.match(result.stdout, /at link:1:7/);
  } finally {
    cleanup(dir);
  }
});

test('a file marked -diff or binary in .gitattributes is still scanned', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, '.gitattributes'), '*.cfg -diff\n*.dat binary\n');
    writeFileSync(join(dir, 'a.cfg'), `token = "${token('b')}"\n`);
    writeFileSync(join(dir, 'b.dat'), `key ${token('c')}\n`);
    git(dir, 'add', '.');
    const report = JSON.parse(flare(dir, '--staged', '--format', 'json').stdout);
    assert.deepEqual(report.findings.map((f) => f.file).sort(), ['a.cfg', 'b.dat']);
    assert.equal(report.summary.skipped.binary, 0);
  } finally {
    cleanup(dir);
  }
});

test('real binary content is skipped and counted', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'image.bin'), Buffer.concat([Buffer.from([0, 1, 2, 0, 255]), Buffer.from(`token ${token('d')}\n`)]));
    writeFileSync(join(dir, 'note.txt'), 'hello\n');
    git(dir, 'add', '.');
    const report = JSON.parse(flare(dir, '--staged', '--format', 'json').stdout);
    assert.equal(report.summary.skipped.binary, 1);
    assert.equal(report.summary.filesScanned, 1);
    assert.equal(report.summary.total, 0);
  } finally {
    cleanup(dir);
  }
});

test('--staged refuses the modes that would not read the index', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'a.txt'), `token ${token('e')}\n`);
    git(dir, 'add', '.');
    for (const flag of ['--summary', '--json', '--csv']) {
      const result = flare(dir, '--staged', flag);
      assert.equal(result.status, 2, flag);
      assert.match(result.stderr, /--staged only scans/, flag);
    }
    assert.equal(flare(dir, '--staged').status, 1);
  } finally {
    cleanup(dir);
  }
});

test('init --hook does not write through a hooks folder linked outside the repository', () => {
  const dir = repo();
  const outside = mkdtempSync(join(tmpdir(), 'flare-linked-hooks-'));
  try {
    rmSync(join(dir, '.git', 'hooks'), { recursive: true, force: true });
    symlinkSync(outside, join(dir, '.git', 'hooks'));
    const result = flare(dir, 'init', '--hook');
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /outside it\. Add this line/);
    assert.equal(existsSync(join(outside, 'pre-commit')), false);
  } finally {
    cleanup(dir, outside);
  }
});

test('init accepts an absolute directory', () => {
  const dir = repo();
  const elsewhere = mkdtempSync(join(tmpdir(), 'flare-elsewhere-'));
  try {
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ dependencies: { pino: '^9' } }));
    const result = flare(elsewhere, 'init', realpathSync(dir), '--hook');
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /found pino in /);
    assert.equal(existsSync(join(dir, '.git', 'hooks', 'pre-commit')), true);
  } finally {
    cleanup(dir, elsewhere);
  }
});

test('exclude globs mean what they did and stay fast on a hostile path', () => {
  const excluded = (excludes, path) => createPathFilter({ excludes, defaultExcludes: false })(path);
  const cases = [
    [['*.md'], 'docs/a.md', true],
    [['*.md'], 'docs/a.mdx', false],
    [['fixtures/**'], 'fixtures/a/b.txt', true],
    [['fixtures/**'], 'src/fixtures/a', false],
    [['**/fixtures/**'], 'src/fixtures/a', true],
    [['**/fixtures/**'], 'fixtures/a', true],
    [['test/**/*.snap'], 'test/a/b/c.snap', true],
    [['test/**/*.snap'], 'test/c.snap', true],
    [['test/**/*.snap'], 'test/c.txt', false],
    [['a?c/*.js'], 'abc/x.js', true],
    [['a?c/*.js'], 'abbc/x.js', false],
    [['build/'], 'build/out.js', true],
    [['build/'], 'src/build', false],
    [['package-lock.json'], 'examples/x/package-lock.json', true],
    [['src/*.ts'], 'src/a/b.ts', false],
    [['**/*.min.js'], 'a/b/c.min.js', true],
    [['*a*b*c'], 'xaxbxc', true],
    [['*a*b*c'], 'xaxbx', false],
  ];
  for (const [excludes, path, want] of cases) assert.equal(excluded(excludes, path), want, `${excludes} on ${path}`);
  assert.equal(createPathFilter({ defaultExcludes: true })('a/node_modules/x/i.js'), true);
  assert.equal(createPathFilter({ defaultExcludes: true })('a/node_modules'), false, 'a file with that name is not a directory');

  const deep = 'a/'.repeat(2000) + 'y';
  const started = performance.now();
  assert.equal(excluded(['**/**/**/**/x'], deep), false);
  assert.equal(excluded(['**/a/**/a/**/a/**/x'], deep), false);
  assert.equal(excluded(['*a*a*a*a*a*a*b'], 'a'.repeat(5000)), false);
  assert.ok(performance.now() - started < 2000);
});

test('directory scans still honour the same globs', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-walk-'));
  try {
    mkdirSync(join(dir, 'src', 'fixtures'), { recursive: true });
    writeFileSync(join(dir, 'src', 'fixtures', 'a.txt'), `token ${token('f')}\n`);
    writeFileSync(join(dir, 'src', 'b.txt'), `token ${token('g')}\n`);
    const all = JSON.parse(flare(dir, '--scan', '.', '--format', 'json').stdout);
    assert.equal(all.summary.total, 2);
    const some = JSON.parse(flare(dir, '--scan', '.', '--format', 'json', '--exclude', '**/fixtures/**').stdout);
    assert.deepEqual(some.findings.map((f) => f.file), ['src/b.txt']);
  } finally {
    cleanup(dir);
  }
});
