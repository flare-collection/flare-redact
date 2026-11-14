// Edge cases of `--staged`, `init --hook` and exclude globs found by review.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
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
  } finally {
    cleanup(dir);
  }
});

test('a NUL byte does not hide the rest of a staged file', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'big.txt'), 'x\n'.repeat(6000) + `token ${token('d')}\n` + 'nul \0 here\n');
    writeFileSync(join(dir, 'image.bin'), Buffer.concat([Buffer.from([0, 1, 2, 0, 255, 10]), Buffer.from(`token ${token('h')}\n`)]));
    git(dir, 'add', '.');
    const report = JSON.parse(flare(dir, '--staged', '--format', 'json').stdout);
    assert.deepEqual(report.findings.map((f) => [f.file, f.line]), [['big.txt', 6001], ['image.bin', 2]]);
  } finally {
    cleanup(dir);
  }
});

test('line numbers hold whatever the diff settings of the repository', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'a.txt'), 'one\n\nthree\n\nfive\nsix\n\neight\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-qm', 'init');
    git(dir, 'config', 'diff.interHunkContext', '5');
    git(dir, 'config', 'diff.suppressBlankEmpty', 'true');
    git(dir, 'config', 'diff.context', '7');
    writeFileSync(join(dir, 'a.txt'), `ONE\n\nthree\n\nfive\ntoken ${token('i')}\n\neight\n`);
    git(dir, 'add', '.');
    const result = flare(dir, '--staged');
    assert.match(result.stdout, /at a\.txt:6:7/);
  } finally {
    cleanup(dir);
  }
});

test('the header of a type change is not read as content', () => {
  const dir = repo();
  try {
    writeFileSync(join(dir, 'jane.roe@example.com.txt'), 'nothing\n');
    writeFileSync(join(dir, 'target.txt'), 'nothing\n');
    git(dir, 'add', '.');
    git(dir, 'commit', '-qm', 'init');
    unlinkSync(join(dir, 'jane.roe@example.com.txt'));
    symlinkSync('target.txt', join(dir, 'jane.roe@example.com.txt'));
    git(dir, 'add', '.');
    const result = flare(dir, '--staged');
    assert.equal(result.status, 0, result.stdout);
  } finally {
    cleanup(dir);
  }
});

test('init --hook never writes through a pre-commit symlink', () => {
  const dir = repo();
  const outside = mkdtempSync(join(tmpdir(), 'flare-hook-target-'));
  try {
    const victim = join(outside, 'victim.sh');
    writeFileSync(victim, 'original\n');
    const hook = join(dir, '.git', 'hooks', 'pre-commit');
    mkdirSync(join(dir, '.git', 'hooks'), { recursive: true });
    symlinkSync(victim, hook);
    assert.match(flare(dir, 'init', '--hook').stdout, /already exists; left unchanged/);
    assert.equal(flare(dir, 'init', '--hook', '--force').status, 0);
    assert.equal(readFileSync(victim, 'utf8'), 'original\n');
    assert.match(readFileSync(hook, 'utf8'), /flare-redact --scan --staged/);
    assert.equal(lstatSync(hook).isSymbolicLink(), false);

    unlinkSync(hook);
    symlinkSync(join(outside, 'missing.sh'), hook);
    assert.match(flare(dir, 'init', '--hook').stdout, /already exists; left unchanged/);
    assert.equal(existsSync(join(outside, 'missing.sh')), false);
  } finally {
    cleanup(dir, outside);
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
