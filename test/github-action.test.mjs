// action.yml runs in other people's workflows: its inputs must never be
// pasted into a shell script, and its report must never print a value.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { annotations, findingsFromSarif, summary } from '../scripts/github-action-report.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const action = readFileSync(join(root, 'action.yml'), 'utf8');
const cli = join(root, 'bin', 'flare-redact.mjs');
const report = join(root, 'scripts', 'github-action-report.mjs');
const secret = 'ghp_' + 'a'.repeat(36);

test('the action is a composite action with Marketplace metadata', () => {
  assert.match(action, /^name: \S/m);
  assert.match(action, /^description: .{20,125}$/m);
  assert.match(action, /^branding:\n {2}icon: \S+\n {2}color: \S+$/m);
  assert.match(action, /^ {2}using: composite$/m);
});

test('every input the steps read is declared', () => {
  const declared = new Set([...action.matchAll(/^ {2}([\w-]+):\n {4}description:/gm)].map((m) => m[1]));
  const used = new Set([...action.matchAll(/inputs\.([\w-]+)/g)].map((m) => m[1]));
  assert.ok(used.size > 0);
  for (const name of used) assert.ok(declared.has(name), `inputs.${name} is not declared`);
});

test('no expression is expanded inside a run script', () => {
  // `${{ inputs.x }}` in `run:` is pasted into the script before bash parses
  // it, so a crafted input could run code. Inputs go through `env:` instead.
  const lines = action.split('\n');
  let runIndent = -1;
  let scripts = 0;
  for (const line of lines) {
    const indent = line.search(/\S/);
    if (runIndent >= 0 && line.trim() && indent <= runIndent) runIndent = -1;
    if (runIndent >= 0) assert.doesNotMatch(line, /\$\{\{/, `expression inside run: ${line.trim()}`);
    const run = /^(\s*)run: \|$/.exec(line);
    if (run) {
      runIndent = run[1].length;
      scripts++;
    }
  }
  assert.ok(scripts >= 2);
});

test('the scripts the action calls exist', () => {
  for (const [, file] of action.matchAll(/\$GITHUB_ACTION_PATH\/([\w./-]+)/g)) {
    assert.ok(existsSync(join(root, file)), file);
  }
});

function scanToSarif(files) {
  const dir = mkdtempSync(join(tmpdir(), 'flare-action-'));
  for (const [name, text] of Object.entries(files)) {
    mkdirSync(join(dir, name, '..'), { recursive: true });
    writeFileSync(join(dir, name), text);
  }
  const run = spawnSync(process.execPath, [cli, '--sarif', '.'], { cwd: dir, encoding: 'utf8' });
  rmSync(dir, { recursive: true, force: true });
  return { status: run.status, sarif: JSON.parse(run.stdout) };
}

test('findings become annotations and a summary without the value', () => {
  const { status, sarif } = scanToSarif({
    'src/config, old.txt': `line one\ndeploy key: ${secret}\n`,
    'clean.txt': 'nothing to see\n',
  });
  assert.equal(status, 1);
  const findings = findingsFromSarif(sarif);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].detector, 'github_token');
  assert.equal(findings[0].file, 'src/config, old.txt');

  const [line] = annotations(findings);
  // Property values escape `,` and `:`, so the file name cannot end the list.
  assert.equal(
    line,
    '::error file=src/config%2C old.txt,line=2,col=13,title=flare-redact%3A GitHub token::GitHub token: Grants access to repositories and account actions.',
  );

  const md = summary(findings);
  assert.match(md, /### flare-redact: 1 finding\n/);
  assert.match(md, /\| GitHub token \(`github_token`\) \| critical \| `src\/config, old\.txt:2:13` \|/);
  for (const text of [line, md]) assert.ok(!text.includes(secret.slice(4)), 'the value leaked');
});

test('a clean scan reports zero', () => {
  const { status, sarif } = scanToSarif({ 'a.txt': 'hello\n' });
  assert.equal(status, 0);
  assert.deepEqual(findingsFromSarif(sarif), []);
  assert.deepEqual(annotations([]), []);
  assert.match(summary([]), /no findings/);
});

test('messages and table cells cannot break out of their command or row', () => {
  const findings = findingsFromSarif({
    runs: [{
      tool: { driver: { rules: [{ id: 'x', name: 'Bad | name' }] } },
      results: [{
        ruleId: 'x',
        message: { text: '100% sure\n::warning::injected' },
        properties: { risk: 'high' },
        locations: [{ physicalLocation: { artifactLocation: { uri: 'dir/a%20b.txt' }, region: { startLine: 3 } } }],
      }],
    }],
  });
  assert.deepEqual(annotations(findings), [
    '::error file=dir/a b.txt,line=3,title=flare-redact%3A Bad | name::100%25 sure%0A::warning::injected',
  ]);
  assert.match(summary(findings), /\| Bad \\\| name \(`x`\) \| high \| `dir\/a b\.txt:3` \|/);
  const cut = summary(Array.from({ length: 5 }, () => findings[0]), 2);
  assert.match(cut, /3 more not shown/);
});

test('the report script writes the step outputs and summary', () => {
  const dir = mkdtempSync(join(tmpdir(), 'flare-action-report-'));
  try {
    const { sarif } = scanToSarif({ 'k.txt': `token ${secret}\n` });
    writeFileSync(join(dir, 'r.sarif'), JSON.stringify(sarif));
    const env = { ...process.env, GITHUB_OUTPUT: join(dir, 'out'), GITHUB_STEP_SUMMARY: join(dir, 'summary') };
    const quiet = execFileSync(process.execPath, [report, join(dir, 'r.sarif'), '--no-annotations'], { env, encoding: 'utf8' });
    assert.equal(quiet, 'flare-redact: 1 finding\n');
    const loud = execFileSync(process.execPath, [report, join(dir, 'r.sarif')], { env, encoding: 'utf8' });
    assert.match(loud, /^::error file=k\.txt,line=1,/);
    assert.equal(readFileSync(join(dir, 'out'), 'utf8'), 'findings=1\nfindings=1\n');
    assert.match(readFileSync(join(dir, 'summary'), 'utf8'), /\| GitHub token/);
    assert.ok(!loud.includes(secret.slice(4)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
