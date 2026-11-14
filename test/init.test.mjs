// `flare-redact init`: suggestions from package.json, and the CI workflow it writes.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { planInit, renderInit, ciWorkflow } from '../dist/init.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const { version } = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const run = (args, cwd) => spawnSync(process.execPath, [cli, 'init', ...args], { cwd, encoding: 'utf8' });

function project(pkg) {
  const dir = mkdtempSync(join(tmpdir(), 'flare-init-'));
  if (pkg) writeFileSync(join(dir, 'package.json'), JSON.stringify(pkg));
  return dir;
}

test('it suggests a step for each library it recognises', () => {
  const plan = planInit({ dependencies: { openai: '^5', pino: '^9' }, devDependencies: { '@anthropic-ai/sdk': '^0.60' } });
  assert.deepEqual(plan.found, ['openai', '@anthropic-ai/sdk', 'pino']);
  assert.equal(plan.install, true);
  assert.ok(!plan.steps.some((s) => s.title.startsWith('console')), 'pino replaces the console step');
  assert.equal(planInit({ dependencies: { 'flare-redact': '^1' } }).install, false);
  assert.deepEqual(planInit(undefined).steps.map((s) => s.title.split(':')[0]), ['console']);
});

test('every import it prints exists in the package', async () => {
  const plan = planInit({ dependencies: { openai: '1', '@anthropic-ai/sdk': '1', '@sentry/node': '1', pino: '1', winston: '1', express: '1' } });
  const text = renderInit(plan, 'package.json') + planInit(undefined).steps[0].code;
  const imports = [...text.matchAll(/import \{ (\w+) \} from '(flare-redact(?:\/[a-z]+)?)'/g)];
  assert.ok(imports.length >= 7);
  for (const [, name, specifier] of imports) {
    const file = specifier === 'flare-redact' ? 'index' : specifier.split('/')[1];
    const mod = await import(`../dist/${file}.js`);
    assert.equal(typeof mod[name], 'function', `${specifier} exports ${name}`);
  }
  for (const preset of text.matchAll(/preset: '(\w+)'/g)) assert.match(preset[1], /^(logs|llm|gdpr|strict)$/);
});

test('any Sentry SDK gets the Sentry step, importing that SDK', () => {
  const plan = planInit({ dependencies: { '@sentry/nextjs': '^9', '@sentry/cli': '^2' } });
  assert.deepEqual(plan.found, ['@sentry/nextjs']);
  const step = plan.steps.find((s) => s.found === '@sentry/nextjs');
  assert.match(step.code, /import \* as Sentry from '@sentry\/nextjs';/);
  assert.match(step.code, /sentryRedact\(\{ preset: 'gdpr' \}\)/);
  assert.deepEqual(planInit({ dependencies: { '@sentry/cli': '^2' } }).found, [], 'the CLI alone is not an SDK');
  assert.doesNotMatch(step.code, /traceLifecycle/, 'Sentry 9 still sends transactions');
  for (const range of ['^11.12.0', '11', '>=11 <13', '~12.1.0']) {
    const [modern] = planInit({ dependencies: { '@sentry/node': range } }).steps;
    assert.match(modern.code, /sentryRedact\(\{ preset: 'gdpr' \}, \{ traceLifecycle: 'stream' \}\)/, range);
  }
  for (const range of ['latest', '*', 'workspace:*', '^10.48.0']) {
    assert.doesNotMatch(planInit({ dependencies: { '@sentry/node': range } }).steps[0].code, /traceLifecycle/, range);
  }
});

test('the console step offers the no-code start', () => {
  const [step] = planInit(undefined).steps;
  assert.match(step.code, /node --import flare-redact\/register app\.js/);
  assert.match(renderInit(planInit(undefined), undefined), /npx flare-redact init --hook/);
});

test('the command prints the plan and never touches source files', () => {
  const dir = project({ dependencies: { winston: '^3' } });
  try {
    const result = run([], dir);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /found winston in package\.json/);
    assert.match(result.stdout, /winstonRedact\(\{ preset: 'logs' \}\)/);
    assert.equal(existsSync(join(dir, '.github')), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('--ci writes the scan workflow once and --force replaces it', () => {
  const dir = project(undefined);
  const workflow = join(dir, '.github', 'workflows', 'flare-redact.yml');
  try {
    assert.equal(run(['--ci'], dir).status, 0);
    assert.equal(readFileSync(workflow, 'utf8'), ciWorkflow(version));
    assert.match(readFileSync(workflow, 'utf8'), new RegExp(`flare-redact@${version.replace(/\./g, '\\.')} flare-redact --scan \\.`));
    writeFileSync(workflow, 'mine');
    assert.match(run(['--ci'], dir).stdout, /already exists; left unchanged/);
    assert.equal(readFileSync(workflow, 'utf8'), 'mine');
    run(['--ci', '--force'], dir);
    assert.equal(readFileSync(workflow, 'utf8'), ciWorkflow(version));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('bad input exits 2 with a reason', () => {
  const dir = project(undefined);
  try {
    writeFileSync(join(dir, 'package.json'), '{ not json');
    const broken = run([], dir);
    assert.equal(broken.status, 2);
    assert.match(broken.stderr, /could not read/);
    const flag = run(['--nope'], dir);
    assert.equal(flag.status, 2);
    assert.match(flag.stderr, /unknown option: --nope/);
    assert.match(run(['--help'], dir).stdout, /USAGE/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
