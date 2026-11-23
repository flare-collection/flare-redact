// Shadow mode: count what a policy would redact before enforcing it, without
// ever keeping a matched value.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { createAudit, shadowConsole } from '../dist/audit.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';

test('observe counts and returns the value unchanged', () => {
  const audit = createAudit();
  const event = { users: [{ email: 'ada@example.com' }, { email: 'bob@example.com' }], password: 'x', ok: true };
  assert.equal(audit.observe(event, 'webhook'), event);
  audit.observe(`key ${TOKEN}`, 'cli');
  audit.observe('nothing here', 'cli');
  const report = audit.report();
  assert.equal(report.scanned, 3);
  assert.equal(report.withFindings, 2);
  assert.equal(report.total, 4);
  assert.deepEqual(report.byDetector, { email: 2, github_token: 1, sensitive_key: 1 });
  assert.deepEqual(report.byRisk, { critical: 2, high: 2 });
  assert.deepEqual(report.byPath, { 'users[].email': 2, password: 1 });
  assert.deepEqual(report.bySource.cli, { scanned: 2, total: 1, byDetector: { github_token: 1 } });
  const text = JSON.stringify(report) + audit.format();
  for (const value of ['ada@example.com', 'bob@example.com', TOKEN]) assert.ok(!text.includes(value), value);
  assert.match(audit.format(), /^4 findings in 2 of 3 values \(66\.7%\) since /);
});

test('redact enforces and counts the same way', () => {
  const audit = createAudit({ preset: 'gdpr' });
  assert.equal(audit.redact('mail ada@example.com'), 'mail a***@***');
  assert.equal(audit.report().byDetector.email, 1);
  audit.reset();
  assert.equal(audit.report().total, 0);
});

test('a matched value is never kept, even when asked for', () => {
  const seen = [];
  const audit = createAudit({ includeValues: true, onFinding: (event) => seen.push(event) });
  audit.observe({ note: `key ${TOKEN}` }, 'job');
  assert.deepEqual(seen, [{ detector: 'github_token', risk: 'critical', source: 'job', path: 'note' }]);
  assert.ok(!JSON.stringify(audit.report()).includes(TOKEN));
});

test('field paths are capped', () => {
  const audit = createAudit({ maxPaths: 2 });
  audit.observe({ a: 'ada@example.com', b: 'ada@example.com', c: 'ada@example.com', d: 'ada@example.com' });
  assert.deepEqual(audit.report().byPath, { '(other)': 2, a: 1, b: 1 });
});

test('an OpenTelemetry meter gets findings and scanned counters', () => {
  const adds = {};
  const meter = {
    createCounter: (name) => ({ add: (n, attrs) => (adds[name] ??= []).push([n, attrs]) }),
  };
  const audit = createAudit({ meter });
  audit.observe('mail ada@example.com', 'api');
  audit.observe('fine', 'api');
  assert.deepEqual(adds['flare_redact.findings'], [[1, { detector: 'email', risk: 'high', source: 'api' }]]);
  assert.equal(adds['flare_redact.scanned'].length, 2);
});

test('shadowConsole counts without changing output, enforce redacts too', () => {
  const lines = [];
  const fake = { log: (...a) => lines.push(a), info() {}, warn() {}, error() {}, debug() {} };
  const audit = createAudit();
  const restore = shadowConsole(audit, fake);
  fake.log('mail', 'ada@example.com');
  assert.deepEqual(lines.pop(), ['mail', 'ada@example.com']);
  assert.equal(audit.report().bySource['console.log'].total, 1);
  restore();
  shadowConsole(audit, fake, { enforce: true });
  fake.log('mail ada@example.com');
  assert.deepEqual(lines.pop(), ['mail a***@***']);
});

const start = (code, env = {}) => spawnSync(
  process.execPath,
  ['--import', 'flare-redact/register', '--input-type=module', '-e', code],
  { cwd: root, encoding: 'utf8', env: { ...process.env, FLARE_REDACT_PRESET: '', FLARE_REDACT_MODE: '', ...env } },
);

test('FLARE_REDACT_MODE=shadow leaves output alone and reports at exit', () => {
  const result = start(`console.log('mail ada@example.com'); console.error('key ${TOKEN}'); console.log('fine')`,
    { FLARE_REDACT_MODE: 'shadow' });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /mail ada@example\.com/);
  assert.match(result.stderr, /\[flare-redact shadow\] 2 findings in 2 of 3 values \(66\.7%\)/);
  assert.match(result.stderr, /github_token +1/);
  assert.equal(result.stderr.split('\n').filter((l) => l.includes(TOKEN)).length, 1, 'only the app printed the token');
});

test('FLARE_REDACT_MODE=audit redacts and reports; a bad mode stops startup', () => {
  const audited = start(`console.log('mail ada@example.com')`, { FLARE_REDACT_MODE: 'audit' });
  assert.match(audited.stdout, /mail a\*\*\*@\*\*\*/);
  assert.match(audited.stderr, /\[flare-redact audit\] 1 finding in 1 of 1 values \(100\.0%\)/);
  const bad = start(`console.log('should not run')`, { FLARE_REDACT_MODE: 'shdow' });
  assert.notEqual(bad.status, 0);
  assert.doesNotMatch(bad.stdout, /should not run/);
  assert.match(bad.stderr, /FLARE_REDACT_MODE must be enforce, shadow or audit/);
  const clean = start(`console.log('fine')`, { FLARE_REDACT_MODE: 'shadow' });
  assert.match(clean.stderr, /0 findings in 0 of 1 values \(0\.0%\)/, 'a clean run still says shadow mode ran');
  const silent = start(`1`, { FLARE_REDACT_MODE: 'shadow' });
  assert.equal(silent.stderr, '', 'no report when nothing was logged');
});
