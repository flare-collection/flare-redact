// `node --import flare-redact/register`: console redaction with no code change.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { registerOptions } from '../dist/register.js';

const root = fileURLToPath(new URL('..', import.meta.url));
const token = 'ghp_' + 'a'.repeat(36);

const start = (code, env = {}) => spawnSync(
  process.execPath,
  ['--import', 'flare-redact/register', '--input-type=module', '-e', code],
  { cwd: root, encoding: 'utf8', env: { ...process.env, FLARE_REDACT_PRESET: '', ...env } },
);

test('every console method is redacted without touching the code', () => {
  const result = start(`
    console.log('token ${token}');
    console.error({ user: 'alice@corp.com', password: 'hunter2' });
    console.warn('card 4242 4242 4242 4242');
  `);
  assert.equal(result.status, 0, result.stderr);
  const output = result.stdout + result.stderr;
  assert.doesNotMatch(output, new RegExp(token));
  assert.doesNotMatch(output, /alice@corp\.com|hunter2|4242 4242 4242 4242/);
  assert.match(result.stdout, /ghp_\*\*\*/);
});

test('FLARE_REDACT_PRESET picks the preset', () => {
  const text = 'Spoke with Emily Clarke today.';
  assert.match(start(`console.log(${JSON.stringify(text)})`).stdout, /Emily Clarke/);
  assert.doesNotMatch(start(`console.log(${JSON.stringify(text)})`, { FLARE_REDACT_PRESET: 'llm' }).stdout, /Emily Clarke/);
});

test('an unknown preset stops the process at startup', () => {
  const result = start(`console.log('should not run')`, { FLARE_REDACT_PRESET: 'lgos' });
  assert.notEqual(result.status, 0);
  assert.doesNotMatch(result.stdout, /should not run/);
  assert.match(result.stderr, /unknown preset "lgos"/);
  assert.throws(() => registerOptions({ FLARE_REDACT_PRESET: 'nope' }), { code: 'ERR_UNKNOWN_PRESET' });
  assert.deepEqual(registerOptions({}), {});
  assert.deepEqual(registerOptions({ FLARE_REDACT_PRESET: ' gdpr ' }), { preset: 'gdpr' });
});
