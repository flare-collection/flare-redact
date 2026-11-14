// Presets: one word instead of a list of tags.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { PRESETS, createVault, redact, scan } from '../dist/index.js';
import { createGateway, resolveConfig, GatewayConfigError } from '../dist/gateway/index.js';

const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));
const TEXT = 'Hi, my name is Alice Johnson, call me at +44 20 7946 0958, IP 203.0.113.7, VIN 1HGCM82633A004352';
const ids = (options) => new Set(scan(TEXT, options).map((f) => f.detector));

test('the four presets exist and only add detectors', () => {
  assert.deepEqual(Object.keys(PRESETS), ['logs', 'llm', 'gdpr', 'strict']);
  assert.deepEqual([...ids({})], []);
  assert.deepEqual([...ids({ preset: 'logs' })], ['phone']);
  const llm = ids({ preset: 'llm' });
  assert.ok(llm.has('private_person') && !llm.has('ipv4') && !llm.has('vin'));
  const gdpr = ids({ preset: 'gdpr' });
  for (const id of llm) assert.ok(gdpr.has(id), `gdpr keeps ${id}`);
  assert.ok(gdpr.has('ipv4') && gdpr.has('vin'));
});

test('strict turns on every detector, high_entropy included', () => {
  assert.equal(redact('token 9f8b7a6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a', { preset: 'strict' }).includes('9f8b7a6c5d4e'), false);
});

test('enable and disable apply on top of a preset, only ignores it', () => {
  assert.ok(ids({ preset: 'logs', enable: ['ipv4'] }).has('ipv4'));
  assert.ok(!ids({ preset: 'gdpr', disable: ['network'] }).has('ipv4'));
  assert.deepEqual([...ids({ preset: 'strict', only: ['email'] })], []);
});

test('an unknown preset fails loudly instead of redacting less', () => {
  assert.throws(() => redact('x', { preset: 'gpdr' }), { code: 'ERR_UNKNOWN_PRESET', message: /use one of: logs, llm, gdpr, strict/ });
});

test('vaults and the LLM path take presets', () => {
  const vault = createVault({ preset: 'llm' });
  const masked = vault.redact('My name is Alice Johnson.');
  assert.doesNotMatch(masked, /Alice/);
  assert.equal(vault.restore(masked), 'My name is Alice Johnson.');
});

test('the CLI takes --preset', () => {
  const result = spawnSync(process.execPath, [cli, '--preset', 'gdpr'], { input: 'IP 203.0.113.7', encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.equal(result.stdout.trim(), 'IP ***.***.***.***');
});

test('the gateway rejects an unknown preset at startup and per request', async () => {
  assert.throws(() => resolveConfig({ upstream: 'http://127.0.0.1:1', policy: { preset: 'nope' } }), GatewayConfigError);
  const gateway = createGateway(resolveConfig({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1', policy: { preset: 'gdpr' } }));
  const { port } = await gateway.listen();
  try {
    const call = (options) => fetch(`http://127.0.0.1:${port}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'IP 203.0.113.7', options }),
    });
    assert.equal((await (await call({})).json()).output, 'IP ***.***.***.***');
    const bad = await call({ preset: 'nope' });
    assert.equal(bad.status, 400);
    assert.equal((await bad.json()).code, 'ERR_BAD_OPTIONS');
  } finally {
    await gateway.close();
  }
});
