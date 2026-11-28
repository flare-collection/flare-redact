import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactAsync, scan, compilePolicy, createVault } from '../dist/index.js';

const input = () => ({
  users: [
    { name: 'Ada', role: 'admin', address: { city: 'London', zip: 'N1 9GU' } },
    { name: 'Grace', role: 'dev', address: { city: 'Arlington' } },
  ],
  req: { headers: { 'x-request-id': 'r1', 'x-tenant': 'acme' }, body: { order: { card: { last4: 4242 } } } },
});

test('paths: a plain path masks that value only', () => {
  const out = redact(input(), { paths: ['users[1].name'] });
  assert.equal(out.users[0].name, 'Ada');
  assert.equal(out.users[1].name, '***');
});

test('paths: * matches any one key or index, and objects are masked whole', () => {
  const out = redact(input(), { paths: ['users.*.address'] });
  assert.deepEqual(out.users.map((u) => u.address), ['***', '***']);
  assert.equal(out.users[0].role, 'admin');
});

test('paths: ** matches any depth, including none', () => {
  const out = redact(input(), { paths: ['**.last4', '**.city'] });
  assert.equal(out.req.body.order.card.last4, '***');
  assert.deepEqual(out.users.map((u) => u.address.city), ['***', '***']);
  assert.equal(out.users[0].address.zip, 'N1 9GU');
  assert.equal(redact({ city: 'Oslo' }, { paths: ['**.city'] }).city, '***');
});

test('paths: brackets take keys that are not identifiers', () => {
  const out = redact({ h: { 'x-tenant': 'acme', 'a.b': 'c', plain: 'p' } }, { paths: ['h["x-tenant"]', "h['a.b']"] });
  assert.deepEqual(out.h, { 'x-tenant': '***', 'a.b': '***', plain: 'p' });
});

test('paths: remove deletes properties and array elements', () => {
  const out = redact(input(), { paths: ['users.*.address', 'req.headers'], remove: true });
  assert.ok(!('address' in out.users[0]));
  assert.ok(!('headers' in out.req));
  assert.deepEqual(redact({ list: ['a', 'b', 'c'] }, { paths: ['list[1]'], remove: true }).list, ['a', 'c']);
});

test('paths: the input is never modified, frozen input included', () => {
  const original = input();
  const snapshot = JSON.stringify(original);
  redact(original, { paths: ['users.*.address'], remove: true });
  assert.equal(JSON.stringify(original), snapshot);
  const frozen = Object.freeze({ a: Object.freeze({ b: 'x' }) });
  assert.deepEqual(redact(frozen, { paths: ['a.b'] }), { a: { b: '***' } });
});

test('paths: the mask option and modes apply to path values', () => {
  assert.equal(redact({ a: 'x' }, { paths: ['a'], mask: '[hidden]' }).a, '[hidden]');
  assert.equal(redact({ a: 'x' }, { paths: ['a'], mode: 'label' }).a, '[REDACTED:sensitive_path]');
  assert.equal(redact({ a: 'x' }, { paths: ['a'], mask: ({ detector }) => `<${detector.id}>` }).a, '<sensitive_path>');
});

test('paths: a replaced value is not scanned again', () => {
  const out = redact({ contact: 'ada@example.com' }, { paths: ['contact'], mode: 'pseudonym', transformSecret: 'k' });
  const once = redact({ contact: 'ada@example.com' }, { paths: ['contact'], mode: 'pseudonym', transformSecret: 'k' });
  assert.equal(out.contact, once.contact);
  assert.notEqual(out.contact, 'ada@example.com');
});

test('paths: detectors and sensitive keys still apply elsewhere', () => {
  const out = redact({ a: 'x', password: 'hunter2', note: 'mail ada@example.com' }, { paths: ['a'] });
  assert.deepEqual(out, { a: '***', password: '***', note: 'mail a***@***' });
});

test('paths: cycles and missing paths are fine', () => {
  const cyclic = { a: { token2: 't' } };
  cyclic.a.self = cyclic;
  const out = redact(cyclic, { paths: ['**.token2', 'no.such.path'] });
  assert.equal(out.a.token2, '***');
});

test('paths: null and undefined stay as they are', () => {
  assert.deepEqual(redact({ a: null, b: 1 }, { paths: ['a', 'b'] }), { a: null, b: '***' });
});

test('paths: scan reports each matched value once, under the path scan uses', () => {
  const findings = scan(input(), { paths: ['users.*.address', '**.last4'] });
  const paths = findings.filter((f) => f.detector === 'sensitive_path').map((f) => f.path);
  assert.deepEqual(paths, ['users[0].address', 'users[1].address', 'req.body.order.card.last4']);
  assert.ok(findings.every((f) => !('value' in f)));
});

test('paths: redactAsync and compiled policies apply them too', async () => {
  const policy = compilePolicy({ paths: ['users.*.name'] });
  assert.deepEqual(policy.redact(input()).users.map((u) => u.name), ['***', '***']);
  assert.deepEqual((await redactAsync(input(), { paths: ['users.*.name'] })).users.map((u) => u.name), ['***', '***']);
  assert.equal(policy.isClean({ users: [{ name: 'Ada' }] }), false);
});

test('paths: a vault restores what a path rule replaced', () => {
  const vault = createVault({ paths: ['users.*.address'], placeholderStyle: 'readable' });
  const safe = vault.redact(input());
  assert.equal(safe.users[0].address.city, '[SENSITIVE_PATH_1]');
  assert.deepEqual(vault.restore(safe).users[0].address, { city: 'London', zip: 'N1 9GU' });
});

test('paths: invalid paths throw ERR_INVALID_PATH', () => {
  for (const bad of ['', 'a..b', '**', 'a.', 'a[', 'a[x]', 'a b', '.a']) {
    assert.throws(() => compilePolicy({ paths: [bad] }), { code: 'ERR_INVALID_PATH' }, bad);
  }
});
