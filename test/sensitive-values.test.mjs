// A value under a sensitive key is masked whatever its type (spec section 9):
// numbers, binary data, and every string or number inside an object, array,
// Map or Set at any depth. Booleans and null are kept.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactAsync, scan, createVault, compilePolicy } from '../dist/index.js';
import { sentryRedact } from '../dist/sentry.js';
import { redactBody } from '../dist/gateway/index.js';

test('numbers under a sensitive key are masked, other numbers are kept', () => {
  assert.deepEqual(
    redact({ cardNumber: '4242424242424242', cvv: 123, pin: 1234, otp: 482913n, amount: 1000 }),
    { cardNumber: '***', cvv: '***', pin: '***', otp: '***', amount: 1000 },
  );
});

test('objects and arrays under a sensitive key are masked at every depth', () => {
  assert.deepEqual(redact({ cookie: { name: 'connect.sid', value: 's%3A_SID_abc' } }), { cookie: { name: '***', value: '***' } });
  assert.deepEqual(
    redact({ Authorization: { scheme: 'Bearer', value: 'EAAG_oauth2_token' } }),
    { Authorization: { scheme: '***', value: '***' } },
  );
  assert.deepEqual(
    redact({ password: { algorithm: 'argon2id', hash: '$argon2id$v=19$abc', params: { cost: 12, salt: 'c2FsdA' }, legacy: false } }),
    { password: { algorithm: '***', hash: '***', params: { cost: '***', salt: '***' }, legacy: false } },
  );
  assert.deepEqual(redact({ password: ['hunter2', ['letmein', 7]] }), { password: ['***', ['***', '***']] });
});

test('booleans, null and look-alike keys stay as they are', () => {
  const input = { hasPassword: true, password: null, token: undefined, max_tokens: 4096, nextPageToken: 'CgkI2c3d' };
  assert.deepEqual(redact(input), input);
});

test('binary data under a sensitive key is masked as its hex text', () => {
  assert.deepEqual(redact({ privateKey: new Uint8Array([1, 2, 255]) }), { privateKey: '***' });
  assert.deepEqual(redact({ secret: Buffer.from('hunter2') }, { mode: 'label' }), { secret: '[REDACTED:sensitive_key]' });
  const hashed = redact({ secret: new Uint8Array([1, 2, 255]).buffer }, { mode: 'hash', transformSecret: 'k' });
  assert.equal(hashed.secret, redact({ secret: '0102ff' }, { mode: 'hash', transformSecret: 'k' }).secret);
  const bytes = new Uint8Array([9, 9]);
  assert.equal(redact({ data: bytes }).data, bytes, 'binary elsewhere is returned as is');
});

test('a number is replaced as its decimal text', () => {
  const opts = { mode: 'hash', transformSecret: 'k' };
  assert.equal(redact({ pin: 1234 }, opts).pin, redact({ pin: '1234' }, opts).pin);
  assert.deepEqual(redact({ pin: 1234 }, { allow: ['1234'] }), { pin: 1234 });
});

test('a shared object keeps its masked and unmasked copies apart', () => {
  const shared = { value: 'abc' };
  const out = redact({ a: shared, cookie: shared, b: shared });
  assert.deepEqual(out, { a: { value: 'abc' }, cookie: { value: '***' }, b: { value: 'abc' } });
  assert.equal(out.a, out.b);
  const first = redact({ cookie: shared, a: shared });
  assert.deepEqual(first, { cookie: { value: '***' }, a: { value: 'abc' } });
});

test('Map entries with a sensitive string key are masked', () => {
  const out = redact(new Map([['authorization', 'Bearer abc'], ['cookies', { sid: 'x1' }], ['host', 'example.com']]));
  assert.equal(out.get('authorization'), '***');
  assert.deepEqual(out.get('cookies'), { sid: '***' });
  assert.equal(out.get('host'), 'example.com');
});

test('errors, URLs and Sets inside a sensitive value are masked', () => {
  const out = redact({ credentials: { error: new Error('bad hunter2'), url: new URL('https://x.test/a'), tags: new Set(['a', 1]) } });
  assert.equal(out.credentials.error.message, '***');
  assert.equal(out.credentials.url, '***');
  assert.deepEqual([...out.credentials.tags], ['***']);
});

test('redactAsync and compiled policies agree with redact', async () => {
  const input = { cvv: 123, cookie: { value: 'abc', secure: true }, note: 'safe' };
  const expected = { cvv: '***', cookie: { value: '***', secure: true }, note: 'safe' };
  assert.deepEqual(await redactAsync(input), expected);
  assert.deepEqual(compilePolicy().redact(input), expected);
  assert.deepEqual(await compilePolicy().redactAsync(input), expected);
});

test('scan reports every value inside a sensitive value', async () => {
  const input = { cvv: 123, cookie: { name: 'sid', value: 'abc', secure: true }, ok: 1 };
  const expected = [['sensitive_key', 'cvv'], ['sensitive_key', 'cookie.name'], ['sensitive_key', 'cookie.value']];
  assert.deepEqual(scan(input).map((f) => [f.detector, f.path]), expected);
  assert.deepEqual((await compilePolicy().scanAsync(input)).map((f) => [f.detector, f.path]), expected);
  assert.equal(scan({ pin: 1234 }, { includeValues: true })[0].value, '1234');
});

test('a vault mints every value under a sensitive key and restores them', () => {
  const vault = createVault({ placeholderStyle: 'readable' });
  const out = vault.redact({ otp: 482913, cookie: { value: 'abc' } });
  assert.deepEqual(out, { otp: '[SENSITIVE_KEY_1]', cookie: { value: '[SENSITIVE_KEY_2]' } });
  assert.deepEqual(vault.restore(out), { otp: '482913', cookie: { value: 'abc' } });
});

test('a vault path rule mints numbers inside the matched object', () => {
  const vault = createVault({ placeholderStyle: 'readable', paths: ['card'] });
  const out = vault.redact({ card: { last4: 4242, brand: 'visa' } });
  assert.deepEqual(out, { card: { last4: '[SENSITIVE_PATH_1]', brand: '[SENSITIVE_PATH_2]' } });
});

test('Sentry typed attributes keep their type, which follows a masked number', () => {
  const span = sentryRedact().beforeSendSpan({
    span_id: 'a1b2c3d4e5f60718',
    attributes: {
      'user.pin': { value: 1234, type: 'integer' },
      'http.request.header.authorization': { value: 'Bearer abc', type: 'string' },
      'http.response.status_code': { value: 200, type: 'integer' },
    },
  });
  assert.deepEqual(span.attributes['user.pin'], { value: '***', type: 'string' });
  assert.deepEqual(span.attributes['http.request.header.authorization'], { value: '***', type: 'string' });
  assert.deepEqual(span.attributes['http.response.status_code'], { value: 200, type: 'integer' });
});

test('the gateway keeps tool and response schemas valid when it redacts a whole body', () => {
  const schema = { type: 'object', properties: { password: { type: 'string', minLength: 8 }, api_key: { type: 'string', description: 'Key from ops@corp.example' } } };
  const body = JSON.stringify({
    model: 'gpt-x',
    messages: [{ role: 'user', content: 'my password is hunter2' }],
    tools: [{ type: 'function', function: { name: 'login', parameters: schema } }],
    response_format: { type: 'json_schema', json_schema: { name: 'r', schema } },
    metadata: { session_id: 7 },
  });
  const out = JSON.parse(redactBody(body, { contentType: 'application/json', nonJson: false, redact: (v) => redact(v) }).body);
  const kept = out.tools[0].function.parameters;
  assert.deepEqual(kept.properties.password, { type: 'string', minLength: 8 });
  assert.equal(kept.properties.api_key.type, 'string');
  assert.doesNotMatch(kept.properties.api_key.description, /ops@corp\.example/, 'strings in a schema are still scanned');
  assert.deepEqual(out.response_format.json_schema.schema.properties.password, { type: 'string', minLength: 8 });
  assert.equal(out.metadata.session_id, '***');
});
