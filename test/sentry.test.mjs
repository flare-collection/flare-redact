// flare-redact/sentry: redact events before Sentry sends them, keep Sentry's own ids.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sentryRedact, redactSentryEvent } from '../dist/sentry.js';

const ids = {
  event_id: 'c3a1f2e4b5d6478f9a0b1c2d3e4f5a6b',
  trace_id: '4bf92f3577b34da6a3ce929d0e0e4736',
  release: 'f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4',
  debug_id: 'a5b2c3d4-e5f6-4789-a012-b3c4d5e6f7a8',
};

// Built at runtime so the source never holds a whole key (push protection reads it).
const stripeKey = 'sk_live_' + '4eC39HqLyjWDarjtT1zdp7dc';

const event = () => ({
  event_id: ids.event_id,
  timestamp: 1763100000.123,
  platform: 'node',
  level: 'error',
  release: ids.release,
  sdk: { name: 'sentry.javascript.node', version: '9.40.0' },
  message: 'Payment failed for alice@corp.com with card 4242 4242 4242 4242',
  exception: { values: [{
    type: 'Error',
    value: 'Invalid token ghp_' + 'a'.repeat(36),
    stacktrace: { frames: [{
      filename: '/srv/app/billing.js',
      function: 'charge',
      lineno: 42,
      context_line: `const key = "${stripeKey}";`,
      vars: { apiKey: stripeKey, amount: 4200 },
    }] },
  }] },
  contexts: { trace: { trace_id: ids.trace_id, span_id: '00f067aa0ba902b7' } },
  request: {
    url: 'https://api.corp.com/users/42?token=abc123secretvalue',
    headers: { Cookie: 'sid=s3cr3t', 'Set-Cookie': 'sid=s3cr3t; HttpOnly', 'User-Agent': 'curl/8.4' },
    cookies: { session: 's3cr3tSessionValue123', theme: 'dark' },
    data: { password: 'hunter2', email: 'bob@corp.com' },
  },
  user: { id: '42', email: 'alice@corp.com', ip_address: '203.0.113.7' },
  debug_meta: { images: [{ type: 'sourcemap', debug_id: ids.debug_id }] },
});

test('an error event loses its secrets and personal data', () => {
  const out = sentryRedact().beforeSend(event());
  const text = JSON.stringify(out);
  for (const leaked of ['alice@corp.com', 'bob@corp.com', '4242 4242 4242 4242', 'a'.repeat(36), '4eC39HqLyjWDarjtT1zdp7dc', 'hunter2', 'abc123secretvalue']) {
    assert.ok(!text.includes(leaked), `${leaked} leaked`);
  }
  assert.equal(out.exception.values[0].stacktrace.frames[0].vars.amount, 4200);
  assert.equal(out.request.headers['User-Agent'], 'curl/8.4');
});

test('cookies are masked whole, in the cookie map and in the headers', () => {
  const out = sentryRedact().beforeSend(event());
  assert.ok(!JSON.stringify(out).includes('s3cr3t'));
  assert.notEqual(out.request.cookies.theme, 'dark');
  assert.deepEqual(Object.keys(out.request.cookies), ['session', 'theme']);
  const raw = sentryRedact().beforeSend({ request: { cookies: 'sid=s3cr3t; theme=dark' } });
  assert.ok(!raw.request.cookies.includes('s3cr3t'));
});

test("Sentry's own ids survive even the strict preset", () => {
  const out = sentryRedact({ preset: 'strict' }).beforeSend(event());
  assert.equal(out.event_id, ids.event_id);
  assert.equal(out.release, ids.release);
  assert.equal(out.contexts.trace.trace_id, ids.trace_id);
  assert.equal(out.debug_meta.images[0].debug_id, ids.debug_id);
  assert.equal(out.timestamp, 1763100000.123);
  assert.deepEqual(out.sdk, { name: 'sentry.javascript.node', version: '9.40.0' });
  assert.ok(!JSON.stringify(out).includes('alice@corp.com'));
});

test('a field is Sentry\'s own by position, never by name alone', () => {
  const token = 'ghp_' + 'c'.repeat(36);
  const out = sentryRedact().beforeSend({
    event_id: ids.event_id,
    extra: { sid: `session ${token}`, release: 'alice@corp.com', environment: 'bob@corp.com', event_id: 'carol@corp.com' },
    request: { data: { level: '4242 4242 4242 4242', timestamp: 'dave@corp.com' } },
    contexts: { app: { trace_id: 'erin@corp.com' } },
    tags: { type: 'frank@corp.com' },
    breadcrumbs: [{ category: 'auth', message: 'login grace@corp.com', data: { span_id: 'heidi@corp.com' } }],
  });
  const text = JSON.stringify(out);
  assert.equal(out.event_id, ids.event_id);
  assert.equal(out.breadcrumbs[0].category, 'auth');
  assert.ok(!text.includes(token), 'a token under extra.sid is masked');
  assert.ok(!text.includes('4242 4242 4242 4242'), 'a card under request.data.level is masked');
  assert.doesNotMatch(text, /(alice|bob|carol|dave|erin|frank|grace|heidi)@corp\.com/);
});

test('stack frames keep their file and function, lose their variables', () => {
  const frame = {
    filename: 'app:///_next/static/chunks/main-3f2a1b9c8d7e6f5a.js',
    abs_path: '/srv/app/dist/main.3f2a1b9c8d7e6f5a4b3c.js',
    function: 'Object.handleRequest',
    module: 'app.billing',
    lineno: 1,
    colno: 4821,
    context_line: `const key = "${stripeKey}";`,
    vars: { filename: 'alice@corp.com', token: 'ghp_' + 'd'.repeat(36) },
  };
  const out = sentryRedact({ preset: 'strict' }).beforeSend({
    exception: { values: [{ type: 'TypeError', value: 'bad card 4242 4242 4242 4242', mechanism: { type: 'generic', handled: false }, stacktrace: { frames: [frame] } }] },
    threads: { values: [{ id: 1, crashed: true, stacktrace: { frames: [frame] } }] },
  });
  for (const got of [out.exception.values[0].stacktrace.frames[0], out.threads.values[0].stacktrace.frames[0]]) {
    for (const key of ['filename', 'abs_path', 'function', 'module', 'lineno', 'colno']) assert.equal(got[key], frame[key], key);
    assert.ok(!got.context_line.includes('4eC39HqLyjWDarjtT1zdp7dc'));
    assert.notEqual(got.vars.filename, 'alice@corp.com', 'a variable called filename is still user data');
    assert.ok(!got.vars.token.includes('d'.repeat(36)));
  }
  assert.equal(out.exception.values[0].type, 'TypeError');
  assert.deepEqual(out.exception.values[0].mechanism, { type: 'generic', handled: false });
  assert.ok(!out.exception.values[0].value.includes('4242 4242 4242 4242'));
});

test('Sentry 11 streamed spans and logs keep their own attributes under strict', () => {
  const hooks = sentryRedact({ preset: 'strict' });
  const typed = (value) => ({ value, type: 'string' });
  const span = hooks.beforeSendSpan({
    name: "SELECT * FROM users WHERE email = 'carol@corp.com'",
    span_id: 'a75d70ac1361845a',
    trace_id: ids.trace_id,
    start_timestamp: 1794646809.66,
    end_timestamp: 1794646809.67,
    is_segment: true,
    status: 'ok',
    attributes: {
      'sentry.release': typed(ids.release),
      'sentry.segment.id': typed('a75d70ac1361845a'),
      'sentry.sdk.version': typed('11.12.0'),
      'sentry.op': typed('db.query'),
      'sentry.segment.name': typed("SELECT * FROM users WHERE email = 'carol@corp.com'"),
      'user.email': typed('alice@corp.com'),
      'app.session': typed(ids.release),
    },
  });
  assert.equal(span.trace_id, ids.trace_id);
  assert.equal(span.end_timestamp, 1794646809.67);
  assert.equal(span.attributes['sentry.release'].value, ids.release);
  assert.equal(span.attributes['sentry.op'].value, 'db.query');
  assert.notEqual(span.attributes['app.session'].value, ids.release, 'the same value under an app attribute is masked');
  assert.doesNotMatch(JSON.stringify(span), /carol@corp\.com|alice@corp\.com/);

  const log = hooks.beforeSendLog({
    level: 'info',
    message: 'login by erin@corp.com',
    severityNumber: 9,
    attributes: { 'sentry.release': ids.release, 'sentry.message.template': 'login by %s', 'sentry.message.parameter.0': 'erin@corp.com', token: 'ghp_' + 'e'.repeat(36) },
  });
  assert.equal(log.level, 'info');
  assert.equal(log.attributes['sentry.release'], ids.release);
  assert.doesNotMatch(JSON.stringify(log), /erin@corp\.com|e{36}/);
});

test('traceLifecycle stream leaves out the hook Sentry 11 ignores', () => {
  const streamed = sentryRedact({}, { traceLifecycle: 'stream' });
  assert.deepEqual(Object.keys(streamed).sort(), ['beforeBreadcrumb', 'beforeSend', 'beforeSendLog', 'beforeSendSpan']);
  assert.equal(Object.keys(sentryRedact({}, { traceLifecycle: 'static' })).length, 5);
});

test('the caller event is never mutated', () => {
  const input = event();
  const before = JSON.stringify(input);
  sentryRedact({ preset: 'gdpr' }).beforeSend(input);
  assert.equal(JSON.stringify(input), before);
});

test('presets reach Sentry data: gdpr masks the user IP', () => {
  assert.equal(sentryRedact().beforeSend(event()).user.ip_address, '203.0.113.7');
  assert.notEqual(sentryRedact({ preset: 'gdpr' }).beforeSend(event()).user.ip_address, '203.0.113.7');
});

test('breadcrumbs, transactions, spans and logs use the same rules', () => {
  const hooks = sentryRedact();
  assert.deepEqual(Object.keys(hooks).sort(), ['beforeBreadcrumb', 'beforeSend', 'beforeSendLog', 'beforeSendSpan', 'beforeSendTransaction']);
  const crumb = hooks.beforeBreadcrumb({ category: 'http', data: { url: 'https://x.test/login?api_key=AKIAIOSFODNN7EXAMPLE' } });
  assert.ok(!crumb.data.url.includes('AKIAIOSFODNN7EXAMPLE'));
  const span = hooks.beforeSendSpan({ span_id: 'a1b2c3d4e5f60718', description: "SELECT * FROM users WHERE email = 'alice@corp.com'" });
  assert.equal(span.span_id, 'a1b2c3d4e5f60718');
  assert.ok(!span.description.includes('alice@corp.com'));
  const transaction = hooks.beforeSendTransaction({ type: 'transaction', spans: [span], transaction: 'GET /users' });
  assert.equal(transaction.transaction, 'GET /users');
  const log = hooks.beforeSendLog({ level: 'info', message: 'login by alice@corp.com', attributes: { token: 'ghp_' + 'b'.repeat(36) } });
  assert.ok(!JSON.stringify(log).includes('alice@corp.com'));
  assert.ok(!JSON.stringify(log).includes('b'.repeat(36)));
  assert.equal(redactSentryEvent('plain alice@corp.com').includes('alice@corp.com'), false);
});
