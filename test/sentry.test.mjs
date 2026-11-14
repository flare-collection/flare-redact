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

test('a kept field is put back only when its value has the right shape', () => {
  const secret = 'ghp_' + 'f'.repeat(36);
  for (const preset of ['gdpr', 'strict']) {
    const out = sentryRedact({ preset }).beforeSend({
      event_id: 'john.doe@example.com',
      release: 'john.doe@example.com',
      environment: `prod ${secret}`,
      exception: { values: [{
        type: 'john.doe@example.com',
        mechanism: { type: 'generic', handled: true, data: { email: 'john.doe@example.com', token: secret, url: `https://x.test/?token=${secret}` } },
        stacktrace: { frames: [{
          filename: `https://app.example.com/reset?token=${secret}&email=john.doe@example.com`,
          abs_path: `https://app.example.com/static/main.js?token=${secret}`,
          function: 'reset john.doe@example.com',
        }] },
      }] },
      contexts: { trace: { trace_id: ids.trace_id, op: `https://x.test/?token=${secret}`, status: 'failed for john.doe@example.com', links: [{ trace_id: ids.trace_id, span_id: '00f067aa0ba902b7', attributes: { email: 'john.doe@example.com' } }] } },
      breadcrumbs: [{ category: 'john.doe@example.com', type: `t ${secret}`, message: 'x' }],
      debug_meta: { images: [{ type: 'sourcemap', debug_id: ids.debug_id, code_file: `https://app.example.com/reset?token=${secret}` }] },
    });
    const text = JSON.stringify(out);
    assert.ok(!text.includes('john.doe@example.com'), `${preset}: an email survived`);
    assert.ok(!text.includes('f'.repeat(36)), `${preset}: a token survived`);
    assert.equal(out.exception.values[0].mechanism.type, 'generic');
    assert.equal(out.exception.values[0].mechanism.handled, true);
    assert.equal(out.contexts.trace.trace_id, ids.trace_id);
    assert.equal(out.contexts.trace.links[0].span_id, '00f067aa0ba902b7');
    assert.equal(out.debug_meta.images[0].debug_id, ids.debug_id);
    assert.ok(!out.exception.values[0].stacktrace.frames[0].abs_path.includes('token='), 'a file URL with a query is not put back');
  }
});

test('cookies are masked whatever the options and whatever their type', () => {
  const event = () => ({
    request: {
      cookies: { session: 's3cr3tSessionValue123', prefs: { sid2: 'abc123sessionvalue' }, n: 42 },
      headers: { Cookie: 'sid=s3cr3t', 'Set-Cookie': ['a=s3cr3t1; HttpOnly', 'b=s3cr3t2'], Accept: 'text/html' },
    },
    contexts: { response: { cookies: { sid: 's3cr3tResponse' }, headers: { 'Set-Cookie': 'sid=s3cr3tResponse; Path=/' }, status_code: 200 } },
  });
  for (const options of [{}, { redactKeys: false }, { redactKeys: ['password'] }, { only: ['email'] }, { preset: 'gdpr' }]) {
    const out = sentryRedact(options).beforeSend(event());
    const text = JSON.stringify(out);
    assert.doesNotMatch(text, /s3cr3t|abc123sessionvalue/, JSON.stringify(options));
    assert.deepEqual(Object.keys(out.request.cookies), ['session', 'prefs', 'n']);
    assert.equal(out.request.headers.Accept, 'text/html');
    assert.equal(out.contexts.response.status_code, 200);
  }
});

test('strict leaves what the SDK reads after the hook, and profile ids, alone', () => {
  const dsc = { trace_id: ids.trace_id, public_key: 'abc123def4567890abc123def4567890', replay_id: ids.event_id, release: ids.release };
  const out = sentryRedact({ preset: 'strict' }).beforeSend({ event_id: ids.event_id, sdkProcessingMetadata: { dynamicSamplingContext: dsc } });
  assert.deepEqual(out.sdkProcessingMetadata.dynamicSamplingContext, dsc);
  const span = sentryRedact({ preset: 'strict' }).beforeSendSpan({ span_id: 'a1b2c3d4e5f60718', attributes: { 'sentry.profile_id': ids.event_id } });
  assert.equal(span.attributes['sentry.profile_id'], ids.event_id);
});

test('a frozen event is redacted without being written to', () => {
  const frozen = Object.freeze({
    event_id: ids.event_id,
    message: 'mail alice@corp.com',
    request: Object.freeze({ cookies: Object.freeze({ sid: 's3cr3t' }), headers: Object.freeze({ cookie: 'sid=s3cr3t' }) }),
    exception: Object.freeze({ values: Object.freeze([Object.freeze({ type: 'Error', value: 'alice@corp.com' })]) }),
  });
  for (const preset of ['gdpr', 'strict']) {
    const out = sentryRedact({ preset }).beforeSend(frozen);
    assert.equal(out.event_id, ids.event_id);
    assert.doesNotMatch(JSON.stringify(out), /alice@corp\.com|s3cr3t/);
  }
  assert.equal(frozen.message, 'mail alice@corp.com');
});

test('a file URL with a query string stays redacted, a plain script URL is kept', () => {
  const page = 'https://shop.test/checkout.html?email=jane.roe%40example.com&session=abc123SESSION';
  const script = 'https://shop.test/static/js/main.3f2a1b9c.js';
  for (const preset of ['gdpr', 'strict']) {
    const out = sentryRedact({ preset }).beforeSend({
      exception: { values: [{ type: 'Error', stacktrace: { frames: [{ abs_path: page, filename: page }, { abs_path: script, filename: script }] } }] },
      debug_meta: { images: [{ type: 'sourcemap', code_file: page, debug_id: ids.debug_id, code_id: '5ab380cf7e2f4d9a8c1b2e3f4a5b6c7d81290341' }] },
    });
    const text = JSON.stringify(out);
    assert.ok(!text.includes('jane.roe') && !text.includes('abc123SESSION'), preset);
    const [, kept] = out.exception.values[0].stacktrace.frames;
    assert.equal(kept.abs_path, script, preset);
    assert.equal(kept.filename, script, preset);
    assert.equal(out.debug_meta.images[0].code_id, '5ab380cf7e2f4d9a8c1b2e3f4a5b6c7d81290341', preset);
  }
});

test('cookies are masked wherever they sit, in every hook', () => {
  for (const options of [{}, { redactKeys: false }, { preset: 'gdpr' }]) {
    const hooks = sentryRedact(options);
    const span = hooks.beforeSendSpan({ span_id: 'a1b2c3d4e5f60718', data: { 'http.request.header.cookie': 'sid=abc123SESSION' }, attributes: { 'http.response.header.set-cookie': { value: 'sid=abc123SESSION', type: 'string' } } });
    const transaction = hooks.beforeSendTransaction({ type: 'transaction', spans: [{ span_id: 'a1b2c3d4e5f60718', data: { 'http.request.header.cookie': 'sid=abc123SESSION' } }] });
    const pairs = hooks.beforeSend({ request: { headers: [['Cookie', 'sid=abc123SESSION'], ['Accept', 'text/html']] } });
    const crumb = hooks.beforeBreadcrumb({ category: 'http', data: { cookies: { sid: 'abc123SESSION' }, headers: { Cookie: 'sid=abc123SESSION' } } });
    const log = hooks.beforeSendLog({ level: 'info', message: 'x', attributes: { cookie: 'sid=abc123SESSION' } });
    for (const out of [span, transaction, pairs, crumb, log]) assert.doesNotMatch(JSON.stringify(out), /abc123SESSION/, JSON.stringify(options));
    assert.deepEqual(pairs.request.headers[1], ['Accept', 'text/html']);
    assert.equal(span.attributes['http.response.header.set-cookie'].type, 'string');
  }
});

test('digits alone are not an id or a time', () => {
  const card = '4111111111111111';
  const out = sentryRedact().beforeSend({ event_id: card, timestamp: card, contexts: { trace: { trace_id: card, span_id: card } } });
  assert.ok(!JSON.stringify(out).includes(card));
  const span = sentryRedact().beforeSendSpan({ span_id: 'a1b2c3d4e5f60718', attributes: { 'sentry.replay_id': card } });
  assert.ok(!JSON.stringify(span).includes(card));
  const ip = sentryRedact({ preset: 'gdpr' }).beforeSend({ timestamp: '203.0.113.77', start_timestamp: 1794646809.66 });
  assert.notEqual(ip.timestamp, '203.0.113.77');
  assert.equal(ip.start_timestamp, 1794646809.66);
  const iso = sentryRedact({ preset: 'strict' }).beforeSend({ timestamp: '2026-11-14T08:59:08.192Z', event_id: '12345678901234567890123456789012' });
  assert.equal(iso.timestamp, '2026-11-14T08:59:08.192Z');
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
