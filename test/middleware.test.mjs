import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createRedactionMiddleware,
  RedactionBlockedError,
} from '../dist/middleware.js';

test('middleware redacts arbitrary structured values with one compiled policy', () => {
  const middleware = createRedactionMiddleware();
  const input = {
    user: 'alice@corp.com',
    nested: { authorization: 'Bearer top-secret-token' },
  };

  const safe = middleware.process(input, { name: 'analytics.track' });
  assert.notEqual(safe, input);
  assert.doesNotMatch(JSON.stringify(safe), /alice@corp|top-secret-token/);
  assert.equal(input.user, 'alice@corp.com');
});

test('observe mode reports value-free findings without changing the payload', () => {
  const events = [];
  const middleware = createRedactionMiddleware({
    action: 'observe',
    policy: { includeValues: true },
    onFindings: (event) => events.push(event),
  });
  const input = { email: 'alice@corp.com' };

  assert.equal(middleware.process(input, { name: 'queue.publish' }), input);
  assert.equal(events.length, 1);
  assert.equal(events[0].name, 'queue.publish');
  assert.equal(events[0].action, 'observe');
  assert.equal(events[0].phase, 'value');
  assert.ok(Object.isFrozen(events[0]));
  assert.ok(Object.isFrozen(events[0].findings));
  assert.ok(events[0].findings.length > 0);
  assert.ok(events[0].findings.every((finding) => !('value' in finding)));
});

test('block mode fails closed with a stable safe error', () => {
  const middleware = createRedactionMiddleware({ action: 'block' });

  assert.throws(
    () => middleware.process({ password: 'hunter2' }, { name: 'webhook.egress' }),
    (error) => {
      assert.ok(error instanceof RedactionBlockedError);
      assert.equal(error.code, 'ERR_REDACTION_BLOCKED');
      assert.equal(error.context.name, 'webhook.egress');
      assert.ok(error.findings.length > 0);
      assert.ok(error.findings.every((finding) => !('value' in finding)));
      assert.doesNotMatch(error.message, /hunter2/);
      return true;
    },
  );
});

test('wrap preserves method this and redacts arguments by default', () => {
  const middleware = createRedactionMiddleware();
  const client = {
    prefix: 'sent',
    send(payload) {
      return `${this.prefix}:${payload.email}`;
    },
  };
  client.send = middleware.wrap(client.send, { name: 'client.send' });

  const output = client.send({ email: 'alice@corp.com' });
  assert.match(output, /^sent:/);
  assert.doesNotMatch(output, /alice@corp/);
});

test('wrap optionally redacts synchronous and promised outputs', async () => {
  const middleware = createRedactionMiddleware();
  const sync = middleware.wrap(
    () => ({ apiKey: 'plain-secret' }),
    { input: false, output: true, name: 'sync.result' },
  );
  const asyncHandler = middleware.wrap(
    async () => ({ email: 'alice@corp.com' }),
    { input: false, output: true, name: 'async.result' },
  );

  assert.equal(sync().apiKey, '***');
  assert.doesNotMatch((await asyncHandler()).email, /alice@corp/);
});

test('wrap can redact selected payload arguments without touching framework objects', () => {
  const middleware = createRedactionMiddleware();
  const request = Object.freeze({ kind: 'framework-request' });
  const callback = () => 'done';
  const handler = middleware.wrap(
    (req, payload, done) => ({ req, payload, done }),
    { input: [1], name: 'queue.publish' },
  );

  const result = handler(request, { email: 'alice@corp.com' }, callback);
  assert.equal(result.req, request);
  assert.equal(result.done, callback);
  assert.doesNotMatch(result.payload.email, /alice@corp/);
  assert.throws(
    () => middleware.wrap(() => {}, { input: [-1] }),
    /non-negative integers/,
  );
});

test('wrapAsync supports asynchronous local semantic providers', async () => {
  const middleware = createRedactionMiddleware({
    policy: {
      semanticProvider: {
        async detect(text) {
          const start = text.indexOf('Alice Example');
          return start < 0 ? [] : [{
            detector: 'local_person',
            label: 'Person',
            why: 'Local test model.',
            start,
            end: start + 'Alice Example'.length,
            confidence: 0.99,
            risk: 'high',
          }];
        },
      },
    },
  });
  const handler = middleware.wrapAsync(async (payload) => payload, {
    name: 'worker.consume',
  });

  const result = await handler({ text: 'Customer Alice Example requested support.' });
  assert.doesNotMatch(result.text, /Alice Example/);
});

test('inspect APIs never return raw values', async () => {
  const middleware = createRedactionMiddleware({ policy: { includeValues: true } });
  const sync = middleware.inspect('alice@corp.com');
  const asyncFindings = await middleware.inspectAsync('bob@corp.com');

  assert.ok(sync.length > 0 && asyncFindings.length > 0);
  assert.ok([...sync, ...asyncFindings].every((finding) => !('value' in finding)));
});

test('middleware validates actions and handlers', () => {
  assert.throws(
    () => createRedactionMiddleware({ action: 'invalid' }),
    /action must be redact, observe, or block/,
  );
  const middleware = createRedactionMiddleware();
  assert.throws(() => middleware.wrap(null), /expects a function/);
  assert.throws(() => middleware.wrapAsync(null), /expects a function/);
});
