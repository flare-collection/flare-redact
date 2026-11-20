// An error's cause and AggregateError's errors are non-enumerable, so a walk
// that only follows enumerable properties dropped the real reason for a
// failure: a failed fetch logged as "fetch failed" without its ECONNREFUSED.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact, redactAsync, scan, scanAsync } from '../dist/index.js';
import { AgentFlowBlockedError, createAgentFlow } from '../dist/agent.js';

const refused = () => Object.assign(new Error('connect ECONNREFUSED for bob@example.com'), { code: 'ECONNREFUSED' });

test('redact keeps an error cause, redacted and still non-enumerable', async () => {
  for (const run of [redact, redactAsync]) {
    const inner = refused();
    const error = new TypeError('fetch failed', { cause: inner });
    const out = await run(error);
    assert.ok(out instanceof TypeError);
    assert.equal(out.message, 'fetch failed');
    assert.equal(Object.getOwnPropertyDescriptor(out, 'cause').enumerable, false);
    assert.notEqual(out.cause, inner);
    assert.equal(out.cause.code, 'ECONNREFUSED');
    assert.doesNotMatch(out.cause.message, /bob@example\.com/);
    assert.match(out.cause.message, /^connect ECONNREFUSED for /);
    assert.equal(inner.message, 'connect ECONNREFUSED for bob@example.com', 'the input is not mutated');
  }
});

test('redact keeps a cause that is not an error and the errors of an AggregateError', async () => {
  for (const run of [redact, redactAsync]) {
    const plain = await run(new Error('failed', { cause: 'token for bob@example.com' }));
    assert.doesNotMatch(plain.cause, /bob@example\.com/);

    const aggregate = await run(new AggregateError([refused(), new Error('second')], 'all failed'));
    assert.ok(aggregate instanceof AggregateError);
    assert.equal(Object.getOwnPropertyDescriptor(aggregate, 'errors').enumerable, false);
    assert.equal(aggregate.errors.length, 2);
    assert.doesNotMatch(aggregate.errors[0].message, /bob@example\.com/);
    assert.equal(aggregate.errors[1].message, 'second');
  }
});

test('a cause chain that loops back terminates', () => {
  const first = new Error('first');
  const second = new Error('second', { cause: first });
  Object.defineProperty(first, 'cause', { value: second, enumerable: false, configurable: true, writable: true });
  const out = redact(first);
  assert.equal(out.cause.cause, out);
});

test('scan reports a secret inside an error cause', async () => {
  const error = new TypeError('fetch failed', { cause: refused() });
  for (const run of [scan, scanAsync]) {
    const findings = await run(error);
    assert.deepEqual(findings.map((finding) => finding.path), ['cause.message']);
  }
});

test('FlareFlow checks a placeholder inside an error cause before restoring it', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    sinks: { 'logs.write': { capabilities: [{ id: 'msg', sources: ['config'], paths: ['/message'] }] } },
  });
  const safe = flow.protectForModel('config', 'db-secret');
  assert.throws(
    () => flow.authorizeForSink('logs.write', new Error('failed', { cause: new Error(safe) })),
    AgentFlowBlockedError,
  );
});
