import assert from 'node:assert/strict';
import { createRedactionMiddleware } from 'flare-redact/middleware';
import { createScopedToolBoundary } from 'flare-redact/tool';

const events = [];
const middleware = createRedactionMiddleware({
  policy: {
    enable: ['high_entropy'],
    refineConfidence: true,
    minConfidence: 0.65,
  },
  onFindings: (event) => events.push(event),
});

const analytics = {
  async track(event, payload) {
    return { accepted: true, event, payload };
  },
};

// Works with any SDK method, route handler, queue consumer, or RPC function.
analytics.track = middleware.wrap(analytics.track, {
  name: 'analytics.track',
});

const receipt = await analytics.track('checkout', {
  email: 'alice@example.com',
  authorization: 'Bearer private-token-value',
});

assert.doesNotMatch(JSON.stringify(receipt), /alice@example|private-token-value/);
assert.ok(events.length > 0);
assert.ok(events.every((event) =>
  event.findings.every((finding) => !('value' in finding))));

// Tool-scoped vaults stop a model from moving one tool's placeholder into
// another tool's arguments to recover the original secret.
const tools = createScopedToolBoundary();
const safeDatabaseResult = tools.redactForModel(
  'database',
  'postgres://admin:s3cretpw@db/prod',
);
const placeholder = safeDatabaseResult.match(/\[FR_[^\]]+\]/)?.[0];
assert.ok(placeholder);
assert.equal(tools.restoreForTool('http_fetch', placeholder), placeholder);
assert.equal(
  tools.restoreForTool('database', safeDatabaseResult),
  'postgres://admin:s3cretpw@db/prod',
);

console.log(JSON.stringify({ receipt, findingEvents: events.length, scoped: true }, null, 2));
