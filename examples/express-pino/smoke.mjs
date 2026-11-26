import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';
import { createApp } from './server.mjs';

const output = new PassThrough();
let logText = '';
output.on('data', (chunk) => { logText += chunk; });

const server = createApp(pino(pinoRedact(), output)).listen(0);
await new Promise((resolve) => server.once('listening', resolve));
const { port } = server.address();

try {
  const response = await fetch(`http://127.0.0.1:${port}/checkout?email=alice@example.com`, {
    method: 'POST',
    headers: {
      authorization: 'Bearer not-a-real-token',
      'content-type': 'application/json',
    },
    body: JSON.stringify({ email: 'alice@example.com', card: '4242 4242 4242 4242' }),
  });
  assert.deepEqual(await response.json(), { ok: true });
  await new Promise((resolve) => setImmediate(resolve));
  assert.doesNotMatch(logText, /alice@example\.com/);
  assert.doesNotMatch(logText, /not-a-real-token/);
  assert.match(logText, /a\*\*\*@\*\*\*/);
  console.log('Express + Pino request log contains no original email or bearer token.');
} finally {
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

// Direct calls. pino never hands the message to formatters.log, and it skips
// formatters.bindings for child loggers, so each of these needs its own hook.
const direct = new PassThrough();
let directText = '';
direct.on('data', (chunk) => { directText += chunk; });
const log = pino(pinoRedact(), direct);
const dsn = 'postgres://admin:s3cr3tPassw0rd@db.internal:5432/app';
log.info('literal alice@example.com');
log.info('dsn %s', dsn);
log.info('json %j', { dsn });
log.error(new Error(`db down: ${dsn}`));
log.child({ user: 'alice@example.com' }).info('child');
log.child({ requestId: 'r1' }).info({ n: 1 }, 'plain child');
await new Promise((resolve) => setImmediate(resolve));
const lines = directText.trim().split('\n');
assert.equal(lines.length, 6);
for (const line of lines) JSON.parse(line);
assert.doesNotMatch(directText, /alice@example\.com|s3cr3tPassw0rd/);
assert.match(directText, /"msg":"dsn postgres:\/\/admin:\*\*\*@db\.internal:5432\/app"/);
assert.match(directText, /"user":"a\*\*\*@\*\*\*"/);
console.log('Pino messages, printf arguments, errors and child bindings contain no original secret.');
