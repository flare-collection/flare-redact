// Recorded HTTP traffic (HAR files from devtools, Playwright and Polly.js) is
// committed to repositories and attached to support tickets; credentials in
// headers, cookies, URLs and bodies must not survive in it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  createRecordingRedactor,
  isCredentialName,
  pollyBeforePersist,
  redactHar,
} from '../dist/recording.js';

const TOKEN = 'ghp_' + 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8';
const SESSION = 'f3a9c1d2e8b7a6f5';
const cli = fileURLToPath(new URL('../bin/flare-redact.mjs', import.meta.url));

const har = () => ({
  log: {
    version: '1.2',
    creator: { name: 'test', version: '1' },
    entries: [{
      startedDateTime: '2026-11-23T10:00:00.000Z',
      time: 12,
      request: {
        method: 'POST',
        url: `https://api.example.com/v1/users?access_token=${SESSION}&page=2`,
        httpVersion: 'HTTP/1.1',
        headers: [
          { name: 'Authorization', value: `Bearer ${TOKEN}` },
          { name: 'X-Api-Key', value: 'k-7c1e0f2a9b' },
          { name: 'Cookie', value: `sid=${SESSION}` },
          { name: 'Accept', value: 'application/json' },
        ],
        cookies: [{ name: 'sid', value: SESSION }],
        queryString: [{ name: 'access_token', value: SESSION }, { name: 'page', value: '2' }],
        postData: {
          mimeType: 'application/json',
          text: JSON.stringify({ email: 'ada@example.com', password: 'hunter2hunter2', plan: 'pro' }),
        },
        headersSize: -1,
        bodySize: -1,
      },
      response: {
        status: 200,
        statusText: 'OK',
        httpVersion: 'HTTP/1.1',
        headers: [
          { name: 'Set-Cookie', value: `sid=${SESSION}; HttpOnly` },
          { name: 'Content-Type', value: 'application/json' },
          { name: 'Content-Length', value: '64' },
        ],
        cookies: [{ name: 'sid', value: SESSION, httpOnly: true }],
        content: {
          size: 64,
          mimeType: 'application/json',
          text: JSON.stringify({ id: 7, token: TOKEN, owner: 'ada@example.com' }),
        },
        redirectURL: '',
        headersSize: -1,
        bodySize: -1,
      },
      cache: {},
      timings: { send: 0, wait: 10, receive: 2 },
    }],
  },
});

const header = (message, name) => message.headers.find((h) => h.name.toLowerCase() === name.toLowerCase()).value;

test('credential names are recognised with or without an x- prefix', () => {
  for (const name of ['Authorization', 'X-Api-Key', 'Proxy-Authorization', 'Set-Cookie', 'Cookie',
    'access_token', 'X-Auth-Token', 'X-Amz-Security-Token', 'Private-Token', 'X-CSRF-Token']) {
    assert.ok(isCredentialName(name), name);
  }
  for (const name of ['Accept', 'Content-Type', 'User-Agent', 'page', 'X-Request-Id']) {
    assert.ok(!isCredentialName(name), name);
  }
});

test('redactHar masks headers, cookies, URLs and bodies and keeps everything else', () => {
  const input = har();
  const out = redactHar(input);
  const text = JSON.stringify(out);
  for (const secret of [TOKEN, SESSION, 'k-7c1e0f2a9b', 'hunter2hunter2', 'ada@example.com']) {
    assert.ok(!text.includes(secret), `leaked ${secret}`);
  }
  const { request, response } = out.log.entries[0];
  assert.equal(header(request, 'Accept'), 'application/json');
  assert.equal(header(request, 'X-Api-Key'), '***');
  assert.match(request.url, /^https:\/\/api\.example\.com\/v1\/users\?access_token=.+&page=2$/);
  assert.deepEqual(request.queryString[1], { name: 'page', value: '2' });
  assert.equal(JSON.parse(request.postData.text).plan, 'pro');
  assert.equal(response.cookies[0].httpOnly, true);
  assert.equal(JSON.parse(response.content.text).id, 7);
  assert.equal(header(response, 'Content-Length'), String(Buffer.byteLength(response.content.text)));
  assert.equal(response.content.size, Buffer.byteLength(response.content.text));
  assert.equal(out.log.entries[0].timings.wait, 10);
  assert.ok(JSON.stringify(input).includes(TOKEN), 'the input is not mutated');
});

test('a body that needs no change keeps its exact text', () => {
  const redactor = createRecordingRedactor();
  const pretty = '{\n  "ok": true\n}';
  assert.equal(redactor.body(pretty, 'application/json'), pretty);
  assert.equal(redactor.body('plain text', 'text/plain'), 'plain text');
});

test('form bodies and base64 text bodies are redacted by field', () => {
  const redactor = createRecordingRedactor();
  assert.equal(
    redactor.body('user=ada&password=hunter2hunter2', 'application/x-www-form-urlencoded'),
    'user=ada&password=***',
  );
  const entry = redactor.entry({
    response: {
      headers: [],
      content: {
        mimeType: 'application/json; charset=utf-8',
        encoding: 'base64',
        text: Buffer.from(JSON.stringify({ token: TOKEN })).toString('base64'),
      },
    },
  });
  assert.ok(!Buffer.from(entry.response.content.text, 'base64').toString().includes(TOKEN));
  const image = { mimeType: 'image/png', encoding: 'base64', text: 'iVBORw0KGgo=' };
  assert.equal(redactor.entry({ response: { content: image } }).response.content, image);
});

test('pollyBeforePersist redacts the recording Polly is about to write, in place', () => {
  const recording = har().log.entries[0];
  pollyBeforePersist()({}, recording);
  assert.ok(!JSON.stringify(recording).includes(TOKEN));
  assert.equal(header(recording.request, 'Accept'), 'application/json');
});

test('flare-redact --har cleans a HAR file from the command line', () => {
  const result = spawnSync(process.execPath, [cli, '--har'], { input: JSON.stringify(har()), encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.ok(!result.stdout.includes(TOKEN));
  assert.equal(JSON.parse(result.stdout).log.entries[0].response.status, 200);

  const bad = spawnSync(process.execPath, [cli, '--har'], { input: '{"not":"har"}', encoding: 'utf8' });
  assert.equal(bad.status, 2);
});
