// flare-redact/ai-sdk: the Vercel AI SDK middleware, driven by fake models with
// the AI SDK's prompt and stream shapes, so no network and no `ai` install.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { flareRedactMiddleware } from '../dist/ai-sdk.js';
import { createSession } from '../dist/session.js';

const EMAIL = 'alice@corp.com';
const CARD = '4242 4242 4242 4242';
const PH = /\[FR_[A-Z_]+_[0-9a-f]{24}\]/g;
// Distinct placeholders, in order of first appearance.
const placeholders = (value) => [...new Set([...JSON.stringify(value).matchAll(PH)].map((m) => m[0]))];

// What wrapLanguageModel does with one middleware: transform the params, then
// hand the wrap step closures that call the model with the transformed params.
function wrap(model, middleware) {
  return {
    async doGenerate(params) {
      const transformed = await middleware.transformParams({ type: 'generate', params, model });
      return middleware.wrapGenerate({
        doGenerate: async () => model.doGenerate(transformed),
        doStream: async () => model.doStream(transformed),
        params: transformed,
        model,
      });
    },
    async doStream(params) {
      const transformed = await middleware.transformParams({ type: 'stream', params, model });
      return middleware.wrapStream({
        doGenerate: async () => model.doGenerate(transformed),
        doStream: async () => model.doStream(transformed),
        params: transformed,
        model,
      });
    },
  };
}

const streamOf = (parts) => new ReadableStream({
  start(controller) {
    for (const part of parts) controller.enqueue(part);
    controller.close();
  },
});

async function collect(stream) {
  const parts = [];
  for await (const part of stream) parts.push(part);
  return parts;
}

const textOf = (parts, type = 'text-delta') => parts.filter((p) => p.type === type).map((p) => p.delta).join('');

test('the provider sees placeholders and the app gets the originals back', async () => {
  let seen;
  const model = {
    async doGenerate(params) {
      seen = params;
      const [email, card] = placeholders(params.prompt);
      return { content: [{ type: 'text', text: `Invoice for ${email}, card ${card}.` }], finishReason: 'stop', usage: {}, warnings: [] };
    },
  };
  const params = {
    prompt: [
      { role: 'system', content: `Support desk. Escalations go to ${EMAIL}.` },
      { role: 'user', content: [{ type: 'text', text: `Bill ${EMAIL}, card ${CARD}`, providerOptions: { anthropic: { cacheControl: { type: 'ephemeral' } } } }] },
    ],
    temperature: 0,
  };
  const result = await wrap(model, flareRedactMiddleware()).doGenerate(params);

  const sent = JSON.stringify(seen.prompt);
  assert.doesNotMatch(sent, /alice@corp\.com|4242 4242/);
  assert.equal(placeholders(seen.prompt).length, 2);
  assert.match(seen.prompt[0].content, /\[FR_EMAIL_/, 'the system prompt is redacted too');
  assert.deepEqual(seen.prompt[1].content[0].providerOptions, params.prompt[1].content[0].providerOptions);
  assert.equal(seen.temperature, 0);
  assert.equal(result.content[0].text, `Invoice for ${EMAIL}, card ${CARD}.`);
  assert.equal(params.prompt[1].content[0].text, `Bill ${EMAIL}, card ${CARD}`, "the caller's params are not written to");
});

test('tool calls and tool results are redacted, and tool inputs come back as valid JSON', async () => {
  const PASSWORD = 'pa"ss\\word';
  let seen;
  const model = {
    async doGenerate(params) {
      seen = params.prompt;
      const [email] = placeholders(params.prompt);
      const password = JSON.stringify(params.prompt).match(/\[FR_SENSITIVE_KEY_[0-9a-f]{24}\]/)[0];
      return {
        content: [
          { type: 'reasoning', text: `The user means ${email}.` },
          { type: 'tool-call', toolCallId: 'call_1', toolName: 'login', input: JSON.stringify({ user: email, password }) },
        ],
        finishReason: 'tool-calls',
        usage: {},
        warnings: [],
      };
    },
  };
  const prompt = [
    { role: 'user', content: [{ type: 'text', text: `Log in as ${EMAIL}` }] },
    { role: 'assistant', content: [{ type: 'tool-call', toolCallId: 'call_0', toolName: 'lookup', input: { user: EMAIL, password: PASSWORD } }] },
    {
      role: 'tool',
      content: [
        { type: 'tool-result', toolCallId: 'call_0', toolName: 'lookup', output: { type: 'json', value: { owner: EMAIL } } },
        { type: 'tool-result', toolCallId: 'call_0', toolName: 'lookup', output: { type: 'text', value: `owner ${EMAIL}` } },
        { type: 'tool-result', toolCallId: 'call_0', toolName: 'lookup', output: { type: 'content', value: [{ type: 'text', text: EMAIL }] } },
        { type: 'tool-result', toolCallId: 'call_0', toolName: 'lookup', output: { type: 'execution-denied', reason: `not for ${EMAIL}` } },
      ],
    },
  ];
  const result = await wrap(model, flareRedactMiddleware()).doGenerate({ prompt });

  const sent = JSON.stringify(seen);
  assert.doesNotMatch(sent, /alice@corp\.com/);
  assert.ok(!sent.includes('pa\\"ss'), 'a value under a secret-named key is redacted');
  assert.equal(seen[1].content[0].toolCallId, 'call_0');
  assert.equal(seen[1].content[0].toolName, 'lookup');
  assert.equal(seen[2].content[0].output.type, 'json');

  assert.equal(result.content[0].text, `The user means ${EMAIL}.`);
  const call = result.content[1];
  assert.equal(call.toolCallId, 'call_1');
  assert.deepEqual(JSON.parse(call.input), { user: EMAIL, password: PASSWORD }, 'quotes and backslashes are escaped inside JSON');
});

test('a placeholder split across stream chunks is rebuilt before it is passed on', async () => {
  const model = {
    async doStream(params) {
      const [email] = placeholders(params.prompt);
      const cut = 7;
      const input = JSON.stringify({ to: email });
      const at = input.indexOf(email) + 5;
      return {
        stream: streamOf([
          { type: 'stream-start', warnings: [] },
          { type: 'text-start', id: 't1' },
          { type: 'text-delta', id: 't1', delta: `Mailing ${email.slice(0, cut)}` },
          { type: 'text-delta', id: 't1', delta: email.slice(cut, cut + 9) },
          { type: 'text-delta', id: 't1', delta: `${email.slice(cut + 9)} now` },
          { type: 'text-end', id: 't1' },
          { type: 'tool-input-start', id: 'c1', toolName: 'send' },
          { type: 'tool-input-delta', id: 'c1', delta: input.slice(0, at) },
          { type: 'tool-input-delta', id: 'c1', delta: input.slice(at) },
          { type: 'tool-input-end', id: 'c1' },
          { type: 'tool-call', toolCallId: 'c1', toolName: 'send', input },
          { type: 'toString', id: 't1', delta: email.slice(0, 3) },
          { type: 'text-start', id: 't2' },
          { type: 'text-delta', id: 't2', delta: `Done: ${email.slice(0, 10)}` },
          { type: 'finish', finishReason: 'stop', usage: {} },
        ]),
        request: { body: 'kept' },
      };
    },
  };
  const result = await wrap(model, flareRedactMiddleware()).doStream({
    prompt: [{ role: 'user', content: [{ type: 'text', text: `Send it to ${EMAIL}` }] }],
  });
  assert.equal(result.request.body, 'kept');
  const parts = await collect(result.stream);

  assert.equal(textOf(parts.filter((p) => p.id === 't1')), `Mailing ${EMAIL} now`);
  assert.equal(textOf(parts.filter((p) => p.id === 'c1'), 'tool-input-delta'), JSON.stringify({ to: EMAIL }));
  assert.equal(parts.find((p) => p.type === 'tool-call').input, JSON.stringify({ to: EMAIL }));
  assert.equal(textOf(parts.filter((p) => p.id === 't2')), 'Done: [FR_EMAIL_', 'a held-back partial placeholder is released at finish, not lost');
  const t1End = parts.findIndex((p) => p.type === 'text-end' && p.id === 't1');
  assert.ok(parts.slice(t1End + 1).every((p) => p.type !== 'text-delta' || p.id !== 't1'), 'every t1 delta comes before text-end');
  assert.deepEqual(parts.find((p) => p.type === 'toString'), { type: 'toString', id: 't1', delta: '[FR' }, 'unknown part types pass through');
  assert.equal(parts.at(-1).type, 'finish');
  assert.ok(parts.every((p) => !JSON.stringify(p).includes('[FR_EMAIL_') || p.id === 't2'), 'no complete placeholder reaches the app');
});

test('files and images pass through untouched', async () => {
  let seen;
  const file = { type: 'file', mediaType: 'application/pdf', filename: 'statement.pdf', data: 'JVBERi0xLjQK' };
  const model = { async doGenerate(params) { seen = params.prompt; return { content: [], finishReason: 'stop', usage: {}, warnings: [] }; } };
  await wrap(model, flareRedactMiddleware()).doGenerate({
    prompt: [{ role: 'user', content: [{ type: 'text', text: `From ${EMAIL}` }, file] }],
  });
  assert.equal(seen[0].content[1], file);
  assert.doesNotMatch(seen[0].content[0].text, /alice/);
});

test('nothing sensitive: the prompt and the result are left as they are', async () => {
  const prompt = [{ role: 'user', content: [{ type: 'text', text: 'What is the capital of France? Port 8080, build 2026.11.' }] }];
  const reply = { content: [{ type: 'text', text: 'Paris.' }], finishReason: 'stop', usage: {}, warnings: [] };
  let seen;
  const model = { async doGenerate(params) { seen = params.prompt; return reply; } };
  const result = await wrap(model, flareRedactMiddleware()).doGenerate({ prompt });
  assert.deepEqual(seen, prompt);
  assert.equal(result, reply);
});

test('JSON output gets escaped originals, in the text and in structuredOutputText', async () => {
  const TERM = 'Project "Falcon"';
  const model = {
    async doGenerate(params) {
      const [term] = placeholders(params.prompt);
      const json = JSON.stringify({ codename: term });
      return { content: [{ type: 'text', text: json }], structuredOutputText: json, finishReason: 'stop', usage: {}, warnings: [] };
    },
  };
  const result = await wrap(model, flareRedactMiddleware({ terms: [TERM] })).doGenerate({
    prompt: [{ role: 'user', content: [{ type: 'text', text: `Summarise ${TERM}` }] }],
    responseFormat: { type: 'json' },
  });
  assert.deepEqual(JSON.parse(result.content[0].text), { codename: TERM });
  assert.deepEqual(JSON.parse(result.structuredOutputText), { codename: TERM });
});

test('reasoning and text-encoded tool input get the original verbatim, even with JSON output', async () => {
  const TERM = 'Project "Falcon"';
  const model = {
    async doStream(params) {
      const [term] = placeholders(params.prompt);
      return {
        stream: streamOf([
          { type: 'reasoning-start', id: 'r' },
          { type: 'reasoning-delta', id: 'r', delta: `about ${term.slice(0, 12)}` },
          { type: 'reasoning-delta', id: 'r', delta: term.slice(12) },
          { type: 'reasoning-end', id: 'r' },
          { type: 'tool-input-start', id: 'x', toolName: 'shell', inputEncoding: 'text' },
          { type: 'tool-input-delta', id: 'x', delta: `echo ${term}` },
          { type: 'tool-input-end', id: 'x' },
          { type: 'tool-call', toolCallId: 'x', toolName: 'shell', input: `echo ${term}` },
          { type: 'text-start', id: 't' },
          { type: 'text-delta', id: 't', delta: JSON.stringify({ codename: term }) },
          { type: 'text-end', id: 't' },
        ]),
      };
    },
  };
  const result = await wrap(model, flareRedactMiddleware({ terms: [TERM] })).doStream({
    prompt: [{ role: 'user', content: [{ type: 'text', text: `Summarise ${TERM}` }] }],
    responseFormat: { type: 'json' },
  });
  const parts = await collect(result.stream);
  assert.equal(textOf(parts, 'reasoning-delta'), `about ${TERM}`);
  assert.equal(textOf(parts, 'tool-input-delta'), `echo ${TERM}`);
  assert.equal(parts.find((p) => p.type === 'tool-call').input, `echo ${TERM}`);
  assert.deepEqual(JSON.parse(textOf(parts)), { codename: TERM });
});

test('a session keeps the same placeholder across calls', async () => {
  const seen = [];
  const model = { async doGenerate(params) { seen.push(placeholders(params.prompt)[0]); return { content: [], finishReason: 'stop', usage: {}, warnings: [] }; } };
  const session = createSession();
  const wrapped = wrap(model, flareRedactMiddleware({ session }));
  const ask = () => wrapped.doGenerate({ prompt: [{ role: 'user', content: [{ type: 'text', text: `I am ${EMAIL}` }] }] });
  await ask();
  await ask();
  assert.equal(seen[0], seen[1]);
  assert.equal(session.size, 1);

  const fresh = wrap(model, flareRedactMiddleware());
  await fresh.doGenerate({ prompt: [{ role: 'user', content: [{ type: 'text', text: `I am ${EMAIL}` }] }] });
  assert.notEqual(seen[2], seen[0], 'without a session each call gets its own vault');
});

test('options take effect, and a bad preset fails at setup', async () => {
  let seen;
  const model = { async doGenerate(params) { seen = JSON.stringify(params.prompt); return { content: [], finishReason: 'stop', usage: {}, warnings: [] }; } };
  const prompt = [{ role: 'user', content: [{ type: 'text', text: `Call +1 415 555 0134 or mail ${EMAIL}` }] }];
  await wrap(model, flareRedactMiddleware()).doGenerate({ prompt });
  assert.match(seen, /\+1 415 555 0134/, 'phone numbers are opt-in');
  await wrap(model, flareRedactMiddleware({ preset: 'logs' })).doGenerate({ prompt });
  assert.doesNotMatch(seen, /415 555/);
  assert.throws(() => flareRedactMiddleware({ preset: 'everything' }), /preset/i);
});

test('the wrap step refuses to call the model if the prompt was not redacted', async () => {
  let called = false;
  const { wrapGenerate, wrapStream } = flareRedactMiddleware();
  const params = { prompt: [{ role: 'user', content: [{ type: 'text', text: EMAIL }] }] };
  await assert.rejects(wrapGenerate({ doGenerate: async () => { called = true; }, params }), /not redacted/);
  await assert.rejects(wrapStream({ doStream: async () => { called = true; }, params }), /not redacted/);
  assert.equal(called, false);
});

test('the middleware declares the versions the AI SDK 5, 6 and 7 look for', () => {
  const middleware = flareRedactMiddleware();
  assert.equal(middleware.specificationVersion, 'v3');
  assert.equal(middleware.middlewareVersion, 'v2');
  for (const hook of ['transformParams', 'wrapGenerate', 'wrapStream']) assert.equal(typeof middleware[hook], 'function');
});
