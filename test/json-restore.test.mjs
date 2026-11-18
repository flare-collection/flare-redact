// Restoring into JSON text: tool-call arguments, partial JSON and JSON-mode
// output must stay valid JSON with the same structure, whatever characters the
// restored value contains.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createVault, restore } from '../dist/index.js';
import { wrapOpenAI, wrapAnthropic } from '../dist/llm.js';
import { createScopedToolBoundary, createToolBoundary } from '../dist/tool.js';
import { createAgentFlow } from '../dist/agent.js';

// A quote, a backslash and control characters, and one that reads like JSON.
const AWKWARD = 'Q"uo\\te\nline\ttab\u0001end';
const FIELDS = 'x","extra":true,"note":"y';
// A URL whose credentials hold a quoted fragment: url_credentials, a default
// detector, captures it whole.
const URL_WITH_QUOTES = `https://user:pa${FIELDS}@example.com/pay`;
const PH = /\[FR_[A-Z_]+_[0-9a-f]{24}\]/g;
const placeholderIn = (value) => JSON.stringify(value).match(PH)?.[0];
const split = (text, at) => [text.slice(0, at), text.slice(at)];

test('restore escapes originals inside a string that is a JSON document', () => {
  const vault = createVault({ terms: [AWKWARD] });
  const masked = vault.redact(`say ${AWKWARD}`);
  const placeholder = masked.slice(4);

  const args = JSON.stringify({ text: placeholder, n: 1 });
  assert.deepEqual(JSON.parse(vault.restore(args)), { text: AWKWARD, n: 1 });
  assert.deepEqual(JSON.parse(restore(`[${JSON.stringify(placeholder)}]`, vault)), [AWKWARD]);
  assert.equal(vault.restore({ args }).args, JSON.stringify({ text: AWKWARD, n: 1 }), 'nested in an object too');

  // Not JSON documents: the original goes back exactly as it was.
  assert.equal(vault.restore(masked), `say ${AWKWARD}`);
  assert.equal(vault.restore(`{ not json ${placeholder}`), `{ not json ${AWKWARD}`);
  assert.equal(vault.restore(`"${placeholder}"`), `"${AWKWARD}"`, 'a quoted string in prose is prose');
  assert.deepEqual(vault.restore({ input: { text: placeholder } }), { input: { text: AWKWARD } }, 'an object leaf is a value, not JSON text');
});

test('a restored value keeps the structure of JSON text', () => {
  const vault = createVault();
  const placeholder = placeholderIn(vault.redact(`call back ${URL_WITH_QUOTES}`));
  assert.ok(placeholder, 'url_credentials captured the URL');
  const restored = vault.restore(JSON.stringify({ amount: 10, callback: placeholder }));
  const parsed = JSON.parse(restored);
  assert.equal(parsed.amount, 10);
  assert.deepEqual(Object.keys(parsed), ['amount', 'callback']);
  assert.ok(URL_WITH_QUOTES.startsWith(parsed.callback));
});

// The awkward value is not a built-in detector match, so it is a custom term.
const TERMS = { terms: [AWKWARD] };

function openAIClient(reply, opts = TERMS) {
  let seen;
  const client = {
    chat: {
      completions: {
        create: async (params) => {
          seen = params;
          return reply(placeholderIn(params.messages));
        },
      },
    },
  };
  wrapOpenAI(client, opts);
  return { client, seen: () => seen };
}

test('wrapOpenAI: tool-call arguments stay valid JSON with the original inside', async () => {
  const { client } = openAIClient((placeholder) => ({
    choices: [{
      message: {
        role: 'assistant',
        content: `Calling the tool for ${placeholder}`,
        tool_calls: [{ id: 'call_1', type: 'function', function: { name: 'save', arguments: JSON.stringify({ note: placeholder, n: 1 }) } }],
        function_call: { name: 'save', arguments: JSON.stringify({ note: placeholder }) },
      },
    }],
  }));
  const res = await client.chat.completions.create({
    model: 'x',
    messages: [{ role: 'user', content: `Save ${AWKWARD}` }],
  });
  const message = res.choices[0].message;
  assert.deepEqual(JSON.parse(message.tool_calls[0].function.arguments), { note: AWKWARD, n: 1 });
  assert.deepEqual(JSON.parse(message.function_call.arguments), { note: AWKWARD });
  assert.equal(message.content, `Calling the tool for ${AWKWARD}`, 'prose content is restored verbatim');
});

test('wrapOpenAI: a captured value with quotes keeps the arguments\' structure', async () => {
  const { client, seen } = openAIClient((placeholder) => ({
    choices: [{ message: { role: 'assistant', content: null, tool_calls: [{ id: 't', type: 'function', function: { name: 'pay', arguments: JSON.stringify({ amount: 10, callback: placeholder }) } }] } }],
  }), {});
  const res = await client.chat.completions.create({ model: 'x', messages: [{ role: 'user', content: `Pay 10, call back ${URL_WITH_QUOTES}` }] });
  assert.doesNotMatch(JSON.stringify(seen().messages), /extra/, "the provider never sees the captured value");
  const args = JSON.parse(res.choices[0].message.tool_calls[0].function.arguments);
  assert.equal(args.amount, 10);
  assert.deepEqual(Object.keys(args), ['amount', 'callback']);
});

test('wrapOpenAI: JSON-mode content is escaped, buffered and streamed', async () => {
  const { client } = openAIClient((placeholder) => ({
    choices: [{ message: { role: 'assistant', content: JSON.stringify({ note: placeholder }) } }],
  }));
  const res = await client.chat.completions.create({
    model: 'x',
    response_format: { type: 'json_object' },
    messages: [{ role: 'user', content: `Save ${AWKWARD}` }],
  });
  assert.deepEqual(JSON.parse(res.choices[0].message.content), { note: AWKWARD });

  const streaming = openAIClient((placeholder) => {
    const json = JSON.stringify({ note: placeholder });
    const at = json.indexOf(placeholder) + 6;
    return (async function* () {
      for (const piece of split(json, at)) yield { choices: [{ index: 0, delta: { content: piece } }] };
    })();
  });
  for (const type of ['json_object', 'json_schema']) {
    const stream = await streaming.client.chat.completions.create({
      stream: true,
      response_format: { type },
      messages: [{ role: 'user', content: `Save ${AWKWARD}` }],
    });
    let text = '';
    for await (const chunk of stream) text += chunk.choices[0]?.delta?.content ?? '';
    assert.deepEqual(JSON.parse(text), { note: AWKWARD }, type);
  }
});

test('wrapOpenAI streaming: argument deltas split mid-placeholder rebuild valid JSON', async () => {
  const { client } = openAIClient((placeholder) => {
    const args = JSON.stringify({ note: placeholder, callback: placeholder });
    const at = args.indexOf(placeholder) + 9;
    return (async function* () {
      yield { choices: [{ index: 0, delta: { content: `Saving ${placeholder.slice(0, 5)}` } }] };
      yield { choices: [{ index: 0, delta: { content: placeholder.slice(5) } }] };
      for (const piece of split(args, at)) {
        yield { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: piece } }] } }] };
      }
    })();
  });
  const stream = await client.chat.completions.create({
    stream: true,
    messages: [{ role: 'user', content: `Save ${AWKWARD}` }],
  });
  let content = '';
  let args = '';
  for await (const chunk of stream) {
    const delta = chunk.choices[0]?.delta ?? {};
    content += delta.content ?? '';
    args += delta.tool_calls?.[0]?.function?.arguments ?? '';
  }
  assert.equal(content, `Saving ${AWKWARD}`, 'prose deltas are restored verbatim');
  assert.deepEqual(JSON.parse(args), { note: AWKWARD, callback: AWKWARD });
});

test('wrapOpenAI streaming: a captured value with quotes keeps the arguments\' structure', async () => {
  const { client } = openAIClient((placeholder) => {
    const args = JSON.stringify({ amount: 10, callback: placeholder });
    return (async function* () {
      for (const piece of split(args, 30)) yield { choices: [{ index: 0, delta: { tool_calls: [{ index: 0, function: { arguments: piece } }] } }] };
    })();
  }, {});
  let args = '';
  for await (const chunk of await client.chat.completions.create({ stream: true, messages: [{ role: 'user', content: `Pay ${URL_WITH_QUOTES}` }] })) {
    args += chunk.choices[0]?.delta?.tool_calls?.[0]?.function?.arguments ?? '';
  }
  const parsed = JSON.parse(args);
  assert.equal(parsed.amount, 10);
  assert.deepEqual(Object.keys(parsed), ['amount', 'callback']);
});

function anthropicClient(reply, opts = TERMS) {
  const client = { messages: { create: async (params) => reply(placeholderIn(params.messages)) } };
  wrapAnthropic(client, opts);
  return client;
}

test('wrapAnthropic streaming: partial_json split mid-placeholder rebuilds valid JSON', async () => {
  const client = anthropicClient((placeholder) => {
    const json = JSON.stringify({ note: placeholder });
    const at = json.indexOf(placeholder) + 3;
    return (async function* () {
      yield { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: `About ${placeholder}` } };
      for (const piece of split(json, at)) {
        yield { type: 'content_block_delta', index: 1, delta: { type: 'input_json_delta', partial_json: piece } };
      }
    })();
  });
  let text = '';
  let json = '';
  for await (const event of await client.messages.create({ stream: true, messages: [{ role: 'user', content: `Save ${AWKWARD}` }] })) {
    text += event.delta?.text ?? '';
    json += event.delta?.partial_json ?? '';
  }
  assert.equal(text, `About ${AWKWARD}`, 'text deltas are restored verbatim');
  assert.deepEqual(JSON.parse(json), { note: AWKWARD });
});

test('wrapAnthropic streaming: a captured value with quotes keeps the tool input\'s structure', async () => {
  const client = anthropicClient((placeholder) => {
    const json = JSON.stringify({ amount: 10, callback: placeholder });
    return (async function* () {
      for (const piece of split(json, 25)) yield { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: piece } };
    })();
  }, {});
  let json = '';
  for await (const event of await client.messages.create({ stream: true, messages: [{ role: 'user', content: `Pay ${URL_WITH_QUOTES}` }] })) json += event.delta?.partial_json ?? '';
  const parsed = JSON.parse(json);
  assert.equal(parsed.amount, 10);
  assert.deepEqual(Object.keys(parsed), ['amount', 'callback']);
});

test('wrapAnthropic: a tool_use input object gets the original value as is', async () => {
  const client = anthropicClient((placeholder) => ({
    content: [
      { type: 'text', text: `Saving ${placeholder}` },
      { type: 'tool_use', id: 'toolu_1', name: 'save', input: { note: placeholder, nested: { list: [placeholder] } } },
    ],
  }));
  const res = await client.messages.create({ messages: [{ role: 'user', content: `Save ${AWKWARD}` }] });
  assert.equal(res.content[0].text, `Saving ${AWKWARD}`);
  assert.deepEqual(res.content[1].input, { note: AWKWARD, nested: { list: [AWKWARD] } });
});

test('tool boundaries: string arguments stay valid JSON, object arguments get the value', () => {
  for (const boundary of [createScopedToolBoundary(), createToolBoundary()]) {
    const scoped = boundary.redactForModel.length === 2;
    const redact = (value) => (scoped ? boundary.redactForModel('db', value) : boundary.redactForModel(value));
    const restoreCall = (call) => (scoped ? boundary.restoreForTool('db', call) : boundary.restoreForTool(call));

    // A value under a secret-named key is masked whole, quotes and all.
    const safe = redact({ user: 'bob', password: FIELDS });
    const call = restoreCall({ name: 'login', arguments: JSON.stringify({ remember: false, password: safe.password }) });
    const args = JSON.parse(call.arguments);
    assert.equal(args.remember, false);
    assert.equal(args.password, FIELDS);
    assert.deepEqual(Object.keys(args), ['remember', 'password']);

    assert.deepEqual(restoreCall({ name: 'login', input: { password: safe.password } }).input, { password: FIELDS });
  }
});

test('agent flows: an authorized restore into string arguments stays valid JSON', () => {
  const flow = createAgentFlow({
    policy: { terms: [AWKWARD] },
    sinks: {
      'notes.save': {
        capabilities: [{ id: 'note', sources: ['user'], detectors: ['custom_term'], paths: ['/arguments'] }],
      },
    },
  });
  const safe = flow.protectForModel('user', AWKWARD);
  const call = flow.authorizeForSink('notes.save', { arguments: JSON.stringify({ note: safe, n: 1 }) });
  assert.deepEqual(JSON.parse(call.arguments), { note: AWKWARD, n: 1 });
});
