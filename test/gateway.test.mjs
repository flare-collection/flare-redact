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

test('configuration refuses what it cannot serve safely', () => {
  assert.throws(() => resolveConfig({ upstream: 'not-a-url' }), GatewayConfigError);
  assert.throws(() => resolveConfig({ upstream: 'ftp://example.com' }), GatewayConfigError);
  assert.throws(() => resolveConfig({ routes: [{ prefix: '/v1', upstream: 'https://example.com' }] }), GatewayConfigError);
  assert.throws(
    () => resolveConfig({ routes: [{ prefix: '/a', upstream: 'https://x.test' }, { prefix: '/a', upstream: 'https://y.test' }] }),
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
