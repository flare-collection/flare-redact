/**
 * The gateway itself: a reverse proxy that redacts what leaves your network, and
 * a small HTTP API that any language can call.
 *
 * The proxy is the part that needs no code change. Point `OPENAI_BASE_URL` (or
 * any vendor's base URL) at the sidecar, and the request body is scrubbed on the
 * way out and the placeholders are put back on the way in — including in a
 * streamed response. Your application keeps sending and receiving real data; the
 * vendor never sees it.
 *
 * Three rules the implementation holds to:
 *
 * 1. **Credentials are forwarded, never redacted.** The `Authorization` header
 *    that authenticates you *to* the upstream is not the secret we are hiding
 *    *from* it. Header values are passed through untouched.
 * 2. **Nothing sensitive is logged.** The audit trail records detector ids and
 *    counts. Bodies, headers and matched values never reach a log line.
 * 3. **Failures are refusals.** An oversized body, an unreachable upstream or an
 *    unparseable request produces an error status, not a partially redacted
 *    request that quietly reaches the vendor.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';

import {
  compilePolicy,
  createVault,
  DETECTORS,
  type Finding,
  type RedactOptions,
  type Vault,
} from '../index.js';
import {
  matchRoute,
  upstreamUrl,
  type GatewayConfig,
  type RouteConfig,
} from './config.js';
import {
  isEventStream,
  parsePath,
  redactBody,
  restoreBody,
  streamRestorer,
  type ParsedPath,
} from './body.js';
import { createLogger, Metrics, SessionStore, type Logger } from './runtime.js';

const PACKAGE_VERSION: string = (() => {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();

/** Connection-scoped headers that must never be forwarded. RFC 9110 §7.6.1. */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/** Response headers the gateway recomputes because it may rewrite the body. */
const REWRITTEN_RESPONSE_HEADERS = new Set(['content-length', 'content-encoding']);

/** Options a client may never set on a gateway-enforced policy. */
const CLIENT_FORBIDDEN_OPTIONS = ['transformSecret', 'hashSalt', 'detectors', 'custom'] as const;

export interface Gateway {
  readonly config: GatewayConfig;
  readonly server: Server;
  readonly metrics: Metrics;
  readonly sessions: SessionStore;
  listen(): Promise<{ host: string; port: number }>;
  close(): Promise<void>;
}

interface RouteRuntime {
  route: RouteConfig;
  options: RedactOptions;
  /** Compiled once per route: detector resolution is not per-request work. */
  policy: ReturnType<typeof compilePolicy>;
  paths?: ParsedPath[];
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    // Set when the request body was deliberately left unread. The socket cannot
    // be reused: the bytes still in flight would be read as the next request.
    readonly closeConnection = false,
  ) {
    super(message);
    this.name = 'HttpError';
  }
}

// The gateway's own endpoints. Everything else — including the rest of `/v1/`,
// which is where every vendor puts `chat/completions`, `models` and `messages` —
// is proxied. Matching the whole `/v1/` prefix here would make the sidecar
// useless in front of the APIs it exists to protect.
const CONTROL_PATHS = new Set([
  '/healthz',
  '/readyz',
  '/metrics',
  '/v1/detectors',
  '/v1/redact',
  '/v1/scan',
  '/v1/sessions',
]);

const SESSION_PATH = /^\/v1\/sessions\/([^/]+)(?:\/(redact|restore))?$/;

/** True for the gateway's own API, which shadows the upstream on these paths. */
function isControlPath(pathname: string): boolean {
  return CONTROL_PATHS.has(pathname) || SESSION_PATH.test(pathname);
}

/** Layer policies, later layers winning field by field. */
function layerPolicies(...layers: Array<RedactOptions | undefined>): RedactOptions {
  return layers.reduce<RedactOptions>((merged, layer) => (layer ? { ...merged, ...layer } : merged), {});
}

function sanitiseClientOptions(input: unknown): RedactOptions {
  if (input === undefined || input === null) return {};
  if (typeof input !== 'object' || Array.isArray(input)) {
    throw new HttpError(400, 'ERR_BAD_OPTIONS', 'options must be a JSON object');
  }
  const options = { ...(input as Record<string, unknown>) };
  for (const forbidden of CLIENT_FORBIDDEN_OPTIONS) {
    if (forbidden in options) {
      throw new HttpError(
        400,
        'ERR_FORBIDDEN_OPTION',
        `"${forbidden}" is configured on the gateway and cannot be set per request`,
      );
    }
  }
  return options as RedactOptions;
}

function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > maxBytes) {
        // Stop reading, but answer with a 413 rather than resetting the socket:
        // a caller that gets a connection reset cannot tell a refusal from a
        // network failure, and a refusal is the whole point of the limit.
        req.pause();
        reject(new HttpError(413, 'ERR_BODY_TOO_LARGE', `request body exceeds ${maxBytes} bytes`, true));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// `BodyInit` only admits ArrayBuffer-backed views, while a Node Buffer is typed
// over ArrayBufferLike. Node never allocates a Buffer on a SharedArrayBuffer, so
// this narrowing is exact, and the view shares memory rather than copying it.
function asBodyInit(buffer: Buffer): Uint8Array<ArrayBuffer> {
  return new Uint8Array(buffer.buffer as ArrayBuffer, buffer.byteOffset, buffer.byteLength);
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  const body = Buffer.from(JSON.stringify(payload), 'utf8');
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'content-length': body.length });
  res.end(body);
}

function sendError(res: ServerResponse, status: number, code: string, message: string): void {
  sendJson(res, status, { error: true, code, message });
}

function tokenMatches(expected: string, presented: string): boolean {
  const a = Buffer.from(expected, 'utf8');
  const b = Buffer.from(presented, 'utf8');
  // timingSafeEqual throws on a length mismatch, which would itself leak length.
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

function summarise(findings: readonly Finding[]): { total: number; byDetector: Record<string, number>; byRisk: Record<string, number> } {
  const byDetector: Record<string, number> = {};
  const byRisk: Record<string, number> = {};
  for (const finding of findings) {
    byDetector[finding.detector] = (byDetector[finding.detector] ?? 0) + 1;
    byRisk[finding.risk] = (byRisk[finding.risk] ?? 0) + 1;
  }
  return { total: findings.length, byDetector, byRisk };
}

/**
 * Write one chunk, waiting for drain when the socket is full.
 *
 * All three outcomes have to be handled or a slow client can wedge the request
 * forever: drain means carry on, error means give up, and close means the client
 * left — which is not an error worth logging.
 */
function writeChunk(res: ServerResponse, chunk: Buffer): Promise<void> {
  if (res.write(chunk)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const settle = (error?: Error) => {
      res.off('drain', onDrain);
      res.off('error', onError);
      res.off('close', onClose);
      if (error) reject(error);
      else resolve();
    };
    const onDrain = () => settle();
    const onClose = () => settle();
    const onError = (error: Error) => settle(error);
    res.on('drain', onDrain);
    res.on('error', onError);
    res.on('close', onClose);
  });
}

export function createGateway(config: GatewayConfig): Gateway {
  const logger: Logger = createLogger(config.log);
  const metrics = new Metrics();
  const sessions = new SessionStore(config.sessions);

  // A route's own policy is the more specific one, so it wins over the
  // gateway-wide default. Both are set by whoever runs the gateway.
  const runtimes: RouteRuntime[] = config.routes.map((route) => {
    const options = layerPolicies(config.policy, route.policy);
    return {
      route,
      options,
      policy: compilePolicy(options),
      ...(route.request.paths?.length ? { paths: route.request.paths.map(parsePath) } : {}),
    };
  });

  const requireAuth = (req: IncomingMessage): void => {
    if (!config.token) return;
    const header = req.headers.authorization;
    const presented = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!presented || !tokenMatches(config.token, presented)) {
      throw new HttpError(401, 'ERR_UNAUTHORIZED', 'a valid bearer token is required');
    }
  };

  const parseJsonBody = async (req: IncomingMessage): Promise<Record<string, unknown>> => {
    const raw = (await readBody(req, config.limits.maxBodyBytes)).toString('utf8');
    if (!raw.trim()) return {};
    try {
      const parsed: unknown = JSON.parse(raw);
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new HttpError(400, 'ERR_BAD_REQUEST', 'request body must be a JSON object');
      }
      return parsed as Record<string, unknown>;
    } catch (error) {
      if (error instanceof HttpError) throw error;
      throw new HttpError(400, 'ERR_BAD_JSON', 'request body is not valid JSON');
    }
  };

  // ---------------------------------------------------------------------- //
  // The /v1 API
  // ---------------------------------------------------------------------- //

  const handleApi = async (req: IncomingMessage, res: ServerResponse, pathname: string): Promise<void> => {
    if (pathname === '/healthz' || pathname === '/readyz') {
      sendJson(res, 200, {
        status: 'ok',
        version: PACKAGE_VERSION,
        routes: config.routes.map((route) => route.name),
        sessions: sessions.size,
      });
      return;
    }

    if (pathname === '/metrics') {
      if (!config.metrics) throw new HttpError(404, 'ERR_NOT_FOUND', 'metrics are disabled');
      const body = metrics.render(sessions.size);
      res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' });
      res.end(body);
      return;
    }

    requireAuth(req);

    // The gateway's own policy is layered *over* the caller's, so a client
    // cannot widen what the operator decided to protect.
    const clientPolicy = async (): Promise<{ payload: Record<string, unknown>; options: RedactOptions }> => {
      const payload = await parseJsonBody(req);
      return { payload, options: layerPolicies(sanitiseClientOptions(payload.options), config.policy) };
    };

    if (pathname === '/v1/detectors' && req.method === 'GET') {
      sendJson(res, 200, {
        // The selectors are reported alongside the catalogue so a client can see
        // which detectors this gateway actually runs without guessing.
        policy: {
          only: config.policy.only ?? null,
          enable: config.policy.enable ?? null,
          disable: config.policy.disable ?? null,
          mode: config.policy.mode ?? 'mask',
        },
        detectors: DETECTORS.map((detector) => ({
          id: detector.id,
          label: detector.label,
          why: detector.why,
          default: detector.default,
          tags: detector.tags ?? [],
          risk: detector.risk ?? null,
        })),
      });
      return;
    }

    if (pathname === '/v1/redact' && req.method === 'POST') {
      const { payload, options } = await clientPolicy();
      const policy = compilePolicy(options);
      const findings = config.auditFindings ? policy.scan(payload.input) : [];
      for (const finding of findings) metrics.finding(finding.detector);
      sendJson(res, 200, {
        output: policy.redact(payload.input),
        ...(config.auditFindings ? { summary: summarise(findings) } : {}),
      });
      return;
    }

    if (pathname === '/v1/scan' && req.method === 'POST') {
      const { payload, options } = await clientPolicy();
      const findings = compilePolicy(options).scan(payload.input);
      sendJson(res, 200, { findings, summary: summarise(findings) });
      return;
    }

    if (pathname === '/v1/sessions' && req.method === 'POST') {
      const { options } = await clientPolicy();
      const record = sessions.create(options);
      sendJson(res, 201, { id: record.id, expiresAt: new Date(record.expiresAt).toISOString() });
      return;
    }

    const sessionRoute = SESSION_PATH.exec(pathname);
    if (sessionRoute) {
      const id = decodeURIComponent(sessionRoute[1]!);
      const action = sessionRoute[2];
      if (!action && req.method === 'DELETE') {
        const removed = sessions.delete(id);
        if (!removed) throw new HttpError(404, 'ERR_NO_SESSION', 'unknown session');
        res.writeHead(204).end();
        return;
      }
      const record = sessions.get(id);
      if (!record) throw new HttpError(404, 'ERR_NO_SESSION', 'unknown or expired session');
      if (req.method !== 'POST') throw new HttpError(405, 'ERR_METHOD', 'use POST');
      const payload = await parseJsonBody(req);
      const output = action === 'restore'
        ? record.session.restore(payload.input)
        : record.session.redact(payload.input);
      sendJson(res, 200, { output, size: record.session.size });
      return;
    }

    throw new HttpError(404, 'ERR_NOT_FOUND', 'no such endpoint');
  };

  // ---------------------------------------------------------------------- //
  // The reverse proxy
  // ---------------------------------------------------------------------- //

  const handleProxy = async (
    req: IncomingMessage,
    res: ServerResponse,
    runtime: RouteRuntime,
    pathname: string,
    search: string,
  ): Promise<number> => {
    const { route, options, policy } = runtime;
    const started = Date.now();
    const raw = await readBody(req, config.limits.maxBodyBytes);
    metrics.bytesIn += raw.length;

    const contentType = String(req.headers['content-type'] ?? '');
    // One vault per request: placeholders must not leak between callers.
    const vault: Vault | undefined = route.response.enabled ? createVault(options) : undefined;

    let body: Buffer = raw;
    let findings: readonly Finding[] = [];

    if (route.request.enabled && raw.length) {
      const text = raw.toString('utf8');
      if (config.auditFindings) {
        try {
          findings = policy.scan(contentType && /json/i.test(contentType) ? JSON.parse(text) : text);
        } catch {
          findings = policy.scan(text);
        }
        for (const finding of findings) metrics.finding(finding.detector);
      }
      const result = redactBody(text, {
        contentType,
        nonJson: route.request.nonJson,
        redact: vault ? <T>(value: T) => vault.redact(value) : <T>(value: T) => policy.redact(value),
        ...(runtime.paths ? { paths: runtime.paths } : {}),
      });
      body = Buffer.from(result.body, 'utf8');
    }

    const headers = new Headers();
    for (const [name, value] of Object.entries(req.headers)) {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.has(lower) || lower === 'host' || lower === 'content-length' || lower === 'accept-encoding') {
        continue;
      }
      if (Array.isArray(value)) {
        for (const entry of value) headers.append(name, entry);
      } else if (value !== undefined) {
        headers.set(name, value);
      }
    }
    for (const [name, value] of Object.entries(route.headers ?? {})) headers.set(name, value);

    const method = req.method ?? 'GET';
    // Content-Length is deliberately not set: the body changed length during
    // redaction, and the fetch implementation recomputes it from the buffer.
    const sendsBody = method !== 'GET' && method !== 'HEAD';

    const target = upstreamUrl(route, pathname, search);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), config.limits.requestTimeoutMs);
    res.on('close', () => controller.abort());

    let upstream: Response;
    try {
      upstream = await fetch(target, {
        method,
        headers,
        ...(sendsBody ? { body: asBodyInit(body) } : {}),
        redirect: 'manual',
        signal: controller.signal,
      });
    } catch (error) {
      metrics.upstreamFailures++;
      clearTimeout(timeout);
      logger.error({
        msg: 'upstream request failed',
        route: route.name,
        method,
        path: pathname,
        reason: (error as Error).name,
      });
      if (!res.headersSent) sendError(res, 502, 'ERR_UPSTREAM', 'the upstream service could not be reached');
      return 502;
    }

    const responseHeaders: Record<string, string | string[]> = {};
    upstream.headers.forEach((value, name) => {
      const lower = name.toLowerCase();
      if (HOP_BY_HOP.has(lower) || REWRITTEN_RESPONSE_HEADERS.has(lower) || lower === 'set-cookie') return;
      responseHeaders[name] = value;
    });
    // Set-Cookie is the one header that may legitimately repeat, and it is only
    // recoverable through getSetCookie(); iterating Headers joins the values.
    const cookies = (upstream.headers as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
    if (cookies.length) responseHeaders['set-cookie'] = cookies;
    responseHeaders['x-flare-redact'] = `route=${route.name}; findings=${findings.length}; restored=${vault ? 'on' : 'off'}`;

    const responseType = upstream.headers.get('content-type') ?? '';
    const streaming = isEventStream(responseType);
    const stream = upstream.body;

    try {
      if (!stream) {
        res.writeHead(upstream.status, responseHeaders).end();
      } else if (vault && streaming) {
        res.writeHead(upstream.status, responseHeaders);
        const restorer = streamRestorer(vault, route.response.streamEscape);
        const decoder = new TextDecoder();
        const reader = stream.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const text = restorer.push(decoder.decode(value, { stream: true }));
          if (text) {
            const chunk = Buffer.from(text, 'utf8');
            metrics.bytesOut += chunk.length;
            await writeChunk(res, chunk);
          }
        }
        const tail = restorer.flush() + decoder.decode();
        if (tail) {
          const chunk = Buffer.from(tail, 'utf8');
          metrics.bytesOut += chunk.length;
          await writeChunk(res, chunk);
        }
        res.end();
      } else if (vault) {
        const text = await upstream.text();
        const restored = restoreBody(text, responseType, vault);
        const chunk = Buffer.from(restored, 'utf8');
        metrics.bytesOut += chunk.length;
        res.writeHead(upstream.status, { ...responseHeaders, 'content-length': chunk.length }).end(chunk);
      } else {
        res.writeHead(upstream.status, responseHeaders);
        const reader = stream.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          const chunk = Buffer.from(value);
          metrics.bytesOut += chunk.length;
          await writeChunk(res, chunk);
        }
        res.end();
      }
    } finally {
      clearTimeout(timeout);
    }

    logger.info({
      msg: 'proxied',
      route: route.name,
      method,
      path: pathname,
      status: upstream.status,
      durationMs: Date.now() - started,
      findings: summarise(findings).byDetector,
      placeholders: vault?.size ?? 0,
    });
    return upstream.status;
  };

  // ---------------------------------------------------------------------- //
  // Dispatch
  // ---------------------------------------------------------------------- //

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://gateway.invalid');
    const pathname = url.pathname;
    const isApi = isControlPath(pathname);

    const handle = async (): Promise<number> => {
      if (isApi) {
        await handleApi(req, res, pathname);
        return res.statusCode;
      }
      const runtime = runtimes.find((candidate) => matchRoute([candidate.route], pathname));
      if (!runtime) {
        sendError(res, 404, 'ERR_NO_ROUTE', 'no route matches this path');
        return 404;
      }
      return handleProxy(req, res, runtime, pathname, url.search);
    };

    handle()
      .then((status) => {
        metrics.request(isApi ? 'api' : (matchRoute(config.routes, pathname)?.name ?? 'none'), status);
      })
      .catch((error: unknown) => {
        const status = error instanceof HttpError ? error.status : 500;
        const code = error instanceof HttpError ? error.code : 'ERR_INTERNAL';
        const message = error instanceof HttpError ? error.message : 'the gateway failed to handle this request';
        if (status >= 500) {
          metrics.errors++;
          logger.error({ msg: 'request failed', path: pathname, status, reason: (error as Error)?.message });
        }
        metrics.request(isApi ? 'api' : 'proxy', status);
        if (!res.headersSent) {
          if (error instanceof HttpError && error.closeConnection) res.setHeader('connection', 'close');
          sendError(res, status, code, message);
        } else res.end();
      });
  });

  server.headersTimeout = config.limits.requestTimeoutMs + 5_000;
  server.requestTimeout = config.limits.requestTimeoutMs + 10_000;

  return {
    config,
    server,
    metrics,
    sessions,
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.listen.port, config.listen.host, () => {
          server.off('error', reject);
          const address = server.address();
          const bound = typeof address === 'object' && address
            ? { host: address.address, port: address.port }
            : { host: config.listen.host, port: config.listen.port };
          logger.info({
            msg: 'listening',
            host: bound.host,
            port: bound.port,
            routes: config.routes.map((route) => `${route.prefix} -> ${route.upstream}`),
            authenticated: Boolean(config.token),
          });
          resolve(bound);
        });
      });
    },
    close() {
      sessions.clear();
      return new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
        server.closeAllConnections?.();
      });
    },
  };
}
