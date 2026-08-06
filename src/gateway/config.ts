/**
 * Gateway configuration: a file, environment variables, and command-line flags,
 * merged in that order of increasing precedence and then validated once.
 *
 * The defaults are the safe ones. The listener binds to loopback, the `/v1` API
 * refuses unauthenticated calls as soon as a token exists, bodies are capped,
 * and an upstream must be an explicit absolute `http(s)` URL — a redaction proxy
 * that can be pointed anywhere by a header is an open relay.
 */

import type { RedactOptions } from '../index.js';

export interface ListenConfig {
  host: string;
  port: number;
}

export interface RequestRedactionConfig {
  /**
   * JSON paths to redact, e.g. `["messages[*].content", "input", "prompt"]`.
   * Omit to redact every string in the body — safest, and the default.
   */
  paths?: string[];
  /** Set false to forward request bodies untouched (response restore still works). */
  enabled: boolean;
  /** Also redact `application/x-www-form-urlencoded` values and plain text. */
  nonJson: boolean;
}

export interface ResponseRestorationConfig {
  /**
   * Put the originals back into the upstream's answer. This is what makes the
   * proxy transparent: the model sees placeholders, your app sees real data.
   */
  enabled: boolean;
  /**
   * How a placeholder inside a streamed frame is replaced. `json` escapes the
   * original for a JSON string context, which is what every LLM streaming API
   * puts on the wire; `none` substitutes verbatim.
   */
  streamEscape: 'json' | 'none';
}

export interface RouteConfig {
  /** Stable name used in logs and metrics. Defaults to the prefix. */
  name: string;
  /** Path prefix this route claims, e.g. `/openai`. `/` is the catch-all. */
  prefix: string;
  /** Absolute upstream origin, e.g. `https://api.openai.com`. */
  upstream: string;
  /** Remove `prefix` before forwarding. Default: true for anything but `/`. */
  stripPrefix: boolean;
  /** Policy overrides layered on top of the gateway-wide policy. */
  policy?: RedactOptions;
  request: RequestRedactionConfig;
  response: ResponseRestorationConfig;
  /** Extra headers to set on the upstream request, e.g. a vendor API version. */
  headers?: Record<string, string>;
}

export interface GatewayConfig {
  listen: ListenConfig;
  /** Bearer token required by `/v1`. Unset means the API is open — loopback only. */
  token?: string;
  policy: RedactOptions;
  routes: RouteConfig[];
  sessions: { ttlMs: number; max: number };
  limits: { maxBodyBytes: number; requestTimeoutMs: number };
  /** Count findings per detector for logs and metrics. Costs one extra scan. */
  auditFindings: boolean;
  metrics: boolean;
  log: 'silent' | 'info' | 'debug';
}

export class GatewayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayConfigError';
  }
}

export const DEFAULT_PORT = 8787;

const DEFAULTS: GatewayConfig = {
  listen: { host: '127.0.0.1', port: DEFAULT_PORT },
  policy: {},
  routes: [],
  sessions: { ttlMs: 30 * 60_000, max: 10_000 },
  limits: { maxBodyBytes: 8 * 1024 * 1024, requestTimeoutMs: 120_000 },
  auditFindings: true,
  metrics: true,
  log: 'info',
};

/** Paths the gateway answers itself; a route may not claim them. */
export const RESERVED_PREFIXES = ['/healthz', '/readyz', '/metrics', '/v1/'];

/** A route as written in a config file: everything but `upstream` is optional. */
export type RawRoute = Partial<Omit<RouteConfig, 'request' | 'response'>> & {
  request?: Partial<RequestRedactionConfig>;
  response?: Partial<ResponseRestorationConfig>;
};

export interface RawConfig {
  listen?: Partial<ListenConfig>;
  token?: string;
  policy?: RedactOptions;
  routes?: RawRoute[];
  upstream?: string;
  sessions?: Partial<GatewayConfig['sessions']>;
  limits?: Partial<GatewayConfig['limits']>;
  auditFindings?: boolean;
  metrics?: boolean;
  log?: GatewayConfig['log'];
}

function normaliseUpstream(value: string, where: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new GatewayConfigError(`${where}: upstream must be an absolute URL, received ${JSON.stringify(value)}`);
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new GatewayConfigError(`${where}: upstream must use http or https, received ${url.protocol}`);
  }
  if (url.search || url.hash) {
    throw new GatewayConfigError(`${where}: upstream must not carry a query string or fragment`);
  }
  // Keep any base path, drop the trailing slash so joining is unambiguous.
  return (url.origin + url.pathname).replace(/\/$/, '');
}

function normalisePrefix(value: string, where: string): string {
  if (!value.startsWith('/')) throw new GatewayConfigError(`${where}: prefix must start with "/"`);
  const trimmed = value.length > 1 ? value.replace(/\/$/, '') : '/';
  for (const reserved of RESERVED_PREFIXES) {
    if (reserved.startsWith(trimmed === '/' ? '/x' : trimmed)) {
      throw new GatewayConfigError(
        `${where}: prefix ${JSON.stringify(trimmed)} would shadow the gateway's own ${reserved} endpoint`,
      );
    }
  }
  return trimmed;
}

function normaliseRoute(raw: RawRoute, index: number): RouteConfig {
  const where = `routes[${index}]`;
  if (!raw.upstream) throw new GatewayConfigError(`${where}: upstream is required`);
  const prefix = normalisePrefix(raw.prefix ?? '/', where);
  return {
    name: raw.name ?? prefix,
    prefix,
    upstream: normaliseUpstream(raw.upstream, where),
    stripPrefix: raw.stripPrefix ?? prefix !== '/',
    ...(raw.policy ? { policy: raw.policy } : {}),
    request: {
      enabled: raw.request?.enabled ?? true,
      nonJson: raw.request?.nonJson ?? false,
      ...(raw.request?.paths?.length ? { paths: raw.request.paths } : {}),
    },
    response: {
      enabled: raw.response?.enabled ?? true,
      streamEscape: raw.response?.streamEscape ?? 'json',
    },
    ...(raw.headers ? { headers: raw.headers } : {}),
  };
}

function positiveInteger(value: string | undefined, where: string): number | undefined {
  if (value === undefined) return undefined;
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new GatewayConfigError(`${where} must be a positive integer, received ${JSON.stringify(value)}`);
  }
  return parsed;
}

function csv(value: string | undefined): string[] | undefined {
  if (!value) return undefined;
  const items = value.split(',').map((item) => item.trim()).filter(Boolean);
  return items.length ? items : undefined;
}

/** Environment overrides, for the container case where a file is inconvenient. */
export function configFromEnv(env: NodeJS.ProcessEnv): RawConfig {
  const raw: RawConfig = {};
  const host = env.FLARE_GATEWAY_HOST;
  const port = positiveInteger(env.FLARE_GATEWAY_PORT, 'FLARE_GATEWAY_PORT');
  if (host || port) raw.listen = { ...(host ? { host } : {}), ...(port ? { port } : {}) };
  if (env.FLARE_GATEWAY_TOKEN) raw.token = env.FLARE_GATEWAY_TOKEN;
  if (env.FLARE_UPSTREAM) raw.upstream = env.FLARE_UPSTREAM;

  const policy: RedactOptions = {};
  const only = csv(env.FLARE_REDACT_ONLY);
  const enable = csv(env.FLARE_REDACT_ENABLE);
  const disable = csv(env.FLARE_REDACT_DISABLE);
  if (only) policy.only = only;
  if (enable) policy.enable = enable;
  if (disable) policy.disable = disable;
  if (env.FLARE_REDACT_MODE) policy.mode = env.FLARE_REDACT_MODE as RedactOptions['mode'];
  if (env.FLARE_REDACT_SECRET) policy.transformSecret = env.FLARE_REDACT_SECRET;
  if (Object.keys(policy).length) raw.policy = policy;

  const maxBodyBytes = positiveInteger(env.FLARE_GATEWAY_MAX_BODY_BYTES, 'FLARE_GATEWAY_MAX_BODY_BYTES');
  const requestTimeoutMs = positiveInteger(env.FLARE_GATEWAY_TIMEOUT_MS, 'FLARE_GATEWAY_TIMEOUT_MS');
  if (maxBodyBytes || requestTimeoutMs) {
    raw.limits = { ...(maxBodyBytes ? { maxBodyBytes } : {}), ...(requestTimeoutMs ? { requestTimeoutMs } : {}) };
  }
  const ttlMs = positiveInteger(env.FLARE_GATEWAY_SESSION_TTL_MS, 'FLARE_GATEWAY_SESSION_TTL_MS');
  if (ttlMs) raw.sessions = { ttlMs };
  if (env.FLARE_GATEWAY_LOG) raw.log = env.FLARE_GATEWAY_LOG as GatewayConfig['log'];
  if (env.FLARE_GATEWAY_METRICS === 'false') raw.metrics = false;
  if (env.FLARE_GATEWAY_AUDIT_FINDINGS === 'false') raw.auditFindings = false;
  return raw;
}

function mergeRaw(base: RawConfig, override: RawConfig): RawConfig {
  return {
    ...base,
    ...override,
    listen: { ...base.listen, ...override.listen },
    policy: { ...base.policy, ...override.policy },
    sessions: { ...base.sessions, ...override.sessions },
    limits: { ...base.limits, ...override.limits },
    routes: override.routes ?? base.routes,
    upstream: override.upstream ?? base.upstream,
  };
}

/**
 * Build a validated configuration from any number of partial layers, later
 * layers winning. Throws {@link GatewayConfigError} with a message that names
 * the offending field — a proxy that starts with a subtly wrong upstream is
 * worse than one that refuses to start.
 */
export function resolveConfig(...layers: Array<RawConfig | undefined>): GatewayConfig {
  const raw = layers.filter((layer): layer is RawConfig => Boolean(layer)).reduce(mergeRaw, {});

  const rawRoutes = raw.routes?.length
    ? raw.routes
    : raw.upstream
      ? [{ prefix: '/', upstream: raw.upstream }]
      : [];
  const routes = rawRoutes.map(normaliseRoute);

  const seen = new Set<string>();
  for (const route of routes) {
    if (seen.has(route.prefix)) throw new GatewayConfigError(`duplicate route prefix ${JSON.stringify(route.prefix)}`);
    seen.add(route.prefix);
  }
  // Longest prefix first, so `/openai/v1` wins over `/openai`.
  routes.sort((a, b) => b.prefix.length - a.prefix.length);

  const log = raw.log ?? DEFAULTS.log;
  if (log !== 'silent' && log !== 'info' && log !== 'debug') {
    throw new GatewayConfigError(`log must be silent, info or debug, received ${JSON.stringify(log)}`);
  }

  const port = raw.listen?.port ?? DEFAULTS.listen.port;
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new GatewayConfigError(`listen.port must be between 0 and 65535, received ${JSON.stringify(port)}`);
  }

  return {
    listen: { host: raw.listen?.host ?? DEFAULTS.listen.host, port },
    ...(raw.token ? { token: raw.token } : {}),
    policy: raw.policy ?? DEFAULTS.policy,
    routes,
    sessions: {
      ttlMs: raw.sessions?.ttlMs ?? DEFAULTS.sessions.ttlMs,
      max: raw.sessions?.max ?? DEFAULTS.sessions.max,
    },
    limits: {
      maxBodyBytes: raw.limits?.maxBodyBytes ?? DEFAULTS.limits.maxBodyBytes,
      requestTimeoutMs: raw.limits?.requestTimeoutMs ?? DEFAULTS.limits.requestTimeoutMs,
    },
    auditFindings: raw.auditFindings ?? DEFAULTS.auditFindings,
    metrics: raw.metrics ?? DEFAULTS.metrics,
    log,
  };
}

/** The route claiming `pathname`, or undefined when the gateway is API-only. */
export function matchRoute(routes: RouteConfig[], pathname: string): RouteConfig | undefined {
  return routes.find((route) => {
    if (route.prefix === '/') return true;
    return pathname === route.prefix || pathname.startsWith(`${route.prefix}/`);
  });
}

/** The upstream URL a request is forwarded to. */
export function upstreamUrl(route: RouteConfig, pathname: string, search: string): string {
  const remainder = route.stripPrefix && route.prefix !== '/' ? pathname.slice(route.prefix.length) : pathname;
  const path = remainder.startsWith('/') ? remainder : `/${remainder}`;
  return `${route.upstream}${path}${search}`;
}
