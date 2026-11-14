/**
 * Sentry hooks that redact an event before it leaves the process: messages,
 * exception values, stack-frame variables and source lines, request data,
 * breadcrumbs, span descriptions and Sentry Logs.
 *
 *   Sentry.init({ dsn, ...sentryRedact({ preset: 'gdpr' }) });
 *
 * Sentry's own identifiers (event, trace, span and debug ids, release,
 * timestamps, SDK metadata) are put back untouched after redaction, so events
 * still group, link to their traces and resolve source maps even under
 * `preset: 'strict'`. Cookies are masked whole: every one is a credential as
 * far as an error tracker is concerned.
 */

import { compilePolicy, type RedactOptions } from './index.js';

/** Keys whose values Sentry needs verbatim. Their whole subtree is kept. */
const STRUCTURAL_KEYS: ReadonlySet<string> = new Set([
  'event_id',
  'trace_id',
  'span_id',
  'parent_span_id',
  'segment_id',
  'replay_id',
  'profile_id',
  'profiler_id',
  'debug_id',
  'sid',
  'release',
  'dist',
  'environment',
  'timestamp',
  'start_timestamp',
  'received',
  'platform',
  'level',
  'sdk',
  'debug_meta',
]);

const MAX_DEPTH = 64;

type Plain = Record<string, unknown>;

const isObject = (value: unknown): value is Plain => typeof value === 'object' && value !== null;
const own = (object: object, key: string): boolean => Object.prototype.hasOwnProperty.call(object, key);

function keepStructure(original: unknown, redacted: unknown, depth: number): unknown {
  if (depth > MAX_DEPTH || !isObject(original) || !isObject(redacted) || original === redacted) return redacted;
  if (Array.isArray(original) && Array.isArray(redacted)) {
    for (let i = 0; i < redacted.length && i < original.length; i++) {
      redacted[i] = keepStructure(original[i], redacted[i], depth + 1);
    }
    return redacted;
  }
  for (const key of Object.keys(redacted)) {
    if (!own(original, key)) continue;
    redacted[key] = STRUCTURAL_KEYS.has(key) ? original[key] : keepStructure(original[key], redacted[key], depth + 1);
  }
  return redacted;
}

export interface SentryRedactor {
  /** Error and message events. */
  beforeSend: <T>(event: T, hint?: unknown) => T;
  /** Transactions: span descriptions (SQL, URLs) and span data. */
  beforeSendTransaction: <T>(event: T, hint?: unknown) => T;
  /** Spans sent on their own (Sentry v8 and later). */
  beforeSendSpan: <T>(span: T) => T;
  /** Sentry Logs: the message and its attributes. */
  beforeSendLog: <T>(log: T) => T;
  /** Breadcrumbs, before they are stored on the scope. */
  beforeBreadcrumb: <T>(breadcrumb: T, hint?: unknown) => T;
}

/**
 * Build the Sentry hooks once and spread them into `Sentry.init`. If you
 * already have a `beforeSend`, call `hooks.beforeSend(event)` from it.
 */
export function sentryRedact(opts: RedactOptions = {}): SentryRedactor {
  const policy = compilePolicy(opts);
  const maskCookie = (value: unknown): unknown => (policy.redact({ cookie: value }) as { cookie: unknown }).cookie;

  const scrub = <T>(input: T): T => {
    if (!isObject(input)) return policy.redact(input);
    const out = keepStructure(input, policy.redact(input), 0) as T & Plain;
    const original = out.request;
    if (!isObject(original) || Array.isArray(original)) return out;
    // Copy before changing anything, so the caller's event is never mutated.
    const request: Plain = { ...original };
    const { cookies, headers } = request;
    if (typeof cookies === 'string') request.cookies = maskCookie(cookies);
    else if (isObject(cookies)) {
      const masked: Plain = {};
      for (const name of Object.keys(cookies)) masked[name] = maskCookie(cookies[name]);
      request.cookies = masked;
    }
    if (isObject(headers) && !Array.isArray(headers)) {
      const copy: Plain = { ...headers };
      for (const name of Object.keys(copy)) {
        if (/^(?:set-)?cookie$/i.test(name)) copy[name] = maskCookie(copy[name]);
      }
      request.headers = copy;
    }
    return { ...out, request };
  };

  return {
    beforeSend: (event) => scrub(event),
    beforeSendTransaction: (event) => scrub(event),
    beforeSendSpan: (span) => scrub(span),
    beforeSendLog: (log) => scrub(log),
    beforeBreadcrumb: (breadcrumb) => scrub(breadcrumb),
  };
}

/** Redact one Sentry event, span, log or breadcrumb. */
export function redactSentryEvent<T>(event: T, opts: RedactOptions = {}): T {
  return sentryRedact(opts).beforeSend(event);
}
