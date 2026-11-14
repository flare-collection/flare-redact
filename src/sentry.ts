/**
 * Sentry hooks that redact an event before it leaves the process: messages,
 * exception values, stack-frame variables and source lines, request data,
 * breadcrumbs, span descriptions and Sentry Logs.
 *
 *   Sentry.init({ dsn, ...sentryRedact({ preset: 'gdpr' }) });
 *
 * Sentry's own fields (event, trace, span and debug ids, release, timestamps,
 * SDK metadata, the file and function of each stack frame) are put back
 * untouched after redaction, so events still group, link to their traces and
 * resolve source maps even under `preset: 'strict'`. They are recognised by
 * where they sit in the event, never by name alone: `extra.release` or a
 * request field called `sid` is user data and is redacted like any other.
 * Cookies are masked whole: every one is a credential as far as an error
 * tracker is concerned.
 */

import { compilePolicy, type RedactOptions } from './index.js';

/** Which fields of a Sentry object are Sentry's own, by position. */
interface Keep {
  /** Fields at this level whose value (and everything under it) is kept. */
  readonly keys?: readonly string[];
  /** Fields at this level to descend into. */
  readonly fields?: Readonly<Record<string, Keep>>;
  /** For an array: the shape of each item. */
  readonly items?: Keep;
  /** Fields at this level whose name matches are kept too. */
  readonly pattern?: RegExp;
}

/**
 * Attributes Sentry sets itself on spans and logs (`sentry.release`,
 * `sentry.op`, `sentry.sdk.version`). The span name, the log message template
 * and its parameters also live under `sentry.` and are user data, so the list
 * is explicit.
 */
const SENTRY_ATTRIBUTES: Keep = {
  pattern: /^sentry\.(?:release|environment|dist|platform|origin|op|source|sample_rate|trace_lifecycle|exclusive_time|is_remote|idle_span_finish_reason|segment\.id|segment\.name\.source|trace\.parent_span_id|replay_id|profiler_id|timestamp\.sequence|sdk\.[a-z_.]+)$/,
};

const FRAME: Keep = {
  keys: [
    'filename', 'abs_path', 'module', 'function', 'raw_function', 'lineno', 'colno', 'in_app',
    'platform', 'package', 'symbol', 'symbol_addr', 'image_addr', 'instruction_addr', 'addr_mode', 'debug_id',
  ],
};
const STACKTRACE: Keep = { fields: { frames: { items: FRAME } } };
/** Exceptions and threads: `{ values: [...] }` or, in older payloads, a bare array. */
const withStack = (keys: readonly string[]): Keep => {
  const item: Keep = { keys, fields: { stacktrace: STACKTRACE, raw_stacktrace: STACKTRACE } };
  return { items: item, fields: { values: { items: item } } };
};

/** Both span formats: the one inside a transaction and the streamed one (Sentry 11). */
const SPAN: Keep = {
  keys: [
    'span_id', 'trace_id', 'parent_span_id', 'segment_id', 'profile_id', 'is_segment', 'links',
    'start_timestamp', 'timestamp', 'end_timestamp', 'exclusive_time', 'op', 'origin', 'status',
  ],
  fields: { data: SENTRY_ATTRIBUTES, attributes: SENTRY_ATTRIBUTES },
};
const BREADCRUMB: Keep = { keys: ['timestamp', 'type', 'level', 'category'] };
const LOG: Keep = {
  keys: ['timestamp', 'level', 'severity_number', 'severityNumber', 'trace_id', 'span_id'],
  fields: { attributes: SENTRY_ATTRIBUTES },
};

const EVENT: Keep = {
  keys: [
    'event_id', 'type', 'timestamp', 'start_timestamp', 'received', 'platform', 'level',
    'release', 'dist', 'environment', 'sdk', 'debug_meta',
  ],
  fields: {
    contexts: {
      fields: {
        trace: SPAN,
        replay: { keys: ['replay_id'] },
        profile: { keys: ['profile_id', 'profiler_id'] },
      },
    },
    exception: withStack(['type', 'module', 'mechanism', 'thread_id']),
    threads: withStack(['id', 'crashed', 'current', 'main']),
    spans: { items: SPAN },
    breadcrumbs: { items: BREADCRUMB, fields: { values: { items: BREADCRUMB } } },
  },
};

type Plain = Record<string, unknown>;

const isObject = (value: unknown): value is Plain => typeof value === 'object' && value !== null;
const own = (object: object, key: string): boolean => Object.prototype.hasOwnProperty.call(object, key);

/** Copy Sentry's own fields from `original` back into the redacted copy. */
function keep(original: unknown, redacted: unknown, spec: Keep): void {
  if (!isObject(original) || !isObject(redacted) || original === redacted) return;
  if (Array.isArray(original) && Array.isArray(redacted)) {
    if (!spec.items) return;
    for (let i = 0; i < redacted.length && i < original.length; i++) keep(original[i], redacted[i], spec.items);
    return;
  }
  if (Array.isArray(original) || Array.isArray(redacted)) return;
  for (const key of spec.keys ?? []) {
    if (own(original, key) && own(redacted, key)) redacted[key] = original[key];
  }
  if (spec.pattern) {
    for (const key of Object.keys(redacted)) {
      if (spec.pattern.test(key) && own(original, key)) redacted[key] = original[key];
    }
  }
  for (const [field, child] of Object.entries(spec.fields ?? {})) {
    if (own(original, field) && own(redacted, field)) keep(original[field], redacted[field], child);
  }
}

export interface SentryRedactor {
  /** Error and message events. */
  beforeSend: <T>(event: T, hint?: unknown) => T;
  /**
   * Transactions: span descriptions (SQL, URLs) and span data. Sentry 11
   * streams spans instead and ignores this hook unless `traceLifecycle` is
   * `'static'`; leave it out there to avoid Sentry's notice about it.
   */
  beforeSendTransaction: <T>(event: T, hint?: unknown) => T;
  /** Spans sent on their own: streamed spans in Sentry 11, standalone spans before. */
  beforeSendSpan: <T>(span: T) => T;
  /** Sentry Logs: the message and its attributes. */
  beforeSendLog: <T>(log: T) => T;
  /** Breadcrumbs, before they are stored on the scope. */
  beforeBreadcrumb: <T>(breadcrumb: T, hint?: unknown) => T;
}

export interface SentryHookOptions {
  /**
   * Sentry's own `traceLifecycle`. `'stream'` (the default in Sentry 11)
   * leaves out `beforeSendTransaction`, which that mode ignores and warns
   * about. Leave it unset on Sentry 8 to 10, or with `'static'`.
   */
  traceLifecycle?: 'static' | 'stream';
}

/**
 * Build the Sentry hooks once and spread them into `Sentry.init`. If you
 * already have a `beforeSend`, call `hooks.beforeSend(event)` from it.
 */
export function sentryRedact(opts: RedactOptions, sentry: { traceLifecycle: 'stream' }): Omit<SentryRedactor, 'beforeSendTransaction'>;
export function sentryRedact(opts?: RedactOptions, sentry?: SentryHookOptions): SentryRedactor;
export function sentryRedact(opts: RedactOptions = {}, sentry: SentryHookOptions = {}): SentryRedactor | Omit<SentryRedactor, 'beforeSendTransaction'> {
  const policy = compilePolicy(opts);
  const maskCookie = (value: unknown): unknown => (policy.redact({ cookie: value }) as { cookie: unknown }).cookie;

  const scrub = <T>(input: T, spec: Keep): T => {
    if (!isObject(input)) return policy.redact(input);
    const out = policy.redact(input) as T & Plain;
    keep(input, out, spec);
    return out;
  };

  const scrubEvent = <T>(input: T): T => {
    const out = scrub(input, EVENT) as T & Plain;
    if (!isObject(out)) return out;
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

  const hooks: SentryRedactor = {
    beforeSend: (event) => scrubEvent(event),
    beforeSendTransaction: (event) => scrubEvent(event),
    beforeSendSpan: (span) => scrub(span, SPAN),
    beforeSendLog: (log) => scrub(log, LOG),
    beforeBreadcrumb: (breadcrumb) => scrub(breadcrumb, BREADCRUMB),
  };
  if (sentry.traceLifecycle !== 'stream') return hooks;
  const { beforeSendTransaction: _unused, ...streamed } = hooks;
  return streamed;
}

/** Redact one Sentry error event or transaction. */
export function redactSentryEvent<T>(event: T, opts: RedactOptions = {}): T {
  return sentryRedact(opts).beforeSend(event);
}
