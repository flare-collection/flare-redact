/**
 * Sentry hooks that redact an event before it leaves the process: messages,
 * exception values, stack-frame variables and source lines, request data,
 * breadcrumbs, span names and Sentry Logs.
 *
 *   Sentry.init({ dsn, ...sentryRedact({ preset: 'gdpr' }) });
 *
 * Sentry's own fields (event, trace, span and debug ids, release, timestamps,
 * SDK metadata, the file and function of each stack frame) are put back after
 * redaction, so events still group, link to their traces and resolve source
 * maps even under `preset: 'strict'`. A field is put back only when both
 * things hold: it sits where Sentry keeps that field (never by name alone, so
 * `extra.release` is user data), and its value has the shape that field has
 * (an id is hex, a release is `name@version`, a file is a path with no query
 * string). A value that fails the shape stays redacted. Cookies are always
 * masked whole, whatever the options say.
 */

import { compilePolicy, type RedactOptions } from './index.js';

type Plain = Record<string, unknown>;
interface Checks {
  redactText: (text: string) => string;
  /**
   * True when nothing but the entropy detector finds anything in the text.
   * Entropy is why Sentry's fields need putting back under `strict` (a commit
   * hash looks random); any other detector firing means real data.
   */
  clean: (text: string) => boolean;
}
/** Decide what a kept field holds: the original, or what redaction made of it. */
type Guard = (original: unknown, redacted: unknown, checks: Checks) => unknown;

const isObject = (value: unknown): value is Plain => typeof value === 'object' && value !== null;
const own = (object: object, key: string): boolean => Object.prototype.hasOwnProperty.call(object, key);

/**
 * A string is put back only if it has the shape (and, when asked, is clean);
 * numbers and booleans always are.
 */
const shaped = (shape: RegExp, mustBeClean = false): Guard => (original, redacted, checks) => {
  if (typeof original === 'number' || typeof original === 'boolean' || original === null) return original;
  if (typeof original !== 'string' || original.length > 200 || !shape.test(original)) return redacted;
  return !mustBeClean || checks.clean(original) ? original : redacted;
};

/** Hex ids and UUIDs. */
const ID = shaped(/^[0-9A-Fa-f-]{8,64}$/);
/** `api@2.3.1`, a commit hash, `2026.11.14-rc1`: never an email (the part after `@` starts with a digit). */
const RELEASE = shaped(/^[A-Za-z0-9][A-Za-z0-9_.+/-]*(?:@v?[0-9][A-Za-z0-9_.+-]*)?$/, true);
/** Numbers and booleans only. */
const FLAG = shaped(/^$/);
/** Seconds since the epoch or an ISO date. */
const TIME = shaped(/^[0-9T:.+Z-]{1,40}$/);
/**
 * Names Sentry or the code gives things: `db.query`, `TypeError`,
 * `Object.handleRequest`, `auto.http.otel`. No `?`, `=`, `&` or `://`, no `@`
 * except as the first character (an npm scope), and no long run of digits, so
 * an address, a URL or a number does not pass.
 */
const NAME: Guard = (original, redacted, checks) => {
  if (typeof original !== 'string') return FLAG(original, redacted, checks);
  const ok = original.length <= 120
    && /^@?[^@?=&\s]+(?: [^@?=&\s]+){0,5}$/.test(original)
    && !original.includes('://')
    && !/[0-9]{6}/.test(original)
    && checks.clean(original);
  return ok ? original : redacted;
};
/** Sentry's own metadata, kept whole. */
const WHOLE: Guard = (original) => original;
/**
 * The file of a stack frame or debug image. The path is kept when it names a
 * file (it ends in an extension, or is a `node:` module); a query string or
 * fragment after it is redacted on its own, since the page URL of an inline
 * script can carry a token.
 */
const SCRIPT: Guard = (original, redacted, checks) => {
  if (typeof original !== 'string' || original.length > 2000) return redacted;
  const cut = original.search(/[?#]/);
  const path = cut < 0 ? original : original.slice(0, cut);
  if (!/\.[A-Za-z0-9]{1,8}$/.test(path) && !/^(?:node:[A-Za-z0-9_/.-]+|<anonymous>|native)$/.test(path)) return redacted;
  if (!checks.clean(path)) return redacted;
  return cut < 0 ? path : path + checks.redactText(original.slice(cut));
};

/** Which fields of a Sentry object are Sentry's own, by position. */
interface Keep {
  /** Fields at this level, each with the shape its value must have. */
  readonly keys?: Readonly<Record<string, Guard>>;
  /** Fields at this level to descend into. */
  readonly fields?: Readonly<Record<string, Keep>>;
  /** For an array: the shape of each item. */
  readonly items?: Keep;
  /** Attribute names (with their guard) kept at this level; the first match wins. */
  readonly attributes?: ReadonlyArray<readonly [RegExp, Guard]>;
}

/**
 * Attributes Sentry sets itself on spans and logs. The span name, the log
 * message template and its parameters also live under `sentry.` and are user
 * data, so the list is explicit.
 */
const SENTRY_ATTRIBUTES: Keep = {
  attributes: [
    [/^sentry\.(?:release|dist)$/, RELEASE],
    [/^sentry\.(?:segment\.id|trace\.parent_span_id|replay_id|profiler_id|profile_id)$/, ID],
    [/^sentry\.sdk\.[a-z_.]+$/, WHOLE],
    [/^sentry\.(?:environment|platform|origin|op|source|trace_lifecycle|segment\.name\.source|idle_span_finish_reason)$/, NAME],
    [/^sentry\.(?:sample_rate|exclusive_time|is_remote|timestamp\.sequence)$/, FLAG],
  ],
};

const FRAME: Keep = {
  keys: {
    filename: SCRIPT, abs_path: SCRIPT, module: NAME, function: NAME, raw_function: NAME, platform: NAME,
    package: SCRIPT, symbol: NAME, lineno: FLAG, colno: FLAG, in_app: FLAG, debug_id: ID,
    symbol_addr: NAME, image_addr: NAME, instruction_addr: NAME, addr_mode: NAME,
  },
};
const STACKTRACE: Keep = { fields: { frames: { items: FRAME } } };
const MECHANISM: Keep = {
  keys: { type: NAME, source: NAME, handled: FLAG, synthetic: FLAG, is_exception_group: FLAG, exception_id: FLAG, parent_id: FLAG },
};
/** Exceptions and threads: `{ values: [...] }` or, in older payloads, a bare array. */
const withStack = (keys: Readonly<Record<string, Guard>>, fields: Readonly<Record<string, Keep>> = {}): Keep => {
  const item: Keep = { keys, fields: { stacktrace: STACKTRACE, raw_stacktrace: STACKTRACE, ...fields } };
  return { items: item, fields: { values: { items: item } } };
};

const LINK: Keep = { keys: { span_id: ID, trace_id: ID, parent_span_id: ID, sampled: FLAG } };
/** Both span formats: the one inside a transaction and the streamed one (Sentry 11). */
const SPAN: Keep = {
  keys: {
    span_id: ID, trace_id: ID, parent_span_id: ID, segment_id: ID, profile_id: ID, is_segment: FLAG,
    start_timestamp: TIME, timestamp: TIME, end_timestamp: TIME, exclusive_time: FLAG,
    op: NAME, origin: NAME, status: NAME,
  },
  fields: { data: SENTRY_ATTRIBUTES, attributes: SENTRY_ATTRIBUTES, links: { items: LINK } },
};
const BREADCRUMB: Keep = { keys: { timestamp: TIME, type: NAME, level: NAME, category: NAME } };
const LOG: Keep = {
  keys: { timestamp: TIME, level: NAME, severity_number: FLAG, severityNumber: FLAG, trace_id: ID, span_id: ID },
  fields: { attributes: SENTRY_ATTRIBUTES },
};

const EVENT: Keep = {
  keys: {
    event_id: ID, type: NAME, timestamp: TIME, start_timestamp: TIME, received: TIME, platform: NAME, level: NAME,
    release: RELEASE, dist: RELEASE, environment: NAME, sdk: WHOLE,
    // Never sent: the SDK reads it after this hook to build the envelope.
    sdkProcessingMetadata: WHOLE,
  },
  fields: {
    contexts: {
      fields: {
        trace: SPAN,
        replay: { keys: { replay_id: ID } },
        profile: { keys: { profile_id: ID, profiler_id: ID } },
      },
    },
    exception: withStack({ type: NAME, module: NAME, thread_id: FLAG }, { mechanism: MECHANISM }),
    threads: withStack({ id: FLAG, crashed: FLAG, current: FLAG, main: FLAG }),
    spans: { items: SPAN },
    breadcrumbs: { items: BREADCRUMB, fields: { values: { items: BREADCRUMB } } },
    debug_meta: {
      fields: {
        images: {
          items: {
            keys: {
              type: NAME, debug_id: ID, code_id: NAME, code_file: SCRIPT, debug_file: SCRIPT, arch: NAME,
              image_addr: NAME, image_size: FLAG, image_vmaddr: NAME,
            },
          },
        },
      },
    },
  },
};

const MASK = '***';
const COOKIE_HEADER = /^(?:set-)?cookie$/i;

/** Every cookie value replaced, whatever its type: a string, a name-to-value map, a list. */
function maskCookies(value: unknown): unknown {
  if (value === undefined || value === null) return value;
  if (Array.isArray(value)) return value.map(() => MASK);
  if (isObject(value)) {
    const out: Plain = {};
    for (const name of Object.keys(value)) out[name] = MASK;
    return out;
  }
  return MASK;
}

/** A copy of a request or response object with its cookies masked. */
function withoutCookies(source: unknown): unknown {
  if (!isObject(source) || Array.isArray(source)) return source;
  const out: Plain = { ...source };
  if (own(out, 'cookies')) out.cookies = maskCookies(out.cookies);
  const { headers } = out;
  if (isObject(headers) && !Array.isArray(headers)) {
    const copy: Plain = { ...headers };
    for (const name of Object.keys(copy)) {
      if (COOKIE_HEADER.test(name)) copy[name] = maskCookies(copy[name]);
    }
    out.headers = copy;
  }
  return out;
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
  const quiet = compilePolicy({ ...opts, disable: [...(opts.disable ?? []), 'high_entropy'] });
  const checks: Checks = {
    redactText: (text) => policy.redact(text),
    clean: (text) => quiet.scan(text).length === 0,
  };

  /**
   * The redacted value with Sentry's own fields put back. It never writes to
   * either argument: a level that changes is copied first, so a frozen event
   * or one that shares objects with the caller is safe.
   */
  const restore = (original: unknown, redacted: unknown, spec: Keep): unknown => {
    if (!isObject(original) || !isObject(redacted)) return redacted;
    if (Array.isArray(original) || Array.isArray(redacted)) {
      if (!Array.isArray(original) || !Array.isArray(redacted) || !spec.items) return redacted;
      const items = spec.items;
      return redacted.map((item, i) => (i < original.length ? restore(original[i], item, items) : item));
    }
    let out = redacted;
    const set = (key: string, value: unknown): void => {
      if (value === out[key]) return;
      if (out === redacted) out = { ...redacted };
      out[key] = value;
    };
    for (const [key, guard] of Object.entries(spec.keys ?? {})) {
      if (own(original, key) && own(redacted, key)) set(key, guard(original[key], redacted[key], checks));
    }
    for (const [field, child] of Object.entries(spec.fields ?? {})) {
      if (own(original, field) && own(redacted, field)) set(field, restore(original[field], redacted[field], child));
    }
    if (spec.attributes) {
      for (const key of Object.keys(redacted)) {
        if (!own(original, key)) continue;
        const rule = spec.attributes.find(([pattern]) => pattern.test(key));
        if (!rule) continue;
        const guard = rule[1];
        const before = original[key];
        const after = redacted[key];
        // Streamed spans and logs wrap each attribute as { value, type }.
        if (guard !== WHOLE && isObject(before) && isObject(after) && own(before, 'value') && own(after, 'value')) {
          const value = guard(before.value, after.value, checks);
          if (value !== after.value) set(key, { ...after, value });
        } else set(key, guard(before, after, checks));
      }
    }
    return out;
  };

  const scrub = <T>(input: T, spec: Keep): T => restore(input, policy.redact(input), spec) as T;

  const scrubEvent = <T>(input: T): T => {
    const out = scrub(input, EVENT);
    if (!isObject(out) || Array.isArray(out)) return out;
    const event: Plain = { ...out };
    if (own(event, 'request')) event.request = withoutCookies(event.request);
    const { contexts } = event;
    if (isObject(contexts) && !Array.isArray(contexts) && own(contexts, 'response')) {
      event.contexts = { ...contexts, response: withoutCookies(contexts.response) };
    }
    return event as T;
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

/**
 * Redact one Sentry error event or transaction. For a span, a log or a
 * breadcrumb use the matching hook from `sentryRedact()`: their own fields
 * sit in different places.
 */
export function redactSentryEvent<T>(event: T, opts: RedactOptions = {}): T {
  return sentryRedact(opts).beforeSend(event);
}
