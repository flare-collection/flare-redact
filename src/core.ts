/**
 * The redaction API itself: redact, scan and compiled policies over strings and
 * structures. Shared by `flare-redact` and `flare-redact/lite`; it never loads
 * entity recognition on its own.
 */
import { SENSITIVE_KEY_DETECTOR, SENSITIVE_PATH_DETECTOR } from './detectors.js';
import { createVault } from './vault.js';
import { bytesText, errorChain, mapGraph, numberText, PathHit, type SensitiveRule } from './graph.js';
import { applyPaths, compilePaths, REMOVE, type CompiledPath } from './paths.js';
import { printfStrings } from './printf.js';
import {
  resolveDetectors,
  keyMatcher,
  allowMatcher,
  makeReplacer,
  scanString,
  redactString,
  type RedactOptions,
  type Finding,
  type Hit,
} from './engine.js';


interface PreparedPolicy {
  opts: RedactOptions;
  dets: ReturnType<typeof resolveDetectors>;
  allow: ReturnType<typeof allowMatcher>;
  replace: ReturnType<typeof makeReplacer>;
  matchKey: ReturnType<typeof keyMatcher>;
  paths: CompiledPath[] | undefined;
}

function preparePolicy(opts: RedactOptions): PreparedPolicy {
  return {
    opts,
    dets: resolveDetectors(opts),
    allow: allowMatcher(opts),
    replace: makeReplacer(opts),
    matchKey: keyMatcher(opts),
    paths: compilePaths(opts.paths),
  };
}

/**
 * Apply the policy's path rules: each matched value is replaced (or removed with
 * `remove: true`) and wrapped so the walk that follows does not scan it again.
 */
function withPaths(input: unknown, policy: PreparedPolicy): unknown {
  const { paths, opts, allow, replace } = policy;
  if (!paths) return input;
  return applyPaths(input, paths, (value) => {
    if (opts.remove) return REMOVE;
    if (value === undefined || value === null) return value;
    if (typeof value === 'string') {
      return new PathHit(allow(value) ? value : replace(value, SENSITIVE_PATH_DETECTOR));
    }
    if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
      return new PathHit(replace(String(value), SENSITIVE_PATH_DETECTOR));
    }
    return new PathHit(typeof opts.mask === 'string' ? opts.mask : '***');
  });
}

/** For scans: wrap each matched value so the walk reports it as one finding. */
function markPaths(input: unknown, policy: PreparedPolicy): unknown {
  const { paths } = policy;
  if (!paths) return input;
  return applyPaths(input, paths, (value) => (value === undefined || value === null ? value : new PathHit(value)));
}

function pathFinding(path: string, value: unknown, includeValues: boolean | undefined): Finding {
  return {
    detector: SENSITIVE_PATH_DETECTOR.id,
    label: SENSITIVE_PATH_DETECTOR.label,
    why: `Value at a redacted path ("${path}").`,
    ...(includeValues && typeof value === 'string' ? { value } : {}),
    path,
    risk: 'critical',
    confidence: 1,
  };
}

function redactPrepared<T>(input: T, policy: PreparedPolicy): T {
  const { opts, dets, allow, replace, matchKey } = policy;
  return mapGraph(
    withPaths(input, policy),
    (value) => redactString(value, dets, allow, replace, opts),
    sensitiveRule(policy),
  ) as T;
}

/** Spec section 9: what replaces a value under a sensitive key. */
function sensitiveRule(policy: PreparedPolicy): SensitiveRule {
  const { allow, replace, matchKey } = policy;
  return {
    matches: matchKey,
    replace: (text) => (allow(text) ? undefined : replace(text, SENSITIVE_KEY_DETECTOR)),
  };
}

export function redact<T>(input: T, opts: RedactOptions = {}): T {
  return redactPrepared(input, preparePolicy(opts));
}

async function resolvedSemanticOptions(text: string, opts: RedactOptions): Promise<RedactOptions> {
  if (!opts.semanticProvider) return opts;
  const findings = await opts.semanticProvider.detect(text);
  return { ...opts, semanticProvider: { detect: () => findings } };
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
async function redactAsyncPrepared<T>(input: T, policy: PreparedPolicy): Promise<T> {
  const { opts, dets, allow, replace } = policy;
  const rule = sensitiveRule(policy);
  const seen = new WeakMap<object, unknown>();
  const seenHot = new WeakMap<object, unknown>();

  const cold = async (text: string): Promise<string> =>
    redactString(text, dets, allow, replace, await resolvedSemanticOptions(text, opts));
  const text = (value: string, hot: boolean): Promise<string> | string =>
    hot ? (rule.replace(value) ?? cold(value)) : cold(value);

  const walk = async (value: unknown, hot = false): Promise<unknown> => {
    if (typeof value === 'string') return text(value, hot);
    if (hot && (typeof value === 'number' || typeof value === 'bigint')) {
      return rule.replace(numberText(value)) ?? value;
    }
    if (!value || typeof value !== 'object') return value;
    if (value instanceof PathHit) return value.value;
    const cache = hot ? seenHot : seen;
    const cached = cache.get(value);
    if (cached !== undefined) return cached;

    if (hot && (value instanceof ArrayBuffer || ArrayBuffer.isView(value))) {
      const out = rule.replace(bytesText(value)) ?? value;
      cache.set(value, out);
      return out;
    }

    if (value instanceof Error) {
      const out = Object.create(Object.getPrototypeOf(value)) as Error;
      cache.set(value, out);
      Object.defineProperties(out, {
        name: { value: value.name, writable: true, configurable: true },
        message: { value: await text(value.message, hot), writable: true, configurable: true },
        ...(typeof value.stack === 'string'
          ? { stack: { value: await text(value.stack, hot), writable: true, configurable: true } }
          : {}),
      });
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        const sensitive = hot || (typeof key === 'string' && rule.matches(key));
        Object.defineProperty(out, key, { ...descriptor, value: await walk(descriptor.value, sensitive) });
      }
      for (const [key, descriptor] of errorChain(value)) {
        Object.defineProperty(out, key, { ...descriptor, value: await walk(descriptor.value, hot) });
      }
      return out;
    }

    if (value instanceof URL || value instanceof URLSearchParams) {
      const masked = await text(value.toString(), hot);
      const out = hot ? masked : value instanceof URL ? new URL(masked) : new URLSearchParams(masked);
      cache.set(value, out);
      return out;
    }

    if (value instanceof Map) {
      const out = new Map<unknown, unknown>();
      cache.set(value, out);
      for (const [key, entry] of value) {
        const sensitive = hot || (typeof key === 'string' && rule.matches(key));
        out.set(await walk(key), await walk(entry, sensitive));
      }
      return out;
    }
    if (value instanceof Set) {
      const out = new Set<unknown>();
      cache.set(value, out);
      for (const entry of value) out.add(await walk(entry, hot));
      return out;
    }
    if (value instanceof Date || value instanceof RegExp || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      return value;
    }

    const out: Record<PropertyKey, unknown> | unknown[] = Array.isArray(value)
      ? new Array(value.length)
      : Object.create(Object.getPrototypeOf(value)) as Record<PropertyKey, unknown>;
    cache.set(value, out);
    for (const key of Reflect.ownKeys(value)) {
      if (Array.isArray(value) && key === 'length') continue;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) continue;
      const isIndex = Array.isArray(value) && typeof key === 'string' && /^(?:0|[1-9][0-9]*)$/.test(key);
      const sensitive = hot || (!isIndex && typeof key === 'string' && rule.matches(key));
      Object.defineProperty(out, key, { ...descriptor, value: await walk(descriptor.value, sensitive) });
    }
    return out;
  };

  return walk(withPaths(input, policy)) as Promise<T>;
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
export async function redactAsync<T>(input: T, opts: RedactOptions = {}): Promise<T> {
  return redactAsyncPrepared(input, preparePolicy(opts));
}

/**
 * Findings for a value stored under a sensitive key (spec section 9): one
 * `sensitive_key` finding for each string, number or binary value inside it,
 * at any depth. Strings the allowlist keeps (and Map keys, which are names) are
 * returned so the caller scans them like any other string.
 */
function sensitiveFindings(
  value: unknown,
  path: string,
  key: string,
  policy: PreparedPolicy,
  out: Finding[],
  seen: WeakSet<object>,
): Array<[string, string]> {
  const { allow, opts } = policy;
  const rest: Array<[string, string]> = [];
  const push = (text: string, at: string) => {
    out.push({
      detector: 'sensitive_key',
      label: 'Sensitive field',
      why: `Value stored under a sensitive field name ("${key}").`,
      ...(opts.includeValues ? { value: text } : {}),
      path: at,
      risk: 'critical',
      confidence: 0.98,
    });
  };
  const visit = (v: unknown, at: string): void => {
    if (typeof v === 'string') {
      if (allow(v)) rest.push([v, at]);
      else push(v, at);
      return;
    }
    if (typeof v === 'number' || typeof v === 'bigint') {
      const text = numberText(v);
      if (!allow(text)) push(text, at);
      return;
    }
    if (!v || typeof v !== 'object') return;
    if (v instanceof PathHit) {
      out.push(pathFinding(at, v.value, opts.includeValues));
      return;
    }
    if (seen.has(v)) return;
    seen.add(v);
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) {
      const text = bytesText(v);
      if (!allow(text)) push(text, at);
      return;
    }
    if (v instanceof URL || v instanceof URLSearchParams) {
      visit(v.toString(), at);
      return;
    }
    if (v instanceof Date || v instanceof RegExp) return;
    if (v instanceof Error) {
      visit(v.message, `${at}.message`);
      for (const [name, descriptor] of errorChain(v)) visit(descriptor.value, `${at}.${name}`);
    }
    if (v instanceof Map) {
      let index = 0;
      for (const [k, entry] of v) {
        if (typeof k === 'string') rest.push([k, `${at}.<map-key:${index}>`]);
        visit(entry, `${at}.<map-value:${index}>`);
        index++;
      }
      return;
    }
    if (v instanceof Set) {
      let index = 0;
      for (const entry of v) visit(entry, `${at}[${index++}]`);
      return;
    }
    if (Array.isArray(v)) {
      v.forEach((entry, i) => visit(entry, `${at}[${i}]`));
      return;
    }
    for (const k of Reflect.ownKeys(v)) {
      const descriptor = Object.getOwnPropertyDescriptor(v, k);
      if (!descriptor?.enumerable || !('value' in descriptor)) continue;
      visit(descriptor.value, `${at}.${typeof k === 'symbol' ? `[${String(k)}]` : k}`);
    }
  };
  visit(value, path);
  return rest;
}

function scanPrepared(input: unknown, policy: PreparedPolicy): Finding[] {
  const { opts, dets, allow, matchKey } = policy;
  const out: Finding[] = [];
  const seen = new WeakSet<object>();
  const seenHot = new WeakSet<object>();

  const push = (h: Hit, location: { line: number; column: number }, path?: string) => {
    const { det: _det, ...f } = h;
    const safe = opts.includeValues ? f : withoutValue(f);
    out.push(path ? { ...safe, ...location, path } : { ...safe, ...location });
  };

  const walk = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      const hits = scanString(value, dets, allow, opts);
      let cursor = 0;
      let line = 1;
      let lineStart = 0;
      for (const h of hits) {
        const start = h.start ?? 0;
        while (cursor < start) {
          if (value.charCodeAt(cursor) === 10) {
            line++;
            lineStart = cursor + 1;
          }
          cursor++;
        }
        push(h, { line, column: start - lineStart + 1 }, path || undefined);
      }
    } else if (value && typeof value === 'object') {
      if (seen.has(value)) return;
      seen.add(value);
      if (value instanceof Error) {
        walk(value.message, path ? `${path}.message` : 'message');
        for (const [key, descriptor] of errorChain(value)) walk(descriptor.value, path ? `${path}.${key}` : key);
      }
      if (value instanceof URL || value instanceof URLSearchParams) {
        walk(value.toString(), path);
        return;
      }
      if (value instanceof Map) {
        let index = 0;
        for (const [key, entry] of value) {
          walk(key, `${path}.<map-key:${index}>`);
          const at = `${path}.<map-value:${index}>`;
          if (typeof key === 'string' && matchKey(key)) {
            for (const [text, p] of sensitiveFindings(entry, at, key, policy, out, seenHot)) walk(text, p);
          } else {
            walk(entry, at);
          }
          index++;
        }
        return;
      }
      if (value instanceof Set) {
        let index = 0;
        for (const entry of value) walk(entry, `${path}[${index++}]`);
        return;
      }
      if (value instanceof Date || value instanceof RegExp || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        return;
      }
    }
    if (Array.isArray(value)) {
      value.forEach((v, i) => {
        if (v instanceof PathHit) out.push(pathFinding(`${path}[${i}]`, v.value, opts.includeValues));
        else walk(v, `${path}[${i}]`);
      });
    } else if (value && typeof value === 'object') {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        const v = descriptor.value as unknown;
        const name = typeof key === 'symbol' ? `[${String(key)}]` : key;
        const child = path ? `${path}.${name}` : name;
        if (v instanceof PathHit) {
          out.push(pathFinding(child, v.value, opts.includeValues));
        } else if (typeof key === 'string' && matchKey(key)) {
          for (const [text, at] of sensitiveFindings(v, child, key, policy, out, seenHot)) walk(text, at);
        } else {
          walk(v, child);
        }
      }
    }
  };

  walk(markPaths(input, policy), '');
  return out;
}

export function scan(input: unknown, opts: RedactOptions = {}): Finding[] {
  return scanPrepared(input, preparePolicy(opts));
}

function withoutValue(finding: Omit<Hit, 'det'>): Finding {
  const { value: _value, ...safe } = finding;
  return safe;
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
async function scanAsyncPrepared(input: unknown, policy: PreparedPolicy): Promise<Finding[]> {
  const { opts, dets, allow, matchKey } = policy;
  const out: Finding[] = [];
  const seen = new WeakSet<object>();
  const seenHot = new WeakSet<object>();

  const walk = async (value: unknown, path: string): Promise<void> => {
    if (typeof value === 'string') {
      const localOpts = await resolvedSemanticOptions(value, opts);
      const hits = scanString(value, dets, allow, localOpts);
      let cursor = 0;
      let line = 1;
      let lineStart = 0;
      for (const h of hits) {
        const start = h.start ?? 0;
        while (cursor < start) {
          if (value.charCodeAt(cursor) === 10) {
            line++;
            lineStart = cursor + 1;
          }
          cursor++;
        }
        const { det: _det, ...finding } = h;
        const located = {
          ...(opts.includeValues ? finding : withoutValue(finding)),
          line,
          column: start - lineStart + 1,
        };
        out.push(path ? { ...located, path } : located);
      }
    } else if (value && typeof value === 'object') {
      if (seen.has(value)) return;
      seen.add(value);
      if (value instanceof Error) {
        await walk(value.message, path ? `${path}.message` : 'message');
        for (const [key, descriptor] of errorChain(value)) await walk(descriptor.value, path ? `${path}.${key}` : key);
      }
      if (value instanceof URL || value instanceof URLSearchParams) {
        await walk(value.toString(), path);
        return;
      }
      if (value instanceof Map) {
        let index = 0;
        for (const [key, entry] of value) {
          await walk(key, `${path}.<map-key:${index}>`);
          const at = `${path}.<map-value:${index}>`;
          if (typeof key === 'string' && matchKey(key)) {
            for (const [text, p] of sensitiveFindings(entry, at, key, policy, out, seenHot)) await walk(text, p);
          } else {
            await walk(entry, at);
          }
          index++;
        }
        return;
      }
      if (value instanceof Set) {
        let index = 0;
        for (const entry of value) await walk(entry, `${path}[${index++}]`);
        return;
      }
      if (value instanceof Date || value instanceof RegExp || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
        return;
      }
    }
    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const v = value[i] as unknown;
        if (v instanceof PathHit) out.push(pathFinding(`${path}[${i}]`, v.value, opts.includeValues));
        else await walk(v, `${path}[${i}]`);
      }
    } else if (value && typeof value === 'object') {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        const v = descriptor.value as unknown;
        const name = typeof key === 'symbol' ? `[${String(key)}]` : key;
        const child = path ? `${path}.${name}` : name;
        if (v instanceof PathHit) {
          out.push(pathFinding(child, v.value, opts.includeValues));
        } else if (typeof key === 'string' && matchKey(key)) {
          for (const [text, at] of sensitiveFindings(v, child, key, policy, out, seenHot)) await walk(text, at);
        } else {
          await walk(v, child);
        }
      }
    }
  };

  await walk(markPaths(input, policy), '');
  return out;
}

export async function scanAsync(input: unknown, opts: RedactOptions = {}): Promise<Finding[]> {
  return scanAsyncPrepared(input, preparePolicy(opts));
}
export async function isCleanAsync(input: unknown, opts: RedactOptions = {}): Promise<boolean> {
  return (await scanAsync(input, opts)).length === 0;
}

export function isClean(input: unknown, opts: RedactOptions = {}): boolean {
  return scan(input, opts).length === 0;
}

export function summary(
  input: unknown,
  opts: RedactOptions = {},
): { total: number; byDetector: Record<string, number>; byRisk: Record<string, number> } {
  return summarizeFindings(scan(input, opts));
}

function summarizeFindings(
  findings: Finding[],
): { total: number; byDetector: Record<string, number>; byRisk: Record<string, number> } {
  const byDetector: Record<string, number> = {};
  const byRisk: Record<string, number> = {};
  for (const f of findings) {
    byDetector[f.detector] = (byDetector[f.detector] ?? 0) + 1;
    byRisk[f.risk] = (byRisk[f.risk] ?? 0) + 1;
  }
  return { total: findings.length, byDetector, byRisk };
}

/**
 * Bind one set of options into a policy you reuse everywhere: in code, on a
 * logger, in HTTP, in front of an LLM. `options` is the same object every
 * adapter (`flare-redact/pino`, `/winston`, `/http`, `/llm`) accepts, so a
 * secret is masked the same way across your whole system.
 */
export function compilePolicy(opts: RedactOptions = {}) {
  const policy = preparePolicy(opts);
  return {
    options: opts,
    redact: <T>(input: T) => redactPrepared(input, policy),
    redactAsync: <T>(input: T) => redactAsyncPrepared(input, policy),
    scan: (input: unknown) => scanPrepared(input, policy),
    scanAsync: (input: unknown) => scanAsyncPrepared(input, policy),
    isClean: (input: unknown) => scanPrepared(input, policy).length === 0,
    isCleanAsync: async (input: unknown) => (await scanAsyncPrepared(input, policy)).length === 0,
    summary: (input: unknown) => summarizeFindings(scanPrepared(input, policy)),
    vault: () => createVault(opts),
    wrapConsole: (target?: Console) => wrapConsole(opts, target),
  };
}

/** Backward-compatible name for a precompiled reusable policy. */
export const createRedactor = compilePolicy;

/** Alias for {@link createRedactor}, read as "define the masking policy once". */
export const definePolicy = compilePolicy;

type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';
type LogFn = (...args: unknown[]) => void;

export function wrapConsole(opts: RedactOptions = {}, target: Console = console): () => void {
  const sink = target as unknown as Record<ConsoleMethod, LogFn>;
  const methods: ConsoleMethod[] = ['log', 'info', 'warn', 'error', 'debug'];
  const original = new Map<ConsoleMethod, LogFn>();
  for (const name of methods) {
    const fn = sink[name].bind(target) as LogFn;
    original.set(name, fn);
    sink[name] = (...args: unknown[]) => fn(...printfStrings(args).map((a) => redact(a, opts)));
  }
  return () => {
    for (const [name, fn] of original) sink[name] = fn;
  };
}
