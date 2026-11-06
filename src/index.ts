import { SENSITIVE_KEY_DETECTOR } from './detectors.js';
import { createVault } from './vault.js';
import { mapGraph } from './graph.js';
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

export type { Mode, Risk, Finding, RedactOptions, SemanticFinding, SemanticProvider } from './engine.js';
export { FlareRedactError, RedactionLimitError } from './engine.js';
export type { Detector } from './detectors.js';
export {
  DETECTORS,
  SENSITIVE_KEY_RE,
  keepPrefix,
  keepLast,
  luhn,
  entropy,
  fnv1a,
} from './detectors.js';
export {
  secretProbability,
  extractFeatures,
  shannonEntropy,
  FEATURES,
  FEATURE_COUNT,
  CONFIDENCE_MODEL,
  type ConfidenceModel,
} from './ml.js';
export {
  recognizeEntities,
  createEntityRecognizer,
  ENTITY_LABELS,
  type EntityLabel,
  type EntityOptions,
  type EntityFinding,
} from './entities.js';
export { pseudonymize, surrogate, fpe } from './transforms.js';
export { hmacFingerprint } from './crypto.js';
export {
  createVault,
  restore,
  buildRestore,
  buildStreamRestore,
  type IncrementalRestorer,
  type Vault,
  type VaultOptions,
} from './vault.js';
export {
  sealVault,
  openVault,
  isSealedVault,
  type SealedVaultV1,
  type SealVaultOptions,
} from './secure-vault.js';
export { createSession, type Session, type SessionOptions, type StreamRestorer } from './session.js';

interface PreparedPolicy {
  opts: RedactOptions;
  dets: ReturnType<typeof resolveDetectors>;
  allow: ReturnType<typeof allowMatcher>;
  replace: ReturnType<typeof makeReplacer>;
  matchKey: ReturnType<typeof keyMatcher>;
}

function preparePolicy(opts: RedactOptions): PreparedPolicy {
  return {
    opts,
    dets: resolveDetectors(opts),
    allow: allowMatcher(opts),
    replace: makeReplacer(opts),
    matchKey: keyMatcher(opts),
  };
}

function redactPrepared<T>(input: T, policy: PreparedPolicy): T {
  const { opts, dets, allow, replace, matchKey } = policy;
  return mapGraph(
    input,
    (value) => redactString(value, dets, allow, replace, opts),
    (key, value) => matchKey(key) && !allow(value)
      ? replace(value, SENSITIVE_KEY_DETECTOR)
      : redactString(value, dets, allow, replace, opts),
  ) as T;
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
  const { opts, dets, allow, replace, matchKey } = policy;
  const seen = new WeakMap<object, unknown>();

  const walk = async (value: unknown): Promise<unknown> => {
    if (typeof value === 'string') {
      const localOpts = await resolvedSemanticOptions(value, opts);
      return redactString(value, dets, allow, replace, localOpts);
    }
    if (!value || typeof value !== 'object') return value;
    const cached = seen.get(value);
    if (cached !== undefined) return cached;

    if (value instanceof Error) {
      const out = Object.create(Object.getPrototypeOf(value)) as Error;
      seen.set(value, out);
      Object.defineProperties(out, {
        name: { value: value.name, writable: true, configurable: true },
        message: {
          value: redactString(
            value.message,
            dets,
            allow,
            replace,
            await resolvedSemanticOptions(value.message, opts),
          ),
          writable: true,
          configurable: true,
        },
        ...(typeof value.stack === 'string'
          ? {
              stack: {
                value: redactString(
                  value.stack,
                  dets,
                  allow,
                  replace,
                  await resolvedSemanticOptions(value.stack, opts),
                ),
                writable: true,
                configurable: true,
              },
            }
          : {}),
      });
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        Object.defineProperty(out, key, { ...descriptor, value: await walk(descriptor.value) });
      }
      return out;
    }

    if (value instanceof URL) {
      const localOpts = await resolvedSemanticOptions(value.toString(), opts);
      const out = new URL(redactString(value.toString(), dets, allow, replace, localOpts));
      seen.set(value, out);
      return out;
    }
    if (value instanceof URLSearchParams) {
      const localOpts = await resolvedSemanticOptions(value.toString(), opts);
      const out = new URLSearchParams(redactString(value.toString(), dets, allow, replace, localOpts));
      seen.set(value, out);
      return out;
    }

    if (value instanceof Map) {
      const out = new Map<unknown, unknown>();
      seen.set(value, out);
      for (const [key, entry] of value) out.set(await walk(key), await walk(entry));
      return out;
    }
    if (value instanceof Set) {
      const out = new Set<unknown>();
      seen.set(value, out);
      for (const entry of value) out.add(await walk(entry));
      return out;
    }
    if (value instanceof Date || value instanceof RegExp || value instanceof ArrayBuffer || ArrayBuffer.isView(value)) {
      return value;
    }

    const out: Record<PropertyKey, unknown> | unknown[] = Array.isArray(value)
      ? new Array(value.length)
      : Object.create(Object.getPrototypeOf(value)) as Record<PropertyKey, unknown>;
    seen.set(value, out);
    for (const key of Reflect.ownKeys(value)) {
      if (Array.isArray(value) && key === 'length') continue;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) continue;
      const raw = descriptor.value as unknown;
      const next = typeof key === 'string' && typeof raw === 'string' && matchKey(key) && !allow(raw)
        ? replace(raw, SENSITIVE_KEY_DETECTOR)
        : await walk(raw);
      Object.defineProperty(out, key, { ...descriptor, value: next });
    }
    return out;
  };

  return walk(input) as Promise<T>;
}

/** Async counterpart for local ML/NER providers whose `detect()` returns a Promise. */
export async function redactAsync<T>(input: T, opts: RedactOptions = {}): Promise<T> {
  return redactAsyncPrepared(input, preparePolicy(opts));
}

function scanPrepared(input: unknown, policy: PreparedPolicy): Finding[] {
  const { opts, dets, allow, matchKey } = policy;
  const out: Finding[] = [];
  const seen = new WeakSet<object>();

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
      }
      if (value instanceof URL || value instanceof URLSearchParams) {
        walk(value.toString(), path);
        return;
      }
      if (value instanceof Map) {
        let index = 0;
        for (const [key, entry] of value) {
          walk(key, `${path}.<map-key:${index}>`);
          walk(entry, `${path}.<map-value:${index}>`);
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
      value.forEach((v, i) => walk(v, `${path}[${i}]`));
    } else if (value && typeof value === 'object') {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        const v = descriptor.value as unknown;
        const name = typeof key === 'symbol' ? `[${String(key)}]` : key;
        const child = path ? `${path}.${name}` : name;
        if (typeof key === 'string' && typeof v === 'string' && matchKey(key) && !allow(v)) {
          out.push({
            detector: 'sensitive_key',
            label: 'Sensitive field',
            why: `Value stored under a sensitive field name ("${key}").`,
            ...(opts.includeValues ? { value: v } : {}),
            path: child,
            risk: 'critical',
            confidence: 0.98,
          });
        } else {
          walk(v, child);
        }
      }
    }
  };

  walk(input, '');
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
      }
      if (value instanceof URL || value instanceof URLSearchParams) {
        await walk(value.toString(), path);
        return;
      }
      if (value instanceof Map) {
        let index = 0;
        for (const [key, entry] of value) {
          await walk(key, `${path}.<map-key:${index}>`);
          await walk(entry, `${path}.<map-value:${index}>`);
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
      for (let i = 0; i < value.length; i++) await walk(value[i], `${path}[${i}]`);
    } else if (value && typeof value === 'object') {
      for (const key of Reflect.ownKeys(value)) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor?.enumerable || !('value' in descriptor)) continue;
        const v = descriptor.value as unknown;
        const name = typeof key === 'symbol' ? `[${String(key)}]` : key;
        const child = path ? `${path}.${name}` : name;
        if (typeof key === 'string' && typeof v === 'string' && matchKey(key) && !allow(v)) {
          out.push({
            detector: 'sensitive_key',
            label: 'Sensitive field',
            why: `Value stored under a sensitive field name ("${key}").`,
            ...(opts.includeValues ? { value: v } : {}),
            path: child,
            risk: 'critical',
            confidence: 0.98,
          });
        } else {
          await walk(v, child);
        }
      }
    }
  };

  await walk(input, '');
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
 * Bind one set of options into a policy you reuse everywhere — in code, on a
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
    sink[name] = (...args: unknown[]) => fn(...args.map((a) => redact(a, opts)));
  }
  return () => {
    for (const [name, fn] of original) sink[name] = fn;
  };
}
