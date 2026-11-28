/**
 * Path rules: redact or remove the value at a named place in a structure, the
 * way pino's `redact.paths` and fast-redact do, with `**` added for any depth.
 *
 *   user.password            one property
 *   users[0].token           an array index
 *   users.*.password         `*` is any one key or index
 *   **.authorization         `**` is any number of levels, including none
 *   headers["x-api-key"]     brackets for keys that are not identifiers
 *
 * Keys are compared exactly, as written. Path rules run before the value
 * detectors and the sensitive-key rule, which still apply everywhere else.
 */
import { FlareRedactError } from './engine.js';

export type PathSegment =
  | { readonly kind: 'key'; readonly key: string }
  | { readonly kind: 'any' }
  | { readonly kind: 'deep' };

export type CompiledPath = readonly PathSegment[];

/** Returned by a censor to delete the property (or array element) instead. */
export const REMOVE: unique symbol = Symbol('flare-redact.remove');

export type Censor = (value: unknown, path: string) => unknown;

const IDENT = /[A-Za-z0-9_$\-]/;

function invalid(path: string, why: string): never {
  throw new FlareRedactError('ERR_INVALID_PATH', `Invalid redaction path ${JSON.stringify(path)}: ${why}`);
}

/** Parse one path into segments, or throw `ERR_INVALID_PATH`. */
export function parsePath(path: string): CompiledPath {
  if (typeof path !== 'string') invalid(String(path), 'a path is a string');
  const src = path.trim();
  if (!src) invalid(path, 'the path is empty');
  const out: PathSegment[] = [];
  let i = 0;
  let expectSegment = true;
  while (i < src.length) {
    const ch = src[i]!;
    if (ch === '.') {
      if (expectSegment) invalid(path, `unexpected "." at ${i}`);
      expectSegment = true;
      i++;
      continue;
    }
    if (ch === '[') {
      const close = src[i + 1] === '"' || src[i + 1] === "'" ? quotedEnd(src, i + 1, path) : src.indexOf(']', i);
      if (close < 0) invalid(path, `unclosed "[" at ${i}`);
      const inner = src.slice(i + 1, close).trim();
      if (inner === '*') out.push({ kind: 'any' });
      else if (/^\d+$/.test(inner)) out.push({ kind: 'key', key: String(Number(inner)) });
      else if (inner.length >= 2 && (inner[0] === '"' || inner[0] === "'") && inner.at(-1) === inner[0]) {
        out.push({ kind: 'key', key: unquote(inner, path) });
      } else invalid(path, `"[${inner}]" is not an index, "*" or a quoted key`);
      i = close + 1;
      expectSegment = false;
      continue;
    }
    if (!expectSegment) invalid(path, `expected "." or "[" at ${i}`);
    let j = i;
    while (j < src.length && src[j] !== '.' && src[j] !== '[') j++;
    const word = src.slice(i, j);
    if (word === '**') out.push({ kind: 'deep' });
    else if (word === '*') out.push({ kind: 'any' });
    else if ([...word].every((c) => IDENT.test(c))) out.push({ kind: 'key', key: word });
    else invalid(path, `"${word}" needs brackets, as ["${word}"]`);
    i = j;
    expectSegment = false;
  }
  if (expectSegment) invalid(path, 'the path ends with "."');
  if (out.every((s) => s.kind === 'deep')) invalid(path, 'the path would match the whole input');
  return out;
}

function quotedEnd(src: string, open: number, path: string): number {
  const quote = src[open];
  for (let k = open + 1; k < src.length; k++) {
    if (src[k] === '\\') {
      k++;
      continue;
    }
    if (src[k] === quote) {
      let close = k + 1;
      while (src[close] === ' ') close++;
      if (src[close] !== ']') invalid(path, `expected "]" after the quoted key at ${k}`);
      return close;
    }
  }
  return invalid(path, `unclosed quote at ${open}`);
}

function unquote(inner: string, path: string): string {
  const body = inner.slice(1, -1);
  let out = '';
  for (let k = 0; k < body.length; k++) {
    if (body[k] === '\\') {
      k++;
      if (k >= body.length) invalid(path, 'a quoted key ends with "\\"');
    }
    out += body[k];
  }
  return out;
}

/** Parse every path once; `undefined` or an empty list means no path rules. */
export function compilePaths(paths: readonly string[] | undefined): CompiledPath[] | undefined {
  if (paths === undefined) return undefined;
  if (!Array.isArray(paths)) invalid(String(paths), '`paths` is an array of strings');
  const compiled = paths.map(parsePath);
  return compiled.length ? compiled : undefined;
}

/**
 * The rules flattened into one table of states: state `i` is one segment of one
 * rule, and each rule ends in an ACCEPT state. A walk carries the small list of
 * states it is in, so matching costs a few array reads per key.
 */
const KEY = 0;
const ANY = 1;
const DEEP = 2;
const ACCEPT = 3;

interface Machine {
  kind: Uint8Array;
  key: (string | undefined)[];
  start: number[];
}

function buildMachine(rules: readonly CompiledPath[]): Machine {
  const kinds: number[] = [];
  const keys: (string | undefined)[] = [];
  const starts: number[] = [];
  for (const rule of rules) {
    starts.push(kinds.length);
    for (const seg of rule) {
      kinds.push(seg.kind === 'key' ? KEY : seg.kind === 'any' ? ANY : DEEP);
      keys.push(seg.kind === 'key' ? seg.key : undefined);
    }
    kinds.push(ACCEPT);
    keys.push(undefined);
  }
  const m: Machine = { kind: Uint8Array.from(kinds), key: keys, start: [] };
  m.start = closeStates(m, starts);
  return m;
}

/** Add the state after every `**`, since `**` may match no level at all. */
function closeStates(m: Machine, states: number[]): number[] {
  for (let i = 0; i < states.length; i++) {
    const s = states[i]!;
    if (m.kind[s] === DEEP && !states.includes(s + 1)) states.push(s + 1);
  }
  return states;
}

/** The states after reading `key`, and whether a rule ends there. */
function stepStates(m: Machine, states: readonly number[], key: string): { next: number[]; hit: boolean } {
  const next: number[] = [];
  for (const s of states) {
    const kind = m.kind[s];
    if (kind === DEEP) {
      if (!next.includes(s)) next.push(s);
    } else if ((kind === ANY || (kind === KEY && m.key[s] === key)) && !next.includes(s + 1)) {
      next.push(s + 1);
    }
  }
  closeStates(m, next);
  let hit = false;
  let w = 0;
  for (const s of next) {
    if (m.kind[s] === ACCEPT) hit = true;
    else next[w++] = s;
  }
  next.length = w;
  return { next, hit };
}

/** When every state names its key, only those keys can matter. */
function namedKeys(m: Machine, states: readonly number[]): string[] | undefined {
  const out: string[] = [];
  for (const s of states) {
    if (m.kind[s] !== KEY) return undefined;
    const key = m.key[s]!;
    if (!out.includes(key)) out.push(key);
  }
  return out;
}

const machines = new WeakMap<readonly CompiledPath[], Machine>();

function isContainer(value: unknown): value is object {
  if (!value || typeof value !== 'object') return false;
  return !(
    value instanceof Date ||
    value instanceof RegExp ||
    value instanceof Map ||
    value instanceof Set ||
    value instanceof Promise ||
    value instanceof WeakMap ||
    value instanceof WeakSet ||
    value instanceof ArrayBuffer ||
    ArrayBuffer.isView(value) ||
    (typeof URL !== 'undefined' && value instanceof URL) ||
    (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams)
  );
}

/**
 * A copy with every own property, made configurable so a frozen input can be
 * copied. Plain objects take the fast path; anything else keeps its prototype
 * and its non-enumerable properties (an Error's message and stack).
 */
function shallowCopy(value: object): Record<string, unknown> {
  const proto = Object.getPrototypeOf(value);
  if (proto === Object.prototype || proto === null) {
    const out = { ...(value as Record<string, unknown>) };
    return proto === null ? Object.assign(Object.create(null) as Record<string, unknown>, out) : out;
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    const d = descriptors[key as keyof typeof descriptors] as PropertyDescriptor;
    d.configurable = true;
    if ('value' in d) d.writable = true;
  }
  return Object.create(proto, descriptors) as Record<string, unknown>;
}

function childPath(parent: string, key: string, isIndex: boolean): string {
  if (isIndex) return `${parent}[${key}]`;
  return parent ? `${parent}.${key}` : key;
}

/**
 * Apply path rules to `input`. Matched values are passed to `censor`, which
 * returns the replacement or {@link REMOVE}. Only the containers on the way to a
 * match are copied; the input is never modified and everything else is shared.
 */
export function applyPaths(input: unknown, rules: readonly CompiledPath[], censor: Censor): unknown {
  let m = machines.get(rules);
  if (!m) {
    m = buildMachine(rules);
    machines.set(rules, m);
  }
  const machine = m;
  const onPath = new Set<object>();

  const walk = (value: unknown, states: readonly number[], path: string): unknown => {
    if (!states.length || !isContainer(value) || onPath.has(value)) return value;
    onPath.add(value);
    try {
      const only = namedKeys(machine, states);
      if (Array.isArray(value)) {
        let out: unknown[] | undefined;
        let removed = false;
        const visit = (i: number): void => {
          if (!Object.prototype.hasOwnProperty.call(value, i)) return;
          const key = String(i);
          const { next, hit } = stepStates(machine, states, key);
          const here = childPath(path, key, true);
          const before = value[i];
          const after = hit ? censor(before, here) : walk(before, next, here);
          if (after !== before) {
            out ??= value.slice();
            out[i] = after;
            if (after === REMOVE) removed = true;
          }
        };
        if (only) {
          for (const key of only) if (/^(?:0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length) visit(Number(key));
        } else {
          for (let i = 0; i < value.length; i++) visit(i);
        }
        if (!out) return value;
        return removed ? out.filter((v) => v !== REMOVE) : out;
      }
      let out: Record<string, unknown> | undefined;
      const keys = only ? only.filter((k) => Object.prototype.hasOwnProperty.call(value, k)) : Object.keys(value);
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (!descriptor || !descriptor.enumerable || !('value' in descriptor)) continue;
        const { next, hit } = stepStates(machine, states, key);
        const here = childPath(path, key, false);
        const before = descriptor.value as unknown;
        const after = hit ? censor(before, here) : walk(before, next, here);
        if (after === before) continue;
        out ??= shallowCopy(value);
        if (after === REMOVE) delete out[key];
        else if (Object.getOwnPropertyDescriptor(out, key)?.writable) out[key] = after;
        else Object.defineProperty(out, key, { ...descriptor, value: after, writable: true, configurable: true });
      }
      return out ?? value;
    } finally {
      onPath.delete(value);
    }
  };

  return walk(input, machine.start, '');
}
