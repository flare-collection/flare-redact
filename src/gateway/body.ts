/**
 * Body handling: which parts of a payload get redacted, and how the originals
 * come back.
 *
 * Two things here are worth reading before changing anything.
 *
 * **Path selection.** Redacting an entire request body is the safe default, but
 * for a chat completion it also rewrites the model name and the tool schema.
 * `messages[*].content` says "only the parts a human typed", which keeps the
 * request semantically intact.
 *
 * **Streamed restoration.** A placeholder can be split across two chunks of a
 * stream, and it always lands inside a JSON string. The incremental restorer
 * handles the split; escaping the *original* for a JSON string context handles
 * the quote in `O'Brien "Bob" Smith` that would otherwise produce a body the
 * client cannot parse.
 */

import { buildStreamRestore, type IncrementalRestorer, type Vault } from '../index.js';

export type PathSegment =
  | { kind: 'key'; name: string }
  | { kind: 'index'; index: number }
  | { kind: 'anyIndex' }
  | { kind: 'anyKey' };

export type ParsedPath = PathSegment[];

export class PathSyntaxError extends Error {
  constructor(path: string, detail: string) {
    super(`invalid body path ${JSON.stringify(path)}: ${detail}`);
    this.name = 'PathSyntaxError';
  }
}

/**
 * Parse `messages[*].content` into segments. Supported: dotted keys, `*` for any
 * key, `[n]` for one index, `[*]` for every element.
 */
export function parsePath(path: string): ParsedPath {
  const segments: ParsedPath = [];
  let index = 0;
  const readName = (): string => {
    const start = index;
    while (index < path.length && path[index] !== '.' && path[index] !== '[') index++;
    return path.slice(start, index);
  };

  while (index < path.length) {
    if (path[index] === '.') {
      index++;
      continue;
    }
    if (path[index] === '[') {
      const close = path.indexOf(']', index);
      if (close < 0) throw new PathSyntaxError(path, 'unclosed "["');
      const inner = path.slice(index + 1, close);
      if (inner === '*') {
        segments.push({ kind: 'anyIndex' });
      } else if (/^\d+$/.test(inner)) {
        segments.push({ kind: 'index', index: Number(inner) });
      } else {
        throw new PathSyntaxError(path, `"[${inner}]" must be a number or "*"`);
      }
      index = close + 1;
      continue;
    }
    const name = readName();
    if (!name) throw new PathSyntaxError(path, 'empty path segment');
    segments.push(name === '*' ? { kind: 'anyKey' } : { kind: 'key', name });
  }

  if (!segments.length) throw new PathSyntaxError(path, 'path is empty');
  return segments;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

/**
 * Apply `transform` to every node matching `segments`, returning a new value.
 * Untouched branches keep their identity, so a large payload with one redacted
 * field is not deep-cloned.
 */
export function transformAtPath(value: unknown, segments: ParsedPath, transform: (node: unknown) => unknown): unknown {
  if (!segments.length) return transform(value);
  const [head, ...rest] = segments as [PathSegment, ...PathSegment[]];

  if (head.kind === 'key' || head.kind === 'anyKey') {
    if (!isPlainObject(value)) return value;
    const keys = head.kind === 'key' ? (head.name in value ? [head.name] : []) : Object.keys(value);
    if (!keys.length) return value;
    const out: Record<string, unknown> = { ...value };
    let changed = false;
    for (const key of keys) {
      const next = transformAtPath(value[key], rest, transform);
      if (next !== value[key]) changed = true;
      out[key] = next;
    }
    return changed ? out : value;
  }

  if (!Array.isArray(value)) return value;
  const indexes = head.kind === 'index' ? (head.index < value.length ? [head.index] : []) : value.map((_, i) => i);
  if (!indexes.length) return value;
  const out = value.slice();
  let changed = false;
  for (const position of indexes) {
    const next = transformAtPath(value[position], rest, transform);
    if (next !== value[position]) changed = true;
    out[position] = next;
  }
  return changed ? out : value;
}

/** Apply `transform` at each of `paths`, in order. */
export function transformAtPaths(value: unknown, paths: ParsedPath[], transform: (node: unknown) => unknown): unknown {
  return paths.reduce((current, path) => transformAtPath(current, path, transform), value);
}

const JSON_TYPE = /^application\/(?:[\w.+-]+\+)?json\b/i;
const FORM_TYPE = /^application\/x-www-form-urlencoded\b/i;
const TEXT_TYPE = /^text\/(?!event-stream)/i;

export const isJsonType = (contentType: string): boolean => JSON_TYPE.test(contentType);
export const isFormType = (contentType: string): boolean => FORM_TYPE.test(contentType);
export const isTextType = (contentType: string): boolean => TEXT_TYPE.test(contentType);
export const isEventStream = (contentType: string): boolean => /^text\/event-stream\b/i.test(contentType);

export interface BodyRedactionOptions {
  contentType: string;
  paths?: ParsedPath[];
  /** Also handle form bodies and plain text, not just JSON. */
  nonJson: boolean;
  /** Redact a parsed value or a string. */
  redact: <T>(value: T) => T;
}

export interface BodyRedactionResult {
  body: string;
  /** True when the body was actually inspected — false means it passed through. */
  handled: boolean;
  /** The parsed body, when it was JSON, so the caller can scan it without reparsing. */
  parsed?: unknown;
}

/**
 * Redact a request body according to its declared content type.
 *
 * A body that claims to be JSON but does not parse is redacted as text rather
 * than forwarded untouched: the client's framing is already broken, and the
 * failure mode that matters is leaking, not mangling.
 */
export function redactBody(raw: string, options: BodyRedactionOptions): BodyRedactionResult {
  const { contentType, paths, nonJson, redact } = options;

  if (isJsonType(contentType)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      return { body: redact(raw), handled: true };
    }
    const next = paths?.length ? transformAtPaths(parsed, paths, (node) => redact(node)) : redact(parsed);
    return { body: JSON.stringify(next), handled: true, parsed: next };
  }

  if (!nonJson) return { body: raw, handled: false };

  if (isFormType(contentType)) {
    const params = new URLSearchParams(raw);
    const out = new URLSearchParams();
    for (const [key, value] of params) out.append(key, redact(value));
    return { body: out.toString(), handled: true };
  }

  if (isTextType(contentType) || !contentType) {
    return { body: redact(raw), handled: true };
  }

  return { body: raw, handled: false };
}

/**
 * Restore a buffered response body. JSON is restored structurally, which is
 * always correct; anything else is restored as text.
 */
export function restoreBody(raw: string, contentType: string, vault: Vault): string {
  if (isJsonType(contentType)) {
    try {
      return JSON.stringify(vault.restore(JSON.parse(raw)));
    } catch {
      return vault.restore(raw);
    }
  }
  return vault.restore(raw);
}

/**
 * Entries whose replacements are safe to splice into a JSON string literal.
 * `JSON.stringify(value).slice(1, -1)` is the escaped inner form of the string.
 */
export function jsonEscapedEntries(vault: Vault): Array<[string, string]> {
  return vault.entries().map(([placeholder, original]) => [placeholder, JSON.stringify(original).slice(1, -1)]);
}

/**
 * A restorer for a streamed response. Placeholders survive chunk boundaries, and
 * `escape: 'json'` makes the substituted original safe inside the JSON frames
 * that every LLM streaming API emits.
 */
export function streamRestorer(vault: Vault, escape: 'json' | 'none'): IncrementalRestorer {
  return buildStreamRestore(escape === 'json' ? jsonEscapedEntries(vault) : vault.entries());
}
