import {
  resolveDetectors,
  keyMatcher,
  allowMatcher,
  scanString,
  type RedactOptions,
} from './engine.js';
import { mapGraph } from './graph.js';

export interface Vault {
  redact<T>(input: T): T;
  restore<T>(input: T): T;
  entries(): Array<[string, string]>;
  readonly size: number;
}

export interface VaultOptions extends RedactOptions {
  placeholder?: (detectorId: string, index: number) => string;
  /** Human-readable counters are predictable; use only for trusted local flows. */
  placeholderStyle?: 'opaque' | 'readable';
}

const escapeRe = (s: string): string => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function opaqueToken(): string {
  const provider = globalThis.crypto;
  if (!provider?.getRandomValues) throw new Error('Web Crypto is required to create opaque vault placeholders.');
  const bytes = provider.getRandomValues(new Uint8Array(12));
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * Build a single-pass restorer from placeholder→original entries. Longest
 * placeholders match first so prefix-like custom tokens cannot clobber peers.
 */
export function buildRestore(entries: Array<[string, string]>): (text: string) => string {
  if (!entries.length) return (t) => t;
  const sorted = [...entries].sort((a, b) => b[0].length - a[0].length);
  const lookup = new Map(sorted);
  const re = new RegExp(sorted.map(([ph]) => escapeRe(ph)).join('|'), 'g');
  return (text) => text.replace(re, (m) => lookup.get(m) ?? m);
}

/**
 * Each original escaped for the inside of a JSON string literal:
 * `JSON.stringify(value).slice(1, -1)`. A placeholder can only sit inside a
 * string in valid JSON, so an original spliced in this form keeps the JSON
 * valid, and quotes, backslashes or control characters in it cannot end the
 * string and add or replace fields.
 */
export function escapeEntriesForJson(entries: Array<[string, string]>): Array<[string, string]> {
  return entries.map(([placeholder, original]) => [placeholder, JSON.stringify(original).slice(1, -1)]);
}

const SIMPLE_ESCAPES: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };

function hex4(text: string, at: number): number {
  const digits = text.slice(at, at + 4);
  return /^[0-9A-Fa-f]{4}$/.test(digits) ? parseInt(digits, 16) : -1;
}

/**
 * `text` read as the content of a JSON string literal, or `undefined` when it
 * is not valid content: an unescaped quote or control character, an unknown or
 * cut-off escape, or a `\u` escape that leaves a lone surrogate (FRS-1 §11).
 */
export function decodeJsonStringContent(text: string): string | undefined {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const code = text.charCodeAt(i);
    if (code === 0x22 || code < 0x20) return undefined;
    if (code !== 0x5c) {
      out += text[i++];
      continue;
    }
    const simple = SIMPLE_ESCAPES[text[i + 1] ?? ''];
    if (simple !== undefined) {
      out += simple;
      i += 2;
      continue;
    }
    if (text[i + 1] !== 'u') return undefined;
    const unit = hex4(text, i + 2);
    i += 6;
    if (unit < 0 || (unit >= 0xdc00 && unit <= 0xdfff)) return undefined;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text[i] === '\\' && text[i + 1] === 'u' ? hex4(text, i + 2) : -1;
      if (low < 0xdc00 || low > 0xdfff) return undefined;
      out += String.fromCharCode(unit, low);
      i += 6;
      continue;
    }
    out += String.fromCharCode(unit);
  }
  return out;
}

/** True when `text` is a complete JSON object or array. */
export function isJsonDocument(text: string): boolean {
  const first = text.trimStart()[0];
  if (first !== '{' && first !== '[') return false;
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
}

/**
 * `buildRestore`, except that a string which is a JSON object or array (tool
 * call arguments, JSON-mode output) gets its originals JSON-escaped, so it is
 * still valid JSON with the same structure after the restore.
 */
export function buildJsonAwareRestore(entries: Array<[string, string]>): (text: string) => string {
  if (!entries.length) return (t) => t;
  const plain = buildRestore(entries);
  let escaped: ((text: string) => string) | undefined;
  return (text) => {
    const restored = plain(text);
    if (restored === text || !isJsonDocument(text)) return restored;
    escaped ??= buildRestore(escapeEntriesForJson(entries));
    return escaped(text);
  };
}

const formatType = (value: unknown): unknown => (value && typeof value === 'object' ? (value as { type?: unknown }).type : undefined);

/**
 * Whether a request body asks for JSON output, so the streamed answer is JSON:
 * OpenAI `response_format` (Chat Completions) or `text.format` (Responses),
 * Anthropic `output_config.format` or the beta `output_format`.
 */
export function requestsJsonOutput(body: unknown): boolean {
  if (!body || typeof body !== 'object') return false;
  const request = body as Record<string, unknown>;
  const openai = [formatType(request.response_format), formatType((request.text as { format?: unknown } | undefined)?.format)];
  const anthropic = [formatType((request.output_config as { format?: unknown } | undefined)?.format), formatType(request.output_format)];
  return openai.some((type) => type === 'json_object' || type === 'json_schema') || anthropic.includes('json_schema');
}

export interface IncrementalRestorer {
  push(chunk: string): string;
  flush(): string;
}

/**
 * Restore placeholders across arbitrary stream chunk boundaries. This uses the
 * actual placeholder strings, so custom formats do not need square brackets.
 */
export function buildStreamRestore(entries: Array<[string, string]>): IncrementalRestorer {
  const restoreText = buildRestore(entries);
  const placeholders = entries.map(([placeholder]) => placeholder);
  let buffer = '';

  const pendingPrefixLength = (): number => {
    let keep = 0;
    for (const placeholder of placeholders) {
      const limit = Math.min(buffer.length, placeholder.length - 1);
      for (let length = limit; length > keep; length--) {
        if (buffer.endsWith(placeholder.slice(0, length))) {
          keep = length;
          break;
        }
      }
    }
    return keep;
  };

  return {
    push(chunk: string): string {
      buffer += chunk;
      const keep = pendingPrefixLength();
      const emitEnd = buffer.length - keep;
      const emit = buffer.slice(0, emitEnd);
      buffer = buffer.slice(emitEnd);
      return restoreText(emit);
    },
    flush(): string {
      const out = restoreText(buffer);
      buffer = '';
      return out;
    },
  };
}

function walkStrings(value: unknown, fn: (s: string) => string): unknown {
  return mapGraph(value, fn);
}

function redactGraph(
  value: unknown,
  redactString: (text: string) => string,
  matchKey: (key: string) => boolean,
  allow: (value: string) => boolean,
  mint: (value: string, detectorId: string) => string,
): unknown {
  return mapGraph(
    value,
    redactString,
    (key, raw) => {
      if (matchKey(key) && !allow(raw)) return mint(raw, 'sensitive_key');
      return redactString(raw);
    },
  );
}

/**
 * A reversible redactor. `redact()` swaps each secret for a stable opaque
 * placeholder and remembers the mapping; `restore()` puts the originals back.
 * The same value always gets the same placeholder, so references survive a
 * round trip — send the redacted text to an LLM, then restore its answer.
 */
export function createVault(opts: VaultOptions = {}): Vault {
  const dets = resolveDetectors(opts);
  const allow = allowMatcher(opts);
  const matchKey = keyMatcher(opts);
  const fmt = opts.placeholder ?? (opts.placeholderStyle === 'readable'
    ? ((id, n) => `[${id.toUpperCase()}_${n}]`)
    : ((id) => `[FR_${id.toUpperCase()}_${opaqueToken()}]`));

  const origToPh = new Map<string, string>();
  const phToOrig = new Map<string, string>();
  const counts = new Map<string, number>();

  const mint = (value: string, detId: string): string => {
    const existing = origToPh.get(value);
    if (existing) return existing;
    const n = (counts.get(detId) ?? 0) + 1;
    counts.set(detId, n);
    const ph = fmt(detId, n);
    const collision = phToOrig.get(ph);
    if (collision !== undefined && collision !== value) {
      throw new Error(`Placeholder generator produced a duplicate token for ${detId}.`);
    }
    origToPh.set(value, ph);
    phToOrig.set(ph, value);
    return ph;
  };

  const redactStr = (text: string): string => {
    const hits = scanString(text, dets, allow, opts);
    if (!hits.length) return text;
    // A value captured from JSON text is stored decoded, so restoring it into
    // JSON escapes it exactly once and restoring it into prose gives the value.
    const json = isJsonDocument(text);
    let out = '';
    let cursor = 0;
    for (const h of hits) {
      out += text.slice(cursor, h.start);
      out += mint(json ? (decodeJsonStringContent(h.value) ?? h.value) : h.value, h.det.id);
      cursor = h.end!;
    }
    return out + text.slice(cursor);
  };

  return {
    redact: <T>(input: T) => redactGraph(input, redactStr, matchKey, allow, mint) as T,
    restore: <T>(input: T) => walkStrings(input, buildJsonAwareRestore([...phToOrig])) as T,
    entries: () => [...phToOrig],
    get size() {
      return phToOrig.size;
    },
  };
}

/**
 * Put originals back into any text/object using a vault or a placeholder→value
 * map. A string that is a JSON object or array gets the originals JSON-escaped.
 */
export function restore<T>(input: T, source: Vault | Map<string, string> | Record<string, string>): T {
  const entries: Array<[string, string]> =
    source instanceof Map
      ? [...source]
      : typeof (source as Vault).entries === 'function'
        ? (source as Vault).entries()
        : Object.entries(source as Record<string, string>);
  if (!entries.length) return input;
  return walkStrings(input, buildJsonAwareRestore(entries)) as T;
}
