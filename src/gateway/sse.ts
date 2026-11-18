/**
 * Frame-aware restoration for `text/event-stream` responses.
 *
 * LLM streaming APIs send one JSON object per SSE event, and the text the model
 * writes arrives in pieces inside those objects: `choices[].delta.content`,
 * `delta.partial_json`, a Responses API `delta`. Restoring the raw bytes of the
 * stream gets two things wrong. A placeholder split across two events is never
 * contiguous on the wire, so it is missed. And some of those strings are
 * themselves JSON (tool-call `arguments`, `partial_json`), so an original that
 * lands in them needs escaping for that inner JSON as well as for the frame.
 *
 * This parses each event, restores every string in its JSON with a restorer
 * per streamed field, escapes for the field's own JSON where the field is JSON,
 * and writes the event back with `JSON.stringify`, which escapes for the frame.
 * An event that nothing was restored in is passed on byte for byte.
 */

import { buildRestore, buildStreamRestore, type IncrementalRestorer, type Vault } from '../index.js';
import { buildJsonAwareRestore, escapeEntriesForJson } from '../vault.js';

export { requestsJsonOutput } from '../vault.js';

export interface SseRestoreOptions {
  /** The request asked for JSON output, so streamed answer text is JSON. */
  jsonOutput?: boolean;
}

export interface SseRestorer {
  push(chunk: string): string;
  flush(): string;
}

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type Segment = string | number;

/** Streamed fields whose text is JSON: function-call arguments and partial tool input. */
const JSON_FIELDS = new Set(['arguments', 'partial_json']);
/** Streamed fields that carry the answer, which is JSON when the request asked for JSON. */
const ANSWER_FIELDS = new Set(['content', 'text', 'delta']);
/** Fields that tell parallel streams apart: choices, tool calls, content blocks, output items. */
const IDENTITY_FIELDS = ['index', 'output_index', 'content_index', 'item_id'] as const;
/** One blank line ends an event; LLM APIs use LF or CRLF line endings. */
const EVENT_END = /\r?\n\r?\n/;
const LINE_BREAK = /\r\n|\r|\n/;

const isObject = (value: Json): value is { [key: string]: Json } => typeof value === 'object' && value !== null && !Array.isArray(value);

interface Leaf {
  path: Segment[];
  value: string;
  /** Set for text that arrives in pieces across events. */
  stream?: { key: string; shape: string; json: boolean };
}

interface Pending {
  restorer: IncrementalRestorer;
  shape: string;
  /** The last event that carried this field, to build a closing event from. */
  root: Json;
  path: Segment[];
  fieldLines: string[];
  eol: string;
}

/** Every string in an event's JSON, with the streamed ones keyed by field and identity. */
function leavesOf(root: Json, jsonOutput: boolean): Leaf[] {
  const type = isObject(root) && typeof root.type === 'string' ? root.type : '';
  const argumentsEvent = type.includes('arguments');
  const reasoningEvent = /reasoning|thinking/.test(type);
  const leaves: Leaf[] = [];
  const walk = (node: Json, path: Segment[], key: string[], shape: string[], inDelta: boolean): void => {
    if (typeof node === 'string') {
      const field = String(path[path.length - 1] ?? '');
      const streamed = inDelta || field === 'delta';
      if (!streamed) {
        leaves.push({ path, value: node });
        return;
      }
      const json = JSON_FIELDS.has(field) || (field === 'delta' && argumentsEvent)
        || (jsonOutput && ANSWER_FIELDS.has(field) && !reasoningEvent);
      leaves.push({ path, value: node, stream: { key: `${type}|${key.join('/')}`, shape: `${type}|${shape.join('/')}`, json } });
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, position) => {
        const identified = isObject(item) && IDENTITY_FIELDS.some((field) => item[field] !== undefined);
        walk(item, [...path, position], [...key, identified ? '[]' : `[${position}]`], [...shape, '[]'], inDelta);
      });
      return;
    }
    if (!isObject(node)) return;
    const tags = IDENTITY_FIELDS.flatMap((field) => (node[field] !== undefined ? [`#${field}=${JSON.stringify(node[field])}`] : []));
    for (const [name, child] of Object.entries(node)) {
      walk(child, [...path, name], [...key, ...tags, name], [...shape, name], inDelta || name === 'delta');
    }
  };
  walk(root, [], [], [], false);
  return leaves;
}

const setAt = (root: Json, path: Segment[], value: string): void => {
  let node = root as { [key: string]: Json } | Json[];
  for (const segment of path.slice(0, -1)) node = (node as Record<string | number, Json>)[segment] as typeof node;
  (node as Record<string | number, Json>)[path[path.length - 1]!] = value;
};

/**
 * The smallest event that carries `tail` for one streamed field: the scalar
 * fields along the way (ids, indexes, `type`), and inside `delta` only the
 * indexes and types that say where the text belongs.
 */
function closingEvent(root: Json, path: Segment[], tail: string): Json {
  const build = (node: Json, depth: number, inDelta: boolean): Json => {
    if (depth === path.length) return tail;
    const segment = path[depth]!;
    const childInDelta = inDelta || segment === 'delta';
    if (Array.isArray(node)) return [build(node[segment as number] ?? null, depth + 1, childInDelta)];
    if (!isObject(node)) return node;
    const out: { [key: string]: Json } = {};
    for (const [name, value] of Object.entries(node)) {
      if (name === segment) continue;
      const keep = inDelta ? name === 'type' || (IDENTITY_FIELDS as readonly string[]).includes(name) : value === null || typeof value !== 'object';
      if (keep) out[name] = value;
    }
    out[segment] = build(node[segment] ?? null, depth + 1, childInDelta);
    return out;
  };
  return build(root, 0, false);
}

interface ParsedEvent {
  /** Non-data lines (event, id, retry, comments), in order. */
  fieldLines: string[];
  data: string | undefined;
  eol: string;
}

function parseEvent(raw: string): ParsedEvent {
  const eol = /\r\n/.test(raw) ? '\r\n' : '\n';
  const fieldLines: string[] = [];
  const data: string[] = [];
  for (const line of raw.split(LINE_BREAK)) {
    if (line === '') continue;
    if (line === 'data' || line.startsWith('data:')) {
      const value = line.slice(5);
      data.push(value.startsWith(' ') ? value.slice(1) : value);
    } else {
      fieldLines.push(line);
    }
  }
  return { fieldLines, data: data.length ? data.join('\n') : undefined, eol };
}

const writeEvent = (fieldLines: string[], data: string, eol: string): string =>
  [...fieldLines, ...data.split('\n').map((line) => `data: ${line}`)].join(eol) + eol + eol;

/**
 * Restore placeholders in an SSE stream of JSON events. Each streamed field
 * (`delta.content`, a tool call's `arguments`, `partial_json`, ...) gets its own
 * restorer, so a placeholder split across events is rebuilt, and a field whose
 * text is JSON gets the original escaped for that JSON before the event itself
 * is serialised.
 */
export function sseRestorer(vault: Vault, options: SseRestoreOptions = {}): SseRestorer {
  const entries = vault.entries();
  const escaped = escapeEntriesForJson(entries);
  const restoreWhole = buildJsonAwareRestore(entries);
  const restorePlain = buildRestore(entries);
  const jsonOutput = options.jsonOutput === true;
  const pending = new Map<string, Pending>();
  let buffer = '';

  // Emit what a field still holds back, as its own event, before the stream
  // moves past that field.
  const close = (keep: (key: string, entry: Pending) => boolean): string => {
    let out = '';
    for (const [key, entry] of [...pending]) {
      if (keep(key, entry)) continue;
      pending.delete(key);
      const tail = entry.restorer.flush();
      if (tail) out += writeEvent(entry.fieldLines, JSON.stringify(closingEvent(entry.root, entry.path, tail)), entry.eol);
    }
    return out;
  };

  const handle = (raw: string): string => {
    const event = parseEvent(raw);
    if (event.data === undefined) return raw;
    let original: Json;
    try {
      original = JSON.parse(event.data) as Json;
    } catch {
      // Not JSON ([DONE], plain text): every streamed field is over.
      const restored = restorePlain(event.data);
      return close(() => false) + (restored === event.data ? raw : writeEvent(event.fieldLines, restored, event.eol));
    }

    const leaves = leavesOf(original, jsonOutput);
    const streamed = leaves.flatMap((leaf) => (leaf.stream ? [leaf.stream] : []));
    const keys = new Set(streamed.map((field) => field.key));
    const shapes = new Set(streamed.map((field) => field.shape));
    // A field this event does not continue is finished, unless the event
    // continues a sibling of the same shape (the next tool call, another
    // choice). An event with no streamed text at all ends every field.
    const before = close((key, entry) => streamed.length > 0 && (keys.has(key) || shapes.has(entry.shape)));

    let restored: Json | undefined;
    for (const leaf of leaves) {
      let value: string;
      if (leaf.stream) {
        let entry = pending.get(leaf.stream.key);
        if (!entry) {
          entry = {
            restorer: buildStreamRestore(leaf.stream.json ? escaped : entries),
            shape: leaf.stream.shape,
            root: original,
            path: leaf.path,
            fieldLines: event.fieldLines,
            eol: event.eol,
          };
          pending.set(leaf.stream.key, entry);
        }
        Object.assign(entry, { root: original, path: leaf.path, fieldLines: event.fieldLines, eol: event.eol });
        value = entry.restorer.push(leaf.value);
      } else {
        value = restoreWhole(leaf.value);
      }
      if (value === leaf.value) continue;
      // `original` stays as the template for closing events; edit a copy.
      restored ??= JSON.parse(event.data) as Json;
      setAt(restored, leaf.path, value);
    }
    return before + (restored === undefined ? raw : writeEvent(event.fieldLines, JSON.stringify(restored), event.eol));
  };

  return {
    push(chunk: string): string {
      buffer += chunk;
      let out = '';
      for (let match = EVENT_END.exec(buffer); match; match = EVENT_END.exec(buffer)) {
        const end = match.index + match[0].length;
        out += handle(buffer.slice(0, end));
        buffer = buffer.slice(end);
      }
      return out;
    },
    flush(): string {
      // An unterminated last event is still an event.
      const rest = buffer;
      buffer = '';
      return (rest.trim() ? handle(rest) : rest) + close(() => false);
    },
  };
}
