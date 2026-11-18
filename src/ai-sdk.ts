/**
 * A language model middleware for the Vercel AI SDK (`ai`). One middleware
 * covers every provider the SDK supports: prompts are redacted to opaque
 * placeholders before the provider sees them, and the placeholders are put
 * back in what the model returns, streamed or not.
 *
 *   import { wrapLanguageModel } from 'ai';
 *   import { flareRedactMiddleware } from 'flare-redact/ai-sdk';
 *
 *   const model = wrapLanguageModel({ model: baseModel, middleware: flareRedactMiddleware() });
 *
 * The types here are structural on purpose: the package does not depend on
 * `ai`, and the same object works with the middleware contracts of AI SDK 5
 * (`v2`), 6 (`v3`) and 7 (`v4`), whose prompt and stream shapes match for
 * everything this touches.
 */

import { buildRestore, buildStreamRestore, createVault, type IncrementalRestorer, type Vault, type VaultOptions } from './vault.js';
import type { Session } from './session.js';

export interface FlareRedactMiddlewareOptions extends VaultOptions {
  /**
   * Keep one vault for a whole conversation instead of one per model call, so
   * a value keeps the same placeholder in every step and turn. The session's
   * own options apply; the other options here are ignored.
   */
  session?: Session;
}

/**
 * The middleware object. It satisfies `LanguageModelMiddleware` from `ai` 5, 6
 * and 7 without importing it.
 */
export interface FlareRedactLanguageModelMiddleware {
  readonly specificationVersion: 'v3';
  readonly middlewareVersion: 'v2';
  transformParams<P>(options: { type: 'generate' | 'stream'; params: P }): Promise<P>;
  wrapGenerate<R>(options: { doGenerate: () => PromiseLike<R>; params: unknown }): Promise<R>;
  wrapStream<S extends { stream: unknown }>(options: { doStream: () => PromiseLike<S>; params: unknown }): Promise<S>;
}

type Obj = Record<string, unknown>;
type Entries = Array<[string, string]>;

const isObj = (value: unknown): value is Obj => typeof value === 'object' && value !== null && !Array.isArray(value);

/** Keys that identify or route a part. They carry no user text and are never rewritten. */
const STRUCTURAL = new Set([
  'type', 'role', 'id', 'toolCallId', 'toolName', 'approvalId', 'approved',
  'mediaType', 'data', 'kind', 'providerOptions', 'providerExecuted',
]);

/** Parts that pass through untouched: files and images, and provider-defined parts. */
const PASS_THROUGH = new Set(['file', 'image', 'reasoning-file', 'custom']);

/** The text of a placeholder's original as it must appear inside a JSON string. */
const jsonEscaped = (entries: Entries): Entries => entries.map(([ph, value]) => [ph, JSON.stringify(value).slice(1, -1)]);

const isJson = (text: string): boolean => {
  try {
    JSON.parse(text);
    return true;
  } catch {
    return false;
  }
};

function redactPrompt(prompt: unknown, vault: Vault): unknown {
  if (!Array.isArray(prompt)) return prompt;

  // Every string that is not structural, one level down: the values of a tool
  // result (`text`, `json`, `error-*`), a denial reason, and fields of part
  // types this version does not know about yet.
  const redactLoose = (part: Obj): Obj => {
    const out: Obj = {};
    for (const [key, value] of Object.entries(part)) out[key] = STRUCTURAL.has(key) ? value : vault.redact(value);
    return out;
  };

  const redactToolOutput = (output: unknown): unknown => {
    if (!isObj(output)) return vault.redact(output);
    if (output.type === 'content' && Array.isArray(output.value)) {
      return {
        ...output,
        value: output.value.map((item) =>
          isObj(item) && item.type === 'text' && typeof item.text === 'string' ? { ...item, text: vault.redact(item.text) } : item),
      };
    }
    return redactLoose(output);
  };

  const redactPart = (part: unknown): unknown => {
    if (typeof part === 'string') return vault.redact(part);
    if (!isObj(part)) return part;
    const type = part.type;
    if (typeof type === 'string' && PASS_THROUGH.has(type)) return part;
    switch (type) {
      case 'text':
      case 'reasoning':
        return typeof part.text === 'string' ? { ...part, text: vault.redact(part.text) } : part;
      case 'tool-call':
        return { ...part, input: vault.redact(part.input) };
      case 'tool-result':
        return 'output' in part ? { ...part, output: redactToolOutput(part.output) } : redactLoose(part);
      default:
        return redactLoose(part);
    }
  };

  return prompt.map((message) => {
    if (!isObj(message)) return message;
    const { content } = message;
    if (typeof content === 'string') return { ...message, content: vault.redact(content) };
    if (Array.isArray(content)) return { ...message, content: content.map(redactPart) };
    return message;
  });
}

interface Restorers {
  /** Text the model wrote. JSON-aware when the call asked for JSON output. */
  text: (text: string) => string;
  /** A complete tool input: JSON-aware when it parses as JSON. */
  toolInput: (input: string) => string;
  /** Any other value: every string in it. */
  value: <T>(value: T) => T;
  /** A streaming restorer for text, or for tool input in the given encoding. */
  stream: (kind: 'text' | 'json' | 'plain') => IncrementalRestorer;
}

function restorers(vault: Vault, jsonOutput: boolean): Restorers {
  const entries = vault.entries();
  const escaped = jsonEscaped(entries);
  const plain = buildRestore(entries);
  const json = buildRestore(escaped);
  return {
    text: jsonOutput ? json : plain,
    // A placeholder can only sit inside a string in valid JSON, so the
    // original goes in escaped; anything that is not JSON gets it verbatim.
    toolInput: (input) => (entries.length && isJson(input) ? json(input) : plain(input)),
    value: (value) => vault.restore(value),
    stream: (kind) => buildStreamRestore(kind === 'json' || (kind === 'text' && jsonOutput) ? escaped : entries),
  };
}

function restoreContent(content: unknown, restore: Restorers): unknown {
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (!isObj(part)) return typeof part === 'string' ? restore.text(part) : part;
    const type = part.type;
    if (typeof type === 'string' && PASS_THROUGH.has(type)) return part;
    if (type === 'text' && typeof part.text === 'string') return { ...restore.value(part), text: restore.text(part.text) };
    if (type === 'tool-call' && typeof part.input === 'string') return { ...part, input: restore.toolInput(part.input) };
    return restore.value(part);
  });
}

/** The stream part types whose `delta` is text the model wrote, and the part that ends each. */
const DELTAS = new Map([
  ['text-delta', 'text-end'],
  ['reasoning-delta', 'reasoning-end'],
  ['tool-input-delta', 'tool-input-end'],
]);
const ENDS = new Map([...DELTAS].map(([delta, end]) => [end, delta]));

function restoreStream(stream: ReadableStream<unknown>, restore: Restorers): ReadableStream<unknown> {
  // One restorer per streamed block, keyed by part type and id, so a
  // placeholder split across deltas is rebuilt before it is passed on.
  const open = new Map<string, { type: string; id: unknown; restorer: IncrementalRestorer }>();
  const textTools = new Set<unknown>();
  const key = (type: string, id: unknown) => `${type}\u0000${String(id)}`;

  const flushOne = (type: string, id: unknown, controller: TransformStreamDefaultController<unknown>) => {
    const block = open.get(key(type, id));
    if (!block) return;
    open.delete(key(type, id));
    const tail = block.restorer.flush();
    if (tail) controller.enqueue({ type, id, delta: tail });
  };
  const flushAll = (controller: TransformStreamDefaultController<unknown>) => {
    for (const { type, id } of [...open.values()]) flushOne(type, id, controller);
  };

  return stream.pipeThrough(new TransformStream<unknown, unknown>({
    transform(part, controller) {
      if (!isObj(part) || typeof part.type !== 'string') {
        controller.enqueue(part);
        return;
      }
      const { type } = part;
      if (DELTAS.has(type) && typeof part.delta === 'string') {
        const k = key(type, part.id);
        let block = open.get(k);
        if (!block) {
          // Reasoning is prose even when the answer is JSON; tool input is JSON
          // unless its tool-input-start said otherwise.
          const kind = type === 'text-delta' ? 'text' : type === 'reasoning-delta' || textTools.has(part.id) ? 'plain' : 'json';
          block = { type, id: part.id, restorer: restore.stream(kind) };
          open.set(k, block);
        }
        const delta = block.restorer.push(part.delta);
        if (delta || part.providerMetadata !== undefined) controller.enqueue({ ...part, delta });
        return;
      }
      const deltaType = ENDS.get(type);
      if (deltaType) {
        flushOne(deltaType, part.id, controller);
        if (type === 'tool-input-end') textTools.delete(part.id);
        // A text-end can carry citations quoting what the model was sent.
        controller.enqueue(restore.value(part));
        return;
      }
      switch (type) {
        case 'tool-input-start':
          if (part.inputEncoding === 'text') textTools.add(part.id);
          controller.enqueue(part);
          return;
        case 'tool-call':
          controller.enqueue(typeof part.input === 'string' ? { ...part, input: restore.toolInput(part.input) } : part);
          return;
        case 'tool-result':
        case 'source':
          controller.enqueue(restore.value(part));
          return;
        case 'finish':
          flushAll(controller);
          controller.enqueue(part);
          return;
        default:
          // Text and reasoning blocks are restored above; files, metadata,
          // errors and raw provider chunks pass through as they arrived.
          controller.enqueue(part);
      }
    },
    flush(controller) {
      flushAll(controller);
    },
  }));
}

const wantsJson = (params: unknown): boolean => isObj(params) && isObj(params.responseFormat) && params.responseFormat.type === 'json';

/**
 * A Vercel AI SDK language model middleware that keeps secrets and personal
 * data out of every prompt, for any provider:
 *
 *   wrapLanguageModel({ model, middleware: flareRedactMiddleware({ preset: 'llm' }) })
 *
 * System, user and assistant text, reasoning, tool-call inputs and tool
 * results are redacted to opaque placeholders before the call; text,
 * reasoning, tool calls and structured output are restored in the result and
 * in the stream, including placeholders split across chunks. Files and images
 * are passed through unchanged. Takes the same options as `wrapOpenAI`.
 */
export function flareRedactMiddleware(opts: FlareRedactMiddlewareOptions = {}): FlareRedactLanguageModelMiddleware {
  const { session, ...vaultOptions } = opts;
  // Fail at setup, not on the first request, when a preset or detector option is wrong.
  if (!session) createVault(vaultOptions);

  // The vault lives exactly as long as one call: transformParams creates it,
  // the wrap step that follows restores with it. The params object is the key.
  const vaults = new WeakMap<object, { vault: Vault; json: boolean }>();
  const vaultFor = (params: unknown): { vault: Vault; json: boolean } => {
    const found = isObj(params) ? vaults.get(params) : undefined;
    if (!found) {
      throw new Error('flareRedactMiddleware: the prompt was not redacted. Pass the middleware object to wrapLanguageModel whole, without replacing transformParams.');
    }
    return found;
  };

  return {
    specificationVersion: 'v3',
    middlewareVersion: 'v2',
    async transformParams<P>({ params }: { params: P }): Promise<P> {
      if (!isObj(params)) return params;
      const vault = session ? session.vault : createVault(vaultOptions);
      const redacted = { ...params, prompt: redactPrompt(params.prompt, vault) };
      vaults.set(redacted, { vault, json: wantsJson(params) });
      return redacted as P;
    },
    async wrapGenerate<R>({ doGenerate, params }: { doGenerate: () => PromiseLike<R>; params: unknown }): Promise<R> {
      const { vault, json } = vaultFor(params);
      const result = await doGenerate();
      if (!isObj(result) || !vault.size) return result;
      const restore = restorers(vault, json);
      const out: Obj = { ...result, content: restoreContent(result.content, restore) };
      if (typeof result.structuredOutputText === 'string') out.structuredOutputText = restore.toolInput(result.structuredOutputText);
      return out as R;
    },
    async wrapStream<S extends { stream: unknown }>({ doStream, params }: { doStream: () => PromiseLike<S>; params: unknown }): Promise<S> {
      const { vault, json } = vaultFor(params);
      const result = await doStream();
      if (!vault.size) return result;
      return { ...result, stream: restoreStream(result.stream as ReadableStream<unknown>, restorers(vault, json)) };
    },
  };
}
