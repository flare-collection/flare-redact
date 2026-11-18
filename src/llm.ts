import { createVault, buildStreamRestore, escapeEntriesForJson, type Vault, type VaultOptions } from './vault.js';

export type { Vault, VaultOptions } from './vault.js';
export { createVault } from './vault.js';

const WRAPPED = Symbol.for('flare-redact.wrapped');

/**
 * A streaming restorer. `json` is for text that is JSON (tool-call arguments,
 * partial JSON, JSON-mode output): the originals go in escaped, so the
 * assembled text stays valid JSON and a restored value cannot add or replace
 * fields in it.
 */
function makeStreamRestorer(vault: Vault, json = false) {
  return buildStreamRestore(json ? escapeEntriesForJson(vault.entries()) : vault.entries());
}

/** OpenAI's `response_format` types whose message content is JSON. */
const JSON_RESPONSE_FORMATS = new Set(['json_object', 'json_schema']);

/** Redact a prompt and hand back the vault so you can restore the reply yourself. */
export function redactPrompt(text: string, opts: VaultOptions = {}): { text: string; vault: Vault } {
  const vault = createVault(opts);
  return { text: vault.redact(text), vault };
}

/**
 * Wrap an OpenAI client so secrets and PII are stripped from every chat prompt
 * before it leaves your process, and restored in the reply. The model never
 * sees the real values; your app still gets the right answer. Streaming works,
 * and wrapping the same client twice is a no-op.
 *
 * Mutates and returns the client.
 */
export function wrapOpenAI<T extends OpenAILike>(client: T, opts: VaultOptions = {}): T {
  const completions = client?.chat?.completions as (OpenAICompletions & Marked) | undefined;
  if (!completions || typeof completions.create !== 'function') {
    throw new Error('wrapOpenAI: expected a client with chat.completions.create');
  }
  if (completions[WRAPPED]) return client;
  const original = completions.create.bind(completions);

  completions.create = (params: OpenAIParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const messages = Array.isArray(params?.messages) ? vault.redact(params.messages) : params?.messages;
    const result = original({ ...params, messages }, ...rest);
    if (params?.stream) {
      const format = (params.response_format as { type?: unknown } | undefined)?.type;
      return wrapOpenAIStream(result, vault, typeof format === 'string' && JSON_RESPONSE_FORMATS.has(format));
    }
    // vault.restore escapes originals inside strings that are JSON documents,
    // which covers tool_calls[].function.arguments and JSON-mode content.
    return Promise.resolve(result).then((res) => vault.restore(res));
  };
  completions[WRAPPED] = true;
  return client;
}

async function* wrapOpenAIStream(result: unknown, vault: Vault, jsonContent: boolean): AsyncGenerator<unknown> {
  const stream = (await result) as AsyncIterable<OpenAIChunk>;
  const restorers = new Map<string, ReturnType<typeof makeStreamRestorer>>();
  // Tool arguments are always JSON; content is JSON when response_format asks for it.
  const getRestorer = (key: string) => {
    let restorer = restorers.get(key);
    if (!restorer) {
      restorer = makeStreamRestorer(vault, jsonContent || key.includes(':tool:'));
      restorers.set(key, restorer);
    }
    return restorer;
  };
  let last: OpenAIChunk | undefined;
  for await (const chunk of stream) {
    last = chunk;
    yield {
      ...chunk,
      choices: chunk.choices.map((choice, choicePosition) => {
        const choiceIndex = choice.index ?? choicePosition;
        const delta = choice.delta;
        if (!delta) return choice;
        let nextDelta = delta;
        if (typeof delta.content === 'string') {
          nextDelta = {
            ...nextDelta,
            content: getRestorer(`choice:${choiceIndex}:content`).push(delta.content),
          };
        }
        if (Array.isArray(delta.tool_calls)) {
          nextDelta = {
            ...nextDelta,
            tool_calls: delta.tool_calls.map((call, callPosition) => {
              const args = call.function?.arguments;
              if (typeof args !== 'string') return call;
              const callIndex = call.index ?? callPosition;
              return {
                ...call,
                function: {
                  ...call.function,
                  arguments: getRestorer(`choice:${choiceIndex}:tool:${callIndex}`).push(args),
                },
              };
            }),
          };
        }
        return { ...choice, delta: nextDelta };
      }),
    };
  }
  for (const [key, restorer] of restorers) {
    const tail = restorer.flush();
    if (!tail) continue;
    const base = last ? { id: last.id, object: last.object, model: last.model } : {};
    const tool = /^choice:(\d+):tool:(\d+)$/.exec(key);
    const content = /^choice:(\d+):content$/.exec(key);
    const choiceIndex = Number(tool?.[1] ?? content?.[1] ?? 0);
    const delta = tool
      ? { tool_calls: [{ index: Number(tool[2]), function: { arguments: tail } }] }
      : { content: tail };
    yield { ...base, choices: [{ index: choiceIndex, delta, finish_reason: null }] };
  }
}

/**
 * Wrap an Anthropic client so secrets and PII are stripped from every message
 * and the system prompt before it's sent, and restored in the reply. Streaming
 * works, and wrapping the same client twice is a no-op.
 *
 * Mutates and returns the client.
 */
export function wrapAnthropic<T extends AnthropicLike>(client: T, opts: VaultOptions = {}): T {
  const messages = client?.messages as (AnthropicMessages & Marked) | undefined;
  if (!messages || typeof messages.create !== 'function') {
    throw new Error('wrapAnthropic: expected a client with messages.create');
  }
  if (messages[WRAPPED]) return client;
  const original = messages.create.bind(messages);

  messages.create = (params: AnthropicParams, ...rest: unknown[]) => {
    const vault = createVault(opts);
    const redacted: AnthropicParams = {
      ...params,
      messages: Array.isArray(params?.messages)
        ? vault.redact(params.messages)
        : params?.messages,
    };
    if (params?.system !== undefined) redacted.system = vault.redact(params.system);
    const result = original(redacted, ...rest);
    if (params?.stream) return wrapAnthropicStream(result, vault);
    return Promise.resolve(result).then((res) => vault.restore(res));
  };
  messages[WRAPPED] = true;
  return client;
}

async function* wrapAnthropicStream(result: unknown, vault: Vault): AsyncGenerator<unknown> {
  const stream = (await result) as AsyncIterable<AnthropicEvent>;
  const restorers = new Map<string, ReturnType<typeof makeStreamRestorer>>();
  // partial_json is the tool input as JSON text; text deltas are prose.
  const getRestorer = (key: string) => {
    let restorer = restorers.get(key);
    if (!restorer) {
      restorer = makeStreamRestorer(vault, key.startsWith('json:'));
      restorers.set(key, restorer);
    }
    return restorer;
  };
  for await (const event of stream) {
    const text = event?.delta?.text;
    const partialJson = event?.delta?.partial_json;
    const index = event.index ?? 0;
    if (event?.type === 'content_block_delta' && typeof text === 'string') {
      yield { ...event, delta: { ...event.delta, text: getRestorer(`text:${index}`).push(text) } };
    } else if (event?.type === 'content_block_delta' && typeof partialJson === 'string') {
      yield {
        ...event,
        delta: {
          ...event.delta,
          partial_json: getRestorer(`json:${index}`).push(partialJson),
        },
      };
    } else {
      yield event;
    }
  }
  for (const [key, restorer] of restorers) {
    const tail = restorer.flush();
    if (!tail) continue;
    const [kind, rawIndex] = key.split(':');
    const index = Number(rawIndex);
    const delta = kind === 'json'
      ? { type: 'input_json_delta', partial_json: tail }
      : { type: 'text_delta', text: tail };
    yield { type: 'content_block_delta', index, delta };
  }
}

type Marked = { [WRAPPED]?: boolean };

interface OpenAIParams {
  messages?: Array<{ content: unknown; [k: string]: unknown }>;
  stream?: boolean;
  [k: string]: unknown;
}
interface OpenAIChunk {
  id?: unknown;
  object?: unknown;
  model?: unknown;
  choices: Array<{
    index?: number;
    delta?: {
      content?: unknown;
      tool_calls?: Array<{
        index?: number;
        function?: { arguments?: unknown; [k: string]: unknown };
        [k: string]: unknown;
      }>;
      [k: string]: unknown;
    };
    [k: string]: unknown;
  }>;
  [k: string]: unknown;
}
interface OpenAICompletions {
  create: (params: OpenAIParams, ...rest: unknown[]) => unknown;
}
interface OpenAILike {
  chat: { completions: OpenAICompletions };
}

interface AnthropicParams {
  messages?: Array<{ content: unknown; [k: string]: unknown }>;
  system?: unknown;
  stream?: boolean;
  [k: string]: unknown;
}
interface AnthropicEvent {
  type?: string;
  index?: number;
  delta?: { text?: unknown; partial_json?: unknown; [k: string]: unknown };
  [k: string]: unknown;
}
interface AnthropicMessages {
  create: (params: AnthropicParams, ...rest: unknown[]) => unknown;
}
interface AnthropicLike {
  messages: AnthropicMessages;
}
