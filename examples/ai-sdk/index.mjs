import assert from 'node:assert/strict';
import { generateText, jsonSchema, stepCountIs, streamText, tool, wrapLanguageModel } from 'ai';
import { MockLanguageModelV4, simulateReadableStream } from 'ai/test';
import { flareRedactMiddleware } from 'flare-redact/ai-sdk';

const EMAIL = 'alice@example.com';
const CARD = '4242 4242 4242 4242';
const usage = {
  inputTokens: { total: 10, noCache: 10, cacheRead: 0, cacheWrite: 0 },
  outputTokens: { total: 10, text: 10, reasoning: 0 },
};
const placeholderIn = (prompt) => JSON.stringify(prompt).match(/\[FR_EMAIL_[0-9a-f]{24}\]/)?.[0];

// A stand-in for any AI SDK provider (OpenAI, Anthropic, Google, Bedrock, ...),
// so the example runs without an API key. It records what it is sent.
const seenByProvider = [];
const provider = new MockLanguageModelV4({
  async doGenerate({ prompt }) {
    seenByProvider.push(JSON.stringify(prompt));
    const email = placeholderIn(prompt);
    const toolAnswered = prompt.some((message) => message.role === 'tool');
    if (!toolAnswered) {
      return {
        content: [{ type: 'tool-call', toolCallId: 'call_1', toolName: 'sendInvoice', input: JSON.stringify({ to: email }) }],
        finishReason: { unified: 'tool-calls', raw: 'tool_calls' },
        usage,
        warnings: [],
      };
    }
    return {
      content: [{ type: 'text', text: `Done: the invoice went to ${email}.` }],
      finishReason: { unified: 'stop', raw: 'stop' },
      usage,
      warnings: [],
    };
  },
  async doStream({ prompt }) {
    seenByProvider.push(JSON.stringify(prompt));
    const email = placeholderIn(prompt);
    return {
      stream: simulateReadableStream({
        chunks: [
          { type: 'stream-start', warnings: [] },
          { type: 'text-start', id: 'text-1' },
          // The placeholder arrives split across two chunks.
          { type: 'text-delta', id: 'text-1', delta: `Writing to ${email.slice(0, 9)}` },
          { type: 'text-delta', id: 'text-1', delta: `${email.slice(9)} now.` },
          { type: 'text-end', id: 'text-1' },
          { type: 'finish', finishReason: { unified: 'stop', raw: 'stop' }, usage },
        ],
      }),
    };
  },
});

// The one line an application adds.
const model = wrapLanguageModel({ model: provider, middleware: flareRedactMiddleware() });

let toolReceived;
const sendInvoice = tool({
  description: 'Email the invoice to a customer',
  inputSchema: jsonSchema({ type: 'object', properties: { to: { type: 'string' } }, required: ['to'] }),
  async execute({ to }) {
    toolReceived = to;
    return { sent: true, to };
  },
});

const result = await generateText({
  model,
  system: 'You are a billing assistant.',
  prompt: `Email the invoice to ${EMAIL}. They paid with ${CARD}.`,
  tools: { sendInvoice },
  stopWhen: stepCountIs(3),
});

const stream = streamText({ model, prompt: `Draft a note to ${EMAIL}` });
let streamed = '';
for await (const delta of stream.textStream) streamed += delta;

for (const prompt of seenByProvider) {
  assert.ok(!prompt.includes(EMAIL) && !prompt.includes(CARD), 'the provider never sees the originals');
}
assert.equal(toolReceived, EMAIL, 'the tool runs with the real address');
assert.equal(result.text, `Done: the invoice went to ${EMAIL}.`);
assert.equal(streamed, `Writing to ${EMAIL} now.`);

console.log(JSON.stringify({
  promptSeenByProvider: JSON.parse(seenByProvider[1]),
  toolReceived,
  textReturnedToApp: result.text,
  streamReturnedToApp: streamed,
}, null, 2));
