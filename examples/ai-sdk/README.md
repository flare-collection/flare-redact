# Vercel AI SDK: private prompts for every provider

This app wraps an AI SDK model with `flareRedactMiddleware()` and runs a
two-step tool call with `generateText`, then a `streamText` reply. A mock model
from `ai/test` stands in for the provider, so it runs without an API key.

From the repository root:

```bash
npm run build
npm --prefix examples/ai-sdk install
npm --prefix examples/ai-sdk start
```

It checks, and prints, that:

- the provider only ever sees opaque placeholders, in the user prompt, the
  earlier tool call and the tool result;
- the `sendInvoice` tool runs with the real address;
- the text returned to the app, and the streamed text, have the real address
  back, even though the placeholder arrived split across two chunks.

In a real app, replace the mock with any provider, for example
`openai('gpt-4o')` from `@ai-sdk/openai` or `anthropic(...)` from
`@ai-sdk/anthropic`. The middleware line stays the same.
