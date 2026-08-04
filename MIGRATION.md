# Migrating flare-redact

## Upgrade

```bash
npm install flare-redact@^1.4.0
```

Version 1.4 is backward compatible with the `1.x` line. Projects pinned to an
older exact version or lockfile stay there until explicitly upgraded.

## 1.4 agent-boundary security upgrade

Version 1.4 is backward compatible, but multi-tool agent applications should
replace a shared `createToolBoundary()` with `createScopedToolBoundary()`.
The legacy boundary restores every placeholder in one conversation vault. A
prompt-injected model can copy a placeholder from one tool result into another
tool's arguments, causing the second tool call to receive the original value.

```js
import { createScopedToolBoundary } from 'flare-redact/tool';

const boundary = createScopedToolBoundary();
const safe = boundary.redactForModel('database', databaseResult);
const call = await model.generateToolCall(safe);

// Map an accepted tool to a runtime-owned scope; never trust arbitrary model
// text as the authorization scope.
const localCall = boundary.restoreForTool(acceptedTool.scope, call);
```

Use one stable scope per tool or trust domain. Same-scope calls restore normally;
cross-scope and unknown placeholders stay opaque. Single-tool applications can
keep `createToolBoundary()` unchanged.

## 1.0 safe-by-default changes

Version 1.0 established the compatibility contract for the `1.x` line. Projects
upgrading directly from `0.9.x` must account for the changes below.

## Breaking change: scan values are opt-in

`scan()` and `scanAsync()` no longer return the raw matched secret by default.
Locations, detector metadata, risk, and confidence are unchanged.

```js
scan(input);                          // value is omitted
scan(input, { includeValues: true }); // value is present
```

Only enable `includeValues` in trusted, in-process diagnostics. Do not send those
findings to logs, CI reports, analytics, or error trackers.

## Object graph behavior

Redaction now terminates safely on circular input and preserves shared
references. It also traverses `Map`, `Set`, enumerable symbol values, `Error`
messages, `URL`, and `URLSearchParams`. If code previously depended on these
values being passed through without inspection, review the new masked output.

## HTTP snapshots

`redactHttp()` now sanitizes the URL string in addition to `query`, `params`,
headers, and body. Use `redactUrl()` directly when logging a URL outside an HTTP
request snapshot.

## LLM and tool calls

OpenAI and Anthropic wrappers now redact the complete message structure,
including tool-call argument strings, and restore streamed tool arguments across
chunk boundaries. For model-agnostic agent loops and MCP, use
`createToolBoundary()` from `flare-redact/tool`.

## Streams

`redactStream()` now buffers bounded multiline private-key records. Complete and
unterminated PEM private keys are masked; an oversized buffered record raises
`RedactionLimitError` with code `ERR_REDACTION_LIMIT`.

## Reusable policies

`createRedactor()` and `definePolicy()` now precompile detector selection and
matchers. `compilePolicy()` is the explicit name for the same API and also
exposes async scan/redaction methods.
