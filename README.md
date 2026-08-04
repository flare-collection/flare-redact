<p align="center">
  <img src="assets/flare-redact.svg" alt="flare-redact" width="200">
</p>

<h1 align="center">flare-redact</h1>

<p align="center">
  <b>Hide secrets & PII in logs, prompts, and text — before they leak.</b>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/flare-redact"><img src="https://img.shields.io/npm/v/flare-redact.svg" alt="npm"></a>
  <a href="https://github.com/flare-collection/flare-redact/actions/workflows/ci.yml"><img src="https://github.com/flare-collection/flare-redact/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/npm/types/flare-redact.svg" alt="TypeScript">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/languages-24-4f46e5" alt="24 languages">
  <img src="https://img.shields.io/badge/detectors-56-4f46e5" alt="56 detectors">
  <img src="https://img.shields.io/badge/runtime-node%20%7C%20browser%20%7C%20edge-blue" alt="Runtimes">
</p>

<p align="center">
  🌐 <b>International by default — 24 languages</b><br>
  🇬🇧 🇨🇳 🇮🇳 🇪🇸 🇸🇦 🇫🇷 🇵🇹 🇷🇺 🇯🇵 🇩🇪 🇰🇷 🇹🇷 🇮🇹 🇮🇷 🇵🇱 🇺🇦 🇳🇱 🇻🇳 🇮🇩 🇹🇭 🇬🇷 🇮🇱 🇦🇿 🇷🇴
</p>

---

Every leaked secret has the same origin story: someone logged an object, and a
password, token, or API key was sitting inside it. The code looked innocent —
`logger.info({ user })` — but `user` carried a session token, and now it's in
your log aggregator, your error tracker, and three vendors' systems forever.

**flare-redact** is one function you wrap around that data. It reads the *content*,
not just the field names, so it catches the AWS key someone pasted into a free-text
`note`, the JWT in an `Authorization` header, the card number in a stack trace — and
masks them, keeping just enough of a hint to stay debuggable.

```js
import { redact } from 'flare-redact';

redact('User alice@corp.com paid with 4242 4242 4242 4242, token ghp_' + 'a'.repeat(36));
// → 'User a***@*** paid with **** **** **** 4242, token ghp_***'
```

Nothing to configure. No list of field paths to maintain. No native build step.

> **The same problem now has a new address: your LLM calls.** Wrap your OpenAI or
> Anthropic client and detected secrets are stripped from prompts and restored in
> the reply — the model never sees those original values, while references survive.
> [Jump to it ↓](#redact-prompts-before-they-reach-an-llm)

<p align="center">
  <img src="assets/demo.svg" alt="Before and after — secrets and PII masked in a log line, across languages" width="820">
</p>

|   |   |   |
|---|---|---|
| 🔍 **Context-aware** — spans carry risk and confidence | 🔐 **Secure vaults** — opaque tokens, optional AES-GCM persistence | 🎭 **Useful test data** — keyed pseudonyms and typed surrogates |
| 🤖 **Scoped LLM + tool boundaries** — stops cross-tool placeholder restore | 🔌 **Universal middleware** — wrap any SDK, handler, queue, or RPC function | 🪶 **Zero runtime dependencies** — Node, browser, and edge |

## Contents

- [Install](#install)
- [Runnable examples](#runnable-examples)
- [Redact anything](#redact-anything)
- [Integrate any SDK or framework](#integrate-any-sdk-or-framework)
- [Redact prompts before they reach an LLM](#redact-prompts-before-they-reach-an-llm)
- [Ways to hide a value](#ways-to-hide-a-value)
- [Reversible redaction](#reversible-redaction)
- [Contextual and model-assisted PII](#contextual-and-model-assisted-pii)
- [Learned confidence, fewer false positives](#learned-confidence-fewer-false-positives)
- [Build a private chat app](#build-a-private-chat-app)
- [Protect tool calls and MCP loops](#protect-tool-calls-and-mcp-loops)
- [Your own words](#your-own-words)
- [See what leaks, and why](#see-what-leaks-and-why)
- [Guard your logger in one line](#guard-your-logger-in-one-line)
- [One policy, everywhere](#one-policy-everywhere)
- [Anonymize a dataset for staging](#anonymize-a-dataset-for-staging)
- [Guard what leaves your app](#guard-what-leaves-your-app)
- [Streams](#streams)
- [Fail a build when a secret sneaks in](#fail-a-build-when-a-secret-sneaks-in)
- [CLI](#cli)
- [What it catches](#what-it-catches)
- [Multilingual secret vocabulary and IDs](#multilingual-secret-vocabulary-and-ids)
- [Custom detectors & allowlists](#custom-detectors--allowlists)
- [API](#api)
- [Security boundaries](#security-boundaries)
- [Why not a field allowlist?](#why-not-a-field-allowlist)

## Install

```bash
npm install flare-redact
```

Node 20+, and it runs in the browser and edge runtimes too — zero dependencies.
Upgrading from `0.9.x`? Read the [`1.0 migration guide`](MIGRATION.md). Existing
projects are not forced across the major version; upgrade explicitly with
`npm install flare-redact@^1.0.0`.

### React and the browser

The core is plain ESM with no Node built-ins, is tree-shakeable
(`sideEffects: false`), and uses the standard Web Crypto API — so `redact`,
`scan`, vaults, and the LLM helpers work unchanged in React, Vue, and edge
functions. CI smoke-tests the core on Bun and Deno on every push.

```jsx
import { redact } from 'flare-redact';

function SupportTicket({ text }) {
  // Mask pasted keys and card numbers before the ticket is rendered or sent on.
  return <pre>{redact(text)}</pre>;
}
```

Only the Node-specific entry points (`flare-redact` CLI, `/stream`, `/pino`,
`/winston`) need Node. One honest caveat: client-side redaction protects what
you *forward* (analytics, logs, LLM calls) — it is not a substitute for
server-side redaction, since the original value already reached the browser.

### Using with AI coding agents

The docs site serves an [`llms.txt`](https://flare-collection.github.io/flare-redact/llms.txt)
and a condensed [`llms-full.txt`](https://flare-collection.github.io/flare-redact/llms-full.txt)
API reference, so coding assistants that read documentation get the current
API instead of guessing. If you use Claude Code, Cursor, or similar agents,
one line in your project rules (`CLAUDE.md`, `.cursor/rules`, `AGENTS.md`)
keeps generated code consistent:

```
For masking secrets/PII in logs, prompts, or datasets, use the flare-redact
package (API: https://flare-collection.github.io/flare-redact/llms-full.txt).
Do not write ad-hoc redaction regexes.
```

## Runnable examples

Clone the repository and run these small applications locally:

| Example | What it proves | Run |
|---|---|---|
| [`openai-privacy`](examples/openai-privacy) | The model sees an opaque placeholder while the app receives the restored value | `npm --prefix examples/openai-privacy start` |
| [`express-pino`](examples/express-pino) | Express keeps the original request while Pino receives a safe snapshot | `npm --prefix examples/express-pino run smoke` |
| [`universal-boundaries`](examples/universal-boundaries) | Any SDK method is sanitized and cross-tool placeholder exfiltration is blocked | `npm --prefix examples/universal-boundaries start` |
| [`github-secret-scan`](examples/github-secret-scan) | Pull requests fail when tracked source or configuration files contain detected secrets or PII | Copy the workflow into your repository |

Run `npm run build` and install an example's dependencies before its first run.

## Redact anything

Strings, arrays, and objects, recursively. The shape you pass in is the shape you
get back.

```js
import { redact } from 'flare-redact';

redact({
  user:     'bob@corp.com',
  password: 'hunter2',
  tokens:   ['ghp_' + 'b'.repeat(36)],
  note:     'my aws key is AKIAIOSFODNN7EXAMPLE',
});
// →
// {
//   user:     'b***@***',
//   password: '***',                     // sensitive field name
//   tokens:   ['ghp_***'],
//   note:     'my aws key is AKIA***',    // found inside free text
// }
```

## Integrate any SDK or framework

`flare-redact/middleware` puts one compiled policy around plain-data function
boundaries. It works without framework dependencies: analytics SDK methods,
server-action payloads, queue consumers, webhook clients, RPC functions,
database writes, and telemetry exporters all use the same boundary shape.

```js
import { createRedactionMiddleware } from 'flare-redact/middleware';

const boundary = createRedactionMiddleware({
  policy: {
    enable: ['high_entropy'],
    refineConfidence: true,
    minConfidence: 0.65,
  },
  onFindings(event) {
    audit.info({
      boundary: event.name,
      count: event.findings.length,
      detectors: event.findings.map((finding) => finding.detector),
    }); // finding metadata is always value-free
  },
});

analytics.track = boundary.wrap(analytics.track, { name: 'analytics.track' });
await analytics.track('checkout', { email, authorization });
// analytics receives a redacted copy; the caller's object stays unchanged
```

The same boundary supports three deployment modes:

```js
createRedactionMiddleware({ action: 'redact' });  // default: sanitize and continue
createRedactionMiddleware({ action: 'observe' }); // report only, change nothing
createRedactionMiddleware({ action: 'block' });   // throw RedactionBlockedError
```

Use `process(value)` directly inside framework hooks. `wrap()` handles sync and
promise-returning functions while preserving method `this`; `wrapAsync()` adds
async local `semanticProvider` support. Inputs are protected by default, and
`{ output: true }` also protects returned values. For signatures containing
framework-native request/response objects or callbacks, protect only plain-data
arguments (`{ input: [1] }`) or call `process(request.body)` explicitly; do not
clone a native `Request`/`Response` object.

## Redact prompts before they reach an LLM

Your app sends user data to OpenAI or Anthropic. Somewhere in that prompt is a
customer's email, an API key, or a card number — and now it's left your systems.
Wrap the client once, and detected secrets are stripped from prompts and put back
in the reply. The model never sees those original values; your code keeps the
references it needs.

```js
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI());

const res = await openai.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Email the invoice to alice@corp.com, card 4242 4242 4242 4242' }],
});
```

```
your app sends  →  Email the invoice to alice@corp.com, card 4242 4242 4242 4242
the model sees  →  Email the invoice to [FR_EMAIL_7f2a…], card [FR_CREDIT_CARD_19be…]
your app gets   →  Sent to alice@corp.com. Card 4242 4242 4242 4242 wasn't stored.
```

`wrapAnthropic` does the same for `messages.create`, including the system prompt.
Both wrappers redact complete message structures, including tool-call arguments.
Streaming text, OpenAI tool arguments, and Anthropic partial JSON are restored
even when a placeholder is split across chunks. There's a `redactPrompt(text)`
too if you'd rather hold the vault yourself.

## Ways to hide a value

Pick a `mode` depending on whether you still need to *reason* about the data
after it's hidden.

```js
redact('bob@corp.com', { mode: 'mask'  }); // 'b***@***'          (default)
redact('bob@corp.com', { mode: 'label' }); // '[REDACTED:email]'

const protectedOptions = { transformSecret: process.env.FLARE_REDACT_SECRET };
redact('bob@corp.com', { ...protectedOptions, mode: 'hash' });
// 'email_3baf4d28d7c88317a…' — HMAC-SHA-256 fingerprint

redact('bob@corp.com', { ...protectedOptions, mode: 'pseudonym' });
// 'kqz@rwmp.dnu' — keyed, deterministic, keeps character classes

redact('bob@corp.com', { ...protectedOptions, mode: 'surrogate' });
// 'user_93a78c61e204@example.invalid' — type-consistent synthetic value
```

Protected deterministic modes require `transformSecret`; they never silently
fall back to a public unsalted fingerprint. `hash` is useful for correlation,
`pseudonym` retains the original character shape, and `surrogate` emits typed
synthetic values such as reserved-domain emails and Luhn-valid card numbers.
Use a separate secret per environment or correlation domain.

`pseudonym` is deliberately **not** described as format-preserving encryption.
It is non-reversible pseudonymization, not NIST FF1. The old `fpe` name remains
as a compatibility alias but is deprecated.

Or replace everything with one fixed string:

```js
redact(payload, { mask: '█' });
redact(payload, { mask: ({ detector }) => `<${detector.id}>` });
```

## Reversible redaction

When you need the originals back — the LLM case above, or handing data to a
system you don't trust and getting it back — use a vault. It swaps each secret
for a stable placeholder and remembers the mapping.

```js
import { createVault } from 'flare-redact';

const vault = createVault();
const safe = vault.redact('charge bob@corp.com on card 4242 4242 4242 4242');
// 'charge [FR_EMAIL_7f2ad4…] on card [FR_CREDIT_CARD_19be63…]'

vault.restore(safe);
// 'charge bob@corp.com on card 4242 4242 4242 4242'
```

The same value gets the same placeholder inside one vault, so references survive
the round trip. Default placeholders include 96 random bits instead of a global
sequence number. Human-readable `[EMAIL_1]` counters remain available through
`createVault({ placeholderStyle: 'readable' })` for trusted local workflows.

The mapping is as sensitive as the original data. Encrypt it before persistence:

```js
import { sealVault, openVault, restore } from 'flare-redact';

const encrypted = await sealVault(vault, process.env.FLARE_REDACT_VAULT_PASSWORD);
await fs.writeFile('session.vault.json', JSON.stringify(encrypted), { mode: 0o600 });

const entries = await openVault(encrypted, process.env.FLARE_REDACT_VAULT_PASSWORD);
restore(safe, new Map(entries));
```

Sealed vaults use PBKDF2-SHA-256 with a fresh salt and AES-256-GCM with a fresh
nonce. Wrong passwords and modified files fail closed.

From the CLI, `--vault` and `--restore` use encrypted files by default. Passwords
come from `FLARE_REDACT_VAULT_PASSWORD` (or the variable named by
`--vault-password-env`) so they do not appear in shell history:

```bash
export FLARE_REDACT_VAULT_PASSWORD='use-a-secret-manager-in-production'
flare-redact --vault session.vault.json < input.txt > safe.txt
flare-redact --restore session.vault.json < safe.txt > restored.txt
```

## Contextual and model-assisted PII

Structured identifiers and credentials are best handled by deterministic rules
and checksum validators. Names and addresses need context, so three conservative
detectors are opt-in:

```js
const findings = scan(
  'Customer name: Alice Example; address: 120 Cedar Street; DOB: 1990-04-23',
  { enable: ['contextual'] },
);

// person_name, street_address, date_of_birth
// each finding includes risk, confidence, and the exact sensitive span
```

For broader multilingual free-text PII, connect a local model without coupling
the zero-dependency core to one ML runtime:

```js
const policy = {
  semanticProvider: {
    async detect(text) {
      return [{
        detector: 'person_model', label: 'Person',
        why: 'Local multilingual NER result.',
        start: 12, end: 25, confidence: 0.94, risk: 'high',
      }];
    },
  },
  minConfidence: 0.8,
};

const safe = await redactAsync(input, policy);
```

Semantic and deterministic spans enter the same overlap arbitration. Higher-risk,
higher-priority, and better-validated findings win instead of whichever regular
expression happens to run first.

## Learned confidence, fewer false positives

Generic, format-agnostic detectors such as `high_entropy` catch unknown-format
keys, but they also fire on benign high-entropy strings: UUIDs, git SHAs, digests,
object ids, and slugs. `refineConfidence` runs a small learned classifier over
each match to tell real secrets from look-alikes, then nudges the confidence
score. Pair it with `minConfidence` to drop the noise.

```js
const noisy = 'id 9fceb02d0ae598e95dc970b74767f19372d61af8 tok Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv';

scan(noisy, { enable: ['high_entropy'] });
// git SHA and the unknown-format token both flagged at a flat 60%

scan(noisy, { enable: ['high_entropy'], refineConfidence: true, minConfidence: 0.5 });
// the SHA is gone; the token survives (refined up to 80%)
```

The classifier is logistic regression over cheap character features (entropy,
character-class mix, structure, and nearby labels like `api_key=` or `commit`).
It is trained offline by [`scripts/train-confidence-model.mjs`](scripts/train-confidence-model.mjs)
and shipped as fixed weights, so the runtime stays zero-dependency, synchronous,
and deterministic — no model download, no native add-on, safe on edge and in the
browser. Only detectors marked `refine` are touched; checksum-validated ones
(cards, IBANs, national ids) are always left alone.

Score a string yourself from `flare-redact` or the `flare-redact/ml` subpath:

```js
import { secretProbability } from 'flare-redact/ml';

secretProbability('Zx9Kq2Lm7Pv4Rt6Wy8Bn3Cf5Hj1Dg0As7Uv', 'authorization: Bearer …'); // ~1.00
secretProbability('9fceb02d0ae598e95dc970b74767f19372d61af8', 'commit …'); // ~0.00
```

## Build a private chat app

If you're building a chat interface — over your own local model or any API — a
**session** is the drop-in layer. One session holds one vault, so a value keeps
the same placeholder across every turn: mask the user's message on the way in,
restore the model's reply on the way out. It's model-agnostic and synchronous.
Run `npm run benchmark` on your own target runtime instead of relying on a
hardware-independent latency claim.

```js
import { createSession } from 'flare-redact';

const session = createSession({ enable: ['pii'] });

// on the way in — the model only ever sees placeholders
const prompt = session.redact(userMessage);
const reply = await myModel.generate(prompt);

// on the way out — the user sees the real values back
show(session.restore(reply));
```

Streaming? Restore token by token, even when a placeholder is split across chunks:

```js
const out = session.stream();
for await (const chunk of modelStream) process(out.push(chunk.text));
process(out.flush());
```

`session.redactMessages([{ role, content }])` masks a whole chat array at once,
including nested tool calls, and `session.reset()` starts a fresh conversation.
Detected original values stay local while your app keeps a reversible reference.

## Protect tool calls and MCP loops

An agent loop has two directions: model-produced arguments need their local
values restored before a tool executes, while tool results need new secrets
masked before they enter model context. Use a separate vault for each tool or
trust domain so a prompt-injected model cannot move one tool's placeholder into
another tool's arguments and recover the original:

```js
import { createScopedToolBoundary } from 'flare-redact/tool';

const boundary = createScopedToolBoundary();

const result = await database.query('select connection_uri from services');
const safeResult = boundary.redactForModel('database', result);
const modelCall = await model.generateToolCall(safeResult);

// Use a runtime-owned tool/trust-domain name, never a model-supplied scope.
const acceptedTool = toolRegistry.resolve(modelCall.name);
const localCall = boundary.restoreForTool(acceptedTool.scope, modelCall);
await executeTool(localCall);
```

Only placeholders minted inside `acceptedTool.scope` are restored. Unknown and
cross-scope placeholders stay opaque. `restoreForApp()` can restore every scope
only at the final trusted application boundary, and `reset(scope?)` clears one
scope or the whole conversation. Scope count is bounded by default.

> **Legacy warning:** `createToolBoundary()` remains backward compatible for a
> single tool or single trust domain, but `restoreForTool()` restores *any*
> placeholder known to that boundary. Do not share one legacy boundary across
> mutually untrusted tools. Prefer `createScopedToolBoundary()` for new agent
> and MCP integrations.

For safe logging without reversibility, use `redactToolCall()`,
`redactToolResult()`, or `redactMcpMessage()` from the same entry point.

## Your own words

Detectors can't know your product codenames, project names, or internal jargon —
so hand them a list. `terms` catches exactly the words you name (any language,
longest match first, word-boundary safe), one-way or reversibly.

```js
// one-way, with your own replacement text
redact('Launch Project Zeus with Falcon', {
  terms: { 'Project Zeus': '[CLASSIFIED]', 'Falcon': '[CLASSIFIED]' },
});
// → 'Launch [CLASSIFIED] with [CLASSIFIED]'

// reversible — send to a model, get it back
const vault = createVault({ terms: ['Project Zeus'] });
const safe = vault.redact('ship Project Zeus');   // 'ship [FR_CUSTOM_TERM_a17c…]'
vault.restore(safe);                               // 'ship Project Zeus'
```

The same works from the CLI, including a full round-trip — mask, send the safe
text anywhere, then restore what comes back:

```bash
# add words inline or from a file, and write an encrypted vault
export FLARE_REDACT_VAULT_PASSWORD='read-this-from-your-secret-manager'
flare-redact --term "Project Zeus" --terms codenames.txt --vault map.json < in > safe

# later, restore the originals from that map
flare-redact --restore map.json < safe > original
```

## See what leaks, and why

`scan()` finds secrets without changing the input, explains every hit in plain
English, and reports one-based line/column locations — without returning the raw
secret by default.

```js
import { scan } from 'flare-redact';

scan('deploy with password=hunter2 and AKIAIOSFODNN7EXAMPLE');
// →
// [
//   { detector: 'generic_assignment', label: 'Assigned secret',
//     why: 'A value assigned to a sensitive-looking field name…', start: 12, … },
//   { detector: 'aws_access_key', label: 'AWS access key ID',
//     why: 'Pairs with a secret key to control cloud resources and billing.', start: 33, … },
// ]
```

Trusted diagnostics can request the original span with
`scan(input, { includeValues: true })`. Never enable that option for logs, CI
reports, analytics, or error tracking.

Need just the shape of it?

```js
import { isClean, summary } from 'flare-redact';

isClean(payload);   // → false
summary(payload);   // → { total: 3, byDetector: { email: 1, github_token: 1, sensitive_key: 1 } }
```

## Guard your logger in one line

`wrapConsole` patches `console.*` so every argument is redacted on the way out,
and hands you a function to undo it.

```js
import { wrapConsole } from 'flare-redact';

const restore = wrapConsole();
console.log('session', { user: 'bob@x.io', token: 'ghp_…' });
// session { user: 'b***@***', token: 'ghp_***' }
restore();
```

Prefer to be explicit? Bind your options once and reuse it:

```js
import { createRedactor } from 'flare-redact';

const safe = createRedactor({ enable: ['high_entropy'] });
logger.info(safe.redact({ event: 'checkout', user }));
```

## One policy, everywhere

Define what "sensitive" means once, and apply it at every layer — your app, your
logger, your HTTP boundary, your LLM calls. Every adapter takes the same options
object, so a secret is masked the same way across the whole system.

```js
import { definePolicy } from 'flare-redact';
const policy = { enable: ['high_entropy'], allow: ['status@acme.com'] };
```

**pino** — reads the values, not a list of field paths you have to maintain:

```js
import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';

const log = pino(pinoRedact(policy));
log.info({ user: 'bob@corp.com' }); // → {"user":"b***@***"}
```

**winston** — a format that redacts every field, symbol metadata left intact:

```js
import winston from 'winston';
import { winstonRedact } from 'flare-redact/winston';

winston.format.combine(winston.format(winstonRedact(policy))(), winston.format.json());
```

**HTTP** — a safe-to-log snapshot of a request; the live request is untouched.
The URL string, query object, params, headers, and body are all sanitized:

```js
import { httpRedactor } from 'flare-redact/http';

app.use(httpRedactor(policy));
app.use((req, _res, next) => { logger.info(req.redacted()); next(); });
// Authorization and Cookie headers, and any secret in the body or query, are masked.
```

Same `policy` object flows into `flare-redact/llm`, `wrapConsole`, `createVault`,
and `redactStream` too.

## Streams

Pipe any log stream through it. Secrets may be split across chunks, and bounded
multiline PEM private keys are masked as one record. Unterminated private keys
fail closed instead of leaking their remaining bytes.

```js
import { redactStream } from 'flare-redact/stream';

process.stdin.pipe(redactStream()).pipe(process.stdout);
```

## Anonymize a dataset for staging

Point it at a JSON or CSV dump with `--mode surrogate` and you get deterministic,
typed synthetic values. The same input maps the same way in every row under one
key, so joins survive without calling the transformation encryption or anonymity.

```bash
export FLARE_REDACT_SECRET='read-this-from-your-secret-manager'
flare-redact --csv --mode surrogate < customers.csv > customers.safe.csv
```

```
Alice,alice@corp.com,4242 4242 4242 4242      Alice,user_93a78c61e204@example.invalid,7042 5270 7797 8927
Bob,bob@corp.com,5555 5555 5555 4444     →    Bob,user_441ae72c0901@example.invalid,0888 2706 6232 0274
Alice,alice@corp.com,4242 4242 4242 4242      Alice,user_93a78c61e204@example.invalid,7042 5270 7797 8927
```

`redactCsv(text, opts)` is available from `flare-redact/csv` for the same thing
in code.

## Guard what leaves your app

Stop PII from reaching an analytics, telemetry, or webhook endpoint — wrap
`fetch` and name the hosts you don't trust with the real data. Every other
request goes through untouched, so your real API calls are never altered.

```js
import { wrapFetch } from 'flare-redact/fetch';

const fetch = wrapFetch(globalThis.fetch, { hosts: ['api.segment.io', 'telemetry.vendor.com'] });
// bodies sent to those hosts are redacted; everything else is left alone
```

## Fail a build when a secret sneaks in

`scan` from code, or `--scan` from the CLI (which exits non-zero on a hit) — drop
it into CI or a pre-commit hook. File scans report `file:line:column`, while
machine-readable JSON and SARIF reports never echo the matched secret value:

```yaml
- uses: actions/checkout@v5
- uses: actions/setup-node@v5
  with:
    node-version: 24
- name: Scan project text files
  run: npx --yes --package flare-redact@1.4.0 flare-redact --scan . --exclude package-lock.json
```

The scan runs on the GitHub runner, reports safe file and source locations, and
fails without sending repository contents to an external scanning service. A
copy-ready workflow lives in [`examples/github-secret-scan`](examples/github-secret-scan).
Recursive scans do not follow symlinks and skip binary files, files over 1 MiB,
and `.git`, `.hg`, `.svn`, `node_modules`, and `vendor` directories by default.
Use repeatable `--exclude` globs, `--max-file-size`, or
`--no-default-excludes` to change that policy.
Exclude globs support `*`, `?`, and `**`; a pattern without `/` matches that
basename at any depth.

```bash
flare-redact --scan --format json .env app.log > flare-redact.json
flare-redact --sarif .env app.log > flare-redact.sarif
```

## CLI

```bash
npm install -g flare-redact
```

```bash
tail -f app.log | flare-redact               # stream redacted logs
FLARE_REDACT_SECRET=… flare-redact --json --mode hash < event.json
FLARE_REDACT_SECRET=… flare-redact --csv --mode surrogate < dump.csv
flare-redact --scan config.env               # list findings + why (exit 1 if any)
flare-redact --scan .                        # recursively scan a project
flare-redact --scan . --exclude 'test/**' --max-file-size 2mb
flare-redact --scan --format json .env app.log # safe machine-readable report
flare-redact --sarif .env > results.sarif    # GitHub code-scanning report
flare-redact --summary --json < event.json   # counts per detector
flare-redact --enable high_entropy < app.log # also catch unknown-format keys
flare-redact --scan --min-confidence 0.9 .env  # only high-confidence findings
flare-redact --enable high_entropy --refine-confidence --min-confidence 0.5 < app.log # drop UUID/SHA noise
flare-redact --list                          # show every detector
```

## What it catches

On by default:

| Detector | Finds |
|---|---|
| `private_key` | PEM private key blocks (RSA/EC/OpenSSH/PGP) |
| `aws_access_key` | AWS access key IDs (`AKIA…`, `ASIA…`) |
| `aws_secret_key` | AWS secret access keys in assignments (`aws_secret_access_key=…`, `"secretAccessKey": …`) |
| `github_token` | GitHub PATs and OAuth tokens (`ghp_…`, `github_pat_…`) |
| `gitlab_token` | GitLab PATs (`glpat-…`) |
| `slack_token` | Slack tokens (`xoxb-…`) |
| `stripe_key` | Stripe secret / restricted keys (`sk_live_…`, `rk_…`) |
| `anthropic_key` | Anthropic API keys (`sk-ant-…`) |
| `openai_key` | OpenAI API keys (`sk-…`) |
| `google_api_key` | Google API keys (`AIza…`) |
| `sendgrid_key` | SendGrid API keys (`SG.…`) |
| `twilio_key` | Twilio SIDs / keys (`AC…`, `SK…`) |
| `npm_token` | npm tokens (`npm_…`) |
| `jwt` | JSON Web Tokens |
| `bearer_token` | `Authorization: Bearer …` |
| `basic_auth` | `Authorization: Basic …` |
| `url_credentials` | passwords inside connection strings |
| `generic_assignment` | `password=`, `api_key: …`, `secret=…` (any language) |
| `email` | email addresses |
| `obfuscated_email` | bracket-obfuscated emails such as `name [at] host [dot] tld` |
| `credit_card` | card numbers (Luhn-validated) |
| `iban` | IBANs (mod-97 validated) |
| `openrouter_key` / `huggingface_token` / `groq_key` / `xai_key` / `perplexity_key` / `replicate_token` | more AI provider keys |
| `discord_bot_token` / `discord_webhook` / `telegram_bot_token` | chat tokens and webhook URLs |
| `shopify_token` / `square_token` / `stripe_webhook_secret` | commerce secrets |
| `digitalocean_token` / `azure_storage_key` / `vault_token` / `databricks_token` | cloud & infra secrets |
| `sentry_dsn` / `new_relic_key` | observability secrets |
| `airtable_pat` / `postman_key` / `linear_key` / `figma_token` / `notion_token` | SaaS workspace tokens |
| `doppler_token` / `supabase_key` / `netlify_token` / `mailgun_key` | platform API keys |

Opt in with `enable`:

| Detector / tag | Finds |
|---|---|
| `high_entropy` | long random-looking tokens of *any* format (entropy-based) |
| `crypto` | Bitcoin & Ethereum addresses, BIP39 seed phrases |
| `finance` | SWIFT/BIC, US ABA routing numbers |
| `vehicle` | VINs (checksum-validated) |
| `network` | IPs, MAC addresses, coordinates, internal URLs |
| `phone` | E.164 and formatted national numbers (`+90 532 123 45 67`, `(555) 123-4567`, `0532 123 45 67`) — digit-count validated, date-safe |

Plus object values whose **key name** is sensitive (`password`, `token`,
`authorization`, `cookie`, `cvv`, …) are masked regardless of content.

## Multilingual secret vocabulary and IDs

Secrets like API keys and card numbers don't care what language your app is in.
Neither does this — but the word-based checks do, so words like *password*,
*secret*, and *token* are recognized as assignments and as object keys in all
**24 languages** below:

| | | |
|---|---|---|
| 🇬🇧 English `password` | 🇨🇳 Chinese `密码` | 🇮🇳 Hindi `पासवर्ड` |
| 🇪🇸 Spanish `contraseña` | 🇸🇦 Arabic `كلمة المرور` | 🇫🇷 French `mot de passe` |
| 🇵🇹 Portuguese `senha` | 🇷🇺 Russian `пароль` | 🇯🇵 Japanese `パスワード` |
| 🇩🇪 German `passwort` | 🇰🇷 Korean `비밀번호` | 🇹🇷 Turkish `şifre` |
| 🇮🇹 Italian `segreto` | 🇮🇷 Persian `رمز عبور` | 🇵🇱 Polish `hasło` |
| 🇺🇦 Ukrainian `пароль` | 🇳🇱 Dutch `wachtwoord` | 🇻🇳 Vietnamese `mật khẩu` |
| 🇮🇩 Indonesian `kata sandi` | 🇹🇭 Thai `รหัสผ่าน` | 🇬🇷 Greek `κωδικός` |
| 🇮🇱 Hebrew `סיסמה` | 🇦🇿 Azerbaijani `şifrə` | 🇷🇴 Romanian `parolă` |

National IDs are opt-in and **checksum-validated**, so a random run of digits is
never mistaken for one. Enable a whole group or a single country by tag:

```js
redact(text, { enable: ['pii'] });        // every national ID below
redact(text, { enable: ['tr', 'de'] });   // just Turkish and German
```

| Detector | Country | Validated by |
|---|---|---|
| `iban` | 🌐 international *(on by default)* | ISO 13616 mod-97 |
| `tr_tckn` | 🇹🇷 Turkey | TCKN checksum |
| `de_tax_id` | 🇩🇪 Germany | ISO 7064 mod-11,10 |
| `es_dni` | 🇪🇸 Spain (DNI/NIE) | control letter mod-23 |
| `it_codice_fiscale` | 🇮🇹 Italy | odd/even table |
| `br_cpf` | 🇧🇷 Brazil | two mod-11 digits |
| `nl_bsn` | 🇳🇱 Netherlands | 11-test |
| `pl_pesel` | 🇵🇱 Poland | weighted mod-10 |
| `ca_sin` | 🇨🇦 Canada | Luhn |
| `us_ssn` | 🇺🇸 United States | issued-range rules |
| `uk_nhs` | 🇬🇧 United Kingdom (NHS) | weighted mod-11 |
| `fr_nir` | 🇫🇷 France (NIR) | INSEE mod-97 key |
| `in_aadhaar` | 🇮🇳 India (Aadhaar) | Verhoeff |
| `au_tfn` | 🇦🇺 Australia (TFN) | weighted mod-11 |
| `cn_resident_id` | 🇨🇳 China | ISO 7064 mod-11,2 |
| `jp_my_number` | 🇯🇵 Japan (My Number) | weighted mod-11 |

Every algorithm has its own tests against known-valid and known-invalid numbers,
so enabling them won't turn your logs into a wall of `[REDACTED]`.

## Custom detectors & allowlists

Teach it your own secrets, and tell it what to leave alone:

```js
redact(text, {
  custom: [{
    id: 'internal_ticket',
    label: 'Internal ticket',
    why: 'Leaks internal issue-tracker IDs.',
    pattern: /\bACME-\d{4,6}\b/g,
    mask: () => '[TICKET]',
    default: true,
  }],
  allow: ['support@acme.com'],        // never redact these exact values
  redactKeys: ['ssn', 'dob'],         // extra sensitive object keys
});
```

## API

```ts
redact<T>(input: T, opts?): T                 // masked copy, same shape
redactAsync<T>(input: T, opts?): Promise<T>   // supports async local NER providers
scan(input, opts?): Finding[]                 // findings + why, input untouched
scanAsync(input, opts?): Promise<Finding[]>   // supports async local NER providers
isClean(input, opts?): boolean                // any secrets at all?
isCleanAsync(input, opts?): Promise<boolean>
summary(input, opts?): { total, byDetector, byRisk }
compilePolicy(opts)                            // pre-resolved reusable sync + async policy
createRedactor(opts) / definePolicy(opts)      // compatibility names for compilePolicy
wrapConsole(opts?, console?): () => void      // patch console.*, returns restore

createVault(opts?): Vault                      // reversible: redact / restore / entries
restore(input, vaultOrMap): T                  // put originals back
sealVault(vaultOrEntries, password): Promise<SealedVaultV1>
openVault(envelope, password): Promise<Array<[placeholder, original]>>

// adapters — each takes the same options object
pinoRedact(opts?)        // 'flare-redact/pino'    → { formatters: { log } }
winstonRedact(opts?)     // 'flare-redact/winston' → a format transform
redactHttp(req, opts?)   // 'flare-redact/http'    → safe-to-log request snapshot
redactUrl(url, opts?)    // 'flare-redact/http'    → sanitized absolute/relative URL
httpRedactor(opts?)      // 'flare-redact/http'    → Express/Connect middleware
redactCsv(text, opts?)   // 'flare-redact/csv'     → anonymize a CSV dataset
wrapFetch(fetch, opts?)  // 'flare-redact/fetch'   → redact egress to named hosts
createRedactionMiddleware(opts?) // 'flare-redact/middleware' → any function/handler

// from 'flare-redact/ml'
secretProbability(value, context?): number      // learned secret-vs-look-alike score, 0..1
extractFeatures(value, context?): number[]      // the raw feature vector

// from 'flare-redact/llm'
wrapOpenAI(client, opts?)                       // scrub prompts, restore replies (+streaming)
wrapAnthropic(client, opts?)                    // same for messages.create + system
redactPrompt(text, opts?): { text, vault }

// from 'flare-redact/tool'
createScopedToolBoundary(opts?)                // scope-safe model ↔ tool/MCP boundary
createToolBoundary(opts?)                      // legacy single-trust-domain boundary
redactToolCall / redactToolResult / redactMcpMessage

// from 'flare-redact/stream'
redactStream(opts?): Transform                  // chunk-safe + bounded multiline PEM redaction

// opts
// {
//   only?, enable?, disable?, custom?,   // which detectors run
//   mode?: 'mask' | 'label' | 'hash' | 'pseudonym' | 'surrogate',
//   transformSecret?, mask?, minConfidence?, refineConfidence?, semanticProvider?, limits?,
//   includeValues?: boolean,                // scan only; unsafe raw values
//   redactKeys?: boolean | RegExp | string[],
//   allow?: RegExp | string[],
//   terms?: string[] | { term: replacement }, termsCaseSensitive?,
// }

createSession(opts?)      // chat/AI apps: redact in, restore out, streaming, reset
```

## Why not a field allowlist?

Path-based redactors (like naming fields in a logger config) only hide the fields
you *remembered* to name. The leak is always the field you forgot — the free-text
message, the nested third-party payload, the string someone concatenated by hand.
flare-redact scans the actual values, so it doesn't depend on your memory.

Built-in patterns are reviewed for bounded structure, exercised by an
adversarial runtime suite, and protected by per-string input and finding limits.
JavaScript RegExp does not provide a formal linear-time guarantee, however, and
arbitrary custom detectors are trusted code. Run the included benchmarks on your
own runtime instead of treating a badge as a security proof:

```bash
npm run benchmark
npm run benchmark:adversarial
```

## Security boundaries

- Detection is best-effort; a clean scan is not proof that data contains no PII.
- `scan()` omits raw values by default. `includeValues` intentionally puts those
  secrets back into process memory and must stay out of external reports.
- `pseudonym` is keyed, deterministic pseudonymization — not NIST FF1 encryption.
- A vault map is sensitive; persist only the authenticated encrypted envelope.
- Restoring a placeholder intentionally reveals its original locally. Do not
  forward restored model output to another untrusted sink automatically.
- A model-produced tool name is untrusted input. Resolve it to a runtime-owned
  tool/trust-domain scope before calling `restoreForTool()`.
- The legacy `createToolBoundary()` restores every placeholder in its shared
  vault. Use `createScopedToolBoundary()` whenever more than one tool or trust
  domain can receive model-produced arguments.
- The 24-language badge describes secret-key vocabulary, not general multilingual
  named-entity recognition. Use a local `semanticProvider` for that task.

Encrypted vaults do not protect a compromised host or secrets already resident
in process memory. Deterministic transforms reveal when two inputs are equal.

## License

MIT © Umud Hasanli
