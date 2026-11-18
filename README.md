<p align="center">
  <img src="assets/flare-redact.svg" alt="flare-redact" width="160">
</p>

<h1 align="center">flare-redact</h1>

<p align="center">
  <b>Keep secrets and personal data out of your logs, Sentry, LLM prompts and commits.</b><br>
  It reads the values, not the field names. Zero dependencies.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/flare-redact"><img src="https://img.shields.io/npm/v/flare-redact?label=npm" alt="npm version"></a>
  <a href="https://github.com/flare-collection/flare-redact/actions/workflows/ci.yml"><img src="https://github.com/flare-collection/flare-redact/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/npm/types/flare-redact.svg" alt="TypeScript">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/detectors-90-4f46e5" alt="90 detectors">
  <img src="https://img.shields.io/badge/languages-24-4f46e5" alt="24 languages">
</p>

<p align="center">
  <a href="https://flare-collection.github.io/flare-redact/">Playground</a>
  · <a href="docs/guide.md">Guide</a>
  · <a href="docs/guide.md#api">API</a>
  · <a href="https://flare-collection.github.io/flare-redact/guides/">Recipes</a>
  · <a href="https://flare-collection.github.io/flare-redact/llms-full.txt">Docs for AI assistants</a>
</p>

<p align="center">
  <img src="assets/demo.svg" alt="Before and after: secrets and PII masked in a log line, across languages" width="820">
</p>

Someone logs an object, a session token was inside it, and now that token sits
in your log aggregator, your error tracker and an LLM provider's servers.
Redaction by field name only hides the fields you remembered to list.
**flare-redact** looks at the values themselves, so the AWS key pasted into a
`note` field and the card number inside a stack trace are masked too.

```js
import { redact } from 'flare-redact';

redact('User alice@corp.com paid with 4242 4242 4242 4242, token ghp_' + 'a'.repeat(36));
// → 'User a***@*** paid with **** **** **** 4242, token ghp_***'

redact({ user: 'bob@corp.com', password: 'hunter2', note: 'my key is AKIAIOSFODNN7EXAMPLE' });
// → { user: 'b***@***', password: '***', note: 'my key is AKIA***' }
```

## Highlights

- 🔍 **Reads content, not field names.** 90 detectors for API keys, tokens, JWTs,
  private keys, cards, IBANs, emails and national IDs, checksum-validated
  wherever a checksum exists.
- ⚡ **No code change needed.** `node --import flare-redact/register app.js`
  redacts every `console.*` call.
- 🤖 **Private LLM calls.** Wrap the OpenAI or Anthropic client: the model sees
  placeholders, your app gets the real values back, streaming included.
- 🔌 **Fits what you already run.** pino, winston, Sentry, Express, `fetch`,
  streams, and any SDK through one middleware.
- 🚫 **Stops leaks before the commit.** A pre-commit hook that scans only the
  lines you add, and a CI scan with SARIF output.
- 🌍 **International by default: 24 languages** of secret vocabulary and
  national ID formats.
- 🪶 **Zero dependencies.** Node 20+, browsers, edge runtimes, Bun and Deno.
- 🐍 **Python, Go and Rust** engines that run the same detector spec and pass
  the same conformance suite.

<p align="center">
  🇬🇧 🇨🇳 🇮🇳 🇪🇸 🇸🇦 🇫🇷 🇵🇹 🇷🇺 🇯🇵 🇩🇪 🇰🇷 🇹🇷 🇮🇹 🇮🇷 🇵🇱 🇺🇦 🇳🇱 🇻🇳 🇮🇩 🇹🇭 🇬🇷 🇮🇱 🇦🇿 🇷🇴
</p>

## Quick start

```bash
npm install flare-redact
```

Then pick the way that suits you:

```bash
# No code change: every console.* call is redacted
node --import flare-redact/register app.js

# Let it read your package.json and print the lines to paste
npx flare-redact init          # openai, @anthropic-ai/sdk, Sentry, pino, winston, express
npx flare-redact init --hook   # also stop any commit that adds a secret
npx flare-redact init --ci     # also scan every pull request
```

Want more than the defaults? Choose a goal instead of a detector list:
`{ preset: 'logs' }`, `'llm'`, `'gdpr'` or `'strict'` ([what each adds](docs/guide.md#presets)).

## Where it plugs in

### Logs

```js
import pino from 'pino';
import { pinoRedact } from 'flare-redact/pino';

const log = pino(pinoRedact());
log.info({ user: 'bob@corp.com', token: 'ghp_…' }, 'login');
// {"user":"b***@***","token":"***","msg":"login", …}
```

winston has `winstonRedact()` from `flare-redact/winston`, and plain `console`
has `wrapConsole()` or the `--import` flag above.

### LLM prompts

```js
import OpenAI from 'openai';
import { wrapOpenAI } from 'flare-redact/llm';

const openai = wrapOpenAI(new OpenAI());
```

```
your app sends  →  Email the invoice to alice@corp.com, card 4242 4242 4242 4242
the model sees  →  Email the invoice to [FR_EMAIL_7f2a…], card [FR_CREDIT_CARD_19be…]
your app gets   →  Sent to alice@corp.com. Card 4242 4242 4242 4242 wasn't stored.
```

`wrapAnthropic` does the same for Claude. Tool calls, MCP messages and agent
tool boundaries are covered too: see [the guide](docs/guide.md#redact-prompts-before-they-reach-an-llm).

### Sentry

```js
import * as Sentry from '@sentry/node';
import { sentryRedact } from 'flare-redact/sentry';

Sentry.init({ dsn: process.env.SENTRY_DSN, ...sentryRedact({ preset: 'gdpr' }) });
```

Events, spans, logs and breadcrumbs are redacted in your process, before they
leave it. Sentry's own ids, release and stack frames stay intact, so grouping
and source maps keep working. [Details and limits](docs/guide.md#one-policy-everywhere).

### Commits and CI

On GitHub, `uses: flare-collection/flare-redact@v1` annotates each finding on the pull request ([inputs](docs/guide.md#fail-a-build-when-a-secret-sneaks-in)).

```bash
npx flare-redact init --hook         # pre-commit: scans only the lines being added
npx flare-redact --scan . --sarif    # CI: exits 1 on a finding, never prints the secret
```

Using [pre-commit](https://pre-commit.com)? Add `repo: https://github.com/flare-collection/flare-redact` with `id: flare-redact` ([setup](docs/guide.md#fail-a-build-when-a-secret-sneaks-in)).

### No Node in the stack?

Point any service at the [sidecar gateway](docs/guide.md#the-sidecar-gateway)
and it redacts request bodies on the way to OpenAI or Anthropic, with no code
change. Or use the [Python, Go and Rust](docs/guide.md#python-go-and-rust) engines:

```python
from flare_redact import create_session

session = create_session(enable=["pii"])
safe = session.redact("Email the invoice to ada@example.com")
```

## How it compares

| Tool | What it does well | What flare-redact adds |
|---|---|---|
| Logger path redaction (pino `redact`, fast-redact) | Fast masking of the fields you list | Finds secrets in fields you never listed and inside free text |
| Sentry server-side scrubbing | Scrubs sensitive-looking fields once events reach Sentry | Redacts in your process, before the event leaves it |
| gitleaks, TruffleHog | Find secrets in git history and files | Masks secrets at runtime in logs, errors and prompts. Use both |
| Microsoft Presidio | Model-based PII detection in prose, as a Python service | Runs in-process with no model and no dependencies; plug a model in with `semanticProvider` when you need that recall |

## FAQ

**How do I hide API keys and passwords in Node.js logs?**
Start the app with `node --import flare-redact/register app.js`, or add
`pinoRedact()` or `winstonRedact()` to your logger. Nothing else to configure.

**How do I keep customer data out of OpenAI or Claude API calls?**
Wrap the client with `wrapOpenAI` or `wrapAnthropic`. Sensitive values become
placeholders before the request is sent and are restored in the reply.

**Will it slow my app down?**
It runs in your process with no model and no network call, and its patterns are
bounded and tested against hostile input. `npm run benchmark` measures it on
your own runtime.

**Does it catch everything?**
No tool does. Detection is best-effort, and names in prose are found by rules,
not a trained model. Read the [security boundaries](docs/guide.md#security-boundaries)
before relying on it for compliance.

## For AI coding assistants

The docs site serves [`llms.txt`](https://flare-collection.github.io/flare-redact/llms.txt)
and [`llms-full.txt`](https://flare-collection.github.io/flare-redact/llms-full.txt).
Add one line to your `AGENTS.md`, `CLAUDE.md` or `.cursor/rules` so generated
code uses the library instead of ad-hoc regexes:

```
For masking secrets or PII in logs, prompts or datasets, use the flare-redact
package (API: https://flare-collection.github.io/flare-redact/llms-full.txt).
```

## Documentation

- [Guide](docs/guide.md): every feature, option and integration, with examples
- [What it catches](docs/guide.md#what-it-catches): the full detector list
- [API reference](docs/guide.md#api) and [CLI](docs/guide.md#cli)
- [Recipes](https://flare-collection.github.io/flare-redact/guides/) and [runnable examples](docs/guide.md#runnable-examples)
- [Changelog](CHANGELOG.md), [migrating from 0.9](MIGRATION.md), [security policy](SECURITY.md)

## Contributing

Bug reports, new detectors and fixes are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).
Found a leak that flare-redact missed? Please report it privately through
[SECURITY.md](SECURITY.md).

If flare-redact kept a secret out of your logs, a ⭐ helps other people find it.

## License

MIT © Umud Hasanli
