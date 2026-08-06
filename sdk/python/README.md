# flare-redact for Python

Hide secrets and PII before they reach a log, a model, or a vendor.

Zero dependencies, one file to read, and the same detector spec as the
JavaScript, Go and Rust engines — so a policy written once behaves identically
in every service you own. Every claim below is covered by the
[shared conformance corpus](../../spec/conformance/).

Not on PyPI yet — it installs from this repository:

```bash
pip install "flare-redact @ git+https://github.com/flare-collection/flare-redact@v1.5.1#subdirectory=sdk/python"
```

```python
from flare_redact import redact

redact("contact ada@example.com with key AKIAIOSFODNN7EXAMPLE")
# 'contact a***@*** with key AKIA***'
```

## Contents

- [Redact anything](#redact-anything)
- [Protect your logs in one line](#protect-your-logs-in-one-line)
- [Send a prompt without sending the data](#send-a-prompt-without-sending-the-data)
- [Wrap the client you already use](#wrap-the-client-you-already-use)
- [One policy, reused](#one-policy-reused)
- [See what leaks, and why](#see-what-leaks-and-why)
- [Ways to hide a value](#ways-to-hide-a-value)
- [Your own words and detector packs](#your-own-words-and-detector-packs)
- [Talk to the gateway instead](#talk-to-the-gateway-instead)
- [Command line](#command-line)
- [API](#api)
- [What this does not do](#what-this-does-not-do)

## Redact anything

Strings, dicts, lists, tuples, sets, exceptions — anything with strings in it.
Shape, types and shared references survive; only the strings change.

```python
from flare_redact import redact

redact({
    "user": {"email": "ada@example.com", "id": 42},
    "db": "postgres://app:s3cr3t@db.internal/main",
    "password": "hunter2",
})
# {'user': {'email': 'a***@***', 'id': 42},
#  'db': 'postgres://app:***@db.internal/main',
#  'password': '***'}
```

Numbers stay numbers, `None` stays `None`, and a structure that points at itself
terminates instead of recursing forever.

## Protect your logs in one line

```python
import logging
import flare_redact.log as flare_log

flare_log.install(enable=["pii"])

logging.getLogger(__name__).info("charge failed for %s", "ada@example.com")
# charge failed for a***@***
```

`install()` adds a filter to the logger *and* wraps each handler's formatter.
Both are needed: the filter sees `record.msg` and `record.args` cheaply and keeps
structured fields structured, while the formatter is the only thing that sees a
rendered traceback — and a secret passed to the function that raised is *in* that
traceback.

```python
from flare_redact.log import RedactingFilter, RedactingFormatter

logger.addFilter(RedactingFilter(enable=["pii"], extra_attributes=["context"]))
handler.setFormatter(RedactingFormatter(logging.Formatter("%(message)s")))
```

## Send a prompt without sending the data

A session mints a stable placeholder per value and remembers it, so the model
sees `[FR_EMAIL_…]` and your user still gets the right answer.

```python
from flare_redact import create_session

session = create_session(enable=["pii"])

safe = session.redact("Email the invoice to ada@example.com and copy grace@example.org")
reply = call_your_model(safe)
print(session.restore(reply))
```

The same value maps to the same placeholder for the life of the session, so a
follow-up turn like *"resend it to the first address"* still resolves. Streaming
works too, including when a placeholder is split across chunks:

```python
restorer = session.stream()
for chunk in model_stream:
    print(restorer.push(chunk), end="")
print(restorer.flush(), end="")
```

## Wrap the client you already use

```python
from openai import OpenAI
from flare_redact.integrations import wrap_openai

client = wrap_openai(OpenAI(), enable=["pii"])

client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Draft a reply to ada@example.com"}],
)
```

Prompts are redacted on the way out and replies restored on the way back. The
wrapper is duck-typed and never imports the vendor SDK, so it keeps working
across client versions and adds nothing to your dependency tree. Wrapping the
same client twice is a no-op. `wrap_anthropic` works the same way.

## One policy, reused

Compiling once resolves the detector list, the mask function and the key tests
a single time — and, more importantly, guarantees your logs, your HTTP layer and
your prompts all agree on what "sensitive" means.

```python
from flare_redact import compile_policy

policy = compile_policy(enable=["pii", "tr"], disable=["ipv4"], min_confidence=0.7)

policy.redact(payload)
policy.redact_str(line)
policy.scan(payload)
policy.summary(payload)
policy.vault()
policy.session()
```

## See what leaks, and why

```python
from flare_redact import scan

for finding in scan({"note": "card 4111 1111 1111 1111"}):
    print(finding.detector, finding.risk, finding.path, finding.line, finding.why)
# credit_card high note 1 A card number in logs is a PCI-DSS violation.
```

Findings never carry the matched value unless you ask for it with
`include_values=True`, because findings are the thing people paste into tickets.

## Ways to hide a value

| `mode` | `ada@example.com` becomes | Use it for |
|---|---|---|
| `mask` (default) | `a***@***` | logs, anything human-read |
| `label` | `[REDACTED:email]` | when you want to see *what* was removed |
| `hash` | `email_12016e848bcb…` | correlating without storing |
| `pseudonym` | `nlp@kmxjgxr.hjh` | keeping shape for parsers |
| `surrogate` | `user_7560a7763fe8@example.invalid` | test data that still validates |

`hash`, `pseudonym` and `surrogate` are keyed and deterministic — pass
`transform_secret` (from your secret manager, never a literal) and the same input
always maps to the same output, so joins survive anonymisation. A missing secret
raises rather than silently producing unkeyed output.

Surrogates are type-aware: a card number becomes another card number with a
valid Luhn check digit, so downstream validation still passes.

## Your own words and detector packs

```python
redact("project Bluebird ships in Q3", terms={"Bluebird": "[PROJECT]"})
# 'project [PROJECT] ships in Q3'
```

Terms match longest-first on Unicode word boundaries, so `Bluebirds` is left
alone. For a whole detector set, write an [FRS-1 pack](../../spec/SPEC.md) and
every language loads the same file:

```python
from flare_redact import load_pack, redact

pack = load_pack("detectors/acme.json")
redact(text, pack=pack)
```

A pack that uses a construct this engine cannot execute exactly — a lookahead, a
`\d` whose meaning differs between languages, an unknown checksum — fails to
load. Failing open is how a redactor leaks.

## Talk to the gateway instead

The local engine implements the portable FRS-1 profile. The
[gateway](../../docker/README.md) runs the full detector set and holds
server-side sessions; point a client at your sidecar when you want the policy
configured in one place for every language in the estate.

```python
from flare_redact.client import GatewayClient

gateway = GatewayClient("http://127.0.0.1:8080", token=os.environ["FLARE_GATEWAY_TOKEN"])

gateway.redact({"email": "ada@example.com"})

with gateway.session(enable=["pii"]) as session:
    safe = session.redact(user_message)
    reply = session.restore(model_reply)
```

Standard library only — no `requests`, no `httpx`. `transform_secret` is never
serialised: configure keyed transforms on the gateway, not in every caller.

## Command line

```bash
tail -f app.log | flare-redact
flare-redact --scan --format json config.env
flare-redact --sarif . > flare-redact.sarif
flare-redact --json --mode label < event.json
```

Exit codes match the JavaScript CLI — `0` clean, `1` findings, `2` error — so the
two are interchangeable in a pipeline or a pre-commit hook. `python -m flare_redact`
works without installing a script.

## API

| | |
|---|---|
| `redact(value, **options)` | redact every string reachable from `value` |
| `scan(value, **options)` | list `Finding`s with paths and line/column |
| `is_clean(value, **options)` | `True` when nothing would be redacted |
| `summary(value, **options)` | counts by detector and by risk |
| `compile_policy(**options)` | a reusable `Policy` |
| `create_vault(**options)` | reversible redaction |
| `create_session(**options)` | a conversation-scoped vault |
| `restore(value, source)` | put originals back from a vault or mapping |
| `load_pack(source)` / `core_pack()` | FRS-1 detector packs |

Options: `only`, `enable`, `disable`, `mode`, `mask`, `transform_secret`,
`redact_keys`, `allow`, `terms`, `terms_case_sensitive`, `min_confidence`,
`refine_confidence`, `include_values`, `max_input_length`, `max_findings`, `pack`.

Requires Python 3.8+. Ships type hints (`py.typed`).

## What this does not do

- **It is not a replacement for not collecting the data.** Redaction is a
  backstop for the places data ends up anyway: logs, prompts, crash reports.
- **`pseudonym` is not encryption.** It is a keyed, shape-preserving pseudonym.
  It is not reversible and does not implement NIST FF1.
- **Detection is not proof.** A detector that has never seen your internal token
  format will not find it — add it with `terms`, a custom pack, or by opening an
  issue.
- **Limits fail closed.** Input over `max_input_length` raises instead of
  returning partially redacted text, because a caller cannot tell partially
  redacted output from clean output.

MIT © Umud Hasanli · [Specification](../../spec/SPEC.md) ·
[Source](https://github.com/flare-collection/flare-redact)
