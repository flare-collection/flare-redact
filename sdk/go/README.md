# flare-redact for Go

Hide secrets and PII before they reach a log, a model, or a vendor.

Standard library only, and the same [FRS-1 detector spec](../../spec/SPEC.md) as
the JavaScript, Python and Rust engines — so a policy written once behaves
identically in every service you own. The [shared conformance corpus](../../spec/conformance/)
runs in `go test`, so "identically" is a test, not a claim.

```bash
go get github.com/flare-collection/flare-redact/sdk/go
```

```go
import flareredact "github.com/flare-collection/flare-redact/sdk/go"

policy, err := flareredact.Compile(flareredact.Options{Enable: []string{"pii"}})
safe, err := policy.RedactString("contact ada@example.com with key AKIAIOSFODNN7EXAMPLE")
// "contact a***@*** with key AKIA***"
```

## Compile once, reuse everywhere

```go
policy, err := flareredact.Compile(flareredact.Options{
    Enable:        []string{"pii", "tr"},
    Disable:       []string{"ipv4"},
    MinConfidence: 0.7,
})
```

Compiling resolves the detector list, the mask function and the key tests once.
More importantly, one `*Policy` shared across your logger, your HTTP client and
your prompt path is what makes "sensitive" mean the same thing in all three.

## Structured values

```go
redacted, err := policy.Redact(map[string]any{
    "user":     map[string]any{"email": "ada@example.com", "id": 42},
    "password": "hunter2",
})
// map[user:map[email:a***@*** id:42] password:***]
```

Scalars stay scalars, and the input is never mutated. Map entries are visited in
ascending key order: Go randomises map iteration, and finding order and vault
placeholder numbering are observable, so the engine imposes an order rather than
inheriting one.

For a struct, go through JSON:

```go
document, _ := json.Marshal(event)
safe, err := policy.RedactJSON(document)
```

Reflection over arbitrary structs is deliberately not attempted — it would
silently skip unexported fields, and a redactor that quietly misses data is worse
than one that says it did nothing.

## Logs

```go
logger := slog.New(flareredact.NewSlogHandler(
    slog.NewJSONHandler(os.Stdout, nil),
    policy,
))
slog.SetDefault(logger)

slog.Info("charge failed", "email", "ada@example.com", "password", pw)
// {"level":"INFO","msg":"charge failed","email":"a***@***","password":"***"}
```

The handler redacts the message, every attribute and every group. Attributes
bound with `WithAttrs` are redacted once, when they are bound, rather than on
every record. If redaction itself fails — an oversized value, say — the field
becomes `[REDACTION FAILED]`; emitting the original is the one outcome this
package exists to prevent.

## Outbound HTTP

```go
client := &http.Client{Transport: &flareredact.Transport{
    Policy: policy,
    Hosts:  []string{"api.segment.io", "hooks.slack.com"},
}}
```

`Hosts` is opt-in by destination: with none set nothing is redacted. You name the
sinks you do not want data flowing to instead of paying to scan every request in
your service.

## Send a prompt without sending the data

```go
session, err := flareredact.NewSession(flareredact.Options{Enable: []string{"pii"}}, flareredact.VaultOptions{})

safe, err := session.Redact(userMessage)   // send this to the model
reply := session.Restore(modelReply)       // show this to the user
```

The same value maps to the same placeholder for the life of the session, so a
follow-up turn like *"resend it to the first address"* still resolves.
Placeholders are opaque by default — random, not numbered — so the text that
leaves your process does not disclose how many distinct people it involved.

Streaming, including a placeholder split across chunks:

```go
restorer := session.Stream()
for chunk := range chunks {
    fmt.Print(restorer.Push(chunk))
}
fmt.Print(restorer.Flush())
```

## Ways to hide a value

| `Mode` | `ada@example.com` becomes | Use it for |
|---|---|---|
| `ModeMask` (default) | `a***@***` | logs, anything human-read |
| `ModeLabel` | `[REDACTED:email]` | when you want to see *what* was removed |
| `ModeHash` | `email_12016e848bcb…` | correlating without storing |
| `ModePseudonym` | `nlp@kmxjgxr.hjh` | keeping shape for parsers |
| `ModeSurrogate` | `user_7560a7763fe8@example.invalid` | test data that still validates |

The keyed modes need `TransformSecret`. A missing secret is `ErrMissingSecret`,
not a silent fallback to unkeyed output. Surrogates are type-aware: a card number
becomes another card number with a valid Luhn digit, so downstream validation
still passes.

## The gateway

Point a client at your [sidecar](../../docker/README.md) when you want the policy
configured in one place for every language in the estate:

```go
gateway := flareredact.NewClient("http://127.0.0.1:8787", flareredact.ClientOptions{
    Token: os.Getenv("FLARE_GATEWAY_TOKEN"),
})
safe, err := gateway.Redact(ctx, payload, flareredact.Options{Enable: []string{"pii"}})
```

## Custom detector packs

```go
pack, err := flareredact.LoadPack(packJSON)
policy, err := flareredact.Compile(flareredact.Options{Pack: pack})
```

A pack that uses a construct this engine cannot execute exactly — a lookahead, a
`\d` whose meaning differs between languages, a checksum it does not implement —
fails to load. Failing open is how a redactor leaks.

## What this does not do

- **It is not a replacement for not collecting the data.** Redaction is a
  backstop for the places data ends up anyway: logs, prompts, crash reports.
- **`ModePseudonym` is not encryption.** It is a keyed, shape-preserving
  pseudonym; it is not reversible and does not implement NIST FF1.
- **Limits fail closed.** Input over `MaxInputLength` returns a `*LimitError`
  rather than partially redacted text.
- **Offsets are rune offsets**, and `MaxInputLength` is in bytes. The first is
  what the other engines report; the second is what Go can enforce cheaply.

MIT © Umud Hasanli · [Specification](../../spec/SPEC.md) ·
[Source](https://github.com/flare-collection/flare-redact)
