# flare-redact for .NET

Hide secrets and PII before they reach a log, a model, or a vendor.

No dependencies, `netstandard2.0` and `net8.0`, and the same
[FRS-1 detector spec](https://github.com/flare-collection/flare-redact/blob/main/spec/SPEC.md)
as the JavaScript, Python, Go, Rust and Java engines, so a policy written once
behaves identically in every service you own. The
[shared conformance corpus](https://github.com/flare-collection/flare-redact/tree/main/spec/conformance)
runs in `dotnet test`, so "identically" is a test, not a claim.

```bash
dotnet add package FlareRedact
```

```csharp
using FlareRedact;

Policy policy = Policy.Compile(new RedactOptions { Enable = { "pii" } });
string safe = policy.RedactString("contact ada@example.com with key AKIAIOSFODNN7EXAMPLE");
// "contact a***@*** with key AKIA***"
```

## Compile once, reuse everywhere

```csharp
Policy policy = Policy.Compile(new RedactOptions
{
    Enable = { "pii", "tr" },
    Disable = { "ipv4" },
    MinConfidence = 0.7,
});
```

Compiling resolves the detector list, the replacement and the key tests once,
and takes a snapshot of the options. A `Policy` is immutable and thread-safe:
share one across your logger, your HTTP layer and your prompt path, and
"sensitive" means the same thing in all three. `Redactor.RedactString(text)` and
friends use a shared default policy for one-off calls.

On .NET 8 the detector patterns are compiled to IL once per process, so a
730,000-character mixed-script log scans in about 50 ms on an Apple Silicon
laptop.

## Structured values

```csharp
object? redacted = policy.Redact(new Dictionary<string, object?>
{
    ["user"] = new Dictionary<string, object?> { ["email"] = "ada@example.com", ["id"] = 42 },
    ["password"] = "hunter2",
});
// {"user":{"email":"a***@***","id":42},"password":"***"}
```

Dictionaries, lists, arrays and anything else enumerable are rebuilt with every
string redacted; the input is never mutated, keys are never rewritten, and a
string stored under a sensitive key (in any of the 24 supported languages) is
replaced whole. On .NET 8, `System.Text.Json`'s `JsonNode` and `JsonElement` come
back as the same kind:

```csharp
JsonNode? safe = (JsonNode?)policy.Redact(JsonNode.Parse(body));
```

Your own classes are not walked by reflection, which would silently skip what it
cannot see. Go through JSON instead:

```csharp
string safe = policy.RedactJson(JsonSerializer.Serialize(order));
```

## Logs

**Microsoft.Extensions.Logging** (`dotnet add package FlareRedact.Extensions.Logging`):

```csharp
builder.Logging
    .AddConsole()
    .AddFlareRedact(new RedactOptions { Enable = { "pii" } }); // after the providers

logger.LogInformation("Charge failed for {Email} with {Password}", email, password);
// Charge failed for a***@*** with ***
```

`AddFlareRedact` wraps every logger provider registered before it, so each one
receives the redacted message, redacted structured values (a `{Password}` value
is replaced whole), the template with its literal text redacted and its holes
intact, redacted scopes and, unless you pass `redactExceptions: false`, a
`RedactedException` whose message and stack trace are redacted.

**Serilog** (`dotnet add package FlareRedact.Serilog`):

```csharp
Log.Logger = new LoggerConfiguration()
    .WriteTo.FlareRedact(wt => wt.Console(), "{\"enable\":[\"pii\"]}")
    .CreateLogger();
```

The wrapping sink redacts properties (destructured objects included), the
literal text of the message template, so `"token " + token` is caught too, and
the exception. `Enrich.WithFlareRedact()` redacts properties only, for pipelines
where you cannot wrap the sinks. Options are the JSON wire format every engine
reads, so they can live in `appsettings.json`.

Logging never throws because of redaction: text over a configured limit is
written as `[flare-redact: text withheld, redaction limit exceeded]`, never as
the original.

## Send a prompt without sending the data

```csharp
var session = new Session(new RedactOptions { Enable = { "pii" } });

string safe = session.RedactString(userMessage);  // send this to the model
string reply = session.RestoreString(modelReply); // show this to the user
```

The same value maps to the same placeholder for the life of the session, so a
follow-up turn like *"resend it to the first address"* still resolves.
Placeholders are opaque by default (`[FR_EMAIL_cfc857cb68d551a680cf0d07]`,
random rather than numbered), so the text that leaves your process does not
disclose how many distinct people it involved. A `Vault` is thread-safe.

Streaming, including a placeholder split across chunks:

```csharp
StreamRestorer restorer = session.Stream();
await foreach (string chunk in chunks) Console.Write(restorer.Push(chunk));
Console.Write(restorer.Flush());
```

When the streamed text is JSON, such as tool-call arguments, use
`session.StreamJson()`: the originals go in JSON-escaped, so the arguments stay
valid JSON with the same structure. `Restore` and `RestoreString` do this on
their own for any string that is a JSON object or array.

## Ways to hide a value

| `Mode` | `ada@example.com` becomes | Use it for |
|---|---|---|
| `Mode.Mask` (default) | `a***@***` | logs, anything human-read |
| `Mode.Label` | `[REDACTED:email]` | when you want to see *what* was removed |
| `Mode.Hash` | `email_7027be51407f75d3…` | correlating without storing |
| `Mode.Pseudonym` | `spi@ptxdstl.ahm` | keeping shape for parsers |
| `Mode.Surrogate` | `user_35dc5970174f@example.invalid` | test data that still validates |

The keyed modes need `TransformSecret`; compiling without one throws instead of
falling back to unkeyed output. Every engine derives the same keyed output from
the same secret. `Mask`, `MaskFunction` and `Terms` (your own words, with their
own replacements) work as in the other engines.

## One configuration for every engine

```csharp
RedactOptions options = RedactOptions.FromJson(File.ReadAllText("redact.json"));
```

`FromJson` reads the camelCase wire format the JavaScript, Python, Go, Rust and
Java engines read, and rejects unknown options rather than ignoring a typo.
`options.ToJson()` writes it back, without the transform secret.

## Custom detector packs

```csharp
Pack pack = Pack.Load(File.ReadAllText("my-pack.json"));
Policy policy = Policy.Compile(new RedactOptions { Pack = pack });
```

A pack that uses a construct this engine cannot run exactly (a lookahead, a `\d`
whose meaning differs between languages, a checksum it does not implement) fails
to load with a `PackException`. Failing open is how a redactor leaks.

## What this does not do

- **It is not a replacement for not collecting the data.** Redaction is a
  backstop for the places data ends up anyway: logs, prompts, crash reports.
- **`Mode.Pseudonym` is not encryption.** It is a keyed, shape-preserving
  pseudonym; it is not reversible and does not implement NIST FF1.
- **Limits fail closed.** Input over `MaxInputLength` throws
  `RedactionLimitException` rather than returning partially redacted text.
- **Offsets are UTF-16 code units**, the unit of `string.Length`, as in
  JavaScript and Java. Matching itself is by code point, so an emoji or a
  letter outside the BMP is one character to every pattern.

MIT © Umud Hasanli · [Specification](https://github.com/flare-collection/flare-redact/blob/main/spec/SPEC.md) ·
[Source](https://github.com/flare-collection/flare-redact)
