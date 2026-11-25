# flare-redact for Java

Hide secrets and PII before they reach a log, a model, or a vendor.

No dependencies, Java 11 and later, and the same
[FRS-1 detector spec](https://github.com/flare-collection/flare-redact/blob/main/spec/SPEC.md)
as the JavaScript, Python, Go, Rust and .NET engines, so a policy written once
behaves identically in every service you own. The
[shared conformance corpus](https://github.com/flare-collection/flare-redact/tree/main/spec/conformance)
runs in `mvn verify`, so "identically" is a test, not a claim. Kotlin, Scala and
other JVM languages use the same jar.

```xml
<dependency>
  <groupId>io.github.flare-collection</groupId>
  <artifactId>flare-redact</artifactId>
  <version>1.12.0</version>
</dependency>
```

```java
import io.github.flarecollection.redact.*;

Policy policy = Policy.compile(RedactOptions.builder().enable("pii").build());
String safe = policy.redactString("contact ada@example.com with key AKIAIOSFODNN7EXAMPLE");
// "contact a***@*** with key AKIA***"
```

## Compile once, reuse everywhere

```java
Policy policy = Policy.compile(RedactOptions.builder()
    .enable("pii", "tr")
    .disable("ipv4")
    .minConfidence(0.7)
    .build());
```

Compiling resolves the detector list, the replacement and the key tests once.
Options and policies are immutable and thread-safe: share one policy across your
logger, your HTTP layer and your prompt path, and "sensitive" means the same
thing in all three. `FlareRedact.redactString(text)` and friends use a shared
default policy for one-off calls.

## Structured values

```java
Map<String, Object> event = Map.of(
    "user", Map.of("email", "ada@example.com", "id", 42),
    "password", "hunter2");
Object redacted = policy.redact(event);
// user.email is now "a***@***", user.id is still 42, password is "***"
```

Maps, collections and arrays are rebuilt with every string redacted; the input is
never mutated, keys are never rewritten, and a string stored under a sensitive
key (in any of the 24 supported languages) is replaced whole. Your own classes
are not walked by reflection, which would silently skip what it cannot see. Go
through JSON instead, with Jackson, Gson or anything else:

```java
String safe = policy.redactJson(objectMapper.writeValueAsString(order));
```

## Logs

**Logback** (`io.github.flare-collection:flare-redact-logback`): wrap any part of
a pattern in `%redact(...)`,

```xml
<conversionRule conversionWord="redact"
    converterClass="io.github.flarecollection.redact.logback.RedactingConverter"/>

<encoder>
  <pattern>%d %-5level %logger - %redact(%msg%n%ex)</pattern>
</encoder>
```

or wrap a whole encoder, including a JSON one, whose lines are then redacted
structurally:

```xml
<encoder class="io.github.flarecollection.redact.logback.RedactingEncoder">
  <options>{"enable":["pii"]}</options>
  <encoder class="ch.qos.logback.classic.encoder.PatternLayoutEncoder">
    <pattern>%d %-5level %logger - %msg%n</pattern>
  </encoder>
</encoder>
```

**Log4j 2** (`io.github.flare-collection:flare-redact-log4j2`): the
`%redact{...}` pattern converter, or a rewrite policy that redacts the message
(a `MapMessage` field by field) and the context data before any appender sees
the event:

```xml
<PatternLayout pattern="%d %-5level %logger - %redact{%msg%n%ex}{{&quot;enable&quot;:[&quot;pii&quot;]}}"/>

<Rewrite name="Redacted">
  <FlareRedact/>
  <AppenderRef ref="File"/>
</Rewrite>
```

Options are the JSON wire format every engine reads. Logging never throws
because of redaction: text over a configured limit is written as a fixed notice,
never as the original.

## Send a prompt without sending the data

```java
Session session = new Session(RedactOptions.builder().enable("pii").build());

String safe = session.redactString(userMessage);  // send this to the model
String reply = session.restoreString(modelReply); // show this to the user
```

The same value maps to the same placeholder for the life of the session, so a
follow-up turn like *"resend it to the first address"* still resolves.
Placeholders are opaque by default (`[FR_EMAIL_cfc857cb68d551a680cf0d07]`,
random rather than numbered), so the text that leaves your process does not
disclose how many distinct people it involved. A `Vault` is thread-safe.

Streaming, including a placeholder split across chunks:

```java
StreamRestorer restorer = session.stream();
for (String chunk : chunks) {
    System.out.print(restorer.push(chunk));
}
System.out.print(restorer.flush());
```

When the streamed text is JSON, such as tool-call arguments, use
`session.streamJson()`: the originals go in JSON-escaped, so the arguments stay
valid JSON with the same structure. `restore` and `restoreString` do this on
their own for any string that is a JSON object or array.

## Ways to hide a value

| `Mode` | `ada@example.com` becomes | Use it for |
|---|---|---|
| `MASK` (default) | `a***@***` | logs, anything human-read |
| `LABEL` | `[REDACTED:email]` | when you want to see *what* was removed |
| `HASH` | `email_7027be51407f75d3…` | correlating without storing |
| `PSEUDONYM` | `spi@ptxdstl.ahm` | keeping shape for parsers |
| `SURROGATE` | `user_35dc5970174f@example.invalid` | test data that still validates |

The keyed modes need `transformSecret`; compiling without one throws instead of
falling back to unkeyed output. Every engine derives the same keyed output from
the same secret. `mask`, `maskFunction` and `terms` (your own words, with their
own replacements) work as in the other engines.

## One configuration for every engine

```java
RedactOptions options = RedactOptions.fromJson(Files.readString(Path.of("redact.json")));
```

`fromJson` reads the camelCase wire format the JavaScript, Python, Go, Rust and
.NET engines read, and rejects unknown options rather than ignoring a typo.
`options.toJson()` writes it back, without the transform secret.

## Custom detector packs

```java
Pack pack = Pack.load(Files.readString(Path.of("my-pack.json")));
Policy policy = Policy.compile(RedactOptions.builder().pack(pack).build());
```

A pack that uses a construct this engine cannot run exactly (a lookahead, a `\d`
whose meaning differs between languages, a checksum it does not implement) fails
to load with a `PackException`. Failing open is how a redactor leaks.

## What this does not do

- **It is not a replacement for not collecting the data.** Redaction is a
  backstop for the places data ends up anyway: logs, prompts, crash reports.
- **`PSEUDONYM` is not encryption.** It is a keyed, shape-preserving pseudonym;
  it is not reversible and does not implement NIST FF1.
- **Limits fail closed.** Input over `maxInputLength`, too many findings, or a
  pattern that exhausts the regular expression stack throws
  `RedactionLimitException` rather than returning partially redacted text.
- **Offsets are UTF-16 code units**, the unit of `String.length()`, as in
  JavaScript and .NET. Matching itself is by code point, and case-insensitive
  matching uses a bundled Unicode 17 table, so results do not change with the
  JDK's Unicode version.

MIT © Umud Hasanli · [Specification](https://github.com/flare-collection/flare-redact/blob/main/spec/SPEC.md) ·
[Source](https://github.com/flare-collection/flare-redact)
