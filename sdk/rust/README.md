# flare-redact for Rust

Hide secrets and PII before they reach a log, a model, or a vendor.

Three dependencies — `regex`, `serde`, `serde_json` — and the same
[FRS-1 detector spec](../../spec/SPEC.md) as the JavaScript, Python and Go
engines, so a policy written once behaves identically in every service you own.
The [shared conformance corpus](../../spec/conformance/) runs in `cargo test`, so
"identically" is a test rather than a claim.

```toml
[dependencies]
flare-redact = "1.5"
```

```rust
use flare_redact::{Options, Policy};

let policy = Policy::compile(Options::new().enable(["pii"]))?;
let safe = policy.redact_str("contact ada@example.com with key AKIAIOSFODNN7EXAMPLE")?;
assert_eq!(safe, "contact a***@*** with key AKIA***");
# Ok::<(), flare_redact::Error>(())
```

## Compile once, reuse everywhere

```rust
use flare_redact::{Mode, Options, Policy};

let policy = Policy::compile(
    Options::new()
        .enable(["pii", "tr"])
        .disable(["ipv4"])
        .min_confidence(0.7),
)?;
# Ok::<(), flare_redact::Error>(())
```

Compiling resolves the detector list, the replacement function and the key tests
once. One `Policy` shared across your logging layer, your HTTP client and your
prompt path is what makes "sensitive" mean the same thing in all three.

## Structured values

```rust
use flare_redact::{Options, Policy};
use serde_json::json;

let policy = Policy::compile(Options::new())?;
let safe = policy.redact(&json!({
    "user": {"email": "ada@example.com", "id": 42},
    "password": "hunter2",
}))?;

assert_eq!(safe["user"]["email"], "a***@***");
assert_eq!(safe["user"]["id"], 42);
assert_eq!(safe["password"], "***");
# Ok::<(), flare_redact::Error>(())
```

Numbers stay numbers and `null` stays `null` — a redactor that stringifies a
number changes what the document means. Objects are visited in sorted key order,
because finding order and vault placeholder numbering are observable and the
other engines impose the same order.

Anything that implements `Serialize` can go through `redact_json`:

```rust
# use flare_redact::{Options, Policy};
# let policy = Policy::compile(Options::new()).unwrap();
let document = serde_json::to_string(&event)?;
let safe = policy.redact_json(&document)?;
```

## Send a prompt without sending the data

```rust
use flare_redact::{Options, PlaceholderStyle, Session};

let mut session = Session::new(Options::new().enable(["pii"]), PlaceholderStyle::Opaque)?;

let safe = session.redact_str("Email the invoice to ada@example.com")?;
let reply = session.restore_str(&call_your_model(&safe));
# Ok::<(), flare_redact::Error>(())
```

The same value maps to the same placeholder for the life of the session, so a
follow-up turn like *"resend it to the first address"* still resolves.
Placeholders are opaque by default — random, not numbered — so the text that
leaves your process does not disclose how many distinct people it involved.

Streaming, including a placeholder split across chunks:

```rust
# use flare_redact::{Options, PlaceholderStyle, Session};
# let session = Session::new(Options::new(), PlaceholderStyle::Opaque).unwrap();
let mut restorer = session.stream();
for chunk in stream {
    print!("{}", restorer.push(&chunk));
}
print!("{}", restorer.flush());
```

## Ways to hide a value

| `Mode` | `ada@example.com` becomes | Use it for |
|---|---|---|
| `Mask` (default) | `a***@***` | logs, anything human-read |
| `Label` | `[REDACTED:email]` | when you want to see *what* was removed |
| `Hash` | `email_12016e848bcb…` | correlating without storing |
| `Pseudonym` | `nlp@kmxjgxr.hjh` | keeping shape for parsers |
| `Surrogate` | `user_7560a7763fe8@example.invalid` | test data that still validates |

The keyed modes need `transform_secret`; a missing one is `Error::MissingSecret`
at compile time, not a silent fallback to unkeyed output. Surrogates are
type-aware: a card number becomes another card number with a valid Luhn digit,
so downstream validation still passes.

## Custom detector packs

```rust
use std::sync::Arc;
use flare_redact::{load_pack, Options, Policy};

let pack = Arc::new(load_pack(&std::fs::read_to_string("detectors/acme.json")?)?);
let policy = Policy::compile(Options::new().pack(pack))?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

A pack that uses a construct this engine cannot execute exactly — a lookahead, a
`\d` whose meaning differs between languages, a checksum it does not implement —
fails to load. Failing open is how a redactor leaks.

## Notes on this implementation

- **`#![forbid(unsafe_code)]`.** There is no unsafe block in the crate.
- **SHA-256 and HMAC are implemented here**, rather than pulled in, for the same
  reason the reference implementation does it: the dependency list should be
  readable in a minute. Correctness is not asserted, it is tested against the
  RFC 4231 and FIPS 180-4 vectors in `tests/engine.rs`.
- **Opaque placeholders use `RandomState`,** which is seeded from the operating
  system at process start. Tokens are unique and unpredictable in practice, but
  this is not a CSPRNG — supply `Vault::with_placeholder` if your threat model
  needs one.
- **Offsets in findings are character offsets**; `max_input_length` is in bytes.
  The first is what the other engines report; the second is what Rust can
  enforce without walking the string.
- **`regex` has no backtracking**, so a pattern cannot turn untrusted input into
  a denial of service. The FRS-1 pattern subset is chosen to compile on that
  engine, which is also why it forbids lookaround.

## What this does not do

- **It is not a replacement for not collecting the data.** Redaction is a
  backstop for the places data ends up anyway: logs, prompts, crash reports.
- **`Mode::Pseudonym` is not encryption.** It is a keyed, shape-preserving
  pseudonym; it is not reversible and does not implement NIST FF1.
- **Limits fail closed.** Input over `max_input_length` returns `Error::Limit`
  rather than partially redacted text.

MIT © Umud Hasanli · [Specification](../../spec/SPEC.md) ·
[Source](https://github.com/flare-collection/flare-redact)
