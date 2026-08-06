# The conformance corpus

Four engines, one answer. `cases.json` holds inputs and options; `expected.json`
holds the output every FRS-1 implementation must produce for them.

| File | What it is |
|---|---|
| `cases.json` | authored by hand — inputs, options, and which checks to run |
| `expected.json` | generated — the required result for every case |

## Running it

| Engine | Command |
|---|---|
| JavaScript / Node | `npm test` |
| Python | `python -m unittest discover -s sdk/python/tests -t sdk/python` |
| Go | `cd sdk/go && go test ./...` |
| Rust | `cd sdk/rust && cargo test` |

## Regenerating expectations

```bash
npm run spec:conformance -- --write
```

Any conforming engine can generate the file — that is the point — but regenerate
from one and **read the diff**. An unexplained line in it is a bug report, not a
formatting change.

## Writing a case

```json
{ "name": "email/basic", "input": "contact ada@example.com", "options": { "enable": ["pii"] } }
```

- `name` is unique and reads as `area/behaviour`.
- `input` is any JSON value. Objects must have their keys in sorted order — see
  [SPEC.md §10](../SPEC.md#10-structured-data) for why traversal order is
  observable and how the corpus keeps the four engines in agreement.
- `options` uses the JSON wire names (camelCase), the same ones the gateway
  accepts.
- `checks` defaults to `["redact", "scan"]`; add `"vault"` for a round trip, and
  set `"vault": {"placeholderStyle": "readable"}` so the placeholders are
  deterministic.

A good case answers a question someone will actually ask. The corpus is
deliberately full of negatives — a Luhn-invalid card, a random 12-digit run, a
date that looks like a phone number — because a redactor that fires on everything
gets turned off.

## Ground rules

- **No astral-plane characters.** Offsets are reported in the host language's
  natural string unit: UTF-16 code units in JavaScript, scalar values elsewhere.
  These coincide for everything below U+10000, and the corpus stays there.
- **No wall-clock or randomness.** Vault cases use readable placeholders; keyed
  transforms use a fixed `transformSecret`.
- **Confidence is compared at six decimal places**, which is finer than any
  decision the library makes with the value and coarse enough that four
  languages' floating-point formatting cannot disagree about the text.
