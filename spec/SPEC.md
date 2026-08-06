# FRS-1 — flare-redact portable redaction spec

**Status:** stable · **Revision:** FRS-1 · **Reference pack:** [`detectors.json`](./detectors.json) · **Schema:** [`detectors.schema.json`](./detectors.schema.json)

FRS-1 defines how a *detector pack* is written and how an engine must execute it,
in enough detail that four independent implementations — JavaScript/TypeScript,
Python, Go and Rust — produce **byte-identical output** for the same input,
options and pack. The [conformance corpus](./conformance/) is the executable form
of this document; a change that breaks it breaks the spec.

The reason for a spec rather than four ports is drift. Detection logic that lives
in four hand-maintained copies diverges within a release or two, and a redactor
that behaves differently per language is worse than no redactor, because the team
stops being able to reason about what leaves the process.

## Contents

- [1. Why a restricted regular-expression subset](#1-why-a-restricted-regular-expression-subset)
- [2. The pattern subset](#2-the-pattern-subset)
- [3. Detector fields](#3-detector-fields)
- [4. The scan algorithm](#4-the-scan-algorithm)
- [5. Overlap resolution](#5-overlap-resolution)
- [6. Confidence](#6-confidence)
- [7. Replacement modes](#7-replacement-modes)
- [8. Keyed transforms](#8-keyed-transforms)
- [9. Sensitive keys, allowlists and terms](#9-sensitive-keys-allowlists-and-terms)
- [10. Structured data](#10-structured-data)
- [11. Vaults and reversible redaction](#11-vaults-and-reversible-redaction)
- [12. Limits and failure modes](#12-limits-and-failure-modes)
- [13. Conformance](#13-conformance)
- [14. Deliberate deviations from the Node detector set](#14-deliberate-deviations-from-the-node-detector-set)

---

## 1. Why a restricted regular-expression subset

The four target engines do not agree on the syntax or the semantics of a "normal"
regular expression:

| Construct | JavaScript | Python `re` | Go `regexp` (RE2) | Rust `regex` |
|---|---|---|---|---|
| Lookahead / lookbehind | yes | yes | **no** | **no** |
| Backreferences | yes | yes | **no** | **no** |
| `\b` | ASCII | **Unicode** | ASCII | **Unicode** |
| `\d`, `\w` | ASCII | **Unicode** | ASCII | **Unicode** |
| `\s` | +Unicode spaces | Unicode | **ASCII, no `\v`** | Unicode |
| `\p{L}` | with `u` flag | **unsupported** | yes | yes |
| `(?s:…)` scoped flags | **no** | yes | yes | yes |
| `$` without multiline | end of input | **also before a final newline** | end of input | end of input |

Every one of those rows is a silent behaviour difference — the kind that makes a
secret redacted on the Node service and passed through on the Python worker. FRS-1
removes the ambiguity by forbidding each divergent construct and providing an
explicit, engine-substituted replacement.

The subset is also RE2-safe by construction: no backtracking constructs means no
catastrophic backtracking, so a pack cannot introduce a ReDoS into a host process.

## 2. The pattern subset

A pattern **may** use:

- literals, and `.` (which never matches a line terminator)
- character classes `[…]`, `[^…]`, ranges, and the escapes `\t \n \r \f \x0B \xHH \\ \. \* \+ \? \( \) \[ \] \{ \} \| \^ \$ \/ \-`
- groups `(…)` (capturing) and `(?:…)` (non-capturing)
- alternation `|`
- quantifiers `* + ? {n} {n,} {n,m}` and their lazy forms `*? +? ?? {n,m}?`
- the two substitution tokens below

A pattern **must not** use:

- any lookaround — `(?=…) (?!…) (?<=…) (?<!…)` — use [`boundary`](#31-boundary) and [`reject`](#32-reject)
- backreferences `\1`, named groups, conditionals, atomic groups, possessive quantifiers
- the shorthands `\b \B \d \D \w \W \s \S` — write the class out (`[0-9]`, `[A-Za-z0-9_]`, `[ \t\n\x0B\f\r]`)
- `\p{…}` / `\P{…}` — use `{{L}}`
- inline flag groups `(?i)`, `(?s:…)` — use the `flags` field and `{{ANY}}`
- anchors `^` and `$` inside `pattern` (they are meaningful only in `reject`, `validators.pattern` and `mask.pattern`, where the spec fixes their semantics)

### Substitution tokens

Engines textually replace these **before** compiling, so the compiled automaton is
native and fast:

| Token | Meaning | JavaScript | Python | Go | Rust |
|---|---|---|---|---|---|
| `{{ANY}}` | any single character, including line terminators | `[\s\S]` | `[\s\S]` | `(?s:.)` | `(?s:.)` |
| `{{L}}` | any single Unicode letter | `\p{L}` | `[^\W\d_]` | `\p{L}` | `\p{L}` |

`{{L}}` must not appear inside a character class — write `(?:{{L}}|[0-9.-])`
instead of `[{{L}}0-9.-]`. This is what lets the Python engine expand it to the
`[^\W\d_]` idiom, which is a complete class and cannot be nested.

### Flags

`flags` is `""` or `"i"`. Case-insensitive matching is Unicode simple case folding.
Engines compile with:

| | |
|---|---|
| JavaScript | `new RegExp(pattern, "gu")` / `"giu"` |
| Python | `re.compile(pattern)` / `re.IGNORECASE` (never `re.ASCII`) |
| Go | `regexp.MustCompile(pattern)` / `"(?i)" + pattern` |
| Rust | `RegexBuilder::new(pattern).case_insensitive(flag)` |

### Anchored sub-patterns

Three fields hold patterns with fixed, engine-independent anchoring:

| Field | Semantics |
|---|---|
| `reject[]` | **prefix match** — the pattern must match starting at offset 0 of the captured value; it need not consume it |
| `validators[].pattern` | **full match** — the pattern must consume the entire (normalised) value |
| `mask.pattern` | **full match**, with `$1`…`$9` group references available in `replacement` |

Implementations wrap these themselves (`^(?:…)` and `^(?:…)$`, or `re.match` /
`re.fullmatch`). Because the wrapping is applied by the engine and never by the
pack author, Python's "`$` also matches before a trailing newline" behaviour is
avoided: Python engines use `re.match` / `re.fullmatch`, which do not have it.

## 3. Detector fields

See [`detectors.schema.json`](./detectors.schema.json) for the machine-readable
contract. The fields that carry semantics beyond their names:

### 3.1 `boundary`

`{"before": <class>, "after": <class>}`. The character immediately *before* the
captured span must **not** belong to `before`'s class, and the character
immediately *after* must not belong to `after`'s class. The start and the end of
the input always satisfy a boundary.

| Class | Members |
|---|---|
| `word` | `[A-Za-z0-9_]` |
| `alnum` | `[A-Za-z0-9]` |
| `digit` | `[0-9]` |
| `hex` | `[0-9A-Fa-f]` |
| `base64` | `[A-Za-z0-9+/=]` |
| `base64url` | `[A-Za-z0-9_+/=-]` |
| `word_dash` | `[A-Za-z0-9_-]` |

Membership is tested on UTF-16 code units in JavaScript, Unicode scalar values
elsewhere; every class is ASCII-only, so the two agree.

`{"before": "word", "after": "word"}` is the portable spelling of `\b…\b` for a
pattern that starts and ends with a word character.

### 3.2 `reject`

Prefix patterns evaluated against the captured value. Any match discards the
candidate. This replaces negative lookahead inside a pattern: `sk-(?!ant-|or-)…`
becomes `"pattern": "sk-…"` plus `"reject": ["sk-(?:ant|or)-"]`.

### 3.3 `validators`

Named, arity-fixed checks implemented natively by every engine. A candidate
survives only if **all** validators return true.

| Name | Check |
|---|---|
| `normalized_match` | remove every character matching `strip`, then full-match `pattern` |
| `luhn` | digits only; length within `[minDigits, maxDigits]` (defaults 2 / unbounded); Luhn sum ≡ 0 (mod 10) |
| `entropy` | Shannon entropy over Unicode code points ≥ `min` bits/symbol |
| `phone` | 8–15 digits; a value without a leading `+` needs ≥ 9 digits and must not end in a separated `19xx`/`20xx` year |
| `iban` | ISO 13616 mod-97 |
| `tckn` | Türkiye T.C. Kimlik No, two check digits |
| `cpf` | Brazil, two mod-11 check digits, rejects repeated digits |
| `dni` | Spain DNI/NIE control letter (mod 23) |
| `bsn` | Netherlands 11-test |
| `pesel` | Poland weighted mod-10 |
| `de_tax_id` | Germany ISO 7064 MOD 11,10 |
| `codice_fiscale` | Italy odd/even table checksum |
| `fr_nir` | France INSEE key = 97 − (n mod 97), Corsica 2A→19 / 2B→18 |
| `aadhaar` | India Verhoeff, first digit 2–9 |
| `tfn` | Australia weighted sum ≡ 0 (mod 11) |
| `cn_resident_id` | China ISO 7064 MOD 11-2 |
| `jp_my_number` | Japan weighted mod-11 |
| `us_ssn` | never-issued ranges (area 0, 666, ≥ 900; group 0; serial 0) |
| `aba` | US routing 3-7-1 mod-10 |
| `nhs` | UK weighted mod-11, rejects repeated digits |
| `vin` | transliterated weighted mod-11, check character at position 9 |

Adding a validator name is a spec revision, not a pack change: an engine that
does not know a name **must fail loudly** when loading the pack rather than
silently skipping the check. Failing open is how a redactor leaks.

### 3.4 `prefilter`

Case-insensitive literals. If none occurs in the subject, the detector is skipped
without running its pattern. A prefilter is only correct when **every** string the
pattern can match contains at least one of the literals; the conformance corpus
exists partly to catch a prefilter that is not.

### 3.5 `context`

`positive` / `negative` are searched (substring semantics, always case-insensitive)
in the window of `window` characters — default 80 — on each side of the captured
span. See [§6](#6-confidence).

## 4. The scan algorithm

For a subject string *S* and a resolved, ordered detector list *D*:

1. **Zero-width normalisation.** If *S* contains any of `U+200B U+200C U+200D
   U+2060 U+FEFF`, build *S′* with those removed plus an index map back to *S*.
   Otherwise *S′* = *S*. All matching happens on *S′*; every offset reported is
   translated back to *S*, and the reported value is the slice of *S* — so
   `p a s​s w o r d` is caught and the original characters are what get
   replaced.
2. For each detector *d* in *D*, **in pack order**:
   1. If `prefilter` is set and no literal occurs in *S′* (case-insensitive), skip *d*.
   2. Scan *S′* left to right for successive non-overlapping matches of `pattern`.
   3. For each match:
      1. Take the span of capture group `capture` (0 = whole match). If the group
         did not participate, discard the candidate.
      2. Apply `boundary` against the neighbours of that span in *S′*.
      3. Apply `reject` against the captured value.
      4. Apply `validators` against the captured value.
      5. Compute confidence ([§6](#6-confidence)); discard if `< minConfidence`.
      6. Translate the span to *S* and emit a candidate.
      7. **A discarded candidate does not rewind the cursor**: scanning resumes at
         the end of the match that produced it. This is what makes the traversal
         order deterministic and identical in a backtracking engine and in RE2.
3. Append candidates from the semantic provider, if the host supplied one.
4. Resolve overlaps ([§5](#5-overlap-resolution)).
5. Return the surviving candidates sorted by `start`, then `end`.

`redact` walks the result once, copying the text between candidates and emitting
the replacement for each — one pass, no nested replacement, and a replacement can
never itself be re-scanned.

## 5. Overlap resolution

Candidates from different detectors routinely cover the same or overlapping text
(`sk-or-v1-…` is both an OpenRouter key and a high-entropy string; an IBAN is also
a run of alphanumerics). FRS-1 picks the **maximum-weight set of non-overlapping
candidates** — weighted interval scheduling — rather than "first detector wins",
because first-wins depends on pack ordering and produces different masking for the
same secret depending on what else is nearby.

```
weight(c) = riskWeight(c.risk) + 10 × c.priority + c.confidence + (c.end − c.start) / 1e6

riskWeight: critical = 1e9, high = 1e6, medium = 1e3, low = 1
```

The algorithm:

1. Sort candidates by `end`, then `start`, **stably** — insertion order (pack
   order, then left-to-right match order) breaks remaining ties.
2. For each *i*, binary-search `p[i]` = the greatest *j* < *i* with `end[j] ≤ start[i]`.
3. `best[i] = max(best[i−1], weight(i) + best[p[i]+1])`.
4. Walk back from the end, taking *i* when `weight(i) + best[p[i]+1] > best[i−1]`.

Every step is integer/IEEE-754 double arithmetic with a fixed evaluation order, so
all four engines compute the same sums. Sort stability is guaranteed by the
language in all four cases (`Array.prototype.sort`, `sorted`, `sort.SliceStable`,
`slice::sort_by`).

A single candidate short-circuits: with fewer than two candidates the list is
returned unchanged.

## 6. Confidence

```
score = detector.confidence
if context.positive matches the window:  score += 0.06
if context.negative matches the window:  score −= 0.25
if refineConfidence and detector.refine: score += (P(secret) − 0.5) × 0.4
score = clamp(score, 0, 1)
```

`P(secret)` comes from the logistic model carried in the pack's `confidenceModel`.
Its 14 features are computed over the captured value plus a ±64-character window:

`log2Len`, `entropy`, `fracLower`, `fracUpper`, `fracDigit`, `fracSymbol`,
`fracHex`, `vowelFrac`, `classTransitionRate`, `hasMixedClasses`, `maxRunFrac`,
`structuredHexId`, `ctxSecret`, `ctxBenign`.

Feature extraction is defined over UTF-16 code units in JavaScript and over
Unicode scalar values elsewhere; the features are ASCII-classifying, and `entropy`
is defined over code points in every engine, so the vectors agree for any input.
The model only ever moves a score that a detector opted into with `refine: true`,
and only when the host passes `refineConfidence`. Checksum-validated detectors
never opt in — they are already certain.

## 7. Replacement modes

| Mode | Replacement |
|---|---|
| `mask` (default) | the detector's `mask` strategy |
| `label` | `[REDACTED:<detector id>]` |
| `hash` | `<detector id>_<HMAC-SHA256(secret, value) truncated to 16 bytes, lowercase hex>` |
| `pseudonym` | keyed, shape-preserving character substitution ([§8](#8-keyed-transforms)) |
| `surrogate` | a type-consistent synthetic value ([§8](#8-keyed-transforms)) |

Mask strategies:

| `type` | Result |
|---|---|
| `fixed` | `text` |
| `keepPrefix` | `value.length ≤ n` → `***`, else first `n` characters + `***` |
| `keepLast` | digits only; last `n` digits, prefixed by `**** ` repeated `ceil((digits − n) / 4)` times, trimmed |
| `keepThroughSeparator` | everything up to and including the `count`-th `separator`, + `***` |
| `replace` | full-match `pattern` → `replacement` with `$1`…`$9`; if the value does not fully match, the value is returned unchanged |

A host-supplied `mask` string or function overrides the strategy for every
detector, and takes precedence over `mode`.

## 8. Keyed transforms

All keyed output derives from HMAC-SHA256 with the host's `transformSecret`. An
empty secret is an **error**, not a silent fallback to unkeyed output.

```
deriveBytes(secret, context, n):
    out = b""
    counter = 0
    while len(out) < n:
        out += HMAC-SHA256(secret, context + "\x00" + str(counter))
        counter += 1
    return out[:n]
```

- **`hash`** — `HMAC-SHA256(secret, value)[:16]` as lowercase hex, prefixed with
  the detector id and `_`.
- **`pseudonym`** — `deriveBytes(secret, "pseudonym:" + value, len(value))`; each
  character is replaced by `alphabet[byte % len(alphabet)]` where the alphabet is
  `a–z`, `A–Z` or `0–9` matching the original character's class. Any other
  character is passed through, so shape (length, punctuation, separators) survives.
  This is **not** format-preserving encryption and is **not** reversible; it is a
  deterministic pseudonym.
- **`surrogate`** — type-consistent synthetic data, per detector id:
  `email` → `user_<HMAC[:6] hex>@example.invalid`; `credit_card` → digit
  substitution with a recomputed Luhn check digit; `phone` → digit substitution;
  `person_name` → a name from the fixed given/family lists; `street_address` →
  `<number> <street> Street`; anything else falls back to `pseudonym`.

Indexing is by **Unicode scalar value** in Python, Go and Rust, and by UTF-16 code
unit in JavaScript. Because the alphabets are ASCII and non-ASCII characters are
passed through unchanged, the outputs agree for all inputs. The `deriveBytes`
length is the length in the engine's own unit; a pack that needs cross-language
identical pseudonyms for astral-plane input should mask those detectors instead.

## 9. Sensitive keys, allowlists and terms

- **`redactKeys`** — when a structured input has a string value under a key that is
  sensitive by name, the value is replaced without pattern matching. The default
  key test is `SENSITIVE_KEY_RE` (`password`, `secret`, `token`, `api_key`,
  `authorization`, `cookie`, `session_id`, `credit_card`, `cvv`, `ssn`, …) **or**
  membership in the multilingual keyword set. The finding is reported as detector
  `sensitive_key`, risk `critical`, confidence `0.98`.
- **`allow`** — exact values (or a host regular expression) that are never
  redacted. Tested against the raw slice *and* against the zero-width-normalised
  slice, so `​`-padded look-alikes cannot slip past an allowlist entry.
- **`terms`** — host-supplied literals, matched longest-first with Unicode letter/
  digit boundaries, reported as detector `custom_term`. Terms are prepended to the
  detector list, so they take part in overlap resolution like any other candidate.

## 10. Structured data

Redacting a structure is defined as redacting every string reachable from it:

- object/dict values, array/list elements, map keys and values, set members
- error/exception messages
- the string form of URLs and query strings

Cycles are visited once. Non-string leaves (numbers, booleans, null, binary
buffers, dates) are returned as-is; a redactor that stringifies numbers changes
meaning, and a redactor that walks binary blobs wastes the caller's CPU.

Finding paths use the host language's natural notation: `user.contact.email`,
`items[0].token`, `headers.<map-key:0>`.

**Traversal order is observable**, because it fixes the order of findings and the
order in which a vault mints placeholders. Sequences are visited in index order.
Mappings are visited in insertion order where the language preserves it
(JavaScript objects, Python dicts, `serde_json::Map` with `preserve_order`) and
in ascending key order where it does not (Go maps). The conformance corpus only
contains mappings whose insertion order already equals their sorted key order, so
the two rules cannot disagree on a conforming input; outside the corpus, treat
mapping traversal order as unspecified and do not depend on it.

## 11. Vaults and reversible redaction

A vault mints a stable placeholder per distinct original value and remembers the
mapping, so the same secret gets the same placeholder everywhere in a session and
`restore` puts the originals back — the round trip that makes "send a prompt to a
model without sending the data" work.

- Default placeholders are **opaque**: `[FR_<DETECTOR_ID>_<12 random bytes, hex>]`.
  They carry no counter, so an observer cannot tell how many distinct values a
  session has seen or which appeared first.
- `readable` placeholders (`[EMAIL_1]`) are predictable and are for local
  debugging only.
- Restoration replaces the longest placeholders first, so a placeholder that is a
  prefix of another cannot clobber it.
- A generator that mints a duplicate placeholder for two different values is an
  error; silently merging them would restore the wrong secret.

Streaming restoration holds back the longest proper prefix of any placeholder that
the emitted tail could still be starting, so a placeholder split across two chunks
is still restored exactly once.

## 12. Limits and failure modes

| Limit | Default | On breach |
|---|---|---|
| `maxInputLength` | 16 MiB per scanned string | error |
| `maxFindings` | 50 000 per scanned string | error |

Both fail **closed** — an error, never a truncated or partially-redacted result.
A caller who receives a partially-redacted string has no way to know it, which is
exactly the failure mode a redactor must not have.

Engines must also reject, at pack-load time: an unknown `spec` revision, an
unknown validator or mask `type`, a pattern containing a forbidden construct, a
duplicate detector id, and a pattern that can match the empty string.

## 13. Conformance

[`conformance/cases.json`](./conformance/cases.json) holds inputs and options;
[`conformance/expected.json`](./conformance/expected.json) holds the required
output for each. Every implementation ships a test that runs the whole corpus:

| Implementation | Command |
|---|---|
| TypeScript / Node | `npm test` (`test/conformance.test.mjs`) |
| Python | `python -m unittest discover sdk/python/tests` |
| Go | `go test ./...` in `sdk/go` |
| Rust | `cargo test` in `sdk/rust` |

The corpus covers each detector's positive and negative cases, overlap resolution,
zero-width evasion, every replacement mode, keyed transform vectors, structured
input, allowlists, terms, confidence thresholds and the limits.

Regenerate expectations with `npm run spec:conformance` after an intentional
behaviour change, and read the diff — an unexplained line in that diff is a bug
report.

## 14. Deliberate deviations from the Node detector set

The Node package's built-in `DETECTORS` remain the reference for the Node API;
`detectors.json` is the portable profile of them. Where they differ, it is on
purpose and listed here.

1. **`seed_phrase` (BIP-39 mnemonics) is not in FRS-1 v1.** Its validator needs the
   2048-word English wordlist, which is a 14 KB payload every SDK would embed for
   one opt-in detector. Node keeps it; a future revision may add a `wordlists`
   section.
2. **Trailing boundaries on dash-terminated tokens are stricter.** `\bglpat-[A-Za-z0-9_-]{20}\b`
   in JavaScript requires a *word* character after a token ending in `-`, which
   truncates such tokens. FRS-1 uses `word_dash`, which does not.
3. **`coordinates` accepts a leading minus after a word character.** The JavaScript
   `\b-?` construction only permitted the minus after a word character, which is
   the opposite of what was intended.
4. **`person_name` matches `name is X` as `\s+is\s+`** rather than `\s*\bis\b\s*`,
   which requires the whitespace that the word boundary implied anyway.
5. **Whitespace inside patterns is the six ASCII space characters** `[ \t\n\x0B\f\r]`,
   not `\s`. No detector in this pack intends to match a non-breaking space or an
   ideographic space as a separator.
6. **`risk` and `confidence` are explicit on every detector** rather than inferred
   from tags and id substrings. The inferred values are preserved exactly; making
   them data removes a rule engines would otherwise have to reimplement.

---

Copyright © Umud Hasanli. Released under the MIT licence with the rest of the
project. Ports are welcome — implement the spec, pass the corpus, open a PR.
