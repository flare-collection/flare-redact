# Changelog

## 1.3.0 — 2026-07-27

### CLI

- Scan a complete project with `flare-redact --scan .`. Directory arguments
  are expanded recursively in deterministic order, overlapping inputs are
  deduplicated, and every finding keeps its file, line, and column for pretty,
  JSON, and SARIF output.
- Compile the detector policy once per CLI invocation and reuse it across every
  discovered file instead of rebuilding detector and allowlist state per file.
- Keep repository scans practical and safe by default: do not follow symlinks,
  skip binary files and directory-discovered files larger than 1 MiB, and
  exclude `.git`, `.hg`, `.svn`, `node_modules`, and `vendor` trees.
- Add repeatable `--exclude <glob>`, human-readable
  `--max-file-size <bytes|kb|mb|gb>`, and `--no-default-excludes` controls.
  Explicit file arguments retain their previous behavior and are not silently
  dropped by the directory size or binary guards.
- Extend value-free JSON reports with `filesScanned`, `pathsSkipped`, and
  per-reason skip counts, making CI coverage visible without leaking contents.
- Let Node drain stdout before the executable exits, preventing JSON, SARIF,
  and pretty reports larger than the operating-system pipe buffer from being
  silently truncated.
- Replace the copy-ready GitHub Actions pipeline with one direct project scan;
  consumers no longer need a shell-specific `git ls-files | xargs` pipeline.

### Verification

- Add end-to-end CLI coverage for recursive findings, default and custom
  exclusions, binary and oversized file guards, symlink safety, overlapping
  input deduplication, explicit opt-outs, scan statistics, and invalid size
  handling, plus complete large-report flushing. The suite grows from 174 to
  181 tests.

## 1.2.0 — 2026-07-24

### Detection

- Add a learned **secret-confidence classifier** to cut false positives from
  generic detectors. When `refineConfidence` is enabled, a small logistic-
  regression model scores each match from a detector marked `refine` (currently
  `high_entropy`) as a real secret versus a benign look-alike (UUID, git SHA,
  digest, object id, slug, dictionary word) and nudges its confidence. Pair with
  `minConfidence` to drop the noise. Checksum-validated detectors are never
  touched.
- The model is character-level logistic regression trained offline by
  `scripts/train-confidence-model.mjs` and shipped as fixed weights in
  `src/confidence-model.ts`, so the runtime stays zero-dependency, synchronous,
  and deterministic — no model download or native add-on, safe on edge and in
  the browser.
- Export `secretProbability`, `extractFeatures`, `shannonEntropy`, and the model
  from the package root and from the new `flare-redact/ml` subpath, so callers
  can build their own confidence filters.

### Detection (continued)

- Teach the opt-in `phone` detector formatted national numbers, not just bare
  E.164: `+90 532 123 45 67`, `(555) 123-4567`, and trunk-0 forms like
  `0532 123 45 67`. Candidates are digit-count validated (8–15) and dotted
  dates such as `07.24.2026` are rejected, so bare digit runs still never
  match.
- Add `gcp_service_account` (service-account JSON `private_key_id`) and
  `gcp_refresh_token` (`1//…` OAuth refresh tokens), both on by default.

### Runtimes

- Officially smoke-test the dependency-free core on **Bun and Deno** in CI on
  every push; publishing now requires those runtimes to pass. A new
  `scripts/runtime-smoke.mjs` exercises redaction, vault sealing via Web
  Crypto, and the ml classifier on any ESM runtime.
- Document React/browser usage: the core is plain ESM, tree-shakeable, and
  Web Crypto based — no Node built-ins outside the CLI and stream/logger
  adapters.

### CLI

- Add `--refine-confidence` to enable the classifier from the command line;
  pairs with `--min-confidence`.

### Verification

- Add `npm run benchmark:graph`, covering the paths adapter users actually hit:
  `redact()` on flat strings and deep object graphs, and reversible vault
  mint + restore round trips. Previously only `scan()` throughput was measured.
- Add direct unit tests for the shape-preserving transforms (keyed
  pseudonymization, Luhn-valid card surrogates, email and person stand-ins)
  and for object-graph traversal: `URL` / `URLSearchParams` rewriting, `Error`
  prototypes with custom properties, shared references, sparse arrays, symbol
  keys, and `Map`/`Set` entries. The suite grows from 162 to 170 tests.

## 1.1.0 — 2026-07-23

### Detection

- Catch AWS **secret** access keys, not just `AKIA…` key IDs: the new
  contextual `aws_secret_key` detector matches 40-character secrets in
  assignments (`AWS_SECRET_ACCESS_KEY=…`, `aws_secret_key: …`,
  `"secretAccessKey": "…"`) in env, YAML, and JSON form, and wins overlap
  resolution against the generic assignment detector. A bare 40-character
  string with no context is never flagged.
- Add 19 service detectors with distinctive low-false-positive formats, all on
  by default: `openrouter_key`, `huggingface_token`, `groq_key`, `xai_key`,
  `perplexity_key`, `replicate_token`, `vault_token` (HashiCorp),
  `databricks_token`, `airtable_pat`, `postman_key`, `linear_key`,
  `figma_token`, `notion_token`, `doppler_token`, `supabase_key`,
  `netlify_token`, `stripe_webhook_secret`, `mailgun_key`, and
  `discord_webhook` URLs.
- Exclude `sk-or-…` (OpenRouter) from the `openai_key` pattern so OpenRouter
  keys are labeled correctly.

### National IDs

- Add five checksum-validated, opt-in national identifiers: France NIR
  (`fr_nir`, INSEE mod-97 key with Corsican 2A/2B departments), India Aadhaar
  (`in_aadhaar`, Verhoeff), Australia TFN (`au_tfn`, weighted mod-11), China
  resident ID (`cn_resident_id`, ISO 7064 mod-11,2 with birth-date check), and
  Japan My Number (`jp_my_number`, weighted mod-11). Enable by country tag
  (`enable: ['fr']`) or all at once (`enable: ['pii']`).

### CLI

- Add `--min-confidence <0-1>` to drop low-confidence findings from any output.
- Add `--include-values` to opt scan reports into raw matched values
  (previously only available via the library API).
- `--version` now reads the real package version instead of a hard-coded
  string, and `--help` documents `fpe` as a deprecated alias of `pseudonym`.

### Verification

- Checksum vectors for the five new national IDs are cross-checked against
  independently computed known-answer examples (including the documented
  NIR, resident-ID, and My Number samples). Every new service detector has a
  detection, labeling, and masking test. The suite grows from 139 to 153
  tests.
- Update repository metadata after the move to the `flare-collection`
  organization so npm provenance can verify automated releases.

## 1.0.1 — 2026-07-23

### Fixed

- Label Anthropic API keys (`sk-ant-…`) with a dedicated `anthropic_key`
  detector instead of reporting them as OpenAI keys. Masks now keep the
  identifying `sk-ant-` prefix; `openai_key` no longer matches `sk-ant-`
  values.

### Verification

- Verify the zero-dependency SHA-256 and HMAC-SHA-256 implementations against
  the FIPS 180-4 and RFC 4231 known-answer vectors, differentially against
  `node:crypto` across key and block-size boundaries, and pin down
  `deriveBytes` counter-mode derivation and `hmacFingerprint` truncation.
  The suite grows from 129 to 139 tests.

## 1.0.0 — 2026-07-23

### Production boundaries

- Sanitize credentials, path segments, query values, and fragments inside HTTP
  URL strings; export `redactUrl()` for standalone use.
- Redact complete OpenAI and Anthropic message structures, including tool-call
  arguments, and restore streamed OpenAI tool arguments and Anthropic partial
  JSON across arbitrary chunk boundaries.
- Add `flare-redact/tool` with one-way tool/MCP helpers and a reversible,
  conversation-scoped `createToolBoundary()` for agent loops.
- Make stream redaction record-aware for multiline PEM private keys, fail closed
  on unterminated keys, and bound buffered record size.

### Safe and stable core

- Omit raw secret values from `scan()` and `scanAsync()` findings by default.
  Trusted diagnostics can opt in with `includeValues: true`.
- Preserve cycles and shared references during redaction; traverse `Map`, `Set`,
  enumerable symbols, `Error`, `URL`, and `URLSearchParams`.
- Make global/sticky allow-list and sensitive-key regular expressions
  deterministic across repeated values.
- Add stable `FlareRedactError` codes; resource and stream limits use
  `ERR_REDACTION_LIMIT`.
- Add `compilePolicy()` and make `createRedactor()` / `definePolicy()` reuse
  resolved detectors and matchers, including async operations.
- Replace bracket-specific streamed vault restoration with matching based on the
  actual placeholder set, including custom placeholder formats.

### Verification

- Expand the test suite from 112 to 129 production-focused tests covering HTTP
  URL leakage, tool/MCP boundaries, streamed tool arguments, circular graphs,
  complex built-ins, multiline keys, custom placeholders, and safe findings.
- Add package export and tarball validation to CI.
- Add a dedicated `0.9.x` to `1.0.0` migration guide.

See [MIGRATION.md](MIGRATION.md) before upgrading.

## 0.9.0 — 2026-07-23

### Security

- Replace 32-bit FNV correlation tokens with keyed HMAC-SHA-256.
- Rename non-reversible shape preservation to `pseudonym`; retain `fpe` only as
  a deprecated compatibility alias and stop describing it as encryption.
- Add deterministic type-consistent `surrogate` mode.
- Require `transformSecret` for hash, pseudonym, and surrogate modes.
- Use opaque 96-bit random vault placeholders by default.
- Add PBKDF2-SHA-256 + AES-256-GCM authenticated vault persistence.
- Make CLI vault files encrypted by default and reject plaintext maps unless
  `--allow-plaintext-vault` is explicit.
- Add per-string input/finding limits and hostile-input benchmarks.

### Detection and resilience

- Add risk and confidence to findings and SARIF output.
- Add weighted risk-aware overlap resolution.
- Add opt-in contextual person-name, street-address, and birth-date detectors.
- Add sync and async semantic-provider hooks for local NER models.
- Detect bracket-obfuscated email addresses, spaced AWS keys, and tokens split
  with zero-width characters while preserving original character spans.
- Add reproducible latency and hostile-input scaling benchmarks.
- Change scan JSON to schema version 2.
- Make line/column calculation linear in input plus findings instead of rescanning
  the prefix for every finding.
- Add runnable OpenAI-compatible, Express + Pino, and copy-ready GitHub Actions
  CLI scan examples.

### Migration

- Upgrade Node.js to version 20 or newer. Opaque vault placeholders and encrypted
  vault persistence rely on the stable Web Crypto API.
- Set `transformSecret` in code, or `FLARE_REDACT_SECRET` for the CLI, when using
  deterministic protected modes.
- Set `FLARE_REDACT_VAULT_PASSWORD` before CLI `--vault` or `--restore`.
- Use `createVault({ placeholderStyle: 'readable' })` only if legacy predictable
  placeholders are required in a trusted local flow.
- Update scan-report consumers for schema version 2 and the `risk` and
  `confidence` fields.

## 0.8.0

- Add file-aware scan reports with line/column locations, safe JSON, and SARIF
  output for CI and code-scanning integrations.
