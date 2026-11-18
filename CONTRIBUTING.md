# Contributing

This is a small, deliberately narrow library, and I'd rather keep it that way
than let it grow into something that tries to do everything. That shapes what
gets merged: changes that make redaction more correct, safer, or easier to
reach for are welcome. Changes that add surface area for its own sake usually
aren't. If you're not sure which side of that line an idea falls on, open an
issue before you write code — it saves us both time.

## How changes get in

- Everything lands through a pull request. Nothing goes straight to `main`,
  mine included.
- A PR needs a green CI run and a code-owner review before it merges. We read every one.
  If it's been sitting for a few days, a ping is fair.
- One idea per PR. A focused diff is far easier to reason about — and to trust —
  than five unrelated ones.
- No new runtime dependencies. Zero-dependency is a feature here, not an
  accident, and I'll push back hard on anything that changes that.

Reviews can be slow and they can be picky. It's a security library; the bar is
higher than usual and that's on purpose. Questions on a PR aren't a rejection —
they're me making sure it's right.

## Running it locally

You'll need Node 20 or newer.

```sh
git clone https://github.com/flare-collection/flare-redact
cd flare-redact
npm install
npm run build
node --test
```

`src/` is the whole library — `detectors.ts` holds the patterns, `index.ts` is
the engine, `cli.ts` is the command line. Tests live in `test/` and run against
the built output in `dist/`, so build before you test.

## Adding a detector

Most contributions are new detectors, so here's what I look at:

- **A bounded built-in pattern.** No backreferences, lookbehind, nested
  quantifiers, or ambiguous unbounded branches. Extend the generated hostile
  cases in `bench/adversarial-runtime.mjs` and measure scaling with
  `npm run benchmark:adversarial`. Do not describe the JavaScript engine as
  formally ReDoS-proof.
- **A real `why`.** One plain sentence a person would actually understand, not a
  restatement of the label.
- **A sensible `mask`.** Leave enough of a hint to stay debuggable where that's
  safe; hide everything where it isn't.
- **Tests for both sides** — a string that should match, and a near-miss that
  should not. A false positive is as much a bug as a false negative.
Anything that fires on ordinary text often enough to be noisy (IPs, phone
numbers, and the like) should default to `false` and be opt-in.

## Commits and PRs

Write commit messages in the imperative — "add X", not "added X" — and say why,
not just what. Reference the issue if there is one. The PR description should
tell me what changed and how you checked it; if it changes behaviour, let the
tests show it.
