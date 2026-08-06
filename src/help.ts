/**
 * The CLI's help system.
 *
 * `--help` prints the summary. `help <topic>` prints the part you actually
 * needed, because a flag list tells you a flag exists and nothing about when to
 * reach for it. Every topic here is written from the behaviour in this
 * repository; if one disagrees with the code, the topic is the bug.
 */

import { DETECTORS } from './index.js';

export interface HelpTopic {
  /** Topic name, as typed after `help`. */
  readonly name: string;
  /** One line, shown in the topic index. */
  readonly summary: string;
  /** The topic itself. */
  readonly body: string;
}

export const HELP = `flare-redact — hide secrets & PII before they hit a log

USAGE
  flare-redact [options] [files...]        stdin if no files
  flare-redact gateway [options]           run the redaction sidecar proxy
  flare-redact help [topic]                explain a topic in depth

OPTIONS
  --scan            list what would be redacted, and why (input unchanged)
  --format <f>      scan output: pretty | json | sarif (default: pretty)
  --sarif           shorthand for --scan --format sarif
  --summary         print a count of findings per detector
  --json            parse input as JSON and redact recursively
  --csv             parse input as CSV and redact every cell
  --mode <m>        mask | label | hash | pseudonym | surrogate
                    (fpe is a deprecated alias for pseudonym)
  --secret-env <n>  read the transform key from env var <n>
                    (default: FLARE_REDACT_SECRET)
  --hash-salt <s>   deprecated; prefer --secret-env
  --min-confidence <n>
                    drop findings below this confidence (0-1)
  --refine-confidence
                    use the learned classifier to refine confidence for
                    generic detectors (fewer false positives on UUIDs,
                    hashes, and slugs); pairs with --min-confidence
  --include-values  include raw matched values in --scan output
                    (unsafe for logs and reports)
  --only <ids>      use only these detectors (comma-separated)
  --enable <ids>    turn on extra detectors (e.g. ipv4,high_entropy)
  --disable <ids>   turn off detectors (e.g. email)
  --mask <str>      replace every secret with this string
  --allow <vals>    never redact these exact values (comma-separated)
  --exclude <glob>  skip matching paths during directory scans (repeatable)
  --max-file-size <size>
                    largest directory-discovered file to scan (default: 1mb)
                    accepts bytes or kb/mb/gb suffixes
  --no-default-excludes
                    also walk .git, .hg, .svn, node_modules, and vendor
  --term <word>     also catch this exact word/phrase (repeatable)
  --terms <file>    also catch every word/phrase in this file (one per line)
  --vault <file>    reversible: write an AES-GCM encrypted map to <file>
  --restore <file>  restore using an encrypted map written by --vault
  --vault-password-env <n>
                    vault password env var (default: FLARE_REDACT_VAULT_PASSWORD)
  --allow-plaintext-vault
                    explicitly allow reading a legacy plaintext vault
  --list            show all detectors and exit
  -h, --help        show this help
  -v, --version     show version

SUBCOMMANDS
  gateway           run a reverse proxy that redacts request bodies and
                    restores the originals in the reply — no code changes
                    in the calling application. See: flare-redact gateway help
  help              explain a topic. Run 'flare-redact help topics' for the
                    index, or 'flare-redact help <detector>' for one detector.

EXAMPLES
  tail -f app.log | flare-redact
  flare-redact --scan config.env
  flare-redact --scan .
  flare-redact --scan . --exclude 'fixtures/**' --max-file-size 2mb
  flare-redact --scan --format json .env app.log
  flare-redact --sarif .env > flare-redact.sarif
  flare-redact --json --mode hash < event.json
  flare-redact --enable high_entropy,ipv4 < app.log
  flare-redact --scan --enable high_entropy --refine-confidence --min-confidence 0.5 app.log

Stuck? 'flare-redact help topics' lists everything this help can explain.
`;

const TOPIC_LIST: readonly HelpTopic[] = [
  {
    name: 'detectors',
    summary: 'choosing what gets redacted, by id or tag',
    body: `DETECTORS — choosing what gets redacted

'flare-redact --list' prints every detector: a filled circle is on by default, a
hollow one is off until you ask for it.

Three flags select, and they are applied in that order:

  --only <ids>      ignore the defaults; run exactly these
  --enable <ids>    add to the defaults
  --disable <ids>   remove from the result

Each accepts detector ids and tags interchangeably, comma-separated. Tags let you
say what you mean without listing thirty ids:

  secret, pii, finance, network, crypto, email, vehicle, contextual, obfuscated
  and country tags: us, gb, de, fr, es, it, nl, pl, tr, ca, au, br, in, cn, jp, id

  flare-redact --enable pii app.log            every PII detector
  flare-redact --only secret .env              secrets only, nothing else
  flare-redact --disable email,ipv4 app.log    defaults minus two

Contextual detectors (names, addresses, dates of birth) are off by default and
tagged 'contextual'. They read surrounding words to decide, so they are the ones
most worth reviewing with --scan before you turn them on in production.

'flare-redact help <detector-id>' explains a single detector.

Custom values that no detector knows about:

  --term <word>     catch this exact word or phrase, repeatable
  --terms <file>    catch every line of a file
  --allow <vals>    never redact these exact values`,
  },
  {
    name: 'modes',
    summary: 'mask, label, hash, pseudonym, surrogate — and which to pick',
    body: `MODES — what replaces a matched value

  --mode mask        the default. Partial, shape-preserving: a***@***, sk-***
  --mode label       the detector's name: [EMAIL], [OPENAI_KEY]
  --mode hash        keyed HMAC-SHA-256. Same input, same output, so you can
                     still count and join on it. Requires a key.
  --mode pseudonym   a fake value of the same shape. Requires a key.
  --mode surrogate   a typed synthetic value — a card number that still passes
                     Luhn, a date that is still a date. Requires a key.

  --mask <str>       ignore all of the above and write a fixed string

hash, pseudonym and surrogate are keyed, and the key never goes on the command
line. Put it in an environment variable:

  export FLARE_REDACT_SECRET='…'
  flare-redact --mode hash app.log

Use --secret-env <NAME> to read a different variable. --hash-salt still works and
is deprecated; it names the same thing badly.

'fpe' is accepted as an alias for 'pseudonym' and warns. It was the wrong word:
none of this is format-preserving encryption, and nothing here is reversible
without a vault — see 'flare-redact help vault'.`,
  },
  {
    name: 'vault',
    summary: 'reversible redaction: get the originals back',
    body: `VAULT — redaction you can undo

A mode replaces a value and forgets it. A vault replaces it with a stable
placeholder and remembers the mapping, so the same secret is always the same
placeholder and the text can be turned back into the original later.

  export FLARE_REDACT_VAULT_PASSWORD='…'
  flare-redact --vault map.json < app.log > safe.log     # redact, save the map
  flare-redact --restore map.json < safe.log             # put the originals back

The map on disk is not plaintext: PBKDF2-SHA-256 derives a key from the password
and the file is an authenticated AES-256-GCM envelope. Lose the password and the
map is gone. The password comes from an environment variable, never a flag —
use --vault-password-env <NAME> to point at a different one.

Placeholders are opaque 96-bit random tokens by default, so a placeholder leaks
nothing about the value behind it.

A vault written by an older version in plaintext still loads, but only if you say
so explicitly with --allow-plaintext-vault.

In code this is createVault() / restore(), and the gateway uses one per request
so placeholders never cross between callers.`,
  },
  {
    name: 'scan',
    summary: 'find secrets without changing anything, and fail CI on them',
    body: `SCAN — report, do not rewrite

  flare-redact --scan config.env      what would be redacted, and why
  flare-redact --scan .               walk a whole project
  flare-redact --summary app.log      just the counts, per detector

--scan never prints the matched value unless you pass --include-values, which is
unsafe for anything you keep. The report carries the detector, the reason, the
file and the position.

Output formats:

  --format pretty   human reading, the default
  --format json     machine reading
  --format sarif    GitHub code scanning and anything else that speaks SARIF
  --sarif           shorthand for --scan --format sarif

Exit codes make it a CI gate:

  0   nothing found
  1   findings (scan mode only)
  2   the command itself failed — bad flag, unreadable file, invalid JSON

  # fail the build if a secret is committed
  npx --yes flare-redact --scan . --exclude package-lock.json

Too noisy? Generic detectors like high_entropy match anything that looks random.
--refine-confidence runs the learned classifier over them and --min-confidence
drops the weak ones:

  flare-redact --scan --enable high_entropy --refine-confidence --min-confidence 0.5 .`,
  },
  {
    name: 'files',
    summary: 'scanning directories: what is walked, what is skipped',
    body: `FILES — what a directory scan actually reads

Give --scan a directory and it walks it. Three things are skipped without being
asked, because scanning them is noise or a hazard:

  - .git, .hg, .svn, node_modules and vendor. Pass --no-default-excludes to walk
    them anyway.
  - files that look binary
  - files larger than --max-file-size (default 1mb; accepts 512kb, 2mb, 1gb)
  - symlinks are not followed

  --exclude <glob>  skip more paths, repeatable:

  flare-redact --scan . --exclude 'fixtures/**' --exclude '*.min.js'

The json report counts what was skipped and why, so a scan that finds nothing
cannot quietly mean a scan that read nothing.`,
  },
  {
    name: 'gateway',
    summary: 'the sidecar proxy: redact without touching application code',
    body: `GATEWAY — redaction without a code change

The library needs you to call it. The gateway does not: it is a reverse proxy
that redacts request bodies on the way out and restores the originals in the
reply, so an application integrates by changing one base URL.

  flare-redact gateway --upstream https://api.openai.com --enable pii

  # then, in the application — nothing else changes
  export OPENAI_BASE_URL=http://127.0.0.1:8787/v1

Streamed responses are restored incrementally, so a placeholder split across two
SSE frames still comes back whole.

It is also a redaction service for languages without a native engine:
POST /v1/redact, POST /v1/scan, GET /v1/detectors and server-side /v1/sessions,
plus /healthz, /readyz and Prometheus /metrics. Those are the only paths the
gateway answers itself — everything else under /v1 is proxied to your upstream.

A container image ships in the repository under docker/.

Full flag list: flare-redact gateway help`,
  },
  {
    name: 'library',
    summary: 'using it from JavaScript and TypeScript',
    body: `LIBRARY — the JavaScript and TypeScript API

  import { redact, scan, compilePolicy, createVault } from 'flare-redact';

  redact('mail ada@example.com')        // 'mail a***@***'
  scan(value)                           // findings, no rewriting
  compilePolicy(options)                // resolve options once, reuse everywhere

redact() takes any value, not just strings: objects, arrays and nested
structures are walked and only the leaves are rewritten.

Adapters live behind subpath imports, so you pay for what you import:

  flare-redact/pino        flare-redact/winston      log transports
  flare-redact/http        flare-redact/fetch        HTTP layers
  flare-redact/llm         flare-redact/session      prompts and conversations
  flare-redact/tool        MCP and multi-tool agent boundaries
  flare-redact/stream      flare-redact/csv          streams and tabular data
  flare-redact/middleware  framework middleware
  flare-redact/ml          the learned confidence classifier
  flare-redact/pack        load an FRS-1 detector pack as ordinary detectors
  flare-redact/gateway     embed the sidecar in your own process

The package has no runtime dependencies. Node 20 or newer; Bun and Deno are
covered by CI.`,
  },
  {
    name: 'sdks',
    summary: 'the Python, Go and Rust engines — installed separately',
    body: `SDKS — the same redactor in four languages

Python, Go and Rust have their own native engines. They are separate packages:
installing flare-redact from npm gives you the JavaScript engine and nothing
else, and it pulls no dependencies of any kind.

  Node    npm install flare-redact

  Go      go get github.com/flare-collection/flare-redact/sdk/go

  Python  pip install "flare-redact @ \\
            git+https://github.com/flare-collection/flare-redact@v1.5.1#subdirectory=sdk/python"

  Rust    flare-redact = { git = "https://github.com/flare-collection/flare-redact", \\
                           tag = "v1.5.1" }

The Python and Rust engines are not on PyPI or crates.io yet, so they install
from the repository. The commands above are the ones that work today.

They are not ports that drift. All four implement FRS-1, the specification in
spec/SPEC.md, and all four run the same conformance corpus in spec/conformance/
in their own test suites — so the same input and the same options produce the
same output whichever engine you use.

If you cannot add a dependency at all, the gateway gives every language an HTTP
endpoint instead: flare-redact help gateway`,
  },
  {
    name: 'env',
    summary: 'every environment variable this tool reads',
    body: `ENVIRONMENT

CLI:
  FLARE_REDACT_SECRET            key for hash, pseudonym and surrogate modes
                                 (override the name with --secret-env)
  FLARE_REDACT_VAULT_PASSWORD    password for an encrypted vault file
                                 (override the name with --vault-password-env)

Gateway:
  FLARE_UPSTREAM                 origin to forward to
  FLARE_GATEWAY_HOST             bind address (default 127.0.0.1)
  FLARE_GATEWAY_PORT             bind port (default 8787)
  FLARE_GATEWAY_TOKEN            bearer token required by the /v1 API
  FLARE_GATEWAY_MAX_BODY_BYTES   request body cap
  FLARE_GATEWAY_TIMEOUT_MS       upstream timeout
  FLARE_GATEWAY_SESSION_TTL_MS   how long a server-side vault lives
  FLARE_GATEWAY_LOG              silent | info | debug
  FLARE_REDACT_ONLY / _ENABLE / _DISABLE / _MODE / _SECRET
                                 the policy, for containers

Secrets are read from the environment and never from flags, because a flag ends
up in shell history and in the process list.`,
  },
  {
    name: 'exit-codes',
    summary: 'what the process returns, and when',
    body: `EXIT CODES

  0   success. In --scan, it also means nothing was found.
  1   --scan found at least one thing. This is what fails a CI job.
  2   the command failed: an unknown flag, a file that could not be read,
      input that was not valid JSON, a bad vault password.

Redaction that finds nothing still exits 0 and prints the input unchanged, so
flare-redact is safe to leave in a pipeline permanently.`,
  },
];

export const TOPICS: readonly HelpTopic[] = TOPIC_LIST;

/** The topic index, as printed by `help topics`. */
export function topicIndex(): string {
  const width = Math.max(...TOPICS.map((topic) => topic.name.length));
  const lines = TOPICS.map((topic) => `  ${topic.name.padEnd(width)}  ${topic.summary}`);
  return `HELP TOPICS

${lines.join('\n')}

  flare-redact help <topic>       read one of these
  flare-redact help <detector>    explain a single detector, e.g. 'help email'
  flare-redact --list             every detector, with defaults marked
`;
}

/** One detector, rendered as its own help page. */
function detectorHelp(id: string): string | undefined {
  const detector = DETECTORS.find((candidate) => candidate.id === id);
  if (!detector) return undefined;
  const tags = detector.tags?.length ? detector.tags.join(', ') : 'none';
  const state = detector.default
    ? 'on by default'
    : `off by default — turn it on with --enable ${detector.id}`;
  return `DETECTOR ${detector.id}

  ${detector.label}

  ${detector.why}

  State   ${state}
  Tags    ${tags}

  flare-redact --only ${detector.id} <file>    run just this one
  flare-redact --disable ${detector.id} <file> run everything except this one
`;
}

/**
 * Suggest the nearest topic or detector for something we do not recognise.
 * Prefix and substring matching only — a typo table would be more machinery
 * than the problem deserves.
 */
function nearest(query: string): string[] {
  const needle = query.toLowerCase();
  const names = [...TOPICS.map((topic) => topic.name), ...DETECTORS.map((detector) => detector.id)];
  // Either direction: "vaults" should find "vault", and "vau" should too.
  return names.filter((name) => name.includes(needle) || needle.includes(name)).slice(0, 5);
}

export interface HelpResult {
  readonly text: string;
  /** 0 when we answered the question, 2 when we could not. */
  readonly code: number;
}

/**
 * Resolve `help [topic]`. Returns the text and the exit code rather than
 * writing, so the caller decides between stdout and stderr and the tests can
 * read it back.
 */
export function renderHelp(topic?: string): HelpResult {
  if (!topic) return { text: HELP, code: 0 };

  const name = topic.toLowerCase();
  if (name === 'topics' || name === 'help') return { text: topicIndex(), code: 0 };

  const found = TOPICS.find((candidate) => candidate.name === name);
  if (found) return { text: `${found.body}\n`, code: 0 };

  const detector = detectorHelp(topic);
  if (detector) return { text: detector, code: 0 };

  const suggestions = nearest(name);
  const hint = suggestions.length
    ? `Did you mean: ${suggestions.join(', ')}?\n\n`
    : '';
  return { text: `No help for "${topic}".\n\n${hint}${topicIndex()}`, code: 2 };
}
