import { chmodSync, readFileSync, writeFileSync } from 'node:fs';
import { discoverScanFiles, type SkipSummary } from './file-discovery.js';
import {
  redact,
  summary,
  compilePolicy,
  createVault,
  restore,
  sealVault,
  openVault,
  isSealedVault,
  DETECTORS,
  type Mode,
  type RedactOptions,
  type Finding,
} from './index.js';
import { redactCsv } from './csv.js';

const VERSION: string = (() => {
  try {
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
})();
type ScanFormat = 'pretty' | 'json' | 'sarif';

const HELP = `flare-redact — hide secrets & PII before they hit a log

USAGE
  flare-redact [options] [files...]        stdin if no files
  flare-redact gateway [options]           run the redaction sidecar proxy

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
                    in the calling application. See: flare-redact gateway --help

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
`;

interface ParsedArgs {
  opts: RedactOptions;
  files: string[];
  scanMode: boolean;
  scanFormat: ScanFormat;
  summaryMode: boolean;
  jsonMode: boolean;
  csvMode: boolean;
  showHelp: boolean;
  showVersion: boolean;
  listMode: boolean;
  vaultFile?: string;
  restoreFile?: string;
  secretEnv: string;
  vaultPasswordEnv: string;
  allowPlaintextVault: boolean;
  excludes: string[];
  maxFileSize: number;
  defaultExcludes: boolean;
}

function csv(s: string | undefined): string[] {
  return s ? s.split(',').map((x) => x.trim()).filter(Boolean) : [];
}

function parseArgs(argv: string[]): ParsedArgs {
  const opts: RedactOptions = {};
  const files: string[] = [];
  let scanMode = false;
  let scanFormat: ScanFormat = 'pretty';
  let summaryMode = false;
  let jsonMode = false;
  let csvMode = false;
  let showHelp = false;
  let showVersion = false;
  let listMode = false;
  let vaultFile: string | undefined;
  let restoreFile: string | undefined;
  let secretEnv = 'FLARE_REDACT_SECRET';
  let vaultPasswordEnv = 'FLARE_REDACT_VAULT_PASSWORD';
  let allowPlaintextVault = false;
  const excludes: string[] = [];
  let maxFileSize = 1024 * 1024;
  let defaultExcludes = true;
  const terms: string[] = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case '--scan': scanMode = true; break;
      case '--format': scanFormat = parseScanFormat(argv[++i]); break;
      case '--sarif': scanMode = true; scanFormat = 'sarif'; break;
      case '--summary': summaryMode = true; break;
      case '--json': jsonMode = true; break;
      case '--csv': csvMode = true; break;
      case '--list': listMode = true; break;
      case '-h': case '--help': showHelp = true; break;
      case '-v': case '--version': showVersion = true; break;
      case '--only': opts.only = csv(argv[++i]); break;
      case '--enable': opts.enable = csv(argv[++i]); break;
      case '--disable': opts.disable = csv(argv[++i]); break;
      case '--allow': opts.allow = csv(argv[++i]); break;
      case '--exclude': {
        const pattern = argv[++i];
        if (!pattern) throw new Error('--exclude requires a non-empty glob');
        excludes.push(pattern);
        break;
      }
      case '--max-file-size': maxFileSize = parseByteSize(argv[++i]); break;
      case '--no-default-excludes': defaultExcludes = false; break;
      case '--mask': opts.mask = argv[++i]; break;
      case '--mode': opts.mode = parseMode(argv[++i]); break;
      case '--hash-salt': opts.hashSalt = argv[++i]; break;
      case '--min-confidence': opts.minConfidence = parseConfidence(argv[++i]); break;
      case '--refine-confidence': opts.refineConfidence = true; break;
      case '--include-values': opts.includeValues = true; break;
      case '--secret-env': secretEnv = envName(argv[++i], '--secret-env'); break;
      case '--term': { const w = argv[++i]; if (w) terms.push(w); break; }
      case '--terms': {
        const lines = readFileSync(argv[++i]!, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        terms.push(...lines);
        break;
      }
      case '--vault': vaultFile = argv[++i]; break;
      case '--restore': restoreFile = argv[++i]; break;
      case '--vault-password-env': vaultPasswordEnv = envName(argv[++i], '--vault-password-env'); break;
      case '--allow-plaintext-vault': allowPlaintextVault = true; break;
      default:
        if (a.startsWith('-')) throw new Error(`unknown option: ${a}`);
        files.push(a);
    }
  }
  if (terms.length) opts.terms = terms;
  return {
    opts,
    files,
    scanMode,
    scanFormat,
    summaryMode,
    jsonMode,
    csvMode,
    showHelp,
    showVersion,
    listMode,
    vaultFile,
    restoreFile,
    secretEnv,
    vaultPasswordEnv,
    allowPlaintextVault,
    excludes,
    maxFileSize,
    defaultExcludes,
  };
}

function envName(value: string | undefined, flag: string): string {
  if (!value || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) {
    throw new Error(`${flag} requires a valid environment-variable name`);
  }
  return value;
}

function parseConfidence(value: string | undefined): number {
  const n = Number(value);
  if (value === undefined || Number.isNaN(n) || n < 0 || n > 1) {
    throw new Error(`--min-confidence requires a number between 0 and 1, got: ${value ?? '(missing)'}`);
  }
  return n;
}

function parseByteSize(value: string | undefined): number {
  const match = value?.trim().match(/^(\d+(?:\.\d+)?)\s*(b|kb|mb|gb)?$/i);
  if (!match) {
    throw new Error(`--max-file-size requires a positive byte size, got: ${value ?? '(missing)'}`);
  }
  const amount = Number(match[1]);
  const unit = (match[2] ?? 'b').toLowerCase();
  const multiplier = unit === 'gb' ? 1024 ** 3 : unit === 'mb' ? 1024 ** 2 : unit === 'kb' ? 1024 : 1;
  const bytes = Math.floor(amount * multiplier);
  if (!Number.isSafeInteger(bytes) || bytes < 1) {
    throw new Error(`--max-file-size requires a positive byte size, got: ${value}`);
  }
  return bytes;
}

function parseScanFormat(value: string | undefined): ScanFormat {
  if (value === 'pretty' || value === 'json' || value === 'sarif') return value;
  throw new Error(`invalid scan format: ${value ?? '(missing)'} (expected pretty, json, or sarif)`);
}

function parseMode(value: string | undefined): Mode {
  if (value === 'mask' || value === 'label' || value === 'hash' || value === 'pseudonym' || value === 'surrogate' || value === 'fpe') return value;
  throw new Error(`invalid mode: ${value ?? '(missing)'} (expected mask, label, hash, pseudonym, or surrogate)`);
}

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

interface LocatedFinding extends Finding {
  file?: string;
}

type ReportFinding = Omit<LocatedFinding, 'value'>;

function reportFinding({ value: _value, ...finding }: LocatedFinding): ReportFinding {
  return finding;
}

function findingLocation(f: LocatedFinding): string {
  if (f.file && f.line !== undefined) return `${f.file}:${f.line}:${f.column ?? 1}`;
  if (f.file && f.path) return `${f.file} @ ${f.path}`;
  if (f.file) return f.file;
  if (f.path) return f.path;
  if (f.line !== undefined) return `${f.line}:${f.column ?? 1}`;
  return f.start !== undefined ? `offset ${f.start}` : '';
}

function formatFindings(findings: LocatedFinding[]): string {
  if (!findings.length) return 'No secrets found.';
  const lines = findings.map((f) => {
    const location = findingLocation(f);
    const where = location ? `\n   at ${location}` : '';
    const value = f.value !== undefined ? `\n   value: ${f.value}` : '';
    return `⚠  ${f.label} (${f.detector}) [${f.risk}, ${(f.confidence * 100).toFixed(0)}%]${where}${value}\n   ${f.why}`;
  });
  const noun = findings.length === 1 ? 'finding' : 'findings';
  return `${findings.length} ${noun}:\n\n${lines.join('\n\n')}`;
}

function formatJson(
  findings: LocatedFinding[],
  scannedFiles: string[],
  includeValues: boolean,
  skipped: SkipSummary,
): string {
  return JSON.stringify({
    schemaVersion: 2,
    tool: { name: 'flare-redact', version: VERSION },
    summary: {
      total: findings.length,
      filesScanned: scannedFiles.length,
      pathsSkipped: Object.values(skipped).reduce((total, count) => total + count, 0),
      skipped,
    },
    findings: includeValues ? findings : findings.map(reportFinding),
  }, null, 2);
}

function formatSarif(findings: LocatedFinding[]): string {
  const rules = [...new Map(findings.map((f) => [f.detector, {
    id: f.detector,
    name: f.label,
    shortDescription: { text: f.label },
    help: { text: f.why },
  }])).values()];
  const results = findings.map((f) => {
    const physicalLocation = f.file ? {
      artifactLocation: { uri: f.file },
      ...(f.line !== undefined ? { region: { startLine: f.line, startColumn: f.column ?? 1 } } : {}),
    } : undefined;
    return {
      ruleId: f.detector,
      level: f.risk === 'critical' ? 'error' : f.risk === 'high' ? 'warning' : 'note',
      message: { text: `${f.label}: ${f.why}` },
      ...(physicalLocation ? { locations: [{ physicalLocation }] } : {}),
      properties: { ...(f.path ? { path: f.path } : {}), risk: f.risk, confidence: f.confidence },
    };
  });
  return JSON.stringify({
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'flare-redact', version: VERSION, informationUri: 'https://github.com/flare-collection/flare-redact', rules } },
      results,
    }],
  }, null, 2);
}

function runScan(
  files: string[],
  jsonMode: boolean,
  opts: RedactOptions,
  format: ScanFormat,
  discovery: { excludes: string[]; maxFileSize: number; defaultExcludes: boolean },
): number {
  const findings: LocatedFinding[] = [];
  let scannedFiles: string[] = [];
  let skipped: SkipSummary = { excluded: 0, binary: 0, oversized: 0, symlink: 0 };
  try {
    const policy = compilePolicy(opts);
    if (files.length) {
      const result = discoverScanFiles(files, discovery);
      scannedFiles = result.files;
      skipped = result.skipped;
    }
    const inputs: Array<string | undefined> = files.length ? scannedFiles : [undefined];
    for (const file of inputs) {
      const raw = file ? readFileSync(file, 'utf8') : readStdin();
      const data = jsonMode ? tryParse(raw, file) : raw;
      if (data === PARSE_ERROR) return 2;
      for (const finding of policy.scan(data)) findings.push(file ? { ...finding, file } : finding);
    }
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }

  const out = format === 'json'
    ? formatJson(findings, scannedFiles, opts.includeValues === true, skipped)
    : format === 'sarif'
      ? formatSarif(findings)
      : formatFindings(findings);
  process.stdout.write(out + '\n');
  return findings.length ? 1 : 0;
}

export async function main(argv: string[]): Promise<number> {
  // The gateway is a long-running server with its own flags; keep it out of the
  // one-shot parser rather than pretending its options belong to the same tool.
  if (argv[0] === 'gateway') {
    const { main: runGateway } = await import('./gateway/cli.js');
    return runGateway(argv.slice(1));
  }

  let parsed: ParsedArgs;
  try {
    parsed = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${HELP}`);
    return 2;
  }
  const {
    opts,
    files,
    scanMode,
    scanFormat,
    summaryMode,
    jsonMode,
    csvMode,
    showHelp,
    showVersion,
    listMode,
    vaultFile,
    restoreFile,
    secretEnv,
    vaultPasswordEnv,
    allowPlaintextVault,
    excludes,
    maxFileSize,
    defaultExcludes,
  } = parsed;

  if (!opts.transformSecret && process.env[secretEnv]) opts.transformSecret = process.env[secretEnv];
  if (opts.mode === 'fpe') {
    process.stderr.write('warning: --mode fpe is deprecated; use --mode pseudonym (this is not encryption)\n');
  }

  if (showHelp) { process.stdout.write(HELP); return 0; }
  if (showVersion) { process.stdout.write(`${VERSION}\n`); return 0; }
  if (listMode) {
    for (const d of DETECTORS) {
      process.stdout.write(`${d.default ? '●' : '○'} ${d.id.padEnd(20)} ${d.label} — ${d.why}\n`);
    }
    return 0;
  }

  if (scanMode && !summaryMode && !vaultFile && !restoreFile) {
    return runScan(files, jsonMode, opts, scanFormat, { excludes, maxFileSize, defaultExcludes });
  }

  let raw: string;
  try {
    raw = files.length ? files.map((f) => readFileSync(f, 'utf8')).join('\n') : readStdin();
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }
  const data: unknown = jsonMode ? tryParse(raw) : raw;
  if (jsonMode && data === PARSE_ERROR) return 2;

  const emit = (out: unknown) =>
    process.stdout.write(jsonMode ? JSON.stringify(out, null, 2) + '\n' : String(out));

  if (restoreFile) {
    try {
      const stored: unknown = JSON.parse(readFileSync(restoreFile, 'utf8'));
      if (isSealedVault(stored)) {
        const password = process.env[vaultPasswordEnv];
        if (!password) throw new Error(`Set ${vaultPasswordEnv} to decrypt the vault.`);
        emit(restore(data, new Map(await openVault(stored, password))));
      } else {
        if (!allowPlaintextVault) {
          throw new Error('Refusing a plaintext vault. Pass --allow-plaintext-vault only for trusted legacy files.');
        }
        emit(restore(data, stored as Record<string, string>));
      }
      return 0;
    } catch (e) {
      process.stderr.write(`${(e as Error).message}\n`);
      return 2;
    }
  }

  if (vaultFile) {
    try {
      const password = process.env[vaultPasswordEnv];
      if (!password) throw new Error(`Set ${vaultPasswordEnv} to encrypt the vault.`);
      const vault = createVault(opts);
      const out = vault.redact(data);
      writeFileSync(vaultFile, JSON.stringify(await sealVault(vault, password), null, 2), { mode: 0o600 });
      chmodSync(vaultFile, 0o600);
      emit(out);
      return 0;
    } catch (e) {
      process.stderr.write(`${(e as Error).message}\n`);
      return 2;
    }
  }

  if (summaryMode) {
    try {
      const s = summary(data, opts);
      process.stdout.write(JSON.stringify(s, null, 2) + '\n');
      return s.total ? 1 : 0;
    } catch (e) {
      process.stderr.write(`${(e as Error).message}\n`);
      return 2;
    }
  }

  try {
    if (jsonMode) {
      process.stdout.write(JSON.stringify(redact(data, opts), null, 2) + '\n');
      return 0;
    }

    if (csvMode) {
      process.stdout.write(redactCsv(raw, opts) + '\n');
      return 0;
    }

    process.stdout.write(redact(raw, opts));
    return 0;
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n`);
    return 2;
  }
}

const PARSE_ERROR = Symbol('parse-error');

function tryParse(raw: string, source?: string): unknown {
  try {
    return JSON.parse(raw);
  } catch (e) {
    process.stderr.write(`invalid JSON${source ? ` in ${source}` : ''}: ${(e as Error).message}\n`);
    return PARSE_ERROR;
  }
}
