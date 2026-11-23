/**
 * Shadow mode: measure what a policy would redact before it is enforced.
 *
 * Turning redaction on in production is a leap of faith: nobody knows how many
 * log lines carry an email, which detector would fire most, or whether a field
 * the team needs would be masked. An audit counts findings by detector, risk,
 * source and field path while the data passes through unchanged, so the
 * decision to enforce rests on numbers. It never stores a matched value.
 *
 *   node --import flare-redact/register app.js   with FLARE_REDACT_MODE=shadow
 *
 *   const audit = createAudit({ preset: 'gdpr', meter });   // meter: OpenTelemetry, optional
 *   audit.observe(event, 'webhook');                         // unchanged, counted
 *   audit.report();                                          // counts only, safe to log
 */
import { compilePolicy, type RedactOptions } from './index.js';
import type { Finding } from './engine.js';

/** The parts of an OpenTelemetry `Meter` an audit uses. */
export interface MeterLike {
  createCounter(name: string, options?: { description?: string; unit?: string }): {
    add(value: number, attributes?: Record<string, string>): void;
  };
}

/** One finding as an audit reports it: no value, no offsets. */
export interface AuditEvent {
  detector: string;
  risk: string;
  source: string;
  path?: string;
}

export interface AuditOptions extends RedactOptions {
  /** An OpenTelemetry meter: `flare_redact.findings` and `flare_redact.scanned` counters are added. */
  meter?: MeterLike;
  /** Called for each finding, with counts-safe fields only. */
  onFinding?: (event: AuditEvent) => void;
  /** Distinct field paths kept in the report; the rest count under `(other)`. Default 500. */
  maxPaths?: number;
}

export interface AuditReport {
  /** When counting started (ISO 8601). */
  since: string;
  /** Values observed. */
  scanned: number;
  /** Values that held at least one finding. */
  withFindings: number;
  /** Findings in all. */
  total: number;
  byDetector: Record<string, number>;
  byRisk: Record<string, number>;
  bySource: Record<string, { scanned: number; total: number; byDetector: Record<string, number> }>;
  /** Findings per field path, array indices folded to `[]`, most frequent first. */
  byPath: Record<string, number>;
}

const bump = (counts: Record<string, number>, key: string, by = 1) => {
  counts[key] = (counts[key] ?? 0) + by;
};

const sortDesc = (counts: Record<string, number>): Record<string, number> =>
  Object.fromEntries(Object.entries(counts).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])));

/** `users[3].email` and `users[7].email` are the same field. */
const foldPath = (path: string): string => path.replace(/\[\d+\]/g, '[]');

export interface Audit {
  /** Count what `value` would have redacted and return it unchanged. */
  observe<T>(value: T, source?: string): T;
  /** Redact `value` and count what was redacted: enforcement with the same numbers. */
  redact<T>(value: T, source?: string): T;
  /** The counts so far. Safe to log: no values. */
  report(): AuditReport;
  /** The report as a short table for a terminal or a log line per row. */
  format(): string;
  /** Start counting again. */
  reset(): void;
}

export function createAudit(opts: AuditOptions = {}): Audit {
  const { meter, onFinding, maxPaths = 500, ...redactOptions } = opts;
  // An audit must never keep a matched value, whatever the caller passed.
  const policy = compilePolicy({ ...redactOptions, includeValues: false });
  const findingsCounter = meter?.createCounter('flare_redact.findings', {
    description: 'Values flare-redact found, by detector, risk and source',
    unit: '{finding}',
  });
  const scannedCounter = meter?.createCounter('flare_redact.scanned', {
    description: 'Values flare-redact checked, by source',
    unit: '{value}',
  });

  let state = fresh();
  function fresh() {
    return {
      since: new Date().toISOString(),
      scanned: 0,
      withFindings: 0,
      total: 0,
      byDetector: {} as Record<string, number>,
      byRisk: {} as Record<string, number>,
      bySource: {} as AuditReport['bySource'],
      byPath: {} as Record<string, number>,
    };
  }

  const record = (findings: Finding[], source: string) => {
    state.scanned += 1;
    const perSource = (state.bySource[source] ??= { scanned: 0, total: 0, byDetector: {} });
    perSource.scanned += 1;
    scannedCounter?.add(1, { source });
    if (!findings.length) return;
    state.withFindings += 1;
    for (const finding of findings) {
      state.total += 1;
      perSource.total += 1;
      bump(state.byDetector, finding.detector);
      bump(state.byRisk, finding.risk);
      bump(perSource.byDetector, finding.detector);
      if (finding.path) {
        const path = foldPath(finding.path);
        if (path in state.byPath || Object.keys(state.byPath).length < maxPaths) bump(state.byPath, path);
        else bump(state.byPath, '(other)');
      }
      findingsCounter?.add(1, { detector: finding.detector, risk: finding.risk, source });
      onFinding?.({
        detector: finding.detector,
        risk: finding.risk,
        source,
        ...(finding.path ? { path: foldPath(finding.path) } : {}),
      });
    }
  };

  const report = (): AuditReport => ({
    since: state.since,
    scanned: state.scanned,
    withFindings: state.withFindings,
    total: state.total,
    byDetector: sortDesc(state.byDetector),
    byRisk: sortDesc(state.byRisk),
    bySource: Object.fromEntries(
      Object.entries(state.bySource).map(([name, s]) => [name, { ...s, byDetector: sortDesc(s.byDetector) }]),
    ),
    byPath: sortDesc(state.byPath),
  });

  return {
    observe(value, source = 'default') {
      record(policy.scan(value), source);
      return value;
    },
    redact(value, source = 'default') {
      record(policy.scan(value), source);
      return policy.redact(value);
    },
    report,
    format() {
      const r = report();
      const share = r.scanned ? ` (${((r.withFindings / r.scanned) * 100).toFixed(1)}%)` : '';
      const findings = `${r.total} ${r.total === 1 ? 'finding' : 'findings'}`;
      const lines = [`${findings} in ${r.withFindings} of ${r.scanned} values${share} since ${r.since}`];
      for (const [detector, count] of Object.entries(r.byDetector)) lines.push(`  ${detector.padEnd(24)} ${count}`);
      const paths = Object.entries(r.byPath).slice(0, 10);
      if (paths.length) lines.push('  top fields:', ...paths.map(([path, count]) => `    ${path.padEnd(22)} ${count}`));
      return lines.join('\n');
    },
    reset() {
      state = fresh();
    },
  };
}

type ConsoleMethod = 'log' | 'info' | 'warn' | 'error' | 'debug';

/**
 * Count what `console.*` would redact without changing what it prints. Each
 * method is its own source (`console.error`). With `enforce: true` the output
 * is redacted as well, and still counted. Returns a function that puts the
 * console back.
 */
export function shadowConsole(
  audit: Audit,
  target: Console = console,
  { enforce = false }: { enforce?: boolean } = {},
): () => void {
  const sink = target as unknown as Record<ConsoleMethod, (...args: unknown[]) => void>;
  const original = new Map<ConsoleMethod, (...args: unknown[]) => void>();
  for (const name of ['log', 'info', 'warn', 'error', 'debug'] as ConsoleMethod[]) {
    const fn = sink[name].bind(target);
    original.set(name, fn);
    const source = `console.${name}`;
    sink[name] = enforce
      ? (...args: unknown[]) => fn(...args.map((arg) => audit.redact(arg, source)))
      : (...args: unknown[]) => {
          try {
            for (const arg of args) audit.observe(arg, source);
          } catch {
            // Counting must never break logging.
          }
          fn(...args);
        };
  }
  return () => {
    for (const [name, fn] of original) sink[name] = fn;
  };
}
