import {
  compilePolicy,
  type Finding,
  type RedactOptions,
} from './index.js';

export type RedactionAction = 'redact' | 'observe' | 'block';
export type SafeFinding = Omit<Finding, 'value'>;

export interface RedactionContext {
  /** Stable name for the boundary, route, queue, SDK method, or sink. */
  name?: string;
  phase?: 'input' | 'output' | 'value';
  /** Caller-owned, non-sensitive correlation metadata. */
  metadata?: Readonly<Record<string, unknown>>;
}

export interface RedactionEvent extends RedactionContext {
  action: RedactionAction;
  /** Findings are always value-free, even if the underlying policy opts in. */
  findings: readonly SafeFinding[];
}

export interface RedactionMiddlewareOptions {
  policy?: RedactOptions;
  /** Redact (default), observe without changing data, or reject on a finding. */
  action?: RedactionAction;
  /** Called only when findings exist. Raw matched values are never exposed. */
  onFindings?: (event: RedactionEvent) => void;
}

export interface WrapOptions {
  /**
   * Sanitize/reject the complete argument array (true, default), no arguments
   * (false), or only the named zero-based argument indexes.
   */
  input?: boolean | readonly number[];
  /** Sanitize/reject the return value, including resolved promises. Default: false. */
  output?: boolean;
  /** Boundary name included in finding events and block errors. */
  name?: string;
  /** Caller-owned, non-sensitive correlation metadata. */
  metadata?: Readonly<Record<string, unknown>>;
}

export interface RedactionMiddleware {
  inspect(value: unknown): readonly SafeFinding[];
  inspectAsync(value: unknown): Promise<readonly SafeFinding[]>;
  process<T>(value: T, context?: RedactionContext): T;
  processAsync<T>(value: T, context?: RedactionContext): Promise<T>;
  wrap<T extends (...args: any[]) => any>(handler: T, opts?: WrapOptions): T;
  wrapAsync<T extends (...args: any[]) => any>(
    handler: T,
    opts?: WrapOptions,
  ): (...args: Parameters<T>) => Promise<Awaited<ReturnType<T>>>;
}

export class RedactionBlockedError extends Error {
  readonly code = 'ERR_REDACTION_BLOCKED';
  readonly findings: readonly SafeFinding[];
  readonly context: Readonly<RedactionContext>;

  constructor(findings: readonly SafeFinding[], context: RedactionContext = {}) {
    const suffix = context.name ? ` at "${context.name}"` : '';
    super(`Sensitive data blocked${suffix}: ${findings.length} finding(s).`);
    this.name = 'RedactionBlockedError';
    this.findings = findings;
    this.context = Object.freeze({ ...context });
  }
}

function safeFindings(findings: Finding[]): readonly SafeFinding[] {
  return Object.freeze(
    findings.map(({ value: _value, ...finding }) => Object.freeze(finding)),
  );
}

function isPromiseLike(value: unknown): value is PromiseLike<unknown> {
  return (
    (typeof value === 'object' || typeof value === 'function') &&
    value !== null &&
    typeof (value as { then?: unknown }).then === 'function'
  );
}

function wrapContext(opts: WrapOptions, phase: 'input' | 'output'): RedactionContext {
  return { name: opts.name, metadata: opts.metadata, phase };
}

function inputIndexes(input: WrapOptions['input']): readonly number[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const unique = new Set<number>();
  for (const index of input) {
    if (!Number.isInteger(index) || index < 0) {
      throw new RangeError('wrap() input indexes must be non-negative integers.');
    }
    unique.add(index);
  }
  return Object.freeze([...unique]);
}

/**
 * Framework-neutral data boundary for SDK methods, route handlers, queues,
 * webhooks, RPC calls, analytics clients, and persistence functions.
 * Detector state is compiled once and reused across every invocation.
 */
export function createRedactionMiddleware(
  opts: RedactionMiddlewareOptions = {},
): RedactionMiddleware {
  const action = opts.action ?? 'redact';
  if (action !== 'redact' && action !== 'observe' && action !== 'block') {
    throw new TypeError('Redaction middleware action must be redact, observe, or block.');
  }
  const policy = compilePolicy(opts.policy ?? {});

  const inspect = (value: unknown): readonly SafeFinding[] => safeFindings(policy.scan(value));
  const inspectAsync = async (value: unknown): Promise<readonly SafeFinding[]> =>
    safeFindings(await policy.scanAsync(value));

  const decide = <T>(
    value: T,
    findings: readonly SafeFinding[],
    context: RedactionContext,
  ): T => {
    if (findings.length) {
      opts.onFindings?.(Object.freeze({ ...context, action, findings }));
      if (action === 'block') throw new RedactionBlockedError(findings, context);
    }
    return value;
  };

  const process = <T>(value: T, context: RedactionContext = {}): T => {
    if (action === 'redact' && !opts.onFindings) return policy.redact(value);
    const resolvedContext = { phase: 'value' as const, ...context };
    const findings = inspect(value);
    decide(value, findings, resolvedContext);
    return action === 'redact' ? policy.redact(value) : value;
  };

  const processAsync = async <T>(value: T, context: RedactionContext = {}): Promise<T> => {
    if (action === 'redact' && !opts.onFindings) return policy.redactAsync(value);
    const resolvedContext = { phase: 'value' as const, ...context };
    const findings = await inspectAsync(value);
    decide(value, findings, resolvedContext);
    return action === 'redact' ? policy.redactAsync(value) : value;
  };

  const wrap = <T extends (...args: any[]) => any>(handler: T, wrapOpts: WrapOptions = {}): T => {
    if (typeof handler !== 'function') throw new TypeError('wrap() expects a function.');
    const input = wrapOpts.input ?? true;
    const indexes = inputIndexes(input);
    const output = wrapOpts.output ?? false;
    const wrapped = function (this: unknown, ...args: Parameters<T>): ReturnType<T> {
      let safeArgs = args;
      if (indexes) {
        safeArgs = [...args] as Parameters<T>;
        for (const index of indexes) {
          if (index < safeArgs.length) {
            safeArgs[index] = process(safeArgs[index], wrapContext(wrapOpts, 'input'));
          }
        }
      } else if (input) {
        safeArgs = process(args, wrapContext(wrapOpts, 'input')) as Parameters<T>;
      }
      const result = Reflect.apply(handler, this, safeArgs) as ReturnType<T>;
      if (!output) return result;
      if (isPromiseLike(result)) {
        return Promise.resolve(result).then((value) =>
          process(value, wrapContext(wrapOpts, 'output'))) as ReturnType<T>;
      }
      return process(result, wrapContext(wrapOpts, 'output'));
    };
    return wrapped as T;
  };

  const wrapAsync = <T extends (...args: any[]) => any>(
    handler: T,
    wrapOpts: WrapOptions = {},
  ): ((...args: Parameters<T>) => Promise<Awaited<ReturnType<T>>>) => {
    if (typeof handler !== 'function') throw new TypeError('wrapAsync() expects a function.');
    const input = wrapOpts.input ?? true;
    const indexes = inputIndexes(input);
    const output = wrapOpts.output ?? false;
    return async function (this: unknown, ...args: Parameters<T>): Promise<Awaited<ReturnType<T>>> {
      let safeArgs = args;
      if (indexes) {
        safeArgs = [...args] as Parameters<T>;
        for (const index of indexes) {
          if (index < safeArgs.length) {
            safeArgs[index] = await processAsync(
              safeArgs[index],
              wrapContext(wrapOpts, 'input'),
            );
          }
        }
      } else if (input) {
        safeArgs = await processAsync(args, wrapContext(wrapOpts, 'input')) as Parameters<T>;
      }
      const result = await Reflect.apply(handler, this, safeArgs) as Awaited<ReturnType<T>>;
      return output
        ? await processAsync(result, wrapContext(wrapOpts, 'output'))
        : result;
    };
  };

  return { inspect, inspectAsync, process, processAsync, wrap, wrapAsync };
}
