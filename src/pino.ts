import { redact, type RedactOptions } from './index.js';

/**
 * Drop-in redaction for pino. Unlike pino's own `redact`, which needs a list of
 * field paths, this reads the values — so it also catches the secret in a
 * free-text message or a nested third-party object.
 *
 *   import pino from 'pino';
 *   import { pinoRedact } from 'flare-redact/pino';
 *
 *   const log = pino(pinoRedact());
 *   log.info({ user: 'bob@corp.com' }); // → { "user": "b***@***" }
 *
 * pino hands `formatters.log` only the merging object, never the message, so
 * one formatter is not enough:
 *
 * - `hooks.logMethod` redacts the message, the printf arguments it
 *   interpolates and an Error passed first (whose message becomes `msg`);
 * - `formatters.log` redacts the merging object after the mixin and the
 *   serializers ran, and `formatters.bindings` the base bindings;
 * - pino does not run `formatters.bindings` for `child()` bindings, so a
 *   logger whose bindings hold something sensitive has its whole line redacted
 *   in `hooks.streamWrite`, where pino has that hook. That is checked once per
 *   logger, so other loggers pay nothing. `setBindings()` after a logger's
 *   first line is not checked again.
 */
export function pinoRedact(opts: RedactOptions = {}) {
  const sensitiveBindings = new WeakMap<object, boolean>();
  let redactLine = false;

  const bindingsNeedRedaction = (logger: unknown): boolean => {
    if (typeof logger !== 'object' || logger === null) return false;
    const known = sensitiveBindings.get(logger);
    if (known !== undefined) return known;
    const read = (logger as { bindings?: () => Record<string, unknown> }).bindings;
    let sensitive = false;
    if (typeof read === 'function') {
      const bindings = read.call(logger);
      sensitive = JSON.stringify(redact(bindings, opts)) !== JSON.stringify(bindings);
    }
    sensitiveBindings.set(logger, sensitive);
    return sensitive;
  };

  return {
    hooks: {
      logMethod(this: unknown, args: unknown[], method: (...args: unknown[]) => unknown): unknown {
        // A plain object first is the merging object: formatters.log covers it,
        // so it is not scanned twice.
        const safe = args.map((arg, index) => (index === 0 && isMergingObject(arg) ? arg : redact(arg, opts)));
        const previous = redactLine;
        redactLine = bindingsNeedRedaction(this);
        try {
          return method.apply(this, safe);
        } finally {
          redactLine = previous;
        }
      },
      streamWrite(line: string): string {
        if (!redactLine) return line;
        try {
          return `${JSON.stringify(redact(JSON.parse(line), opts))}\n`;
        } catch {
          return `${JSON.stringify({ msg: '[REDACTION FAILED]' })}\n`;
        }
      },
    },
    formatters: {
      bindings(bindings: Record<string, unknown>): Record<string, unknown> {
        return redact(bindings, opts);
      },
      log(object: Record<string, unknown>): Record<string, unknown> {
        return redact(object, opts);
      },
    },
  };
}

function isMergingObject(value: unknown): boolean {
  return typeof value === 'object' && value !== null && !(value instanceof Error);
}
