import { redact, type RedactOptions } from './index.js';

/**
 * A winston format transform. It redacts every enumerable field of the log
 * `info` in place, so winston's own symbol-keyed metadata (level, message)
 * stays intact.
 *
 *   import winston from 'winston';
 *   import { winstonRedact } from 'flare-redact/winston';
 *
 *   const log = winston.createLogger({
 *     format: winston.format.combine(winston.format(winstonRedact())(), winston.format.json()),
 *     transports: [new winston.transports.Console()],
 *   });
 */
export function winstonRedact(opts: RedactOptions = {}) {
  return (info: Record<string, unknown>): Record<string, unknown> => {
    for (const key of Object.keys(info)) {
      info[key] = redact(info[key], opts);
    }
    // Formats placed after this one read two more things: format.splat()
    // interpolates and merges the raw arguments kept under Symbol.for('splat'),
    // and format.errors() reads the message and stack an Error keeps as
    // non-enumerable properties.
    const meta = info as Record<symbol, unknown>;
    if (Array.isArray(meta[SPLAT])) meta[SPLAT] = redact(meta[SPLAT], opts);
    if (info instanceof Error) {
      for (const key of ['message', 'stack'] as const) {
        if (typeof info[key] === 'string') info[key] = redact(info[key], opts);
      }
    }
    return info;
  };
}

const SPLAT = Symbol.for('splat');
