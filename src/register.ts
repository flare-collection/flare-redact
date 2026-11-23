/**
 * Redaction without touching the code: load this module before the
 * application starts and every console.log, info, warn, error and debug call
 * is redacted.
 *
 *   node --import flare-redact/register app.js
 *   NODE_OPTIONS="--import flare-redact/register" npm start
 *
 * FLARE_REDACT_PRESET picks a preset (logs, llm, gdpr, strict).
 *
 * FLARE_REDACT_MODE picks what happens:
 *   enforce  redact the output (the default)
 *   shadow   leave the output as it is and count what would have been redacted
 *   audit    redact the output and count what was redacted
 * In shadow and audit mode the counts go to stderr when the process exits, and
 * every FLARE_REDACT_REPORT_EVERY seconds when that is set. They never include
 * a matched value.
 *
 * An unknown preset or mode stops the process at startup: a typo should fail
 * the deploy, not leave the logs unredacted.
 */

import { compilePolicy, wrapConsole, type RedactOptions } from './index.js';
import { createAudit, shadowConsole } from './audit.js';

export const PRESET_ENV = 'FLARE_REDACT_PRESET';
export const MODE_ENV = 'FLARE_REDACT_MODE';
export const REPORT_EVERY_ENV = 'FLARE_REDACT_REPORT_EVERY';

export type RegisterMode = 'enforce' | 'shadow' | 'audit';

type Env = Record<string, string | undefined>;

/** The options the environment asks for. Throws on an unknown preset. */
export function registerOptions(env: Env): RedactOptions {
  const preset = env[PRESET_ENV]?.trim();
  const opts: RedactOptions = preset ? { preset: preset as RedactOptions['preset'] } : {};
  compilePolicy(opts);
  return opts;
}

/** The mode the environment asks for. Throws on an unknown one. */
export function registerMode(env: Env): RegisterMode {
  const mode = (env[MODE_ENV]?.trim().toLowerCase() || 'enforce') as RegisterMode;
  if (mode !== 'enforce' && mode !== 'shadow' && mode !== 'audit') {
    throw new Error(`${MODE_ENV} must be enforce, shadow or audit, not ${JSON.stringify(env[MODE_ENV])}`);
  }
  return mode;
}

/** Seconds between reports, 0 for only at exit. Throws on anything but a whole number. */
export function reportEvery(env: Env): number {
  const raw = env[REPORT_EVERY_ENV]?.trim();
  if (!raw) return 0;
  if (!/^\d+$/.test(raw)) throw new Error(`${REPORT_EVERY_ENV} must be a number of seconds, not ${JSON.stringify(raw)}`);
  return Number(raw);
}

const env: Env = typeof process === 'undefined' ? {} : process.env;
const opts = registerOptions(env);
const mode = registerMode(env);

if (mode === 'enforce') {
  wrapConsole(opts);
} else {
  const every = reportEvery(env);
  const audit = createAudit(opts);
  shadowConsole(audit, console, { enforce: mode === 'audit' });
  const print = () => {
    if (audit.report().scanned) process.stderr.write(`[flare-redact ${mode}] ${audit.format()}\n`);
  };
  if (typeof process !== 'undefined' && typeof process.on === 'function') {
    process.on('exit', print);
    if (every > 0) setInterval(print, every * 1000).unref?.();
  }
}
