/**
 * Redaction without touching the code: load this module before the
 * application starts and every console.log, info, warn, error and debug call
 * is redacted.
 *
 *   node --import flare-redact/register app.js
 *   NODE_OPTIONS="--import flare-redact/register" npm start
 *
 * FLARE_REDACT_PRESET picks a preset (logs, llm, gdpr, strict). An unknown
 * name stops the process at startup: a typo should fail the deploy, not leave
 * the logs unredacted.
 */

import { compilePolicy, wrapConsole, type RedactOptions } from './index.js';

export const PRESET_ENV = 'FLARE_REDACT_PRESET';

/** The options the environment asks for. Throws on an unknown preset. */
export function registerOptions(env: Record<string, string | undefined>): RedactOptions {
  const preset = env[PRESET_ENV]?.trim();
  const opts: RedactOptions = preset ? { preset: preset as RedactOptions['preset'] } : {};
  compilePolicy(opts);
  return opts;
}

const env = typeof process === 'undefined' ? {} : process.env;
wrapConsole(registerOptions(env));
