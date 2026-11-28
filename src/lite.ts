/**
 * flare-redact/lite: the same redaction, scanning, path rules, sensitive keys
 * and reversible vaults, without entity recognition (people and addresses found
 * from name lists in free text). That leaves out about half of the bundle, for
 * browsers, edge functions and other places where size matters. Every secret
 * and PII detector is still here; the output is identical to `flare-redact` for
 * any options that do not ask for `entities`, which throws here instead.
 */
export {
  redact,
  redactAsync,
  scan,
  scanAsync,
  isClean,
  isCleanAsync,
  summary,
  compilePolicy,
  createRedactor,
  definePolicy,
  wrapConsole,
} from './core.js';
export {
  createVault,
  restore,
  buildRestore,
  buildStreamRestore,
  type IncrementalRestorer,
  type Vault,
  type VaultOptions,
} from './vault.js';
export type { Mode, Risk, Finding, RedactOptions, SemanticFinding, SemanticProvider, Preset } from './engine.js';
export { FlareRedactError, RedactionLimitError, PRESETS } from './engine.js';
export type { Detector } from './detectors.js';
export {
  CORE_DETECTORS as DETECTORS,
  SENSITIVE_KEY_RE,
  NON_SECRET_TOKEN_KEY_RE,
  isSensitiveKeyName,
  keepPrefix,
  keepLast,
  luhn,
} from './detectors.js';
