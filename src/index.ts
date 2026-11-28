export type { Mode, Risk, Finding, RedactOptions, SemanticFinding, SemanticProvider, Preset } from './engine.js';
export { FlareRedactError, RedactionLimitError, PRESETS } from './engine.js';
export type { Detector } from './detectors.js';
export { DETECTORS } from './all-detectors.js';
export {
  CORE_DETECTORS,
  SENSITIVE_KEY_RE,
  NON_SECRET_TOKEN_KEY_RE,
  isSensitiveKeyName,
  keepPrefix,
  keepLast,
  luhn,
  entropy,
  fnv1a,
} from './detectors.js';
export {
  secretProbability,
  extractFeatures,
  shannonEntropy,
  FEATURES,
  FEATURE_COUNT,
  CONFIDENCE_MODEL,
  type ConfidenceModel,
} from './ml.js';
export {
  recognizeEntities,
  createEntityRecognizer,
  ENTITY_LABELS,
  type EntityLabel,
  type EntityOptions,
  type EntityFinding,
} from './entities.js';
export { pseudonymize, surrogate, fpe } from './transforms.js';
export { hmacFingerprint } from './crypto.js';
export {
  createVault,
  restore,
  buildRestore,
  buildStreamRestore,
  type IncrementalRestorer,
  type Vault,
  type VaultOptions,
} from './vault.js';
export {
  sealVault,
  openVault,
  isSealedVault,
  type SealedVaultV1,
  type SealVaultOptions,
} from './secure-vault.js';
export { createSession, type Session, type SessionOptions, type StreamRestorer } from './session.js';

// Entity recognition registers itself with the engine when this loads; the
// lite entry point leaves it out.
import './entities.js';

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
