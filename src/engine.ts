import { CORE_DETECTORS, type Detector } from './detectors.js';
import { hmacFingerprint } from './crypto.js';
import { pseudonymize, surrogate } from './transforms.js';
import { isSensitiveKeyName } from './i18n.js';
import { normalizeKeyName, prefilterPattern } from './fold.js';
import { buildTermsDetector, type TermSpec } from './terms.js';
import { secretProbability } from './ml.js';
import type { EntityLabel, EntityOptions } from './entities.js';
import { ENTITY_LABELS, entitySupport, type EntitySupport } from './entity-hook.js';

export type Mode = 'mask' | 'label' | 'hash' | 'pseudonym' | 'surrogate' | 'fpe';
export type Risk = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  detector: string;
  label: string;
  why: string;
  /**
   * The matched secret. Omitted by default because findings are commonly
   * logged or exported. Set `includeValues: true` only for trusted diagnostics.
   */
  value?: string;
  start?: number;
  end?: number;
  /** One-based line within the scanned string. */
  line?: number;
  /** One-based UTF-16 column within the scanned string. */
  column?: number;
  path?: string;
  risk: Risk;
  confidence: number;
}

export interface SemanticFinding {
  detector: string;
  label: string;
  why: string;
  start: number;
  end: number;
  risk?: Risk;
  confidence?: number;
}

export interface SemanticProvider {
  detect(text: string): SemanticFinding[] | Promise<SemanticFinding[]>;
}

/**
 * Named policies, so a caller picks a goal instead of a list of tags. Each one
 * adds to the default detectors; `enable` and `disable` still apply on top.
 */
export const PRESETS = {
  /** Log lines: the defaults plus phone numbers. */
  logs: ['phone'],
  /** Prompts and chat: every personal identifier plus free-text people and addresses. */
  llm: ['pii', 'entities'],
  /** Everything GDPR treats as personal data, network and device identifiers included. */
  gdpr: ['pii', 'entities', 'network', 'vehicle', 'crypto'],
  /** Every detector, including the noisy entropy and finance ones. */
  strict: ['*'],
} as const satisfies Record<string, readonly string[]>;

export type Preset = keyof typeof PRESETS;

export interface RedactOptions {
  /**
   * A named policy: `logs`, `llm`, `gdpr` or `strict`. Adds to the defaults;
   * `enable` and `disable` apply on top, and `only` ignores it.
   */
  preset?: Preset;
  only?: string[];
  enable?: string[];
  disable?: string[];
  custom?: Detector[];
  /**
   * Replace the built-in detector set entirely — for example with the detectors
   * of a loaded FRS-1 pack. `custom` is still appended on top.
   */
  detectors?: Detector[];
  mode?: Mode;
  /** A fixed mask, or a function of the match; `text` is the whole string it was found in. */
  mask?: string | ((f: { value: string; detector: Detector; text?: string }) => string);
  /** @deprecated Use transformSecret. */
  hashSalt?: string;
  /** Secret key for hash, pseudonym, and surrogate modes. Never hard-code it. */
  transformSecret?: string;
  redactKeys?: boolean | RegExp | string[];
  /**
   * Values to redact by where they are, as pino's `redact.paths` and fast-redact
   * write them: `user.password`, `users[0].token`, `users.*.password` (`*` is any
   * one key or index), `**.authorization` (`**` is any depth) and
   * `headers["x-api-key"]`. Keys compare exactly. A matched value is masked
   * whatever its type; detectors and `redactKeys` still apply everywhere else.
   */
  paths?: string[];
  /** Delete the properties `paths` matches instead of masking them (default: false). */
  remove?: boolean;
  allow?: RegExp | string[];
  /** Your own words/phrases to always catch — masked one-way, or reversible in a vault. */
  terms?: TermSpec[] | Record<string, string>;
  /** Match `terms` case-sensitively (default: false). */
  termsCaseSensitive?: boolean;
  /** Optional local detector/model for names, addresses, and other semantic PII. */
  semanticProvider?: SemanticProvider;
  /**
   * Recognise people, addresses, phone numbers, personal dates, account numbers,
   * handles, personal URLs and secrets in free text, without a model. `true`
   * turns on every label; an object picks labels and tunes the recogniser.
   * `enable: ['entities']` is the same as `entities: true`.
   */
  entities?: boolean | EntityOptions;
  /** Drop findings below this confidence (default: 0). */
  minConfidence?: number;
  /**
   * Let the learned classifier refine confidence for generic detectors that
   * over-fire on benign high-entropy text (UUIDs, git SHAs, digests, slugs).
   * Only detectors marked `refine` are affected; checksum-validated ones are
   * left untouched. Pair with `minConfidence` to drop likely false positives.
   * Default: false.
   */
  refineConfidence?: boolean;
  /** Include raw matched values in scan results. Unsafe for logs and reports. */
  includeValues?: boolean;
  limits?: {
    /** Maximum UTF-16 input length per scanned string (default: 16 MiB). */
    maxInputLength?: number;
    /** Maximum findings returned per string (default: 50,000). */
    maxFindings?: number;
  };
}

export interface Hit extends Finding {
  value: string;
  det: Detector;
}

export class FlareRedactError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = 'FlareRedactError';
    this.code = code;
  }
}

export class RedactionLimitError extends FlareRedactError {
  constructor(message: string) {
    super('ERR_REDACTION_LIMIT', message);
    this.name = 'RedactionLimitError';
  }
}

export type Replace = (value: string, det: Detector, text?: string) => string;

function matches(entry: string, d: Detector): boolean {
  return d.id === entry || (d.tags?.includes(entry) ?? false);
}

/** The tags a preset turns on. Throws on a name that is not a preset. */
export function presetTags(preset: string | undefined): readonly string[] {
  if (preset === undefined) return [];
  if (!Object.prototype.hasOwnProperty.call(PRESETS, preset)) {
    throw new FlareRedactError(
      'ERR_UNKNOWN_PRESET',
      `unknown preset ${JSON.stringify(preset)}; use one of: ${Object.keys(PRESETS).join(', ')}`,
    );
  }
  return PRESETS[preset as Preset];
}

let defaultList: { support: EntitySupport | undefined; list: Detector[] } | undefined;

/** The built-in detectors, with the entity detectors when entity support is installed. */
function defaultDetectors(): Detector[] {
  const support = entitySupport();
  if (defaultList && defaultList.support === support) return defaultList.list;
  const list = support ? [...CORE_DETECTORS, ...support.detectors] : CORE_DETECTORS;
  defaultList = { support, list };
  return list;
}

/** Entity support, or a clear error in builds that leave it out. */
function requireEntities(): EntitySupport {
  const support = entitySupport();
  if (!support) {
    throw new FlareRedactError(
      'ERR_ENTITIES_UNAVAILABLE',
      'Entity recognition (`entities`) is not part of flare-redact/lite. Import from "flare-redact" to use it.',
    );
  }
  return support;
}

export function resolveDetectors(opts: RedactOptions): Detector[] {
  const base = opts.detectors ?? defaultDetectors();
  const all = opts.custom?.length ? [...base, ...opts.custom] : base;
  if (!entitySupport()) {
    // An explicit ask for entity recognition fails loudly where it is left out.
    for (const entry of [...(opts.enable ?? []), ...(opts.only ?? [])]) {
      const isEntity = entry === 'entities' || (ENTITY_LABELS as readonly string[]).includes(entry);
      if (isEntity && !all.some((d) => matches(entry, d))) requireEntities();
    }
  }
  const preset = presetTags(opts.preset);
  const everything = preset.includes('*');
  let chosen: Detector[];
  if (opts.only?.length) {
    chosen = all.filter((d) => opts.only!.some((e) => matches(e, d)));
  } else {
    const { enable, disable } = opts;
    chosen = all.filter((d) => {
      const on = d.default || everything || preset.some((e) => matches(e, d)) || (enable?.some((e) => matches(e, d)) ?? false);
      const off = disable?.some((e) => matches(e, d)) ?? false;
      return on && !off;
    });
  }
  if (opts.entities) {
    const support = requireEntities();
    const labels = ((typeof opts.entities === 'object' && opts.entities.labels) || support.labels) as readonly string[];
    for (const det of support.detectors) {
      if (chosen.includes(det) || !labels.includes(det.id)) continue;
      if (opts.disable?.some((e) => matches(e, det))) continue;
      chosen = [...chosen, det];
    }
  }
  const termsDet = buildTermsDetector(opts.terms, opts.termsCaseSensitive);
  return termsDet ? [termsDet, ...chosen] : chosen;
}

export function keyMatcher(opts: RedactOptions): (key: string) => boolean {
  const rk = opts.redactKeys;
  if (rk === false) return () => false;
  if (rk instanceof RegExp) return (k) => {
    rk.lastIndex = 0;
    return rk.test(k);
  };
  if (Array.isArray(rk)) {
    const set = new Set(rk.map(normalizeKeyName));
    return (k) => set.has(normalizeKeyName(k));
  }
  return isSensitiveKeyName;
}

export function allowMatcher(opts: RedactOptions): (value: string) => boolean {
  const a = opts.allow;
  if (!a) return () => false;
  if (a instanceof RegExp) return (v) => {
    a.lastIndex = 0;
    return a.test(v);
  };
  const set = new Set(a);
  return (v) => set.has(v);
}

export function makeReplacer(opts: RedactOptions): Replace {
  const secret = opts.transformSecret ?? opts.hashSalt ?? '';
  const mask = opts.mask;
  const mode = opts.mode ?? 'mask';
  if (typeof mask === 'string') return () => mask;
  if (typeof mask === 'function') return (value, det, text) => mask({ value, detector: det, text });
  if (mode === 'label') return (_value, det) => `[REDACTED:${det.id}]`;
  if (mode === 'hash') return (value, det) => `${det.id}_${hmacFingerprint(secret, value)}`;
  if (mode === 'pseudonym' || mode === 'fpe') return (value) => pseudonymize(value, secret);
  if (mode === 'surrogate') return (value, det) => surrogate(value, det, secret);
  return (value, det) => (det.mask ? det.mask(value) : '***');
}

const scanPatterns = new WeakMap<RegExp, RegExp>();

/**
 * The pattern a scan actually runs: global, and — only when the detector reads a
 * capture group — carrying `d` so the group's exact bounds are available.
 * Recompiling is cached per source pattern, because scanString runs this for
 * every detector on every string.
 */
function scanPattern(det: Detector): RegExp {
  const cached = scanPatterns.get(det.pattern);
  if (cached) return cached;
  let flags = det.pattern.flags;
  if (!flags.includes('g')) flags += 'g';
  if (det.capture !== undefined && !flags.includes('d')) flags += 'd';
  const compiled = flags === det.pattern.flags ? det.pattern : new RegExp(det.pattern.source, flags);
  scanPatterns.set(det.pattern, compiled);
  return compiled;
}

/**
 * Where the capture group actually starts. The `d` flag gives exact bounds; the
 * search fallback keeps older behaviour for a hand-written detector compiled
 * without it, which only differs when the captured text also appears earlier in
 * the match.
 */
function captureOffset(m: RegExpExecArray, group: number, value: string): number {
  const indices = (m as RegExpExecArray & { indices?: Array<[number, number] | undefined> }).indices;
  const span = indices?.[group];
  if (span) return span[0] - m.index;
  return m[0].indexOf(value);
}

function normalizedView(text: string): { text: string; sourceIndex?: number[] } {
  if (!/[\u200B\u200C\u200D\u2060\uFEFF]/.test(text)) return { text };
  let normalized = '';
  const sourceIndex: number[] = [];
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code === 0x200b || code === 0x200c || code === 0x200d || code === 0x2060 || code === 0xfeff) continue;
    normalized += text[i]!;
    sourceIndex.push(i);
  }
  return { text: normalized, sourceIndex };
}


const prefilters = new WeakMap<Detector, RegExp>();

/**
 * A detector's prefilter as one case-insensitive search (SPEC §4), compiled once
 * per detector. It follows the pattern's own case rules, so it can never skip a
 * detector that would match, and it scans the subject without copying it.
 */
function prefilterOf(det: Detector): RegExp | undefined {
  if (!det.prefilter?.length) return undefined;
  let re = prefilters.get(det);
  if (!re) {
    re = prefilterPattern(det.prefilter);
    prefilters.set(det, re);
  }
  return re;
}
interface PlanEntry {
  det: Detector;
  re: RegExp;
  prefilter: RegExp | undefined;
}

interface ScanPlan {
  support: EntitySupport | undefined;
  regex: PlanEntry[];
  entity: Detector[];
}

const scanPlans = new WeakMap<readonly Detector[], ScanPlan>();

/**
 * Everything scanString needs per detector, worked out once per detector list
 * instead of once per string: the compiled scan pattern, the prefilter and
 * whether entity recognition handles it. A compiled policy keeps its list, so
 * this runs once per policy.
 */
function scanPlan(dets: readonly Detector[]): ScanPlan {
  const support = entitySupport();
  const cached = scanPlans.get(dets);
  if (cached && cached.support === support) return cached;
  const plan: ScanPlan = { support, regex: [], entity: [] };
  for (const det of dets) {
    if (support?.isEntityDetector(det)) plan.entity.push(det);
    else plan.regex.push({ det, re: scanPattern(det), prefilter: prefilterOf(det) });
  }
  scanPlans.set(dets, plan);
  return plan;
}

export function scanString(
  text: string,
  dets: Detector[],
  allow: (v: string) => boolean,
  opts: RedactOptions = {},
): Hit[] {
  const maxInputLength = opts.limits?.maxInputLength ?? 16 * 1024 * 1024;
  const maxFindings = opts.limits?.maxFindings ?? 50_000;
  if (text.length > maxInputLength) {
    throw new RedactionLimitError(`Input length ${text.length} exceeds the configured limit of ${maxInputLength}.`);
  }
  const normalized = normalizedView(text);
  const subject = normalized.text;
  const hits: Hit[] = [];
  const plan = scanPlan(dets);
  const entities = plan.support;
  const entityDetectors = plan.entity.length ? plan.entity : undefined;
  for (const { det, re, prefilter } of plan.regex) {
    if (prefilter && !prefilter.test(subject)) continue;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(subject)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      const captured = det.capture === undefined ? m[0] : m[det.capture];
      const normalizedValue = captured ?? '';
      if (!normalizedValue) continue;
      const relativeStart = det.capture === undefined ? 0 : captureOffset(m, det.capture, normalizedValue);
      if (relativeStart < 0) continue;
      const normalizedStart = m.index + relativeStart;
      const normalizedEnd = normalizedStart + normalizedValue.length;
      if (det.boundary && !withinBoundary(det.boundary, subject, normalizedStart, normalizedEnd)) continue;
      if (det.reject?.some((pattern) => { pattern.lastIndex = 0; return pattern.test(normalizedValue); })) continue;
      if (det.validate && !det.validate(normalizedValue)) continue;
      const start = normalized.sourceIndex?.[normalizedStart] ?? normalizedStart;
      const end = normalized.sourceIndex
        ? (normalized.sourceIndex[normalizedEnd - 1] ?? (normalizedEnd - 1)) + 1
        : normalizedEnd;
      const value = text.slice(start, end);
      if (allow(value) || (value !== normalizedValue && allow(normalizedValue))) continue;
      const confidence = scoreConfidence(det, text, start, end, opts);
      if (confidence < (opts.minConfidence ?? 0)) continue;
      hits.push({
        detector: det.id,
        label: det.label,
        why: det.why,
        value,
        start,
        end,
        risk: detectorRisk(det),
        confidence,
        det,
      });
      if (hits.length > maxFindings) {
        throw new RedactionLimitError(`Finding count exceeds the configured limit of ${maxFindings}.`);
      }
    }
  }

  if (opts.semanticProvider) {
    const semanticFindings = opts.semanticProvider.detect(text);
    if (!Array.isArray(semanticFindings)) {
      throw new TypeError('Semantic provider is asynchronous; use scanAsync() or redactAsync().');
    }
    for (const finding of semanticFindings) {
      if (!Number.isInteger(finding.start) || !Number.isInteger(finding.end) || finding.start < 0 || finding.end <= finding.start || finding.end > text.length) {
        throw new TypeError(`Semantic provider returned an invalid span for ${finding.detector}.`);
      }
      const value = text.slice(finding.start, finding.end);
      if (allow(value) || (finding.confidence ?? 0.8) < (opts.minConfidence ?? 0)) continue;
      const det: Detector = {
        id: finding.detector,
        label: finding.label,
        why: finding.why,
        pattern: /(?!)/,
        default: false,
        risk: finding.risk ?? 'high',
        confidence: finding.confidence ?? 0.8,
      };
      hits.push({ ...finding, value, risk: det.risk!, confidence: det.confidence!, det });
      if (hits.length > maxFindings) {
        throw new RedactionLimitError(`Finding count exceeds the configured limit of ${maxFindings}.`);
      }
    }
  }
  if (entityDetectors) {
    const byId = new Map(entityDetectors.map((det) => [det.id, det]));
    const tuning = typeof opts.entities === 'object' ? opts.entities : {};
    for (const finding of entities!.recognize(text, { ...tuning, labels: [...byId.keys()] as EntityLabel[] })) {
      const det = byId.get(finding.detector)!;
      const value = text.slice(finding.start, finding.end);
      if (allow(value) || finding.confidence < (opts.minConfidence ?? 0)) continue;
      hits.push({ ...finding, label: det.label, why: det.why, value, det });
      if (hits.length > maxFindings) {
        throw new RedactionLimitError(`Finding count exceeds the configured limit of ${maxFindings}.`);
      }
    }
  }
  if (hits.length < 2) return hits;
  return selectNonOverlapping(hits);
}

/** Start and end of input always satisfy a boundary; see `spec/SPEC.md` §3.1. */
function withinBoundary(
  boundary: NonNullable<Detector['boundary']>,
  subject: string,
  start: number,
  end: number,
): boolean {
  if (boundary.before && start > 0 && boundary.before.has(subject[start - 1]!)) return false;
  if (boundary.after && end < subject.length && boundary.after.has(subject[end]!)) return false;
  return true;
}

function selectNonOverlapping(hits: Hit[]): Hit[] {
  const sorted = [...hits].sort((a, b) => a.end! - b.end! || a.start! - b.start!);
  const previous: number[] = [];
  for (let i = 0; i < sorted.length; i++) {
    let lo = 0;
    let hi = i - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (sorted[mid]!.end! <= sorted[i]!.start!) {
        found = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    previous[i] = found;
  }

  const best = new Array<number>(sorted.length + 1).fill(0);
  for (let i = 1; i <= sorted.length; i++) {
    const include = hitWeight(sorted[i - 1]!) + best[previous[i - 1]! + 1]!;
    best[i] = Math.max(best[i - 1]!, include);
  }

  const selected: Hit[] = [];
  for (let i = sorted.length; i > 0;) {
    const hit = sorted[i - 1]!;
    const include = hitWeight(hit) + best[previous[i - 1]! + 1]!;
    if (include > best[i - 1]!) {
      selected.push(hit);
      i = previous[i - 1]! + 1;
    } else {
      i--;
    }
  }
  return selected.reverse().sort((a, b) => a.start! - b.start! || a.end! - b.end!);
}

function hitWeight(hit: Hit): number {
  const risk = hit.risk === 'critical' ? 1e9 : hit.risk === 'high' ? 1e6 : hit.risk === 'medium' ? 1e3 : 1;
  return risk + (hit.det.priority ?? 0) * 10 + hit.confidence + (hit.end! - hit.start!) / 1_000_000;
}

function detectorRisk(det: Detector): Risk {
  if (det.risk) return det.risk;
  if (det.tags?.includes('secret') || /(?:token|key|auth|credential|password|seed_phrase)/.test(det.id)) return 'critical';
  if (det.tags?.includes('pii') || /(?:email|phone|card|ssn|iban|person|address|dob)/.test(det.id)) return 'high';
  if (det.tags?.includes('network')) return 'medium';
  return 'high';
}

/** How far the learned model can move a base confidence score, up or down. */
const REFINE_STRENGTH = 0.4;

function scoreConfidence(
  det: Detector,
  text: string,
  start: number,
  end: number,
  opts: RedactOptions = {},
): number {
  let score = det.confidence ?? (det.id === 'high_entropy' ? 0.6 : det.validate ? 0.99 : 0.92);
  if (det.context) {
    const radius = det.context.window ?? 80;
    const nearby = text.slice(Math.max(0, start - radius), Math.min(text.length, end + radius));
    if (det.context.positive) {
      det.context.positive.lastIndex = 0;
      if (det.context.positive.test(nearby)) score += 0.06;
    }
    if (det.context.negative) {
      det.context.negative.lastIndex = 0;
      if (det.context.negative.test(nearby)) score -= 0.25;
    }
  }
  if (opts.refineConfidence && det.refine) {
    const window = text.slice(Math.max(0, start - 64), Math.min(text.length, end + 64));
    const p = secretProbability(text.slice(start, end), window);
    score += (p - 0.5) * REFINE_STRENGTH;
  }
  return Math.max(0, Math.min(1, score));
}

export function redactString(
  text: string,
  dets: Detector[],
  allow: (v: string) => boolean,
  replace: Replace,
  opts: RedactOptions = {},
): string {
  const hits = scanString(text, dets, allow, opts);
  if (!hits.length) return text;
  let out = '';
  let cursor = 0;
  for (const h of hits) {
    out += text.slice(cursor, h.start);
    out += replace(h.value, h.det, text);
    cursor = h.end!;
  }
  return out + text.slice(cursor);
}
