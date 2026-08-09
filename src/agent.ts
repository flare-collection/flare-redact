import { compilePolicy, type RedactOptions } from './index.js';
import { restore } from './vault.js';

const FLOW_TOKEN = /\[FR_FLOW_[a-f0-9]{32}\]/g;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const DEFAULT_TOKEN_TTL_MS = 60 * 60 * 1000;
const DEFAULT_MAX_MAPPINGS = 10_000;
const DEFAULT_MAX_EVENTS = 1_000;

export type AgentFlowViolationReason =
  | 'unknown_token'
  | 'key_position'
  | 'capability_denied'
  | 'capability_budget_exceeded'
  | 'sink_budget_exceeded';

export interface AgentFlowBudget {
  /** Maximum restored placeholder occurrences across the lifetime of the flow. */
  maxUses?: number;
  /** Maximum distinct protected values restored to this sink. */
  maxUniqueValues?: number;
  /** Maximum cumulative UTF-8 bytes restored to this sink. */
  maxBytes?: number;
}

export interface AgentFlowCapability {
  /** Stable, audit-safe identifier. First matching capability wins. */
  id: string;
  /** Trusted source ids, or `*`. */
  sources: readonly string[] | '*';
  /** Detector ids, or `*`. Defaults to `*`. */
  detectors?: readonly string[] | '*';
  /** JSON Pointer patterns. `*` matches one segment; a terminal `**` matches descendants. */
  paths: readonly string[];
  /** Optional cumulative occurrence budget for this capability. */
  maxUses?: number;
}

export interface AgentFlowSinkPolicy {
  capabilities: readonly AgentFlowCapability[];
  /** Cumulative sink-wide leakage budget. */
  budget?: AgentFlowBudget;
}

export interface AgentFlowLimits {
  /** Lifetime of a protected value before its mapping is forgotten. Default: 1 hour. */
  tokenTtlMs: number;
  /** Maximum live protected values. Default: 10,000. */
  maxMappings: number;
  /** Maximum retained value-free audit events. Default: 1,000. */
  maxEvents: number;
}

export interface AgentFlowViolation {
  reason: AgentFlowViolationReason;
  sink: string;
  /** JSON Pointer to the string carrying the placeholder. Empty string is the root. */
  path: string;
  source?: string;
  detector?: string;
  capability?: string;
  limit?: keyof AgentFlowBudget;
}

export interface AgentFlowBudgetUsage {
  uses: number;
  uniqueValues: number;
  bytes: number;
}

export interface AgentFlowDecision {
  allowed: boolean;
  sink: string;
  occurrences: number;
  restorable: number;
  violations: readonly AgentFlowViolation[];
  projectedBudget: Readonly<AgentFlowBudgetUsage>;
}

export type AgentFlowEvent =
  | {
      type: 'protected';
      time: number;
      source: string;
      occurrences: number;
      detectors: readonly string[];
      liveMappings: number;
    }
  | {
      type: 'authorized';
      time: number;
      sink: string;
      occurrences: number;
      capabilities: readonly string[];
      budget: Readonly<AgentFlowBudgetUsage>;
    }
  | {
      type: 'blocked';
      time: number;
      sink: string;
      occurrences: number;
      violations: readonly AgentFlowViolation[];
    }
  | {
      type: 'revoked';
      time: number;
      source?: string;
      mappings: number;
    };

export interface AgentFlowSnapshot {
  liveMappings: number;
  sources: Readonly<Record<string, number>>;
  sinks: Readonly<Record<string, Readonly<AgentFlowBudgetUsage>>>;
  events: readonly AgentFlowEvent[];
}

export interface AgentFlowOptions {
  /** Detection policy applied before data enters model context. */
  policy?: RedactOptions;
  /** Runtime-owned sink policy. Never derive this object from model output. */
  sinks?: Readonly<Record<string, AgentFlowSinkPolicy>>;
  limits?: Partial<AgentFlowLimits>;
  /** Receives value-free events only. */
  onEvent?: (event: AgentFlowEvent) => void;
  /** Injectable monotonic wall clock for deterministic tests. */
  now?: () => number;
}

export interface AgentFlow {
  /** Detect and replace sensitive source values before they enter model context. */
  protectForModel<T>(source: string, value: T): T;
  /** Inspect a model-produced sink call without restoring or consuming budget. */
  inspectForSink(sink: string, value: unknown): AgentFlowDecision;
  /** Atomically authorize and restore a sink call, or throw without restoring anything. */
  authorizeForSink<T>(sink: string, value: T): T;
  /** Restore all live mappings only at the trusted final application boundary. */
  restoreForApp<T>(value: T): T;
  /** Revoke every mapping minted by one trusted source. */
  revokeSource(source: string): number;
  /** Forget mappings and counters, replacing retained history with one reset event. */
  reset(): void;
  /** Value-free state suitable for audit logs and tests. */
  snapshot(): AgentFlowSnapshot;
  readonly size: number;
}

export class AgentFlowBlockedError extends Error {
  readonly code = 'ERR_AGENT_FLOW_BLOCKED';
  readonly sink: string;
  readonly decision: AgentFlowDecision;

  constructor(decision: AgentFlowDecision) {
    super(`Agent flow blocked ${decision.violations.length} policy violation(s) at sink "${decision.sink}".`);
    this.name = 'AgentFlowBlockedError';
    this.sink = decision.sink;
    this.decision = decision;
  }
}

export class AgentFlowLimitError extends Error {
  readonly code = 'ERR_AGENT_FLOW_LIMIT';

  constructor(message: string) {
    super(message);
    this.name = 'AgentFlowLimitError';
  }
}

interface TokenRecord {
  token: string;
  original: string;
  source: string;
  detector: string;
  createdAt: number;
  expiresAt: number;
  uses: number;
}

interface CompiledCapability {
  id: string;
  sources: ReadonlySet<string> | '*';
  detectors: ReadonlySet<string> | '*';
  paths: readonly (readonly string[])[];
  maxUses: number;
  uses: number;
}

interface CompiledSink {
  capabilities: readonly CompiledCapability[];
  budget: Required<AgentFlowBudget>;
  uses: number;
  bytes: number;
  uniqueTokens: Set<string>;
}

interface TokenOccurrence {
  token: string;
  record?: TokenRecord;
  path: string;
  keyPosition: boolean;
  capability?: CompiledCapability;
}

interface Evaluation {
  decision: AgentFlowDecision;
  occurrences: TokenOccurrence[];
  capabilityIncrements: Map<CompiledCapability, number>;
  newUniqueTokens: Set<string>;
  addedBytes: number;
}

function immutableViolation(violation: AgentFlowViolation): AgentFlowViolation {
  return Object.freeze({ ...violation });
}

function immutableBudget(usage: AgentFlowBudgetUsage): Readonly<AgentFlowBudgetUsage> {
  return Object.freeze({ ...usage });
}

function validateIdentifier(value: string, label: string): string {
  if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} must match ${IDENTIFIER.source}.`);
  }
  return value;
}

function boundedInteger(value: unknown, fallback: number, label: string, max: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || (resolved as number) < 0 || (resolved as number) > max) {
    throw new RangeError(`${label} must be an integer from 0 to ${max}.`);
  }
  return resolved as number;
}

function decodePointerSegment(segment: string): string {
  if (/~(?:[^01]|$)/.test(segment)) throw new TypeError('JSON Pointer paths may only use ~0 and ~1 escapes.');
  return segment.replace(/~1/g, '/').replace(/~0/g, '~');
}

function parsePathPattern(pattern: string): readonly string[] {
  if (typeof pattern !== 'string' || pattern.length > 512) {
    throw new TypeError('Capability paths must be strings no longer than 512 characters.');
  }
  if (pattern === '') return Object.freeze([]);
  if (!pattern.startsWith('/')) throw new TypeError('Capability paths must be JSON Pointers beginning with /.');
  const parts = pattern.slice(1).split('/').map(decodePointerSegment);
  const recursive = parts.indexOf('**');
  if (recursive !== -1 && recursive !== parts.length - 1) {
    throw new TypeError('The ** path wildcard is only valid as the final segment.');
  }
  return Object.freeze(parts);
}

function pointerSegment(value: string): string {
  return value.replace(/~/g, '~0').replace(/\//g, '~1');
}

function appendPointer(path: string, segment: string): string {
  return `${path}/${pointerSegment(segment)}`;
}

function pathMatches(pattern: readonly string[], path: readonly string[]): boolean {
  for (let index = 0; index < pattern.length; index++) {
    const expected = pattern[index];
    if (expected === '**') return true;
    if (index >= path.length || (expected !== '*' && expected !== path[index])) return false;
  }
  return pattern.length === path.length;
}

function pointerParts(path: string): readonly string[] {
  if (!path) return [];
  return path.slice(1).split('/').map(decodePointerSegment);
}

function compileSelector(values: readonly string[] | '*', label: string): ReadonlySet<string> | '*' {
  if (values === '*') return '*';
  if (!Array.isArray(values) || values.length === 0 || values.length > 256) {
    throw new TypeError(`${label} must be * or a non-empty array with at most 256 entries.`);
  }
  return new Set(values.map((value) => validateIdentifier(value, label)));
}

function matchesSelector(selector: ReadonlySet<string> | '*', value: string): boolean {
  return selector === '*' || selector.has(value);
}

function compileSinks(raw: AgentFlowOptions['sinks']): Map<string, CompiledSink> {
  const sinks = new Map<string, CompiledSink>();
  const entries = Object.entries(raw ?? {});
  if (entries.length > 256) throw new RangeError('Agent flow supports at most 256 configured sinks.');

  for (const [rawSink, policy] of entries) {
    const sink = validateIdentifier(rawSink, 'Sink id');
    if (!policy || !Array.isArray(policy.capabilities) || policy.capabilities.length > 256) {
      throw new TypeError(`Sink "${sink}" must define a capabilities array with at most 256 entries.`);
    }
    const ids = new Set<string>();
    const capabilities = policy.capabilities.map((capability): CompiledCapability => {
      const id = validateIdentifier(capability.id, 'Capability id');
      if (ids.has(id)) throw new TypeError(`Sink "${sink}" contains duplicate capability id "${id}".`);
      ids.add(id);
      if (!Array.isArray(capability.paths) || capability.paths.length === 0 || capability.paths.length > 256) {
        throw new TypeError(`Capability "${id}" must define 1 to 256 destination paths.`);
      }
      return {
        id,
        sources: compileSelector(capability.sources, `Sources for capability "${id}"`),
        detectors: compileSelector(capability.detectors ?? '*', `Detectors for capability "${id}"`),
        paths: Object.freeze(capability.paths.map(parsePathPattern)),
        maxUses: boundedInteger(capability.maxUses, Number.MAX_SAFE_INTEGER, `maxUses for capability "${id}"`, Number.MAX_SAFE_INTEGER),
        uses: 0,
      };
    });
    sinks.set(sink, {
      capabilities: Object.freeze(capabilities),
      budget: {
        maxUses: boundedInteger(policy.budget?.maxUses, Number.MAX_SAFE_INTEGER, `maxUses for sink "${sink}"`, Number.MAX_SAFE_INTEGER),
        maxUniqueValues: boundedInteger(policy.budget?.maxUniqueValues, Number.MAX_SAFE_INTEGER, `maxUniqueValues for sink "${sink}"`, Number.MAX_SAFE_INTEGER),
        maxBytes: boundedInteger(policy.budget?.maxBytes, Number.MAX_SAFE_INTEGER, `maxBytes for sink "${sink}"`, Number.MAX_SAFE_INTEGER),
      },
      uses: 0,
      bytes: 0,
      uniqueTokens: new Set(),
    });
  }
  return sinks;
}

function randomToken(records: ReadonlyMap<string, TokenRecord>): string {
  const provider = globalThis.crypto;
  if (!provider?.getRandomValues) throw new Error('Web Crypto is required to create FlareFlow placeholders.');
  for (;;) {
    const bytes = provider.getRandomValues(new Uint8Array(16));
    let hex = '';
    for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
    const token = `[FR_FLOW_${hex}]`;
    if (!records.has(token)) return token;
  }
}

function utf8Length(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}

function findTokens(value: string): string[] {
  FLOW_TOKEN.lastIndex = 0;
  return [...value.matchAll(FLOW_TOKEN)].map((match) => match[0]);
}

function isAtomicObject(value: object): boolean {
  return value instanceof Date
    || value instanceof RegExp
    || value instanceof Promise
    || value instanceof WeakMap
    || value instanceof WeakSet
    || value instanceof ArrayBuffer
    || ArrayBuffer.isView(value);
}

function collectOccurrences(input: unknown, records: ReadonlyMap<string, TokenRecord>): TokenOccurrence[] {
  const occurrences: TokenOccurrence[] = [];
  const seen = new WeakSet<object>();

  const collectString = (value: string, path: string, keyPosition = false): void => {
    for (const token of findTokens(value)) {
      occurrences.push({ token, record: records.get(token), path, keyPosition });
    }
  };

  const walk = (value: unknown, path: string): void => {
    if (typeof value === 'string') {
      collectString(value, path);
      return;
    }
    if (!value || typeof value !== 'object' || seen.has(value)) return;
    seen.add(value);

    if (value instanceof Error) {
      collectString(value.message, appendPointer(path, 'message'));
      if (typeof value.stack === 'string') collectString(value.stack, appendPointer(path, 'stack'));
    }
    if (value instanceof URL || value instanceof URLSearchParams) {
      collectString(value.toString(), path);
      return;
    }
    if (isAtomicObject(value)) return;
    if (value instanceof Map) {
      let index = 0;
      for (const [key, entry] of value) {
        const keyPath = appendPointer(path, `<map-key:${index}>`);
        if (typeof key === 'string') collectString(key, keyPath, true);
        else walk(key, keyPath);
        walk(entry, appendPointer(path, `<map-value:${index}>`));
        index++;
      }
      return;
    }
    if (value instanceof Set) {
      let index = 0;
      for (const entry of value) walk(entry, appendPointer(path, `<set:${index++}>`));
      return;
    }
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index++) {
        if (Object.prototype.hasOwnProperty.call(value, index)) walk(value[index], appendPointer(path, String(index)));
      }
    }

    const arrayIndexes = Array.isArray(value) ? new Set(Object.keys(value).filter((key) => /^\d+$/.test(key))) : undefined;
    let propertyIndex = 0;
    for (const key of Reflect.ownKeys(value)) {
      if (key === 'length' || (typeof key === 'string' && arrayIndexes?.has(key))) continue;
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable || !('value' in descriptor)) continue;
      const keyTokens = typeof key === 'string' ? findTokens(key) : [];
      const segment = typeof key === 'symbol'
        ? `[${String(key)}]`
        : keyTokens.length > 0
          ? `<object-key:${propertyIndex}>`
          : key;
      const child = appendPointer(path, segment);
      for (const token of keyTokens) {
        occurrences.push({ token, record: records.get(token), path: child, keyPosition: true });
      }
      walk(descriptor.value, child);
      propertyIndex++;
    }
  };

  walk(input, '');
  return occurrences;
}

function capabilityFor(
  sink: CompiledSink | undefined,
  occurrence: TokenOccurrence,
): CompiledCapability | undefined {
  if (!sink || !occurrence.record || occurrence.keyPosition) return undefined;
  const path = pointerParts(occurrence.path);
  return sink.capabilities.find((capability) =>
    matchesSelector(capability.sources, occurrence.record!.source)
      && matchesSelector(capability.detectors, occurrence.record!.detector)
      && capability.paths.some((pattern) => pathMatches(pattern, path)));
}

/**
 * FlareFlow: deterministic, model-independent information-flow enforcement for
 * tool-using agents. The trusted runtime labels sources and sinks; model output
 * can carry opaque placeholders but cannot grant itself permission to restore
 * them.
 */
export function createAgentFlow(options: AgentFlowOptions = {}): AgentFlow {
  const now = options.now ?? Date.now;
  const limits: AgentFlowLimits = {
    tokenTtlMs: boundedInteger(options.limits?.tokenTtlMs, DEFAULT_TOKEN_TTL_MS, 'tokenTtlMs', 30 * 24 * 60 * 60 * 1000),
    maxMappings: boundedInteger(options.limits?.maxMappings, DEFAULT_MAX_MAPPINGS, 'maxMappings', 1_000_000),
    maxEvents: boundedInteger(options.limits?.maxEvents, DEFAULT_MAX_EVENTS, 'maxEvents', 100_000),
  };
  if (limits.tokenTtlMs === 0) throw new RangeError('tokenTtlMs must be at least 1 millisecond.');
  if (limits.maxMappings === 0) throw new RangeError('maxMappings must be at least 1.');

  const sinks = compileSinks(options.sinks);
  const records = new Map<string, TokenRecord>();
  const reverse = new Map<string, Map<string, Map<string, string>>>();
  const events: AgentFlowEvent[] = [];
  let activeSource: string | undefined;
  let activeMinted: string[] | undefined;
  let activeOccurrences = 0;
  let activeDetectors: Set<string> | undefined;
  let activeOperation: string | undefined;

  const runOperation = <T>(name: string, operation: () => T): T => {
    if (activeOperation !== undefined) {
      throw new Error(`FlareFlow ${name}() must not run re-entrantly during ${activeOperation}().`);
    }
    activeOperation = name;
    try {
      return operation();
    } finally {
      activeOperation = undefined;
    }
  };

  const retainEvent = (event: AgentFlowEvent): void => {
    if (limits.maxEvents === 0) return;
    if (events.length >= limits.maxEvents) events.splice(0, events.length - limits.maxEvents + 1);
    events.push(event);
  };

  const deliverEvent = (event: AgentFlowEvent): AgentFlowEvent => {
    const frozen = Object.freeze(event);
    options.onEvent?.(frozen);
    return frozen;
  };

  const recordEvent = (event: AgentFlowEvent): void => {
    // Audit callbacks run before an operation commits. A failing audit sink
    // therefore fails closed instead of returning restored data without a log.
    retainEvent(deliverEvent(event));
  };

  const removeToken = (token: string): boolean => {
    const record = records.get(token);
    if (!record) return false;
    records.delete(token);
    const byDetector = reverse.get(record.source);
    const byValue = byDetector?.get(record.detector);
    if (byValue?.get(record.original) === token) byValue.delete(record.original);
    if (byValue?.size === 0) byDetector?.delete(record.detector);
    if (byDetector?.size === 0) reverse.delete(record.source);
    return true;
  };

  const sweep = (): void => {
    const time = now();
    for (const [token, record] of records) {
      if (record.expiresAt <= time) removeToken(token);
    }
  };

  const mint = (original: string, detector: string): string => {
    if (!activeSource || !activeMinted || !activeDetectors) {
      throw new Error('FlareFlow placeholder minting escaped its protected source transaction.');
    }
    activeOccurrences++;
    activeDetectors.add(detector);
    let byDetector = reverse.get(activeSource);
    if (!byDetector) {
      byDetector = new Map();
      reverse.set(activeSource, byDetector);
    }
    let byValue = byDetector.get(detector);
    if (!byValue) {
      byValue = new Map();
      byDetector.set(detector, byValue);
    }
    const existing = byValue.get(original);
    if (existing && records.has(existing)) return existing;
    if (records.size >= limits.maxMappings) {
      throw new AgentFlowLimitError(`FlareFlow exceeded its ${limits.maxMappings} live mapping limit.`);
    }
    const token = randomToken(records);
    const createdAt = now();
    records.set(token, {
      token,
      original,
      source: activeSource,
      detector,
      createdAt,
      expiresAt: createdAt + limits.tokenTtlMs,
      uses: 0,
    });
    byValue.set(original, token);
    activeMinted.push(token);
    return token;
  };

  const policy = compilePolicy({
    ...(options.policy ?? {}),
    mask: ({ value, detector }) => mint(value, detector.id),
  });

  const evaluate = (rawSink: string, value: unknown): Evaluation => {
    const sinkId = validateIdentifier(rawSink, 'Sink id');
    sweep();
    const sink = sinks.get(sinkId);
    const occurrences = collectOccurrences(value, records);
    const violations: AgentFlowViolation[] = [];
    const capabilityIncrements = new Map<CompiledCapability, number>();
    const newUniqueTokens = new Set<string>();
    let restorable = 0;
    let addedBytes = 0;

    for (const occurrence of occurrences) {
      const record = occurrence.record;
      if (!record) {
        violations.push(immutableViolation({
          reason: 'unknown_token',
          sink: sinkId,
          path: occurrence.path,
        }));
        continue;
      }
      if (occurrence.keyPosition) {
        violations.push(immutableViolation({
          reason: 'key_position',
          sink: sinkId,
          path: occurrence.path,
          source: record.source,
          detector: record.detector,
        }));
        continue;
      }
      const capability = capabilityFor(sink, occurrence);
      if (!capability) {
        violations.push(immutableViolation({
          reason: 'capability_denied',
          sink: sinkId,
          path: occurrence.path,
          source: record.source,
          detector: record.detector,
        }));
        continue;
      }
      occurrence.capability = capability;
      const pending = (capabilityIncrements.get(capability) ?? 0) + 1;
      capabilityIncrements.set(capability, pending);
      if (capability.uses + pending > capability.maxUses) {
        violations.push(immutableViolation({
          reason: 'capability_budget_exceeded',
          sink: sinkId,
          path: occurrence.path,
          source: record.source,
          detector: record.detector,
          capability: capability.id,
          limit: 'maxUses',
        }));
        continue;
      }
      restorable++;
      addedBytes += utf8Length(record.original);
      if (!sink?.uniqueTokens.has(record.token)) newUniqueTokens.add(record.token);
    }

    const projected: AgentFlowBudgetUsage = {
      uses: (sink?.uses ?? 0) + restorable,
      uniqueValues: (sink?.uniqueTokens.size ?? 0) + newUniqueTokens.size,
      bytes: (sink?.bytes ?? 0) + addedBytes,
    };
    if (sink && restorable > 0) {
      const checks: Array<[keyof AgentFlowBudget, number, number]> = [
        ['maxUses', projected.uses, sink.budget.maxUses],
        ['maxUniqueValues', projected.uniqueValues, sink.budget.maxUniqueValues],
        ['maxBytes', projected.bytes, sink.budget.maxBytes],
      ];
      for (const [limit, projectedValue, maximum] of checks) {
        if (projectedValue > maximum) {
          violations.push(immutableViolation({
            reason: 'sink_budget_exceeded',
            sink: sinkId,
            path: '',
            limit,
          }));
        }
      }
    }

    const decision: AgentFlowDecision = Object.freeze({
      allowed: violations.length === 0,
      sink: sinkId,
      occurrences: occurrences.length,
      restorable,
      violations: Object.freeze(violations),
      projectedBudget: immutableBudget(projected),
    });
    return { decision, occurrences, capabilityIncrements, newUniqueTokens, addedBytes };
  };

  return {
    protectForModel<T>(rawSource: string, value: T): T {
      return runOperation('protectForModel', () => {
        const source = validateIdentifier(rawSource, 'Source id');
        sweep();
        activeSource = source;
        activeMinted = [];
        activeOccurrences = 0;
        activeDetectors = new Set();
        try {
          const protectedValue = policy.redact(value);
          if (activeOccurrences > 0) {
            recordEvent({
              type: 'protected',
              time: now(),
              source,
              occurrences: activeOccurrences,
              detectors: Object.freeze([...activeDetectors].sort()),
              liveMappings: records.size,
            });
          }
          return protectedValue;
        } catch (error) {
          for (const token of activeMinted) removeToken(token);
          throw error;
        } finally {
          activeSource = undefined;
          activeMinted = undefined;
          activeDetectors = undefined;
          activeOccurrences = 0;
        }
      });
    },

    inspectForSink(rawSink: string, value: unknown): AgentFlowDecision {
      return runOperation('inspectForSink', () => evaluate(rawSink, value).decision);
    },

    authorizeForSink<T>(rawSink: string, value: T): T {
      return runOperation('authorizeForSink', () => {
        const evaluation = evaluate(rawSink, value);
        const { decision } = evaluation;
        if (!decision.allowed) {
          recordEvent({
            type: 'blocked',
            time: now(),
            sink: decision.sink,
            occurrences: decision.occurrences,
            violations: decision.violations,
          });
          throw new AgentFlowBlockedError(decision);
        }
        if (decision.occurrences === 0) return value;

        const sink = sinks.get(decision.sink)!;
        const capabilities = new Set<string>();
        for (const occurrence of evaluation.occurrences) {
          if (occurrence.capability) capabilities.add(occurrence.capability.id);
        }
        const entries = evaluation.occurrences.flatMap((occurrence): Array<[string, string]> =>
          occurrence.record && occurrence.capability
            ? [[occurrence.token, occurrence.record.original]]
            : []);
        // Clone and restore before either the audit event or budget state commits.
        // Exotic graph descriptors may reject cloning; such a failure must not
        // consume an otherwise valid capability.
        const restored = restore(value, new Map(entries));
        recordEvent({
          type: 'authorized',
          time: now(),
          sink: decision.sink,
          occurrences: decision.restorable,
          capabilities: Object.freeze([...capabilities].sort()),
          budget: decision.projectedBudget,
        });
        for (const [capability, increment] of evaluation.capabilityIncrements) {
          capability.uses += increment;
        }
        sink.uses += decision.restorable;
        sink.bytes += evaluation.addedBytes;
        for (const token of evaluation.newUniqueTokens) sink.uniqueTokens.add(token);
        for (const occurrence of evaluation.occurrences) {
          if (occurrence.record && occurrence.capability) occurrence.record.uses++;
        }
        return restored;
      });
    },

    restoreForApp<T>(value: T): T {
      return runOperation('restoreForApp', () => {
        sweep();
        return restore(value, new Map([...records].map(([token, record]) => [token, record.original])));
      });
    },

    revokeSource(rawSource: string): number {
      return runOperation('revokeSource', () => {
        const source = validateIdentifier(rawSource, 'Source id');
        sweep();
        const tokens = [...records]
          .filter(([, record]) => record.source === source)
          .map(([token]) => token);
        recordEvent({ type: 'revoked', time: now(), source, mappings: tokens.length });
        for (const token of tokens) removeToken(token);
        return tokens.length;
      });
    },

    reset(): void {
      runOperation('reset', () => {
        sweep();
        const removed = records.size;
        const resetEvent = deliverEvent({ type: 'revoked', time: now(), mappings: removed });
        records.clear();
        reverse.clear();
        for (const sink of sinks.values()) {
          sink.uses = 0;
          sink.bytes = 0;
          sink.uniqueTokens.clear();
          for (const capability of sink.capabilities) capability.uses = 0;
        }
        events.length = 0;
        retainEvent(resetEvent);
      });
    },

    snapshot(): AgentFlowSnapshot {
      return runOperation('snapshot', () => {
        sweep();
        const sources: Record<string, number> = {};
        for (const record of records.values()) sources[record.source] = (sources[record.source] ?? 0) + 1;
        const sinkUsage: Record<string, Readonly<AgentFlowBudgetUsage>> = {};
        for (const [id, sink] of sinks) {
          sinkUsage[id] = immutableBudget({
            uses: sink.uses,
            uniqueValues: sink.uniqueTokens.size,
            bytes: sink.bytes,
          });
        }
        return Object.freeze({
          liveMappings: records.size,
          sources: Object.freeze(sources),
          sinks: Object.freeze(sinkUsage),
          events: Object.freeze([...events]),
        });
      });
    },

    get size() {
      return runOperation('size', () => {
        sweep();
        return records.size;
      });
    },
  };
}
