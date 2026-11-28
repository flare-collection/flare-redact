type StringMapper = (value: string) => string;

/**
 * The parts of an error chain that JavaScript keeps non-enumerable: `cause`
 * and AggregateError's `errors`. A logger prints them, so a walk that only
 * follows enumerable properties would drop the real reason for a failure.
 */
export function errorChain(error: Error): Array<[string, PropertyDescriptor]> {
  const out: Array<[string, PropertyDescriptor]> = [];
  for (const key of ['cause', 'errors']) {
    const descriptor = Object.getOwnPropertyDescriptor(error, key);
    if (descriptor && !descriptor.enumerable && 'value' in descriptor) out.push([key, descriptor]);
  }
  return out;
}
/**
 * How a walk treats values under a sensitive key (spec section 9). Everything
 * reachable from such a value is sensitive: strings, numbers and binary data
 * are replaced whole, at any depth, whatever the nested member names are.
 */
export interface SensitiveRule {
  /** Whether a member name (or a string Map key) is sensitive. */
  matches(key: string): boolean;
  /** The replacement for a sensitive value's text, or undefined when the allowlist keeps it. */
  replace(text: string): string | undefined;
}

/** The text a sensitive number stands for: ECMAScript Number::toString (or the bigint digits). */
export function numberText(value: number | bigint): string {
  return String(value);
}

/** The text sensitive binary data stands for: its bytes in lowercase hex. */
export function bytesText(value: ArrayBuffer | ArrayBufferView): string {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
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

/**
 * Clone and transform a JavaScript object graph without losing cycles, shared
 * references, Map/Set contents, symbol metadata, or custom prototypes.
 */
/**
 * A value that a path rule already replaced. The walk that follows unwraps it
 * without scanning it again, so a replacement is never redacted twice.
 */
export class PathHit {
  constructor(readonly value: unknown) {}
}

export function mapGraph(
  input: unknown,
  mapString: StringMapper,
  rule?: SensitiveRule,
  startHot = false,
): unknown {
  // A value reached under a sensitive key is cloned separately from the same
  // value reached elsewhere, so a shared reference can never carry an unmasked
  // copy into a sensitive position or a masked copy out of one.
  const seen = new WeakMap<object, unknown>();
  const seenHot = new WeakMap<object, unknown>();

  const hotText = (text: string): string => rule?.replace(text) ?? mapString(text);

  const walk = (value: unknown, hot = false): unknown => {
    if (typeof value === 'string') return hot ? hotText(value) : mapString(value);
    if (hot && (typeof value === 'number' || typeof value === 'bigint')) {
      return rule?.replace(numberText(value)) ?? value;
    }
    if (!value || typeof value !== 'object') return value;
    if (value instanceof PathHit) return value.value;
    const cache = hot ? seenHot : seen;
    const cached = cache.get(value);
    if (cached !== undefined) return cached;

    if (hot && (value instanceof ArrayBuffer || ArrayBuffer.isView(value))) {
      const out = rule?.replace(bytesText(value)) ?? value;
      cache.set(value, out);
      return out;
    }

    if (value instanceof Error) {
      const out = Object.create(Object.getPrototypeOf(value)) as Error;
      cache.set(value, out);
      const text = hot ? hotText : mapString;
      Object.defineProperties(out, {
        name: { value: value.name, writable: true, configurable: true },
        message: { value: text(value.message), writable: true, configurable: true },
        ...(typeof value.stack === 'string'
          ? { stack: { value: text(value.stack), writable: true, configurable: true } }
          : {}),
      });
      copyEnumerable(value, out, walk, hot, rule);
      for (const [key, descriptor] of errorChain(value)) {
        Object.defineProperty(out, key, { ...descriptor, value: walk(descriptor.value, hot) });
      }
      return out;
    }

    if (value instanceof URL || value instanceof URLSearchParams) {
      // A masked URL is no longer a URL, so a sensitive one becomes its masked text.
      const out = hot
        ? hotText(value.toString())
        : value instanceof URL
          ? new URL(mapString(value.toString()))
          : new URLSearchParams(mapString(value.toString()));
      cache.set(value, out);
      return out;
    }

    if (isAtomicObject(value)) return value;

    if (value instanceof Map) {
      const out = new Map<unknown, unknown>();
      cache.set(value, out);
      for (const [key, entry] of value) {
        const sensitive = hot || (typeof key === 'string' && rule !== undefined && rule.matches(key));
        out.set(walk(key), walk(entry, sensitive));
      }
      return out;
    }

    if (value instanceof Set) {
      const out = new Set<unknown>();
      cache.set(value, out);
      for (const entry of value) out.add(walk(entry, hot));
      return out;
    }

    if (Array.isArray(value)) {
      const out: unknown[] = new Array(value.length);
      cache.set(value, out);
      for (let i = 0; i < value.length; i++) {
        if (Object.prototype.hasOwnProperty.call(value, i)) out[i] = walk(value[i], hot);
      }
      copyEnumerable(value, out, walk, hot, rule, true);
      return out;
    }

    const out = Object.create(Object.getPrototypeOf(value)) as Record<PropertyKey, unknown>;
    cache.set(value, out);
    copyEnumerable(value, out, walk, hot, rule);
    return out;
  };

  return walk(input, startHot && rule !== undefined);
}

const INDEX = /^(?:0|[1-9][0-9]*)$/;

function copyEnumerable(
  source: object,
  target: object,
  walk: (value: unknown, hot?: boolean) => unknown,
  hot: boolean,
  rule?: SensitiveRule,
  skipIndices = false,
): void {
  // A plain target has no setters except __proto__, so an ordinary data
  // property can be assigned instead of defined, which is several times faster.
  const proto = Object.getPrototypeOf(target);
  const plain = proto === Object.prototype || proto === null;
  for (const key of Reflect.ownKeys(source)) {
    if (skipIndices && typeof key === 'string' && (key === 'length' || INDEX.test(key))) continue;
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (!descriptor?.enumerable || !('value' in descriptor)) continue;
    const raw = descriptor.value as unknown;
    const next = walk(raw, hot || (typeof key === 'string' && rule !== undefined && rule.matches(key)));
    if (plain && key !== '__proto__' && descriptor.writable && descriptor.configurable) {
      (target as Record<PropertyKey, unknown>)[key] = next;
    } else {
      Object.defineProperty(target, key, { ...descriptor, value: next });
    }
  }
}
