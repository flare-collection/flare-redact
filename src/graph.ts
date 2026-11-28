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
type SensitiveValueMapper = (key: string, value: string) => string;

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
  mapSensitiveValue?: SensitiveValueMapper,
): unknown {
  const seen = new WeakMap<object, unknown>();

  const walk = (value: unknown): unknown => {
    if (typeof value === 'string') return mapString(value);
    if (!value || typeof value !== 'object') return value;
    if (value instanceof PathHit) return value.value;
    const cached = seen.get(value);
    if (cached !== undefined) return cached;

    if (value instanceof Error) {
      const out = Object.create(Object.getPrototypeOf(value)) as Error;
      seen.set(value, out);
      Object.defineProperties(out, {
        name: { value: value.name, writable: true, configurable: true },
        message: { value: mapString(value.message), writable: true, configurable: true },
        ...(typeof value.stack === 'string'
          ? { stack: { value: mapString(value.stack), writable: true, configurable: true } }
          : {}),
      });
      copyEnumerable(value, out, walk, mapSensitiveValue);
      for (const [key, descriptor] of errorChain(value)) {
        Object.defineProperty(out, key, { ...descriptor, value: walk(descriptor.value) });
      }
      return out;
    }

    if (value instanceof URL) {
      const out = new URL(mapString(value.toString()));
      seen.set(value, out);
      return out;
    }

    if (value instanceof URLSearchParams) {
      const out = new URLSearchParams(mapString(value.toString()));
      seen.set(value, out);
      return out;
    }

    if (isAtomicObject(value)) return value;

    if (value instanceof Map) {
      const out = new Map<unknown, unknown>();
      seen.set(value, out);
      for (const [key, entry] of value) out.set(walk(key), walk(entry));
      return out;
    }

    if (value instanceof Set) {
      const out = new Set<unknown>();
      seen.set(value, out);
      for (const entry of value) out.add(walk(entry));
      return out;
    }

    if (Array.isArray(value)) {
      const out: unknown[] = new Array(value.length);
      seen.set(value, out);
      for (let i = 0; i < value.length; i++) {
        if (Object.prototype.hasOwnProperty.call(value, i)) out[i] = walk(value[i]);
      }
      copyEnumerable(value, out, walk, mapSensitiveValue, true);
      return out;
    }

    const out = Object.create(Object.getPrototypeOf(value)) as Record<PropertyKey, unknown>;
    seen.set(value, out);
    copyEnumerable(value, out, walk, mapSensitiveValue);
    return out;
  };

  return walk(input);
}

const INDEX = /^(?:0|[1-9][0-9]*)$/;

function copyEnumerable(
  source: object,
  target: object,
  walk: (value: unknown) => unknown,
  mapSensitiveValue?: SensitiveValueMapper,
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
    const next = typeof key === 'string' && typeof raw === 'string' && mapSensitiveValue
      ? mapSensitiveValue(key, raw)
      : walk(raw);
    if (plain && key !== '__proto__' && descriptor.writable && descriptor.configurable) {
      (target as Record<PropertyKey, unknown>)[key] = next;
    } else {
      Object.defineProperty(target, key, { ...descriptor, value: next });
    }
  }
}
