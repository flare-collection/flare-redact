/**
 * A snapshot serializer for Vitest and Jest: secrets and personal data are
 * masked before a snapshot is written, so a token that reached a rendered
 * component, an error message or a recorded response is never committed.
 *
 * Vitest: `snapshotSerializers: ['flare-redact/snapshot']` in the config, or
 * `expect.addSnapshotSerializer(createSnapshotSerializer(options))` in a test.
 */
import { compilePolicy, type RedactOptions } from './index.js';

type Printer = (value: unknown, ...rest: unknown[]) => string;

export interface SnapshotSerializer {
  test(value: unknown): boolean;
  serialize(value: unknown, config: unknown, indentation: string, depth: number, refs: unknown, printer: Printer): string;
}

/**
 * A serializer that takes over only values that need masking, and hands the
 * masked copy back to the snapshot printer, so the usual formatting is kept
 * and clean values are untouched.
 */
export function createSnapshotSerializer(opts: RedactOptions = {}): SnapshotSerializer {
  const policy = compilePolicy(opts);
  // Masked output goes back through the printer, which asks `test` again; a
  // mask that still looks like a finding must not be masked in a loop.
  const masked = new WeakSet<object>();
  const maskedText = new Set<string>();
  return {
    test: (value) => {
      if (typeof value === 'string') return !maskedText.has(value) && !policy.isClean(value);
      if (typeof value !== 'object' || value === null || masked.has(value)) return false;
      return !policy.isClean(value);
    },
    serialize: (value, config, indentation, depth, refs, printer) => {
      const out = policy.redact(value);
      if (typeof out === 'string') maskedText.add(out);
      else if (typeof out === 'object' && out !== null) masked.add(out);
      try {
        return printer(out, config, indentation, depth, refs);
      } finally {
        if (typeof out === 'string') maskedText.delete(out);
      }
    },
  };
}

const serializer = createSnapshotSerializer();

export const test = serializer.test;
export const serialize = serializer.serialize;
export default serializer;
