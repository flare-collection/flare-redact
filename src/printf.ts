// Shared by wrapConsole and shadowConsole. Not exported from the package.
const BUILT_IN_TO_STRING = new Set<unknown>([
  Object.prototype.toString,
  Array.prototype.toString,
  Error.prototype.toString,
  Date.prototype.toString,
  RegExp.prototype.toString,
  Function.prototype.toString,
  Number.prototype.toString,
  Boolean.prototype.toString,
  String.prototype.toString,
  Symbol.prototype.toString,
  BigInt.prototype.toString,
]);

/**
 * `console.log('%s', value)` calls a user-defined `toString()` while it
 * formats, after the arguments were redacted, so the text that method returns
 * would be printed as it is. Call it first, for exactly the arguments a `%s`
 * consumes, so the redactor sees the text that will be printed.
 */
export function printfStrings(args: unknown[]): unknown[] {
  const [format] = args;
  if (typeof format !== 'string' || args.length < 2 || !format.includes('%s')) return args;
  const out = args.slice();
  let next = 1;
  for (let i = 0; i < format.length - 1 && next < args.length; i++) {
    if (format[i] !== '%') continue;
    const spec = format.charAt(++i);
    if (!'sdifjoOc'.includes(spec)) continue; // %% and unknown specifiers take no argument
    const value = args[next];
    if (spec === 's' && typeof value === 'object' && value !== null) {
      const toString = (value as { toString?: unknown }).toString;
      if (typeof toString === 'function' && !BUILT_IN_TO_STRING.has(toString)) {
        try {
          out[next] = String(value);
        } catch {
          // A throwing toString prints nothing secret; leave it to the console.
        }
      }
    }
    next++;
  }
  return out;
}
