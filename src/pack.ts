/**
 * FRS-1 detector packs.
 *
 * A pack is a JSON description of a detector set, written in a restricted
 * pattern subset that compiles to the same automaton in JavaScript, Python, Go
 * and Rust. Loading one here turns it into ordinary `Detector` objects, so a
 * pack behaves exactly like a built-in detector — including in overlap
 * resolution, `enable`/`disable`, vaults and every adapter.
 *
 *   import { loadPack } from 'flare-redact/pack';
 *   import { redact } from 'flare-redact';
 *
 *   const pack = loadPack(JSON.parse(await readFile('detectors/acme.json', 'utf8')));
 *   redact(text, { detectors: pack.detectors });
 *
 * The loader is strict on purpose. A pack that uses a construct this engine
 * cannot execute exactly as `spec/SPEC.md` describes — a lookahead, a `\d` whose
 * meaning differs between languages, a checksum this build does not know — fails
 * to load. Failing open is how a redactor leaks.
 */

import {
  entropy,
  keepLast,
  keepPrefix,
  phoneValid,
  type Detector,
} from './detectors.js';
import {
  aadhaarValid,
  abaValid,
  bsnValid,
  cnResidentIdValid,
  codiceFiscaleValid,
  cpfValid,
  deTaxIdValid,
  dniValid,
  frNirValid,
  ibanValid,
  jpMyNumberValid,
  luhnCheck,
  nhsValid,
  peselValid,
  ssnValid,
  tcknValid,
  tfnValid,
  vinValid,
} from './checksums.js';
import { FlareRedactError, type Risk } from './engine.js';

export const SPEC_REVISION = 'FRS-1';

export interface PackDocument {
  spec: string;
  id: string;
  version: string;
  title?: string;
  description?: string;
  license?: string;
  confidenceModel?: {
    version: number;
    features: string[];
    weights: number[];
    bias: number;
  };
  detectors: PackDetector[];
}

export interface PackDetector {
  id: string;
  label: string;
  why: string;
  pattern: string;
  flags?: string;
  capture?: number;
  boundary?: { before?: string; after?: string };
  reject?: string[];
  validators?: Array<Record<string, unknown> & { name: string }>;
  mask: Record<string, unknown> & { type: string };
  default: boolean;
  tags?: string[];
  risk: Risk;
  priority?: number;
  confidence: number;
  refine?: boolean;
  prefilter?: string[];
  context?: { positive?: string; negative?: string; window?: number };
}

export interface Pack {
  id: string;
  version: string;
  title: string;
  detectors: Detector[];
  byId: Map<string, Detector>;
  confidenceModel?: PackDocument['confidenceModel'];
}

export class PackError extends FlareRedactError {
  constructor(message: string) {
    super('ERR_PACK_INVALID', message);
    this.name = 'PackError';
  }
}

const ASCII = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
};

function charSet(...parts: string[]): ReadonlySet<string> {
  return new Set(parts.join(''));
}

/** Neighbour characters a captured span may not touch. See `spec/SPEC.md` §3.1. */
export const BOUNDARY_CLASSES: Readonly<Record<string, ReadonlySet<string>>> = {
  word: charSet(ASCII.lower, ASCII.upper, ASCII.digits, '_'),
  alnum: charSet(ASCII.lower, ASCII.upper, ASCII.digits),
  digit: charSet(ASCII.digits),
  hex: charSet(ASCII.digits, 'abcdefABCDEF'),
  base64: charSet(ASCII.lower, ASCII.upper, ASCII.digits, '+/='),
  base64url: charSet(ASCII.lower, ASCII.upper, ASCII.digits, '_+/=-'),
  word_dash: charSet(ASCII.lower, ASCII.upper, ASCII.digits, '_-'),
};

const RISKS: readonly string[] = ['low', 'medium', 'high', 'critical'];

// Engine-side expansion of the two portable tokens. `[\s\S]` is total, so it
// means "any character" no matter how `\s` is defined; `\p{L}` needs the `u`
// flag, which is why only patterns that use it are compiled with it.
const ANY = '[\\s\\S]';
const LETTER = '\\p{L}';

function expandTokens(pattern: string): string {
  return pattern.split('{{ANY}}').join(ANY).split('{{L}}').join(LETTER);
}

const FORBIDDEN_ESCAPES = new Set('bBdDwWsSpP123456789AZzGkK'.split(''));

/** Reject constructs whose meaning differs between the FRS-1 target engines. */
function assertPortable(pattern: string, where: string): void {
  let index = 0;
  let inClass = false;
  while (index < pattern.length) {
    const ch = pattern[index]!;
    if (ch === '\\') {
      const next = pattern[index + 1];
      if (next === undefined) throw new PackError(`${where}: pattern ends with a dangling backslash`);
      if (FORBIDDEN_ESCAPES.has(next)) {
        throw new PackError(
          `${where}: '\\${next}' is not portable across FRS-1 engines; ` +
          'write the character class out, or use {{ANY}} / {{L}}',
        );
      }
      index += 2;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      index++;
      continue;
    }
    if (ch === '[') {
      index++;
      if (pattern[index] === '^') index++;
      if (pattern[index] === ']') index++;
      inClass = true;
      continue;
    }
    if (ch === '(' && pattern[index + 1] === '?') {
      const kind = pattern[index + 2];
      if (kind !== ':') {
        throw new PackError(
          `${where}: '(?${kind ?? ''}' is not portable across FRS-1 engines; ` +
          "only '(...)' and '(?:...)' groups are allowed",
        );
      }
      index += 3;
      continue;
    }
    if (ch === '^' || ch === '$') {
      throw new PackError(`${where}: anchors are not allowed inside a detector pattern`);
    }
    index++;
  }
  if (inClass) throw new PackError(`${where}: unterminated character class`);
}

interface CompileOptions {
  flags?: string;
  where: string;
  portable?: boolean;
  anchor?: 'prefix' | 'full';
}

function compile(pattern: string, { flags = '', where, portable = true, anchor }: CompileOptions): RegExp {
  if (portable) assertPortable(pattern, where);
  const expanded = expandTokens(pattern);
  const body = anchor === 'prefix' ? `^(?:${expanded})` : anchor === 'full' ? `^(?:${expanded})$` : expanded;
  // `u` is only added when the pattern needs it: it also tightens escape rules,
  // and a pack author should not have to satisfy them for patterns that never
  // mention a Unicode property.
  const jsFlags = (flags.includes('i') ? 'i' : '') + (expanded.includes('\\p{') ? 'u' : '') + (anchor ? '' : 'g');
  try {
    return new RegExp(body, jsFlags);
  } catch (error) {
    throw new PackError(`${where}: invalid pattern (${(error as Error).message})`);
  }
}

/** Substitute `$1`–`$9` (and `$$`) in a mask replacement template. */
function expandReplacement(template: string, match: RegExpExecArray): string {
  let out = '';
  for (let index = 0; index < template.length; index++) {
    const ch = template[index]!;
    const next = template[index + 1];
    if (ch === '$' && next === '$') {
      out += '$';
      index++;
      continue;
    }
    if (ch === '$' && next !== undefined && next >= '1' && next <= '9') {
      out += match[Number(next)] ?? '';
      index++;
      continue;
    }
    out += ch;
  }
  return out;
}

function buildMask(spec: PackDetector['mask'], where: string): (value: string) => string {
  switch (spec.type) {
    case 'fixed': {
      const text = String(spec.text ?? '***');
      return () => text;
    }
    case 'keepPrefix':
      return keepPrefix(Number(spec.n));
    case 'keepLast':
      return keepLast(Number(spec.n));
    case 'keepThroughSeparator': {
      const separator = String(spec.separator);
      const count = Number(spec.count);
      return (value) => {
        let index = -separator.length;
        for (let n = 0; n < count; n++) {
          index = value.indexOf(separator, index + separator.length);
          if (index < 0) return '***';
        }
        return value.slice(0, index + separator.length) + '***';
      };
    }
    case 'replace': {
      const re = compile(String(spec.pattern), {
        where: `${where} mask`,
        portable: false,
        anchor: 'full',
        flags: String(spec.flags ?? ''),
      });
      const replacement = String(spec.replacement);
      return (value) => {
        re.lastIndex = 0;
        const match = re.exec(value);
        return match ? expandReplacement(replacement, match) : value;
      };
    }
    default:
      throw new PackError(`${where}: unknown mask type ${JSON.stringify(spec.type)}`);
  }
}

const NAMED_VALIDATORS: Readonly<Record<string, (value: string) => boolean>> = {
  phone: phoneValid,
  iban: ibanValid,
  tckn: tcknValid,
  cpf: cpfValid,
  dni: dniValid,
  bsn: bsnValid,
  pesel: peselValid,
  de_tax_id: deTaxIdValid,
  codice_fiscale: codiceFiscaleValid,
  fr_nir: frNirValid,
  aadhaar: aadhaarValid,
  tfn: tfnValid,
  cn_resident_id: cnResidentIdValid,
  jp_my_number: jpMyNumberValid,
  us_ssn: ssnValid,
  aba: abaValid,
  nhs: nhsValid,
  vin: vinValid,
};

const DIGITS_ONLY = /[^0-9]/g;

function buildValidator(spec: { name: string } & Record<string, unknown>, where: string): (value: string) => boolean {
  if (spec.name === 'normalized_match') {
    const strip = spec.strip
      ? compile(String(spec.strip), { where: `${where} validator strip`, portable: false })
      : undefined;
    const target = compile(String(spec.pattern), { where: `${where} validator`, portable: false, anchor: 'full' });
    return (value) => {
      const candidate = strip ? value.replace(strip, '') : value;
      target.lastIndex = 0;
      return target.test(candidate);
    };
  }
  if (spec.name === 'luhn') {
    const min = Number(spec.minDigits ?? 2);
    const max = Number(spec.maxDigits ?? 0);
    return (value) => {
      const digits = value.replace(DIGITS_ONLY, '');
      if (digits.length < min) return false;
      if (max && digits.length > max) return false;
      return luhnCheck(digits);
    };
  }
  if (spec.name === 'entropy') {
    const min = Number(spec.min);
    return (value) => entropy(value) >= min;
  }
  const named = NAMED_VALIDATORS[spec.name];
  if (!named) {
    throw new PackError(
      `${where}: unknown validator ${JSON.stringify(spec.name)}. Refusing to load a pack ` +
      'whose checks this engine cannot perform.',
    );
  }
  return named;
}

function boundaryClass(name: string | undefined, where: string): ReadonlySet<string> | undefined {
  if (name === undefined) return undefined;
  const members = BOUNDARY_CLASSES[name];
  if (!members) throw new PackError(`${where}: unknown boundary class ${JSON.stringify(name)}`);
  return members;
}

function toDetector(spec: PackDetector): Detector {
  for (const field of ['id', 'label', 'why', 'pattern', 'mask', 'default', 'risk', 'confidence'] as const) {
    if (spec[field] === undefined) throw new PackError(`detector is missing required field ${JSON.stringify(field)}`);
  }
  const where = `detector ${JSON.stringify(spec.id)}`;
  if (!RISKS.includes(spec.risk)) throw new PackError(`${where}: risk must be one of ${RISKS.join(', ')}`);
  if (!(spec.confidence >= 0 && spec.confidence <= 1)) {
    throw new PackError(`${where}: confidence must be between 0 and 1`);
  }
  const flags = spec.flags ?? '';
  if (flags !== '' && flags !== 'i') throw new PackError(`${where}: only the 'i' flag is portable`);

  const pattern = compile(spec.pattern, { flags, where });
  pattern.lastIndex = 0;
  const empty = new RegExp(pattern.source, pattern.flags.replace('g', ''));
  if (empty.test('')) throw new PackError(`${where}: pattern matches the empty string`);

  // Count capture groups by making the whole pattern optional and matching the
  // empty string: the result array is one entry per group, plus the whole match.
  const capture = spec.capture ?? 0;
  const probe = new RegExp(`(?:${pattern.source})|`, pattern.flags.replace(/[gdy]/g, ''));
  const groups = (probe.exec('')?.length ?? 1) - 1;
  if (capture > groups) throw new PackError(`${where}: capture group ${capture} does not exist`);

  const context = spec.context;
  return {
    id: spec.id,
    label: spec.label,
    why: spec.why,
    pattern,
    ...(capture > 0 ? { capture } : {}),
    ...(spec.boundary
      ? {
          boundary: {
            ...(spec.boundary.before ? { before: boundaryClass(spec.boundary.before, where)! } : {}),
            ...(spec.boundary.after ? { after: boundaryClass(spec.boundary.after, where)! } : {}),
          },
        }
      : {}),
    ...(spec.reject?.length
      ? { reject: spec.reject.map((p) => compile(p, { flags, where: `${where} reject`, portable: false, anchor: 'prefix' })) }
      : {}),
    ...(spec.validators?.length
      ? {
          validate: ((validators) => (value: string) => validators.every((check) => check(value)))(
            spec.validators.map((v) => buildValidator(v, where)),
          ),
        }
      : {}),
    mask: buildMask(spec.mask, where),
    default: spec.default,
    ...(spec.tags?.length ? { tags: spec.tags } : {}),
    risk: spec.risk,
    ...(spec.priority ? { priority: spec.priority } : {}),
    confidence: spec.confidence,
    ...(spec.refine ? { refine: true } : {}),
    ...(spec.prefilter?.length ? { prefilter: spec.prefilter } : {}),
    ...(context
      ? {
          context: {
            ...(context.positive
              ? { positive: compile(context.positive, { flags: 'i', where: `${where} context`, portable: false, anchor: undefined }) }
              : {}),
            ...(context.negative
              ? { negative: compile(context.negative, { flags: 'i', where: `${where} context`, portable: false, anchor: undefined }) }
              : {}),
            ...(context.window ? { window: context.window } : {}),
          },
        }
      : {}),
  };
}

/**
 * Compile an FRS-1 pack document into detectors this engine can run.
 * Throws {@link PackError} for anything it cannot honour exactly.
 */
export function loadPack(document: PackDocument): Pack {
  if (document?.spec !== SPEC_REVISION) {
    throw new PackError(
      `unsupported pack revision ${JSON.stringify(document?.spec)}; this engine implements ${SPEC_REVISION}`,
    );
  }
  if (!Array.isArray(document.detectors) || document.detectors.length === 0) {
    throw new PackError('a pack must declare at least one detector');
  }
  const detectors: Detector[] = [];
  const byId = new Map<string, Detector>();
  for (const spec of document.detectors) {
    const detector = toDetector(spec);
    if (byId.has(detector.id)) throw new PackError(`duplicate detector id ${JSON.stringify(detector.id)}`);
    byId.set(detector.id, detector);
    detectors.push(detector);
  }
  return {
    id: document.id,
    version: document.version,
    title: document.title ?? document.id,
    detectors,
    byId,
    ...(document.confidenceModel ? { confidenceModel: document.confidenceModel } : {}),
  };
}
